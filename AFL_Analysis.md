American Fuzzy Lop（AFL）
=
# 插桩
* AFL编译完之后会生成afl-gcc，afl-clang，afl-as。后续使用afl-gcc对源码编译时就会进行插桩。
  * afl-clang也是重定向到afl-gcc
## afl-gcc
* 首先看下afl-gcc代码，`main`函数完成寻找`afl-as`和对编译参数调整。
```c
  find_as(argv[0]);
  edit_params(argc, argv);
  execvp(cc_params[0], (char**)cc_params);
```
* 在`edit_params`中，会把`afl-gcc`替换为`gcc`(`afl-clang`替换为`clang`)。而且会添加`-B`参数，使用`afl-as`做汇编。
```c
  cc_params[cc_par_cnt++] = "-B";
  cc_params[cc_par_cnt++] = as_path;
```
* 所以，`afl-gcc`主要是对`gcc`做对封装，最终编译还是调用对`gcc`。并且使用`afl-as`汇编。
## afl-as
* 函数`add_instrumentation`完成对代码对插桩。
```c
printf(outf, use_64bit ? trampoline_fmt_64 : trampoline_fmt_32, R(MAP_SIZE));
```
* 以32位为例，插入的代码如下
```
static const u8* trampoline_fmt_32 =

  "\n"
  "/* --- AFL TRAMPOLINE (32-BIT) --- */\n"
  "\n"
  ".align 4\n"
  "\n"
  "leal -16(%%esp), %%esp\n"
  "movl %%edi,  0(%%esp)\n"
  "movl %%edx,  4(%%esp)\n"
  "movl %%ecx,  8(%%esp)\n"
  "movl %%eax, 12(%%esp)\n"
  "movl $0x%08x, %%ecx\n"
  "call __afl_maybe_log\n"
  "movl 12(%%esp), %%eax\n"
  "movl  8(%%esp), %%ecx\n"
  "movl  4(%%esp), %%edx\n"
  "movl  0(%%esp), %%edi\n"
  "leal 16(%%esp), %%esp\n"
  "\n"
  "/* --- END --- */\n"
  "\n";
  ```
  * 这段代码主要实现的功能为
    1. 开栈，保存`edi` `edx` `ecx` `eax`寄存器的值
    2. 对`ecx`赋值为一个随机值，并调用`__afl_maybe_log`；该随机值为每个代码块的标识
    3. 恢复寄存器和栈
  * `__afl_maybe_log`主要完成以下功能
    1. 将当前代码块的随机值和上一代码块随机值做异或
    2. 将异或值作为偏移，将共享内存(64kb)中对应字节累加，标识该分支的命中次数
    3. 将当前代码块随机值右移一位，并保存为`__afl_prev_loc`
  ```c
  "__afl_maybe_log:\n"
  "\n"
  "  lahf\n"
  "  seto %al\n"
  "\n"
  "  /* Check if SHM region is already mapped. */\n"
  "\n"
  "  movl  __afl_area_ptr, %edx\n"
  "  testl %edx, %edx\n"
  "  je    __afl_setup\n"
  "\n"
  "__afl_store:\n"
  "\n"
  "  /* Calculate and store hit for the code location specified in ecx. There\n"
  "     is a double-XOR way of doing this without tainting another register,\n"
  "     and we use it on 64-bit systems; but it's slower for 32-bit ones. */\n"
  "\n"
#ifndef COVERAGE_ONLY
  "  movl __afl_prev_loc, %edi\n"
  "  xorl %ecx, %edi\n"
  "  shrl $1, %ecx\n"
  "  movl %ecx, __afl_prev_loc\n"
#else
  "  movl %ecx, %edi\n"
#endif /* ^!COVERAGE_ONLY */
  "\n"
#ifdef SKIP_COUNTS
  "  orb  $1, (%edx, %edi, 1)\n"
#else
  "  incb (%edx, %edi, 1)\n"
#endif /* ^SKIP_COUNTS */
  "\n"
  "__afl_return:\n"
  "\n"
  "  addb $127, %al\n"
  "  sahf\n"
  "  ret\n"
  ...
  ```
  * 64kb的内存空间大概可以保存2k-10k的程序分支点，对于复杂程序可能出现重用情况
  * 对当前代码块随机值做右移操作可以区分`A->A`和`B->B`。在不右移对情况下都为0
