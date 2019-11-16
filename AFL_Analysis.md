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
    2. 对`ecx`赋值为一个随机值`R(MAP_SIZE)`，并调用`__afl_maybe_log`；该随机值为每个代码块的标识
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
# afl-fuzz
编译target完成后，就可以通过afl-fuzz开始fuzzing了。其大致思路是，对输入的seed文件不断地变化，并将这些mutated input喂给target执行，检查是否会造成崩溃。因此，fuzzing涉及到大量的fork和执行target的过程。
AFL实现了一套fork server机制。其基本思路是：启动target进程后，target会运行一个fork server；fuzzer并不负责fork子进程，而是与这个fork server通信，并由fork server来完成fork及继续执行目标的操作。这样设计的最大好处，就是不需要调用execve()，从而节省了载入目标文件和库、解析符号地址等重复性工作。
```
afl-fuzz --fork--> (forkserver --execve--> target) --fork--> target's child
    |                  |
    <-------pipe------->
```
## fork server
* `init_forkserver`函数初始化`forkerserver`。此时父进程仍为`fuzzer`，子进程为`forkerserver`。
* 父进程和子进程之间采用管道通信。具体使用了2个管道，一个用于传递状态，另一个用于传递命令。
* 子进程创建完成后就调用`execev`执行目标被fuzz进程。
```c
  if (pipe(st_pipe) || pipe(ctl_pipe)) PFATAL("pipe() failed");
  forksrv_pid = fork();
  if (!forksrv_pid) {
    ...
    if (dup2(ctl_pipe[0], FORKSRV_FD) < 0) PFATAL("dup2() failed");
    if (dup2(st_pipe[1], FORKSRV_FD + 1) < 0) PFATAL("dup2() failed");  
    ...
    execv(target_path, argv);
  }
  ...
  fsrv_ctl_fd = ctl_pipe[1];
  fsrv_st_fd  = st_pipe[0];
  ...
  rlen = read(fsrv_st_fd, &status, 4);
  ...
  /* If we have a four-byte "hello" message from the server, we're all set.
     Otherwise, try to figure out what went wrong. */
  if (rlen == 4) {
    OKF("All right - fork server is up.");
    return;
  }  
```
* 子进程`forkserver`与父进程通信代码在插桩代码`__afl_maybe_log`中。
* `__afl_forkserver`向管道写入数据，通知父进程。然后进入等待，通过`__afl_fork_wait_loop`读取管道数据。接收都命令就`fork`子进程(被测程序)
```c
  "__afl_forkserver:\n"
  "\n"
  "  /* Enter the fork server mode to avoid the overhead of execve() calls. */\n"
  "\n"
  "  pushl %eax\n"
  "  pushl %ecx\n"
  "  pushl %edx\n"
  "\n"
  "  /* Phone home and tell the parent that we're OK. (Note that signals with\n"
  "     no SA_RESTART will mess it up). If this fails, assume that the fd is\n"
  "     closed because we were execve()d from an instrumented binary, or because\n" 
  "     the parent doesn't want to use the fork server. */\n"
  "\n"
  "  pushl $4          /* length    */\n"
  "  pushl $__afl_temp /* data      */\n"
  "  pushl $" STRINGIFY((FORKSRV_FD + 1)) "  /* file desc */\n"
  "  call  write\n"
  "  addl  $12, %esp\n"
  "\n"
  "  cmpl  $4, %eax\n"
  "  jne   __afl_fork_resume\n"
  "\n"
  "__afl_fork_wait_loop:\n"
  "\n"
  "  /* Wait for parent by reading from the pipe. Abort if read fails. */\n"
  "\n"
  "  pushl $4          /* length    */\n"
  "  pushl $__afl_temp /* data      */\n"
  "  pushl $" STRINGIFY(FORKSRV_FD) "        /* file desc */\n"
  "  call  read\n"
  "  addl  $12, %esp\n"
  "\n"
  "  cmpl  $4, %eax\n"
  "  jne   __afl_die\n"
  "\n"
  "  /* Once woken up, create a clone of our process. This is an excellent use\n"
  "     case for syscall(__NR_clone, 0, CLONE_PARENT), but glibc boneheadedly\n"
  "     caches getpid() results and offers no way to update the value, breaking\n"
  "     abort(), raise(), and a bunch of other things :-( */\n"
  "\n"
  "  call fork\n"
  "\n"
  "  cmpl $0, %eax\n"
  "  jl   __afl_die\n"
  "  je   __afl_fork_resume\n"
  "\n"
  ```
  * forkserver fork出来的子进程跳转到`__afl_fork_resume`，会关闭管道，并跳转到`__afl_store`，继续开始执行被测程序。
  ```c
    "__afl_fork_resume:\n"
  "\n"
  "  /* In child process: close fds, resume execution. */\n"
  "\n"
  "  pushl $" STRINGIFY(FORKSRV_FD) "\n"
  "  call  close\n"
  "\n"
  "  pushl $" STRINGIFY((FORKSRV_FD + 1)) "\n"
  "  call  close\n"
  "\n"
  "  addl  $8, %esp\n"
  "\n"
  "  popl %edx\n"
  "  popl %ecx\n"
  "  popl %eax\n"
  "  jmp  __afl_store\n"
  "\n"
  ```
  * forkserver将fork出来的子进程的pid写入管道，通知父进程`fuzzer`。然后等待子进程执行完毕，将子进程结束状态写入管道通知父进程。接着继续进入`__afl_fork_wait_loop`等待父进程下发命令。
  ```c
  "  /* In parent process: write PID to pipe, then wait for child. */\n"
  "\n"
  "  movl  %eax, __afl_fork_pid\n"
  "\n"
  "  pushl $4              /* length    */\n"
  "  pushl $__afl_fork_pid /* data      */\n"
  "  pushl $" STRINGIFY((FORKSRV_FD + 1)) "      /* file desc */\n"
  "  call  write\n"
  "  addl  $12, %esp\n"
  "\n"
  "  pushl $0             /* no flags  */\n"
  "  pushl $__afl_temp    /* status    */\n"
  "  pushl __afl_fork_pid /* PID       */\n"
  "  call  waitpid\n"
  "  addl  $12, %esp\n"
  "\n"
  "  cmpl  $0, %eax\n"
  "  jle   __afl_die\n"
  "\n"
  "  /* Relay wait status to pipe, then loop back. */\n"
  "\n"
  "  pushl $4          /* length    */\n"
  "  pushl $__afl_temp /* data      */\n"
  "  pushl $" STRINGIFY((FORKSRV_FD + 1)) "  /* file desc */\n"
  "  call  write\n"
  "  addl  $12, %esp\n"
  "\n"
  "  jmp __afl_fork_wait_loop\n"
  "\n"
  ```
  * 父进程通过`run_target`来向管道下发命令，通知forkserver执行fork
  ```c
      s32 res;
    /* In non-dumb mode, we have the fork server up and running, so simply
       tell it to have at it, and then read back PID. */
    if ((res = write(fsrv_ctl_fd, &prev_timed_out, 4)) != 4) {
      if (stop_soon) return 0;
      RPFATAL(res, "Unable to request new process from fork server (OOM?)");
    }    
    if ((res = read(fsrv_st_fd, &child_pid, 4)) != 4) {
      if (stop_soon) return 0;
      RPFATAL(res, "Unable to request new process from fork server (OOM?)");
    }
    if (child_pid <= 0) FATAL("Fork server is misbehaving (OOM?)");
  }
  ```
  * 父进程记录被测程序的推出状态
  ```c
      if ((res = read(fsrv_st_fd, &status, 4)) != 4) {
      if (stop_soon) return 0;
      RPFATAL(res, "Unable to communicate with fork server (OOM?)");
    }
    ...
    if ((res = read(fsrv_st_fd, &status, 4)) != 4) {
      if (stop_soon) return 0;
      RPFATAL(res, "Unable to communicate with fork server (OOM?)");
    }
```  
# qemu mode
## 插桩
* qemu模式下，插桩的代码也是`afl_maybe_log`。不同于编译插桩，qemu模式下不是用随机值来标识代码块。而是通过当前代码块地址计算得到`cur_loc  = (cur_loc >> 4) ^ (cur_loc << 8); cur_loc &= MAP_SIZE - 1;`，然后将对应共享内存中的字节累加。
```c
static inline void afl_maybe_log(abi_ulong cur_loc) {

  static __thread abi_ulong prev_loc;

  /* Optimize for cur_loc > afl_end_code, which is the most likely case on
     Linux systems. */

  if (cur_loc > afl_end_code || cur_loc < afl_start_code || !afl_area_ptr)
    return;

  /* Looks like QEMU always maps to fixed locations, so ASAN is not a
     concern. Phew. But instruction addresses may be aligned. Let's mangle
     the value to get something quasi-uniform. */

  cur_loc  = (cur_loc >> 4) ^ (cur_loc << 8);
  cur_loc &= MAP_SIZE - 1;

  /* Implement probabilistic instrumentation by looking at scrambled block
     address. This keeps the instrumented locations stable across runs. */

  if (cur_loc >= afl_inst_rms) return;

  afl_area_ptr[cur_loc ^ prev_loc]++;
  prev_loc = cur_loc >> 1;

}
```
## forkserver  
* 与编译模式类似，`forkserver`启动后会向管道写数据通知`fuzzer`，然后进入死循环等待命令下发。
```c
  if (write(FORKSRV_FD + 1, tmp, 4) != 4) return;
  ...
  while (1) {
    ...
    if (read(FORKSRV_FD, tmp, 4) != 4) exit(2);
    ...
  }
``` 
* 接收到命令后，就会fork子进程开始fuzz
```c
    child_pid = fork();
    if (child_pid < 0) exit(4);

    if (!child_pid) {

      /* Child process. Close descriptors and run free. */

      afl_fork_child = 1;
      close(FORKSRV_FD);
      close(FORKSRV_FD + 1);
      close(t_fd[0]);
      return;

    }
```
* forkserver等待子进程执行完，并向fuzzer返回子进程结束状态
```c
    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) exit(5);

    /* Collect translation requests until child dies and closes the pipe. */

    afl_wait_tsl(cpu, t_fd[0]);

    /* Get and relay exit status to parent. */

    if (waitpid(child_pid, &status, 0) < 0) exit(6);
    if (write(FORKSRV_FD + 1, &status, 4) != 4) exit(7);
```
# 变异
* AFL维护了一个队列(queue)，每次从这个队列中取出一个文件，对其进行大量变异，并检查运行后是否会引起目标崩溃、发现新路径等结果。变异的主要类型如下：
1. bitflip，按位翻转，1变为0，0变为1
2. arithmetic，整数加/减算术运算
3. interest，把一些特殊内容替换到原文件中
4. dictionary，把自动生成或用户提供的token替换/插入到原文件中
5. havoc，中文意思是“大破坏”，此阶段会对原文件进行大量变异，具体见下文
6. splice，中文意思是“绞接”，此阶段会将两个文件拼接起来得到一个新的文件

## bitflip
* bitflip会根据翻转量/步长进行多种不同的翻转，按照顺序依次为：
1. bitflip 1/1，每次翻转1个bit，按照每1个bit的步长从头开始
2. bitflip 2/1，每次翻转相邻的2个bit，按照每1个bit的步长从头开始
3. bitflip 4/1，每次翻转相邻的4个bit，按照每1个bit的步长从头开始
4. bitflip 8/8，每次翻转相邻的8个bit，按照每8个bit的步长从头开始，即依次对每个byte做翻转
5. bitflip 16/8，每次翻转相邻的16个bit，按照每8个bit的步长从头开始，即依次对每个word做翻转
6. bitflip 32/8，每次翻转相邻的32个bit，按照每8个bit的步长从头开始，即依次对每个dword做翻转
### 自动touken检测
* 在进行bitflip 1/1变异时，对于每个byte的最低位(least significant bit)翻转还进行了额外的处理：如果连续多个bytes的最低位被翻转后，程序的执行路径都未变化，而且与原始执行路径不一致(检测程序执行路径的方式可见上篇文章中“分支信息的分析”一节)，那么就把这一段连续的bytes判断是一条token。
* 为了控制这样自动生成的token的大小和数量，AFL还在`config.h`中通过宏定义了限制
```c
/* Length limits for auto-detected dictionary tokens: */

#define MIN_AUTO_EXTRA      3
#define MAX_AUTO_EXTRA      32
/* Maximum number of auto-extracted dictionary tokens to actually use in fuzzing
   (first value), and to keep in memory as candidates. The latter should be much
   higher than the former. */

#define USE_AUTO_EXTRAS     50
#define MAX_AUTO_EXTRAS     (USE_AUTO_EXTRAS * 10)
```
### effector map
* 在进行bitflip 8/8变异时，AFL还生成了一个非常重要的信息：effector map。
* 在对每个byte进行翻转时，如果其造成执行路径与原始路径不一致，就将该byte在effector map中标记为1，即“有效”的，否则标记为0，即“无效”的。后续fuzz会重点针对有效字节。
## arithmetic
* 与bitflip类似的是，arithmetic根据目标大小的不同，也分为了多个子阶段：
1. arith 8/8，每次对8个bit进行加减运算，按照每8个bit的步长从头开始，即对文件的每个byte进行整数加减变异
2. arith 16/8，每次对16个bit进行加减运算，按照每8个bit的步长从头开始，即对文件的每个word进行整数加减变异
3. arith 32/8，每次对32个bit进行加减运算，按照每8个bit的步长从头开始，即对文件的每个dword进行整数加减变异
* 运算的上限在`config.h`中定义。
```c
/* Maximum offset for integer addition / subtraction stages: */

#define ARITH_MAX           35
```
* 对于运算后结果和`bitflip`一样的用例会直接跳过不执行。
## interest
* interest分为以下几个阶段
1. interest 8/8，每次对8个bit进替换，按照每8个bit的步长从头开始，即对文件的每个byte进行替换
2. interest 16/8，每次对16个bit进替换，按照每8个bit的步长从头开始，即对文件的每个word进行替换
3. interest 32/8，每次对32个bit进替换，按照每8个bit的步长从头开始，即对文件的每个dword进行替换
* interest值在`config.h`中定义
```c
#define INTERESTING_8 \
  -128,          /* Overflow signed 8-bit when decremented  */ \
  -1,            /*                                         */ \
   0,            /*                                         */ \
   1,            /*                                         */ \
   16,           /* One-off with common buffer size         */ \
   32,           /* One-off with common buffer size         */ \
   64,           /* One-off with common buffer size         */ \
   100,          /* One-off with common buffer size         */ \
   127           /* Overflow signed 8-bit when incremented  */

#define INTERESTING_16 \
  -32768,        /* Overflow signed 16-bit when decremented */ \
  -129,          /* Overflow signed 8-bit                   */ \
   128,          /* Overflow signed 8-bit                   */ \
   255,          /* Overflow unsig 8-bit when incremented   */ \
   256,          /* Overflow unsig 8-bit                    */ \
   512,          /* One-off with common buffer size         */ \
   1000,         /* One-off with common buffer size         */ \
   1024,         /* One-off with common buffer size         */ \
   4096,         /* One-off with common buffer size         */ \
   32767         /* Overflow signed 16-bit when incremented */

#define INTERESTING_32 \
  -2147483648LL, /* Overflow signed 32-bit when decremented */ \
  -100663046,    /* Large negative number (endian-agnostic) */ \
  -32769,        /* Overflow signed 16-bit                  */ \
   32768,        /* Overflow signed 16-bit                  */ \
   65535,        /* Overflow unsig 16-bit when incremented  */ \
   65536,        /* Overflow unsig 16 bit                   */ \
   100663045,    /* Large positive number (endian-agnostic) */ \
   2147483647    /* Overflow signed 32-bit when incremented */
```
## dictionary
* dictionary有如下几个阶段
1. user extras (over)，从头开始，将用户提供的tokens依次替换到原文件中
2. user extras (insert)，从头开始，将用户提供的tokens依次插入到原文件中
3. auto extras (over)，从头开始，将自动检测的tokens依次替换到原文件中
* 用户提供的tokens，是在词典文件中设置并通过`-x`选项指定的，如果没有则跳过相应的子阶段。
### user extras (over)
* AFL先按照长度从小到大进行排序，然后检查tokens的数量，如果数量大于预设的`MAX_DET_EXTRAS`（默认值为200），那么对每个token会根据概率来决定是否进行替换：
```c
#define MAX_DET_EXTRAS      200
```
```c
    for (j = 0; j < extras_cnt; j++) {

      /* Skip extras probabilistically if extras_cnt > MAX_DET_EXTRAS. Also
         skip them if there's no room to insert the payload, if the token
         is redundant, or if its entire span has no bytes set in the effector
         map. */

      if ((extras_cnt > MAX_DET_EXTRAS && UR(extras_cnt) >= MAX_DET_EXTRAS) ||
          extras[j].len > len - i ||
          !memcmp(extras[j].data, out_buf + i, extras[j].len) ||
          !memchr(eff_map + EFF_APOS(i), 1, EFF_SPAN_ALEN(i, extras[j].len))) {

        stage_max--;
        continue;

      }

      last_len = extras[j].len;
      memcpy(out_buf + i, extras[j].data, last_len);

      if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

      stage_cur++;

    }
``` 
* 这里的`UR(extras_cnt)`是运行时生成的一个0到`extras_cnt`之间的随机数。
### user extras (insert)
* 这个阶段没有对tokens数量的限制，全部tokens都会从原文件的第1个byte开始，依次向后插入；
* 由于原文件并未发生替换，所以`effector map`不会被使用。
* 这一子阶段最特别的地方，就是变异不能简单地恢复。AFL采取的方式是：将原文件分割为插入前和插入后的部分，再加上插入的内容，将这3部分依次复制到目标缓冲区中。
### auto extras (over)
* 这一阶段与`user extras (over)`很类似，区别在于，这里的`tokens`是最开始`bitflip`阶段自动生成的。
* 自动生成的`tokens`总量会由`USE_AUTO_EXTRAS`限制。
## havoc
* havoc包含了对原文件的多轮变异，每一轮都是将多种方式组合（stacked）而成
1. 随机选取某个bit进行翻转
2. 随机选取某个byte，将其设置为随机的interesting value
3. 随机选取某个word，并随机选取大、小端序，将其设置为随机的interesting value
4. 随机选取某个dword，并随机选取大、小端序，将其设置为随机的interesting value
5. 随机选取某个byte，对其减去一个随机数
6. 随机选取某个byte，对其加上一个随机数
7. 随机选取某个word，并随机选取大、小端序，对其减去一个随机数
8. 随机选取某个word，并随机选取大、小端序，对其加上一个随机数
9. 随机选取某个dword，并随机选取大、小端序，对其减去一个随机数
10. 随机选取某个dword，并随机选取大、小端序，对其加上一个随机数
11. 随机选取某个byte，将其设置为随机数
12. 随机删除一段bytes
13. 随机选取一个位置，插入一段随机长度的内容，其中75%的概率是插入原文中随机位置的内容，25%的概率是插入一段随机选取的数
14. 随机选取一个位置，替换为一段随机长度的内容，其中75%的概率是替换成原文中随机位置的内容，25%的概率是替换成一段随机选取的数
15. 随机选取一个位置，用随机选取的token（用户提供的或自动生成的）替换
16. 随机选取一个位置，用随机选取的token（用户提供的或自动生成的）插入
## splice
* splice是将两个seed文件拼接得到新的文件，并对这个新文件继续执行havoc变异。
* AFL在seed文件队列中随机选取一个，与当前的seed文件做对比。如果两者差别不大，就再重新随机选一个；如果两者相差比较明显，那么就随机选取一个位置，将两者都分割为头部和尾部。最后，将当前文件的头部与随机文件的尾部拼接起来，就得到了新的文件。
## cycle
* 当队列中的全部文件都变异测试后，就完成了一个`cycle`，整个队列又会从第一个文件开始，再次进行变异，不过与第一次变异不同的是，这一次就不需要再进行`deterministic fuzzing`(前4项)了。


