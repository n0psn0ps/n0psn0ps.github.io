---
layout: post
title: Peeling Back the Layers of an Onion: Syscalls & ASM
---

![The Art Of Nick Blinko.jpeg](Peeling%20Back%20the%20Layers%20of%20an%20Onion%20Syscalls%20&%20ASM%20d35e654a51374a588b7a54e07d60b13b/The_Art_Of_Nick_Blinko.jpeg)

Recently I wrote a [blog post](https://n0psn0ps.github.io/2024/06/27/A-Short-Tale-of-Sysctl/) on a mobile application I was testing. The application implemented a protection that disallowed the user from accessing the main login and dashboard of the app. I racked my brain against the problem over a weekend and wrote two demo applications to try and replicate the protection I saw. 

For one I noticed a few inconsistencies with this application. I got mixed results when I searched for the supervisor call using the `/ask` command in r2frida. Sometimes the output would point to the app's SVC instructions and other times I would get zero results back. When I did get results back it timed out the application and I would not get any results from my r2pipe script. 

To replicate this issue, I decided to write an iOS application in a mix of Swift and Assembly using the `access` system call. To understand what the access system call does read more [here](https://man7.org/linux/man-pages/man2/access.2.html). At a basic level, it does the following:

> Checks whether the calling process can access the file *pathname*.
> 

What I decided to implement in the ASM code was to check known paths and binaries on a jailbroken device. These paths would not be present on a jailed device. Typically in C, our code would look something like the following:

```python
[TRUNCATED]
    int fd = access("/bin/bash", F_OK);
[TRUNCATED]
```

Then in ASM to call the `access` syscall would look something like this:

```python
[TRUNCATED]
    mov x16, #33 // SYS_ACCESS (access)
    svc #0
[TRUNCATED]
```

When using a system call we use the `MOV` instruction along with the [*syscall number*](https://theapplewiki.com/wiki/Kernel_Syscalls) and register x16. 

> x16 and x17 - Intra-procedural Call Registers. Temporary registers for immediate values. They are also used for indirect function calls and PLT (Procedure Linkage Table) stubs. x16 is used as the system call number for the svc instruction in macOS.
> 

Our system call number for access is 33 or #33 in our assembly code. You can reference the syscall header [file](https://opensource.apple.com/source/xnu/xnu-1228/bsd/sys/syscall.h.auto.html) but in r2frida you can search using the `ask` command. I will talk about this later in approach 2. 

```python
[0x100dfa434]> ask? | grep access
0x80.284=access_extended
0x80.33=access
0x80.466=faccessat
access=0x80,33,0,
access_extended=0x80,284,0,
faccessat=0x80,466,0,
```

### Layer 0x1: Function Level Bypass

My first approach is to modify the Swift `checkForJailbreak` function then the return value of `check_jailbreak`. It is simple enough to use the same approach in my other blog post. The function in the original code will look like this:

```python
   func checkForJailbreak() -> Bool {
        return check_jailbreak() != 0
    }
```

And in r2frida like this:

```python
[0x102fc6434]> :iE~+jail
[TRUNCATED]
0x10481c000 f check_jailbreak
```

or

```python
[0x102fc6434]> :iE~+jail
[TRUNCATED]
0x10481d51c f $s9svcCaller11ContentViewV17checkForJailbreakSbyF
```

We can approach this bypass in two ways. First locating the address of the function and then dynamically tracing it. This will allow us to observe the return value of the function. As I had mentioned prior in the first section of this post the access system call will take a file path value and store that into a int var. This var will then contain either a `1` or `0`. We can confirm this based on the `Retval` in the terminal output. 

```python
[0x102fc6434]> :iE~+jail
[TRUNCATED]
0x10481d51c f $s9svcCaller11ContentViewV17checkForJailbreakSbyF
[0x102fc6434]> :dtf 0x10481d51c
true
[0x102fc6434]> :dc
INFO: resumed spawned process
[0x102fc6434]> [dtf onLeave][Wed Aug 28 2024 22:31:45 GMT-0700] 0x10481d51c@0x10481d51c - args: . Retval: 0x1
```

Second, we will want to dynamically instrument the function’s value from `0x1` to `0x0`, as seen below using `:di0`. This will be the same for both functions I called out above.

```python
[0x102fc6434]> :di0 `:iE~+check_jailbreak[0]`
[0x102fc6434]> :dc
```

### Layer 0x2: ASM Instruction Bypass

My third approach is to step back and search for the responsible system call and modify the underlying MOV instructions. We will want to set our config evals for the iOS binary. This is so we can explicitly search specific assembly instructions. 

```python
.:e/
```

Then using the following one-liner in r2frida we can search and grep out the supervisor calls.

```python
[0x104bca434]> /ai svc | grep svc
0x104bc8088             010000d4  svc 0
```

Once we find the appropriate address of the supervisor call we will want to use `pd` along with `-50`. This will allow us to backtrace and look for the system call in the assembly code, plus the associated `MOV` instructions which will move the value of `1` into `x0`. You can see each of these commented in the text block below after the `CBZ` instructions.

```python
[0x104bca434]> pd -50 @ 0x104bc8088
          [TRUNCATED]
            ;-- sym.check_jailbreak:
            0x104bc8000      fd7bbfa9       stp x29, x30, [sp, -0x10]!
            0x104bc8004      fd030091       mov x29, sp
            0x104bc8008      a0040010       adr x0, sym.msg_start      ; 0x104bc809c
            0x104bc800c      52130094       bl 0x104bccd54
            0x104bc8010      80060010       adr x0, sym.paths          ; 0x104bc80e0
            0x104bc8014      610180d2       mov x1, 0xb
            0x104bc8018      0a000094       bl sym.check_paths
            0x104bc801c      a0040050       adr x0, sym.msg_end        ; 0x104bc80b2
            0x104bc8020      4d130094       bl 0x104bccd54
        ┌─< 0x104bc8024      800000b4       cbz x0, sym.no_jailbreak
        │   0x104bc8028      200080d2       mov x0, 1 //instruction one
        │   ;-- hit0_40:
        │   0x104bc802c      fd7bc1a8       ldp x29, x30, [sp], 0x10
        │   0x104bc8030      c0035fd6       ret
        │   ;-- sym.no_jailbreak:
        │   ;-- hit0_41:
        └─> 0x104bc8034      000080d2       mov x0, 0
            ;-- hit0_42:
            0x104bc8038      fd7bc1a8       ldp x29, x30, [sp], 0x10
            0x104bc803c      c0035fd6       ret
            ;-- sym.check_paths:
            0x104bc8040      f457bfa9       stp x20, x21, [sp, -0x10]!
            0x104bc8044      f40300aa       mov x20, x0
            0x104bc8048      f50301aa       mov x21, x1
            ;-- sym.check_next_path:
        ┌─> 0x104bc804c      808640f8       ldr x0, [x20], 8           ; 0xee ; 238
       ┌──< 0x104bc8050      000100b4       cbz x0, sym.all_paths_checked
       │╎   0x104bc8054      a0030070       adr x0, sym.msg_check_path ; 0x104bc80cb
       │╎   0x104bc8058      3f130094       bl 0x104bccd54
       │╎   0x104bc805c      08000094       bl sym.file_exists
       │└─< 0x104bc8060      60ffffb4       cbz x0, sym.check_next_path
       │    0x104bc8064      200080d2       mov x0, 1 //instruction two
       │    ;-- hit0_43:
       │    0x104bc8068      f457c1a8       ldp x20, x21, [sp], 0x10
       │    0x104bc806c      c0035fd6       ret
       │    ;-- sym.all_paths_checked:
       │    ;-- hit0_44:
       └──> 0x104bc8070      000080d2       mov x0, 0
            ;-- hit0_45:
            0x104bc8074      f457c1a8       ldp x20, x21, [sp], 0x10
            0x104bc8078      c0035fd6       ret
            ;-- sym.file_exists:
            0x104bc807c      fd7bbfa9       stp x29, x30, [sp, -0x10]!
            0x104bc8080      fd030091       mov x29, sp
            0x104bc8084      300480d2       mov x16, 0x21              ; '!'
```

Additionally, we can grep the `MOV` instructions associated with the access system call using the following one-liner.

```python
[0x104bca434]> pd -50 @ 0x104bc8088 | grep 'mov x0, 1'
        │   0x104bc8028      200080d2       mov x0, 1
       │    0x104bc8064      200080d2       mov x0, 1
```

To bypass this check we want to change the value of each `mov x0, 1` to `mov x0, 0`.

```python
wa mov x0, 0 @ 0x104bc8028; wa mov x0, 0 @ 0x104bc8064
```

Lastly, our script will look something like this: 

```python
# file checker test
import r2pipe
import time

r = r2pipe.open("frida://spawn/usb//n0ps.svcCaller")

r.cmd(".:e/")
print("[x] Calculating SVC addresses")

# locate supervisor call 
svcInst = r.cmd("/ai svc | grep svc").split()
address = svcInst[0]

# modify mov x0, 1 to mov x0, 0
output = r.cmd("pd -50 @ " + address + " | grep 'mov x0, 1'").split()
print(output)
r.cmd("wa mov x0, 0 @ " + output[1])
r.cmd("wa mov x0, 0 @ " + output[7])

# continue application
r.cmd(":dc")

time.sleep(10000)

```

### Conclusion

In this post I wanted to display an alternative method for searching assembly instructions at runtime. Back tracing from a supervisor call and attempting to locate the `MOV` instructions associated with the access system call. If you would like to test this out for yourself you can download the IPA and script [here](https://github.com/n0psn0ps/svcCaller/tree/main). 

### Resources

I wanted to include at least a few articles for the reader. Each of the links below are important to  understanding the `libSystem.dylib` library and the associated system calls on macOS / iOS.

[https://gpanders.com/blog/exploring-mach-o-part-1/](https://gpanders.com/blog/exploring-mach-o-part-1/) 

[https://developer.arm.com/documentation/102374/0101/System-calls?lang=en](https://developer.arm.com/documentation/102374/0101/System-calls?lang=en) 

[https://eclecticlight.co/?s=assembly](https://eclecticlight.co/?s=assembly) 

[https://www.amazon.com/64-Bit-Assembly-Language-Larry-Pyeatt/dp/0128192216](https://www.amazon.com/64-Bit-Assembly-Language-Larry-Pyeatt/dp/0128192216)
