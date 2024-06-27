---
layout: post
title: A Short Tale of Sysctl
---

![Untitled](/assets/syscallCover.jpeg)

The topic of this blog post is not new. Other people have done a better job explaining how to analyze `syscalls`. Please see the following [presentation](https://youtu.be/qFLJjByneA4?si=ofEOOmSIk2_aIXau) and [training](https://www.youtube.com/live/sgNDYgLyAP4?si=BI_juNbKwFl2swu7&t=12395) on the subject by [Hexploitable](https://x.com/Hexploitable). 

To preface I will not include a script or any reference to the application's bundle name. I will also leave the scripting exercise up to the reader. I mainly want to discuss a jailbreak protection found in mobile reversing that I have yet to run into.  

### What is a syscall?

A system call or [syscall](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) is a lower-level request or command made to the OS kernel. Think of this as the lowest level of communication between userland (application) to the kernel asking for a service such as a file operation or network-level communication. 

**What is sysctl**

In short, [sysctl](https://developer.apple.com/documentation/installer_js/system/1812308-sysctl) is a system call responsible for gathering data about an operating system like kernel-related data or hardware components. 

Reading the man page for `sysctl` we can see more than one flag is present that will allow us to read kernel-related flags: 

```
     kern.osrelease                              string        no
     kern.osrevision                             integer       no
     kern.ostype                                 string        no
     kern.osversion                              string        yes
```

If we are to run the following command in a macOS terminal we should get something like the following:

```
❯ sysctl kern.version
kern.version: Darwin Kernel Version 23.5.0: Wed May  1 20:12:58 PDT 2024; root:xnu-10063.121.3~5/RELEASE_ARM64_T6000
```

Now that we have some level of character-building for our story let's dig into the analysis.

### Investigation

During my initial investigation, I installed and attempted to start the application on a jailbroken rootful and rootless device. I was met with two states one that would either stop the execution of what we will call the “Login ViewController” on the rootful device or state two on a rootless device where the app would continue execution to the Login prompt. Based on this side-by-side behavior, I deduced that some checks were being done against the device in the rootful state. 

My thought process was first, to dig into the strings referenced in the binary and the use of the [NSFileManager](https://developer.apple.com/documentation/foundation/filemanager) class. Using frida-trace I saw that a specific ViewController was loaded called and disallowed the user from login into the application. This was a dead end so I decided to pivot into searching for various system calls. 

I used a frida script to start tracing the open, read, getpid, etc. In hopes that maybe a process was being caught or a file path… Using this same frida script to monitor the onLeave and onEnter callbacks I found that sysctl was the one system call being used for this jailbreak protection. It was called multiple times during the start of the application. I noticed various calls to the following in the mibs value of sysctl. 

```
        "1,1": "KERN_OSTYPE",
        "1,2": "KERN_OSRELEASE",
        "1,4": "KERN_VERSION",
        "1,24": "KERN_HOSTNAME",
```

### Comparison on sysctl

Sysctl felt like a decent candidate since it was likely doing a check against the kernel. Also I could not find another reasonable system call used in the application binary that would protect an unsupported version of the OS. Using r2 we can see when listing the symbols sysctl is indeed being used.

```
[0x100be0000]> is~+sysctl
0x0 u sysctl
0x0 u sysctlbyname
```

and the binary contains more than one cross-reference to sysctl. 

```
[0x1000061d0]> axt 0x100e3ba60
sym.func.1000570e4 0x10005725c [CALL:--x] bl sym.imp.sysctl
sym.func.1001c4398 0x1001c4420 [CALL:--x] bl sym.imp.sysctl
sym.func.100a748a4 0x100a748ec [CALL:--x] bl sym.imp.sysctl
sym.func.100a9dc08 0x100a9dc68 [CALL:--x] bl sym.imp.sysctl
sym.func.100b78f48 0x100b78fa0 [CALL:--x] bl sym.imp.sysctl
sym.func.100b78f48 0x100b79068 [CALL:--x] bl sym.imp.sysctl
sym.func.100b92634 0x100b926b8 [CALL:--x] bl sym.imp.sysctl
sym.func.100c6d2a0 0x100c6d300 [CALL:--x] bl sym.imp.sysctl
sym.func.100d54ae4 0x100d54b64 [CALL:--x] bl sym.imp.sysctl
sym.func.100d54ae4 0x100d54bf0 [CALL:--x] bl sym.imp.sysctl
[TRUNCATED]
```

Interestingly each function above contained a [cbz](https://developer.arm.com/documentation/ddi0597/2024-03/Base-Instructions/CBNZ--CBZ--Compare-and-Branch-on-Nonzero-or-Zero-?lang=en) or compare branch zero right after the branch with link operation for the sysctl system call. And the amount of kernel checks I was from sysctl were the same number of xrefs. So this was likely the culprit of the check being done.

```
[0x1001c4398]> pdga @ sym.func.1001c4398 | grep -i cbz -B 1
    0x1001c4420 bl sym.imp.sysctl               |    iVar1 = sym.imp.sysctl(iVar3 + 0x20, 2, &iStack_48, &uStack_58, 0, 0);
    0x1001c4424 cbz w0, 0x1001c44ec             |    if (iVar1 == 0) {
```

If we seek the specified function and instructions. We see an if-else statement that does a comparison against the 32-bit integer iVar1 which is the value of the sysctl system call. So if this integer is equal to zero it will run the block of code inside the if statement. 

```
    0x1001c4424 cbz w0, 0x1001c44ec             |    if (iVar1 == 0) {
    0x1001c44f0 bl sym.imp.time                 |        sym.imp.time(&iStack_50);
    0x1001c44f8 bl sym.imp.swift_bridgeObjectRelease    |        sym.imp.swift_bridgeObjectRelease(iVar3);
    0x1001c4504 b.vs 0x1001c4538                |        if (SBORROW8(iStack_50, iStack_48)) {
    0x1001c4538 brk 1                           |    // WARNING: Treating indirect jump as call
    0x1001c4538 brk 1                           |            UNRECOVERED_JUMPTABLE = SoftwareBreakpoint(1, 0x1001c453c);
    0x1001c4538 brk 1                           |            (*UNRECOVERED_JUMPTABLE)();
    0x1001c4538 brk 1                           |            return;
                                                |        }
    0x1001c4508 scvtf d0, x8                    |        fVar6 = iStack_50 - iStack_48;
                                                |    }
```

### Bypass

The bypass was simple enough all I did was change the value of sysctl to the expected value of `0x0`.  This successfully altered the if-else statement in the application to display the login prompt.
