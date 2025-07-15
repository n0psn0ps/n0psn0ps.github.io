---
layout: post
title: ⏪ 8kSec Frida Lab Solution ⏪
---

![Untitled](/assets/blinko10.jpg)


This blog post explains how to bypass the Frida detection in the 8kSec iOS lab challenge titled "Frida in the Middle." I aimed to approach this lab using two distinct techniques to circumvent the protection mechanism at roughly three different locations. Generally, this lab can be solved with the first patch I created, but I will share all three of the scripts on my GitHub at the end of the blog post. 

### Analysis

Since the IPA is written in Swift and uses a trampoline executable to run the code, you need to load the debug dylib containing all the main functions.

The main dylib contains a Swift Boolean function that performs a socket check against localhost. This function takes four arguments—socket, address, address_len, and filedes—and returns either 0 or 1. It references a secondary function that points to freeaddrinfo and getaddrinfo. According to the man page:

```bash
...[F]unction is used to get a list of IP addresses and port numbers for host hostname and service servname.  It is a replacement for and provides more flexibility than the gethostbyname(3) and getservbyname(3) functions.
```

### Patch 1 - Boolean function

The first technique involved bypassing the main function I called out above. Starting with analyzing the included libraries of the IPA we use the following command:

```bash
:il
```

Our goal is to locate the exact function used to check for Frida in the dylib. Once we find out the library and function of interest. We can use the dynamic trace command to observe the output of the application when running on a jailbroken device that detects frida-server running.

To examine all the exported functions we can use this command:

```bash
:iE
```

Then use this command to dynamically trace the output of the function once the application starts on the iOS device. 

```bash
:dtf 0xsomeAddr
```

 We can then combine our final command into a one-liner like so. 

```bash
r.cmd('s `:il~+dylibName[0]`;:di0 `:iE~+someFunc[0]`')
```

Let's move on to technique number two. 

### Patch 2 - Localhost reference

Analyzing the same function in Ghidra, we see a reference that I called out above pointing to getaddrinfo. 

I renamed the variable for clarity during the reverse engineering process. 

```bash
getAddInfo = _getaddrinfo((char *)(lVar7 + 0x20),(char *)(lVar8 + 0x20),&aStack_88,&local_90);
```

This variable takes in four values, which match the parameters from the man page reference: *socket, address, address_len, and filedes*. By locating the reference to 127.0.0.1 in the code, we can use a NOP operation on that memory location to likely bypass the Frida detection check. 

Using Ghidra's string search command, we can find a reference to localhost. Examining the cross references leads us to the main function in the dylib that uses the getaddrinfo function to protect the app. 

```bash
[TRUNCATED]
        00008c94 00 00 1c 91     add        x0=>s_127.0.0.1_0000d700,x0,#0x700               = "127.0.0.1"
        00008c98 28 01 80 52     mov        w8,#0x9
        00008c9c e1 03 08 aa     mov        x1,x8
        00008ca0 28 00 80 52     mov        w8,#0x1
        00008ca4 e8 7f 00 b9     str        w8,[sp, #local_144]
[TRUNCATED]
```

After examining the previous opcodes in Ghidra to the r2frida function trace found with `pdr.`, I identified another `ADD` instruction earlier in the function. Logically, we can bypass the app's protection by applying a `NOP` operation to the second `ADD` instruction at the corresponding address. 

We will run the following commands:

```bash
s `:il~+dylibName[0]`;s `:iE~+someFunc[0]`; e anal.slow = false; e anal.nopskip = true; e emu.str = true; afr.; afna.;pdr.~+add
afn auto.sub.104c94b70 0x104c90c40
│ 0x104c90c4c      fdc30691       add x29, sp, 0x1b0
│ 0x104c90c94      00001c91       add x0, x0, 0x700
│ 0x104c90d4c      00201791       add x0, x0, 0x5c8
│ 0x104c90e28      08810091       add x8, x8, 0x20
│ 0x104c90e64      01810091       add x1, x8, 0x20
│ 0x104c90fe8      ff030791       add sp, sp, 0x1c0
```

And then we can use the `wao nop` command to `NOP` out the address:

```bash
wao nop @ 0x104c90c94;:dc
```

`wao` is to write over the desired op instruction - write at op? [over]write all ops? what address [is] obsolete? Let’s move on to the final bypass. 

### Patch 3 - Overwrite tbz

Using Ghidra to analyze the Mach-O binary, we can identify the ARM64 `TBZ` instruction that controls the nested if-else statement. 

```bash
  if ((getAddInfo == 0) && (local_90 != (addrinfo *)0x0)) {
    getAddInfo = _socket(local_90->ai_family,local_90->ai_socktype,local_90->ai_protocol);
    if (getAddInfo < 0) {
[TRUNCATED]
```

I renamed the variables to clarify the application logic in the nested if-else statement. Our focus is on the value returned by the getaddrinfo function, which performs a boolean comparison and returns either 0 or 1. 

If the variable is greater than 0, execution will continue to the next three lines and set the result to false. The paVar3 variable will then be passed to the defer function nested within our main function of interest.

```bash
 [TRUNCATED]
      _$s16functionOfInterestF6$deferL_yyF(paVar3);
      _swift_bridgeObjectRelease(uVar9);
      bVar4 = false;
    }
    else {
      local_1a8 = paVar3->ai_addr;
      if (local_1a8 == (sockaddr *)0x0) {
        local_1a8 = (sockaddr *)0x0;
      }
      iVar5 = _connect(getAddInfo,local_1a8,paVar3->ai_addrlen);
      _close(getAddInfo);
      bVar4 = iVar5 == 0;
      _$s16functionOfInterestF6$deferL_yyF(paVar3);
      _swift_bridgeObjectRelease(uVar9);
    }
```

Similar to the first section of the code block, the value of paVar3 will be passed to the defer function. We will then run a similar command to above, emulate various strings, and analyze the function location. 

This will give us the proper ARM64 instructions for the function. 

```bash
r.cmd('s `:il~+dylibName[0]`; s `:iE~+someFunc[0]`; e anal.slow = false; e anal.nopskip = true; e emu.str = true; afr.; afna.')
time.sleep(2)
r.cmd('wao nop @ `pdr.~+tbz[1]`')
r.cmd(':dc')
```

Alternatively, we can modify the instruction to `mov w0, 0`, which effectively bypasses the check by directly changing the logic in the function's flow from an `ADD` to a `MOV`. 

```bash
wa mov w0, 0
```

### Endnotes

In conclusion, we performed the following: 

- [Patch 1](https://github.com/n0psn0ps/automation-r2pipe/blob/main/fitmPatch01.py) - **Boolean function**: This technique involves patching a Boolean function that performs socket checks against localhost. The approach uses radare2 commands to locate and modify the debug dylib containing the protection mechanism.
- [Patch 2](https://github.com/n0psn0ps/automation-r2pipe/blob/main/fitmPatch02.py) - **Localhost reference**: This method targets the reference to "127.0.0.1" in the code. By identifying the add instruction that references the localhost string and applying a `NOP` operation to it, the detection check can be bypassed.
- [Patch 3](https://github.com/n0psn0ps/automation-r2pipe/blob/main/fitmPatch03.py) - **Overwrite tbz**: The third technique focuses on modifying the ARM64 TBZ instruction that controls the nested if-else statement in the detection logic. This can be done either by applying a `NOP` instruction to the `TBZ` instruction or by directly setting the return value to zero with "mov w0, 0".

If you are interested in this lab, you can give it a try here: https://academy.8ksec.io/course/ios-application-exploitation-challenges.
