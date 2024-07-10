---
layout: post
title: MHL 📵 No Escape 📵 Solution
---

![Untitled](/assets/blink02.jpg)

I finally had time to work on one of the iOS mobile hacking exercises at [Mobile Hacking Labs](https://www.mobilehackinglab.com/). I wanted to do a quick write-up on how I analyzed the `No Escape` application using r2frida. 

### Analysis

This section will be a snapshot of the commands and outputs. Which in and of itself could be a standalone script for quick recon and intelligence gathering of an application. 

Load into r2frida

```
❯ r2 'frida://spawn/usb//com.mobilehackinglab.No-Escape'

```

Check classes

```
[0x100e04868]> :ic~+escape
_TtC9No_EscapeP33_46A0F3C550DABD6C4FDD9346E5310C1E19ResourceBundleClass
EFSQLLikeEscapedExpression
No_Escape.SceneDelegate
No_Escape.ViewController
No_Escape.AppDelegate

```

Check methods

```
[0x100e04868]> :ic No_Escape.SceneDelegate
0x0000000100e05738 - window
0x0000000100e057e4 - setWindow:
0x0000000100e05af0 - scene:willConnectToSession:options:
0x0000000100e05b90 - sceneDidDisconnect:
0x0000000100e05c00 - sceneDidBecomeActive:
0x0000000100e05c70 - sceneWillResignActive:
0x0000000100e05ce0 - sceneWillEnterForeground:
0x0000000100e05e94 - sceneDidEnterBackground:
0x0000000100e05fd0 - init
0x0000000100e06038 - .cxx_destruct

[0x100e04868]> :ic No_Escape.ViewController
0x0000000100e00008 - messageLabel
0x0000000100e000b4 - setMessageLabel:
0x0000000100e003d8 - image
0x0000000100e00484 - setImage:
0x0000000100e01f20 - viewDidLoad
0x0000000100e021ac - initWithNibName:bundle:
0x0000000100e023d8 - initWithCoder:
0x0000000100e02458 - .cxx_destruct

[0x100e04868]> :ic No_Escape.AppDelegate
0x0000000100e02654 - window
0x0000000100e02700 - setWindow:
0x0000000100e029c8 - application:didFinishLaunchingWithOptions:
0x0000000100e03770 - application:configurationForConnectingSceneSession:options:
0x0000000100e03824 - application:didDiscardSceneSessions:
0x0000000100e0469c - init
0x0000000100e047d0 - .cxx_destruct

```

String search

```
[0x100e04868]> :/ Jail
Searching 4 bytes: 4a 61 69 6c
Searching 4 bytes in [0x0000000100dfc000-0x0000000100f60000]
hits: 1

0x100f4b5a0 hit0_0 Jail broken device!

```

```
[0x100e04868]> :/ jail
Searching 4 bytes: 6a 61 69 6c
Searching 4 bytes in [0x0000000100dfc000-0x0000000100f60000]
hits: 2

0x100f4b6cf hit1_0 jailbroken. This may compromise security. Quitting...
0x100f4c649 hit1_1 jailbreak_test.txt

```

```
[0x100f4c649]> :/ bin
Searching 3 bytes: 62 69 6e
Searching 3 bytes in [0x0000000100708000-0x000000010086c000]
hits: 5

0x1008586c0 hit1_0 bin/bash
0x1008586cf hit1_1 bin/sshd
0x1008586e2 hit1_2 bin
0x1008623c5 hit1_3 bined
0x100862515 hit1_4 bined

```

```
[0x102bd06cf]> :/ sbin
Searching 4 bytes: 73 62 69 6e
Searching 4 bytes in [0x0000000100698000-0x00000001007fc000]
hits: 1

0x1007e86ce hit1_0 sbin/sshd

```

List exports grep escape keyword

```
[0x104068868]> :iE~+escape
[TRUNCATED]
0x1041b8160 v $s9No_Escape11AppDelegateCMn
0x1041cf418 v $s9No_Escape11AppDelegateCN
0x104068788 f $s9No_Escape11AppDelegateCfD
0x10406a068 f $s9No_Escape12isJailbrokenSbyF
0x10406b3e0 f $s9No_Escape13ColorResourceV23__derived_struct_equalsySbAC_ACtFZ
0x10406b230 f $s9No_Escape13ColorResourceV4hash4intoys6HasherVz_tF
[TRUNCATED]
```

### No_Escape12isJailbroken

Now that I have gone through my initial recon of the application I would like to overview the exported function responsible for the jailbreak check. 

Parse functions of interest

```
[0x100690f70]> :iE~+jail
0x10054e068 f $s9No_Escape12isJailbrokenSbyF

```

Seek to the addresses and print out assembly instructions at that location. I was particularly interested in the tbz and mov instructions. 

```
[0x104068868]> s 0x10406a068
[0x10406a068]> pd			
[TRUNCATED]
						0x10406a074      29000094       bl sym._s9No_Escape22checkForJailbreakFiles33_BCE8F13474E5A52C60853EA803F80A81LLSbyF
        ┌─< 0x10406a078      a0000036       tbz w0, 0, 0x10406a08c
       ┌──< 0x10406a07c      01000014       b 0x10406a080
       └──> 0x10406a080      20008052       mov w0, 1
        │   0x10406a084      a0c31fb8       stur w0, [x29, -4]
       ┌──< 0x10406a088      04000014       b 0x10406a098
       │└─> 0x10406a08c      dc000094       bl sym._s9No_Escape33checkForWritableSystemDirectories33_BCE8F13474E5A52C60853EA803F80A81LLSbyF
       │    0x10406a090      a0c31fb8       stur w0, [x29, -4]
       │┌─< 0x10406a094      01000014       b 0x10406a098
       └└─> 0x10406a098      a8c35fb8       ldur w8, [x29, -4]
        ┌─< 0x10406a09c      a8000036       tbz w8, 0, 0x10406a0b0
       ┌──< 0x10406a0a0      01000014       b 0x10406a0a4
       └──> 0x10406a0a4      20008052       mov w0, 1
        │   0x10406a0a8      e00b00b9       str w0, [sp, 8]
       ┌──< 0x10406a0ac      04000014       b 0x10406a0bc
       │└─> 0x10406a0b0      93010094       bl sym._s9No_Escape12canOpenCydia33_BCE8F13474E5A52C60853EA803F80A81LLSbyF
       │    0x10406a0b4      e00b00b9       str w0, [sp, 8]
       │┌─< 0x10406a0b8      01000014       b 0x10406a0bc
       └└─> 0x10406a0bc      e80b40b9       ldr w8, [sp, 8]            ; 5
        ┌─< 0x10406a0c0      a8000036       tbz w8, 0, 0x10406a0d4
       ┌──< 0x10406a0c4      01000014       b 0x10406a0c8
       └──> 0x10406a0c8      20008052       mov w0, 1
        │   0x10406a0cc      e00700b9       str w0, [sp, 4]
       ┌──< 0x10406a0d0      04000014       b 0x10406a0e0
       │└─> 0x10406a0d4      1b020094       bl sym._s9No_Escape21checkSandboxViolation33_BCE8F13474E5A52C60853EA803F80A81LLSbyF
[TRUNCATED]
```

4 exported functions appear to be running on the device. Checking for a jailbroken device by looking for writeable system locations not present on a jailed device, binaries typically found on a jailed device, installation of cydia, and sandboxing violations. 

### Local Analysis of Binary

Since I found the exported function of interest I decided to also pull the IPA and analyze the ARM64 binary using radare2 on my laptop. This would give me additional insight into each function called via the `No Escape` application. 

Loading the binary into r2

```
❯ r2 -AA No\ Escape
```

Seek to function and locate 4 references to checks on the device. 

```
[0x10000a068]> pdf~+sym
            ; CALL XREF from sym.func.1000047a0 @ 0x100004934(x)
            ; CALL XREF from sym.func.100006940 @ 0x10000696c(x)
┌ 176: sym.No_Escape.isJailbroken (int64_t arg_20h);
│           0x10000a074      29000094       bl sym No_Escape.checkForJailbreakFiles._BCE8F13474E5A52C60853EA803F80A81 ; sym.No_Escape.checkForJailbreakFiles._BCE8F13474E5A52C60853EA803F80A81
│      │└─> 0x10000a08c      dc000094       bl sym No_Escape.checkForWritableSystemDirectories._BCE8F13474E5A52C60853EA803F80A81 ; sym.No_Escape.checkForWritableSystemDirectories._BCE8F13474E5A52C60853EA803F80A81
│      │└─> 0x10000a0b0      93010094       bl sym No_Escape.canOpenCydia._BCE8F13474E5A52C60853EA803F80A81 ; sym.No_Escape.canOpenCydia._BCE8F13474E5A52C60853EA803F80A81
│      │└─> 0x10000a0d4      1b020094       bl sym No_Escape.checkSandboxViolation._BCE8F13474E5A52C60853EA803F80A81 ; sym.No_Escape.checkSandboxViolation._BCE8F13474E5A52C60853EA803F80A81
```

Seeking to each check addresses and analyze the add op code 

Check for jailbreak files

```
│           0x10000a168      00c01991       add x0, x0, 0x670          ; 0x100150670 ; "/Applications/Cydia.app"
│           0x10000a198      00401a91       add x0, x0, 0x690          ; 0x100150690 ; "/Library/MobileSubstrate/MobileSubstrate.dylib"
│           0x10000a1c0      00fc1a91       add x0, x0, 0x6bf          ; 0x1001506bf ; "/bin/bash"
│           0x10000a1e8      00241b91       add x0, x0, 0x6c9          ; 0x1001506c9 ; "/usr/sbin/sshd"
│           0x10000a210      00601b91       add x0, x0, 0x6d8          ; 0x1001506d8 ; "/etc/apt"
│           0x10000a238      00841b91       add x0, x0, 0x6e1          ; 0x1001506e1 ; "/bin"
```

Check for writable system directories

```
│           0x10000a47c      00001991       add x0, x0, 0x640          ; 0x100150640 ; "/private/jailbreak_test.txt"
│           0x10000a4b0      00701991       add x0, x0, 0x65c          ; 0x10015065c ; "This is a test."
```

Check for cydia

```
 pdf~add
│           0x10000a7d4      00401891       add x0, x0, 0x610          ; 0x100150610 ; "cydia://package/com.example.package"
```

Check sandbox violation

```
│           0x10000a958      00c01791       add x0, x0, 0x5f0          ; 0x1001505f0 ; "/private/var/lib/apt/"
```

Check for all tbz and mov op codes 

```
[0x10000a068]> pdf~tbz; pdf~mov
│       ┌─< 0x10000a078      a0000036       tbz w0, 0, 0x10000a08c
│       ┌─< 0x10000a09c      a8000036       tbz w8, 0, 0x10000a0b0
│       ┌─< 0x10000a0c0      a8000036       tbz w8, 0, 0x10000a0d4
│       ┌─< 0x10000a0e4      a8000036       tbz w8, 0, 0x10000a0f8
│      └──> 0x10000a080      20008052       mov w0, 1
│      └──> 0x10000a0a4      20008052       mov w0, 1
│      └──> 0x10000a0c8      20008052       mov w0, 1
│      └──> 0x10000a0ec      28008052       mov w8, 1
│      │└─> 0x10000a0f8      08008052       mov w8, 0
```

### Approach 0x01

Approach one was to bypass the jailbreak detection using r2frida.

Begin trace of function.

```
[0x10054e068]> :dtf `:iE~+jail[0]`
true
[0x10054e068]> :dc
INFO: resumed spawned process
[0x10054e068]> [dtf onLeave][Mon Jul 01 2024 10:51:29 GMT-0700] 0x10292a068@0x10292a068 - args: . Retval: 0x1
[dtf onLeave][Mon Jul 01 2024 10:51:29 GMT-0700] 0x10292a068@0x10292a068 - args: . Retval: 0x1

```

Bypass boolean function

```
[0x10054e068]> :di0 `:iE~+jail[0]`
[0x10054e068]> :dc

```

### Approach 0x02

I thought using an r2pipe script to automated this bypass would be a fun exercise and extend on some other posts I have done over the last few months. But I wanted to take a different approach for the bypass. Instead of bypassing the exact function itself and modifying the underlying value, what about overwriting the tbz and mov instructions in the function responsible for this check? 

**mov instructions** 

We are only concerned about the first 3 mov instructions in the exported function. So we will use the following one-liner to seek the location and print out all the mov instruction registers.

```
s `:iE~+jail[0]`; pd~mov[1]]
```

**tbz instructions**

We are only concerned about the 4 tbz instructions in the exported function. So we will use the one-liner below to seek to the location of the function and print out all the tbz instruction registers. 

```
s `:iE~+jail[0]`; pd~tbz[1]
```

The final script can be found [here](https://github.com/n0psn0ps/automation-r2pipe/blob/main/noEscBypass.py). Thanks for reading. 😈

![Untitled](/assets/cert.png)
