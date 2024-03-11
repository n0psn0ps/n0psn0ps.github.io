---
layout: post
title: Native🪝and Automation Using r2frida and r2pipe
---

![Untitled](/assets/cover.jpeg)

After taking some time to digest the content of a recent training presented at [ringzer0](https://ringzer0.training/trainings/mobile-reverse-engineering-r2frida.html) focused on the use of `r2frida`. I wanted to explore reversing an Android application that loads a few custom functions from a native library. First off this is originally an application put together by the folks at `Optiv` and can be found [here](https://www.optiv.com/insights/source-zero/blog/attacking-jni-boundary-frida). The main purpose is to demonstrate how to reverse native libraries in Android applications using `frida`. I will be demonstrating how to bypass a password check functionality done in the native library then automate the process. But do read their blog post as a stand alone it is super informative. 

First off I will need to install the `ndkcrackme` application onto my physical Android device using `adb`. Then use `r2frida` to launch the application on the device and use the `:dc` command to start the application which will allow the native code to be loaded at runtime.

```
r2 'frida://launch/usb//com.optiv.ndkcrackme'
INFO: resumed spawned process
 -- Control the height of the terminal on serial consoles with e scr.height
[0x00000000]> :dc
Continue thread(s).
```

**Note:** For this application to load the functions from the native library you will need to continue the execution of the NDK app. 

Then we will want to analyze which imported libraries are loaded into the application and filter them for the library file of interest. As called out in the blog post our library of interest is the `libnative-lib.so`.

```
[0x00000000]> :il~+native
0x000000711ed80000 0x000000711edb6000 libnativeloader.so
0x000000711edf0000 0x000000711edf8000 libnativehelper.so
0x00000071218e4000 0x00000071218e9000 libnativebridge_lazy.so
0x000000711ecfb000 0x000000711ecff000 libnativeloader_lazy.so
0x0000007122483000 0x0000007122496000 libnativedisplay.so
0x000000711e56d000 0x000000711e574000 libnativewindow.so
0x0000007122dde000 0x0000007122de4000 libnativebridge.so
0x00000071217c9000 0x00000071217e1000 android.hardware.cas.native@1.0.so
0x0000006e1d180000 0x0000006e1d1b6000 libnative-lib.so **
```

Once we have found our binary of interested we can then begin our analysis of the native functions that are used by the application and imported from our library. We will seek to the address `0x6e1d18f478` which is the start address of the native binary. Then list all exports in the current binary. 

```
[0x00000000]> s 0x0000006e1d180000
[0x6e1d180000]> :iE~+optiv
0x6e1d18f328 f Java_com_optiv_ndkcrackme_MainActivity_a
0x6e1d18f478 f Java_com_optiv_ndkcrackme_MainActivity_b **
0x6e1d18f5c8 f Java_com_optiv_ndkcrackme_MainActivity_c
0x6e1d18f704 f Java_com_optiv_ndkcrackme_MainActivity_d
0x6e1d18f81c f Java_com_optiv_ndkcrackme_MainActivity_e
```

**Note:** Due to memory related protections such as [ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization) the address of the library and function will change during each launch of the application. 

Our main function of interest is the `Java_com_optiv_ndkcrackme_MainActivity_b`
this will do the comparison against the password submitted in the TextView of the Android application. 
So now we will dynamically trace the function using the address of the `b` function.

```
[0x6e1d180000]> :dtf 0x6e1d18f478 xi
true
[0x6e1d180000]> [dtf onLeave][Thu Feb 22 2024 20:30:05 GMT-0800] 0x6e1d18f478@0x6e1d18f478 - args: 0xb400006f4e4d6110, 549577402868. Retval: 0x0
```

![Untitled](/assets/ndkReject.png)

We can see that it returns false so all we will need to do is flip the value to be true and then our password should be accepted by the application. 
So now to do this we will intercept the function and change the return value to 1. Using the `:di1` flag and the address of our function. 

```
[0x6e1d180000]> :di1 0x6e1d18f478

[0x6e1d180000]> [dtf onLeave][Thu Feb 22 2024 20:30:47 GMT-0800] 0x6e1d18f478@0x6e1d18f478 - args: 0xb400006f4e4d6110, 549577402868. Retval: 0x1
```

![Untitled](/assets/ndkAccept.png)

And now we can see that the prompt has been changed to `Password accepted!` with any value submitted in the TextField.  
## Automation
Manually bypassing the function is great. But let's create a quick script so each time the application is launched using `r2` our bypass is injected into the application state at runtime. We can do this with python using [r2pipe](https://github.com/radareorg/radare2-r2pipe). Which allows us to extend its functionality into methods found in python (or any language you prefer). A simple script would start by importing `r2pipe` and `time`.  

```
import r2pipe
import time
```

**Note:** During my own testing I found that I needed to add the `time` library and implement a call to `sleep` so as to not immediately kill all instrumentation done at run time. 

Then we will need to launching the application using `r2frida` similar to the manual process detailed earlier, but this time we are using `r` as our variable to access the application and modify it using the `r2pipe` method `cmd()`.

```
# launch the android application
r = r2pipe.open("frida://launch/usb//com.optiv.ndkcrackme")
```

Using the `cmd()` method in our script we can begin to modify the state of the application. To start I will continue executing the app. Once done executing the library address can be found and stored in `addr`. We can then use python to `split()` the desired address and store it in `splitAddr`. 

```
# search library, split addr, print address
addr = r.cmd(':dc');
addr = r.cmd(':il~+libnative-lib');
splitAddr = addr.split(" ", 1)[0]
```

With the `cmd()` method we can seek to the native functions address and store the address of the function in `eAddr`.

```
# seek to addr 
r.cmd("s " + splitAddr)
# split function address 
eAddr = r.cmd(':iE~Java_com_optiv_ndkcrackme_MainActivity_b').split(" ", 1)[0]
```

Then we will dynamically instrument the functions value using the `:di1` command. Allowing us to set the `Java_com_optiv_ndkcrackme_MainActivity_b` functions boolean value to `true` no matter what password is submitted into the NDK app.

```
# dynamic inst at eAddr
r.cmd(':di1 ' + eAddr)
print("[X] Function bypassed. Any password now accepted.")
```

Finally we will set the `sleep()` method to a high value so as not to immediately kill the application. 

```
# sleep 
time.sleep(10000)
```

If you are interested in testing out this app and the `r2pipe` python script you can download it [here](https://github.com/n0psn0ps/automation-r2pipe). I encourage you to read [Phil Stokes]() post on the SentinelOne blog on using `r2` and `r2pipe` [Automating String Decryption and Other Reverse Engineering Tasks in radare2 With r2pipe](https://www.sentinelone.com/labs/automating-string-decryption-and-other-reverse-engineering-tasks-in-radare2-with-r2pipe/). Which in part became my inspiration for this post. Again, if you have the opportunity to participate in the training put together by [@as0ler](https://twitter.com/as0ler) [@enovella_](https://twitter.com/enovella_) and [@hexsploitable](https://twitter.com/Hexploitable) I would highly encourage it. 

