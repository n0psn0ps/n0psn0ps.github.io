---
layout: post
title: macOS r2frida & r2pipe Automation
---

In this blog, I wanted to show an example of how to use how to use `r2frida` in macOS. Most of the ways I have used it up until now are solely on mobile platforms. I thought it would be a fun exercise to port over the iOS training application `DVIA` to macOS. 

Installing the application is fairly straightforward. Using `sideloadly` I was able to install the `DVIA` directly to my M1 laptop. After installation, you will need to boot the laptop into recovery mode and run the following command in the terminal. 

```
csrutil disable
```

This will disable System Integrity Protection (SIP) you can read more about that [here](https://developer.apple.com/documentation/security/disabling_and_enabling_system_integrity_protection). I will not go over all the details but in short *"SIP protects the entire system by preventing the execution of unauthorized code"*.

Secondly, we will want to modify the boot arguments of the non-volatile random access memory (nvram). I won't go into detail about this here there are a ton of resources online on how to disable certain security controls to run unsigned and untrusted binaries. You may also run into an issue where you need to self-sign. I will let that be an exercise for the reader.

Lastly, I had a lazy workaround that I encountered during instrumentation. My analysis method was to attach `DVIA` using `lldb` first then continue the execution of the program using `c`. After that, I would then attach to the process using `r2frida`. If I tried to attach to the running instance of `DVIA` with only `frida` or `r2frida` I would get a crash related to a signing issue. 

### Approach
My initial approach was to port over the bypasses straight from the iOS application to macOS. But things are done just a little different on macOS so I had to modify my initial `r2frida` commands to fit how macOS interprets the `DVIA` apps arm64 binary. 
If you want to follow along you will need three tools installed locally on your machine:
- *r2frida*
- *lldb*
- *Hopper (trial version works)*

Things I will not cover are how to use `Hopper` and `lldb` extensively. I will assume the reader has some basic knowledge of each. Also as a note using `Hopper` alongside `r2frida` is a bit redundant since we can more or less use `r2frida` to search for classes, methods, and functions inside an application. 
### Jailbreak Checks
Let's start with the two jailbreak bypasses found in the `DVIA` application. The first check was fairly straightforward and required no modification of my initial script. Where as the second I ran into some issues and needed to change my approach entirely.
##### Jailbreak 1 Bypass 
Loading the mach-o binary into `Hopper` we can search for the keyword jail and we see quite a few references. But our function of interest is `isJailbroken` in the `JailbreakDetectionVC` class as seen below.

![Untitled](/assets/Pasted image 20240313133202.png)

In `r2frida` we will use the command `:dtf` to dynamically trace the function call when the first jailbreak button is tapped. We see when the button is pressed we are met with a Boolean return value. This is value is `0x1` or True. We will want to change this value to False so `0x0`.

![Untitled](/assets/Pasted image 20240313133132.png)

We can use the command `:di0` or dynamically instrument the value and change it to zero. Below is a quick one-liner to overwrite the value.  

```
# bypass jailbreak check one
r.cmd(':di0 `:ic JailbreakDetectionVC~isJailbroken[0]`')
```

##### Jailbreak 2 Bypass 

Let's first talk over how the second check is being done and how we would like to approach this. In `Hopper` we see a reference to the [NSFileManager](https://developer.apple.com/documentation/foundation/nsfilemanager) class and method `fileExistsAtPath:`. 
Reference one point to a file located on disk `/bin/bash` and the second `/usr/sbin/sshd`, a common file found on a jailbroken iPhone device. In our case, these will be files present on a macOS system. So ostensibly the machine will be "jailbroken" to the application. 

![Untitled](/assets/Pasted image 20240313133437.png)

In iOS I used the following approach to bypass the check of the file. 

```
# bypass jailbreak check two
r.cmd(':di0 `:ic NSFileManager~+fileExistsAtPath:[0]`')
```

But when attempting this same bypass on macOS the application crashes upon detection. Interestingly this does not happen on iOS. (Another rabbit hole :) ) I spent some time digging into this issue since I was generally curious. 

I found that multiple `metalib` files are referenced by this class and if we overwrite the value of these references to this class it will crash the application. The four files in question are:

```
Original path: /System/Library/Frameworks/CoreImage.framework/Resources/ci_stdlib.metallib
Original path: /System/Library/Frameworks/CoreImage.framework/Resources/ci_filters.metallib
Original path: /System/Library/Frameworks/CoreImage.framework/Resources/ci_stdlib_stitchable.metallib
Original path: /System/Library/Frameworks/CoreImage.framework/Resources/ci_filters_stitchable.metallib
```

Each are related to the [CoreImage](https://developer.apple.com/documentation/coreimage) framework which is an image processing and analysis technology that provides high-performance processing for still and video images for macOS. 

So fundamentally our approach will have to change. We can either use a `frida` script to overwrite known values we obtained from the binary during our analysis with `Hopper`. Or we can attempt to locate the strings and overwrite them in the binary. I will show both approaches to better understand common bypass methodologies using `r2frida`.

**Approach 1:** *Modifying the String via Frida Script* 

An easy approach would be to create a frida script in our working directory. We can then load this js script at runtime and alter the behavior of the macOS application. 
Let's break down what is happening in the script. 
First, we are hooking into a specific class `NSFileManager`, and printing the `onEnter` value of the original file path when the class is called in the application. We will print the second argument which will be the value of the file and its corresponding path and convert it to a string.  

```
Interceptor.attach(ObjC.classes.NSFileManager['- fileExistsAtPath:'].implementation, {
    onEnter: function (args) {
        var originalPath = ObjC.Object(args[2]).toString();
        console.log('Original path:', originalPath);
```

We will then use an if statement to do a comparison of the string at the location.  The first is  `/bin/bash` and the second `/usr/sbin/sshd` if the file and path match we will modify this string with `/xyc`. We know this file does not exist on the machine so our Boolean comparison should return False. 

```
        if (originalPath === '/bin/bash') {
            var newPath = ObjC.classes.NSString.stringWithString_('/xyc');
            args[2] = newPath;
            console.log('Modified path:', newPath.toString());
        }

	if (originalPath === '/usr/sbin/sshd') {
            var newPath = ObjC.classes.NSString.stringWithString_('/xyc');
            args[2] = newPath;
            console.log('Modified path:', newPath.toString());
        }
   }
});
```

Loading the script is simple enough with the following command. 

```
[0x100758000]> :. ./binBash.js
```

**Approach 2:** *Overwrite the String Reference*

The second approach is incredibly concise and I would say more elegant. It does not require a script and can be packaged nicely into a one-liner with `r2pipe`.
So first we need to use the `:/` command to locate strings passed as an argument. We will start with the keyword `usr` since we want to locate a reference to the location of `/usr/sbin/sshd` in the application at runtime. 

Reference to **sshd**

![Untitled](/assets/Pasted image 20240604224021.png)

Reference to **bash**

![Untitled](/assets/Pasted image 20240604224037.png)

First, we will seek to the address of the hardcoded string value using `s` and the address. Then use the `wx 00` command to overwrite this reference.

```
[0x100928709]> s 0x10092ace3
[0x10092ace3]> wx 00
[0x10092ace3]> s 0x1009286fa
[0x1009286fa]> wx 00
[0x1009286fa]> s 0x10092ace3
[0x10092ace3]> wx 00
```

Modifying the above series of commands slightly to be a one-liner it could look something like this.

```
r.cmd("s `:/ bin~bash[0]`; wx 222f787963220a ; s `:/ usr~sbin[0]`; wx 222f787963220a")
```

I changed the value of the `wx` command to reflect the hex representation of `/xyc` using the following:

```
echo "/xyc" | od -A n -t x1 | sed 's/ *//g'
```
### Anti piracy Check

Using `Hooper` and searching for the keyword piracy we get quite a few different hits for the `SFAntiPiracy` check. Below is what you can see in Hopper but let's switch to `r2frida`. This will make out reversing and scripting process easier.

![Untitled](/assets/Pasted image 20240313125758.png)

![Untitled](/assets/Pasted image 20240313125742.png)

![Untitled](/assets/Pasted image 20240313125950.png)

Similar to Hopper you can use `r2frida` to locate the associated functions for the class `SFAntiPiracy`. All of these functions deal with checking various artifacts on the device such as the installation of cydia, loading a cydia tweak, files typically inaccessible on a non-jailbroken device, system-level checks, etc. 

![Untitled](/assets/Pasted image 20240313130237.png)

For brevity, I won't go into too much detail on checking these functions. But I do believe you should practice this on your own. As an example, I will show the first function `isTheApplicationCracked` being dynamically traced in `r2frida`. Again we see the use of a simple Boolean check against the application. It returns `0x1` when the check is run. 

![Untitled](/assets/Pasted image 20240313130213.png)

One nice feature in `r2frida` is the ability to pipe the output into a scripting language pre-installed on the OS such as awk, grep, less, etc. In this example I wanted to use `awk` to parse the `:ic` output and apply this to our automation script.

![Untitled](/assets/Pasted image 20240313124243.png)

Now that we have the functions we want to bypass we can apply this to a simple online for our python script. It would look something like this.

```
# bypass piracy check
r.cmd(":di0 `:ic SFAntiPiracy~+isTheApplicationCracked`; :di0 `:ic SFAntiPiracy~+isTheDeviceJailbroken`; :di0 `:ic SFAntiPiracy~+isTheApplicationTamperedWith`; :di0 `:ic SFAntiPiracy~+urlCheck`; :di0 `:ic SFAntiPiracy~+cydiaCheck`; :di0 `:ic SFAntiPiracy~+inaccessibleFilesCheck`; :di0 `:ic SFAntiPiracy~+plistCheck`; :di0 `:ic SFAntiPiracy~+processesCheck`; :di0 `:ic SFAntiPiracy~+fstabCheck`; :di0 `:ic SFAntiPiracy~+systemCheck`; :di0 `:ic SFAntiPiracy~+symbolicLinkCheck`; :di0 `:ic SFAntiPiracy~+filesExistCheck`; :di0 `:ic SFAntiPiracy~+isPirated`; :di0 `:ic SFAntiPiracy~+isJailbroken`; :di0 `:ic SFAntiPiracy~+killApplication`; :di0 `:ic SFAntiPiracy~+runningProcesses`")
```

But we could clean this up a bit more and reduce the length of this command. We can do this by using a for statement and running our `r2frida` command with the values of our functions. 

```
print("[X] Piracy check bypassed.\n")
out = r.cmd(":ic SFAntiPiracy~[2]")

addr = out.split()
for addrs in addr:
    r.cmd(f":di0 `:ic SFAntiPiracy~+{addrs}`")
```
### Application Patch Check

For this exercise, the original intent using `DVIA` is to patch the IPA with something like `ghidra` and the load it back onto the device. But again I wanted to take a different approach and use `r2frida`. Similar to our first exercise we will use the `:di0` command to dynamically instrument the function. 

![Untitled](/assets/Pasted image 20240318204931.png)

```
:di0 `:ic ApplicationPatchingDetailsVC~+kill[0]`
```

### Login Check

Analyzing the function previously in iOS there are two string values used as part of this login check. Using `Hopper` you can obtain these values. Alternatively, you can find them using `r2frida` as well ;)

`Hopper`
![Untitled](/assets/Pasted image 20240314165227.png)

![Untitled](/assets/Pasted image 20240314165655.png)

`r2frida`

![Untitled](/assets/Pasted image 20240606172659.png)

Again we can see the use of [isEqualToString:](https://developer.apple.com/documentation/foundation/nsstring/1407803-isequaltostring ) method found in `NSString` class which is part of the Foundation library. But as we saw before we cannot use this as part of our bypass. So we can either overwrite or modify the string value. 

![Untitled](/assets/Pasted image 20240314165526.png)

I would again like to show one last approach to bypassing a specific function. We can modify the value of an assembly code operation. Which is a great exercise in and of itself. We will start by seeking to the location of the loginMethod.  Then analyze the function in question.  
Then we want to locate the address/es responsible for this function using the [cbz](https://developer.arm.com/documentation/dui0489/i/arm-and-thumb-instructions/cbz-and-cbnz) operations. In assembly, the cbz operation stands for compare and branch on zero. So based on this assumption, we can deduce that these two addresses handle the string comparison being done (I did not go into detail on how or why cbz is the operation you want to overwrite but you can use either `Hopper` or `r2frida` to do this analysis on your own). If this comparison is incorrectly handled by the application we will not be met with the login prompt.

![Untitled](/assets/Pasted image 20240606170544.png)

So our approach will be to overwrite the instruction at that point with a no-operation or nop using the following:

```
wx 00 @ 0x10484fccc
```

We will clean this up and re-write our commands into a one-liner. 

```
# Login Bypass 
r.cmd("s `:ic ApplicationPatchingDetailsVC~+loginMethod[0]`; af; wx 00 @ `pdr~cbz w0[1]`;wx 00 @ `pdr~cbz w23[1]`") 
print("[X] Application Patching login function now bypassed.\n")
```

### Show Alert Check

For our last exercise let's have some fun modifying the string value for the pop-up in the application patching exercise. First, we will need to search for the keyword Google using the following:

![Untitled](/assets/Pasted image 20240607101706.png)
 
Then we will seek to the location of the string Google and overwrite the value using the `w` command with our new text `n0ps was here`. 

```
r.cmd("s `:/ I love Google ~+google[0]`; w n0ps was here") 
print("[X] Application Patching overwrite string.\n")
```

### Conclusion

In this blog post, my goal was to show the reader how to use common techniques to bypass various detections found in an iOS application when ported over to macOS. We covered the following topics:
- Modifying hardcoded string references
- Searching for string references and assembly operations
- Dynamic tracing and instrumentation
- Writing a custom frida script 

