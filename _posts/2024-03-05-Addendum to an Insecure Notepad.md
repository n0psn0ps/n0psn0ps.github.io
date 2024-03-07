---
layout: post
title: Addendum to an Insecure Notepad
---

![Untitled](/assets/solar.jpeg)

I recently went through a 4 day training on `r2frida` at [ringzer0](https://ringzer0.training/trainings/mobile-reverse-engineering-r2frida.html). So as part of my own learning process I thought I would add a little addendum to my prior blog post showing an `r2frida` bypass for the 'insecure' Notepad iOS app. Some context will be removed from this post assuming the reader has digested the prior blog post.

First we will launch the application from the iPhone connected via usb. Then use the `:dc` command to continue the execution of the application (or child).

```
r2 'frida://launch/usb//com.some.app' 
```

and 

```
:dc
```

Next we want to investigate the corresponding address for the `NSString` class and method `isEqualToString`. This class method is include in the Foundation framework and is used to compare the our password string during submission in the ViewController.
We will use `:ic` and then the name of the class and the `~` and `+` flags to filter out our method name keyword.

```
[0x104340000]> :ic NSString~+equal
0x00000001851f0df8 - ams_caseInsensitiveEquals:
0x00000001a94c3b38 - _webkit_isCaseInsensitiveEqualToString:
0x000000018948d078 - isEqualToIgnoringCase:
0x00000001b4082294 - mf_isEqualToAddress:
0x00000001ca4aa434 - ea_isEqualToEmailAddress:
0x00000001980102c0 - ef_caseInsensitiveIsEqualToString:
0x000000018d123a0c - _cn_caseInsensitiveIsEqual:
0x0000000197d7b22c - br_isEqualToStringForHFS:isCaseSensitive:
0x0000000199ba5410 - isEqualToStringCaseInsensitive:
0x0000000199b96f18 - isEqualAsURL:
0x0000000193a356b0 - parsec_isCaseInsensitiveEqualToString:
0x0000000182627ca4 - isEqualToString:
0x00000001826f4cd0 - _web_isCaseInsensitiveEqualToString:
0x00000001825a2050 - isEqual:
```

Next I want to dynamically trace the function using `:dtf` we will identify the objective-c function using `objc` and use the `%i` to format the onLeave value using the decimal value. 

```
[0x104340000]> :dtf objc:NSString.isEqualToString:$ %i
true
```

Then we will type in our password in the text field and click the check mark to submit our incorrect password. We can then see the `Retval` is 0 or false.

![Untitled](/assets/added-img1.png)

```
[0x104340000]> [dtf onLeave][Wed Feb 21 2024 20:40:42 GMT-0600] objc:NSString.isEqualToString:$@0x182627ca4 - args: . Retval: 0
```

To change the return value of the onLeave function we will want to use the command `:di1` to replace the function after onLeave to return True or 1. 

```
[0x104a24000]> :di1 0x182627ca4
```

![Untitled](/assets/added-img2.png)

And we can see that the onLeave argument retval value is now 1. Which corresponds to the change made using the `:dt` command. 

```
[0x104a24000]> [dtf onLeave][Wed Feb 21 2024 20:58:24 GMT-0600] objc:NSString.isEqualToString:$@0x182627ca4 - args: . Retval: 1
```

I would highly suggest taking the `r2frida` training put together by [@as0ler](https://twitter.com/as0ler) [@enovella_](https://twitter.com/enovella_) and [@hexsploitable](https://twitter.com/Hexploitable). This overview is just a small and simple snippet of what you will learn. 

