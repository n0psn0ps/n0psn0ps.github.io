---
layout: post
title: Hacking BLE Communication via the Apollo LED Strip Light
---

I have spent the last year reading, researching, and testing mobile applications in my free time. While slowly dabbling in IoT assessment methodologies. 
The “Apollo Light” is one particular device that caught my attention over Christmas in 2021. The light is basically a strip light with mobile app integration. They can be controlled by devices like Alexa allowing ease of use and access throughout the house.

My methodology was to take a sort of penetration testing approach and look at how the device was interacting with the mobile application: 

+ Assess the BLE communication 
+ How is the mobile device communicating with the light
+ Can the BLE commands from the device be spoofed from another application

## Assessing the BLE Communication
So first off I installed the necessary application to communicate with the LED light strip. This application is called Apollo Lighting and created by the developer [qh-tek](https://play.google.com/store/apps/developer?id=qh-tek). The developer who appears to be based in China creates applications for BLE light management. 

<img src="https://github.com/n0psn0ps/n0psn0ps.github.io/blob/master/assets/apolloPlaystore.png?raw=true" width="75%"/>

The Apollo Lighting application controls the light either with a spin dial control, a playlist of songs, or voice audio.

<img src="https://github.com/n0psn0ps/n0psn0ps.github.io/blob/master/assets/dial.png?raw=true" width="75%"/>

I decided to dig into how the application communicates with the device first. If you are not familiar with BLE there are a ton of great resources available either in book or blog form. My quick approaches to the subject were the Android [documentation](https://developer.android.com/guide/topics/connectivity/bluetooth/ble-overview), Practical IoT Hacking and Hacking the Internet of Things: Bluetooth Low Energy. All are great resources and gave me a jump start on the workings of BLE. 

But in a nutshell when approaching BLE we want to understand a few things. BLE uses a completely different form of communication called GATT. Whereas most of us are familiar with over the wire communication such as TCP and UDP. 

> “GATT is an acronym for the __Generic ATTribute__ Profile, and it defines the way that two Bluetooth Low Energy devices transfer data back and forth using concepts called __Services__ and __Characteristics__. It makes use of a generic data protocol called the __Attribute Protocol (ATT)__...”

[https://learn.adafruit.com/introduction-to-bluetooth-low-energy/gatt](https://learn.adafruit.com/introduction-to-bluetooth-low-energy/gatt)

Typically we have a central device (computer, tablet, or phone) and a peripheral device (light, fridge, speaker, etc). Once the devices sync communication is served via GATT. Each operation is sent via a profile, service, and a set of characteristics. As can be seen below we have a write command to a device with the value of 564c005900f0aa captured in Wireshark. 

<img src="https://github.com/n0psn0ps/n0psn0ps.github.io/blob/master/assets/gattSnippet.png?raw=true"/>

Once this operation is sent from the central device to the periphery an action is committed changing the state of the device. Say turning on and off a light or changing the color. To find this information Android has a pretty useful feature built into the developer settings called __Enable Bluetooth HCI snoop log__. This allows developers to log and debug any issues between two devices using BLE. But this luckily comes in handy when reverse engineering BLE communications. Not only does it log information between two devices, the captured traffic can be dumped into wireshark for analysis. So I first enabled the settings as seen below. 

<img src="https://github.com/n0psn0ps/n0psn0ps.github.io/blob/master/assets/bluetoothSnoop?raw=true" width="75%"/>

After enabling the setting I began changing the light color and turning it on and off. Then I pull the log file from my Android device and I carefully went through the Wireshark packet capture. Locating each UUID value and code that corresponded to the host and controller. 

<img src="https://github.com/n0psn0ps/n0psn0ps.github.io/blob/master/assets/wireshark.png?raw=true" width="75%"/>

Below is a key I quickly gathered. From the data I found various operations sent from the mobile device to the light. Each corresponding to a different state change on the device. 

<img src="https://github.com/n0psn0ps/n0psn0ps.github.io/blob/master/assets/lightCodes.png?raw=true" width="75%"/>

Briefly overviewing the Wireshark packet capture I noticed there was no credential based authentication happening between the Android device and Apollo light. So my next step was to control the LED strip without the recommended application.

## Sending Unauthenticated Commands to the Light
I began playing with how I could control the Apollo LED Strip Light. I decided to use a quick and easy approach with the nRF Connect application. This allowed me to connect to the device and send the necessary codes to control the Apollo light. Below is a screenshot of all the available GATT devices that I could connect to using the Android device.

<img src="https://github.com/n0psn0ps/n0psn0ps.github.io/blob/master/assets/nfsconnectDevices.png?raw=true" width="75%"/>

I connected to my Apollo light device named __AP-9215B999C62E__ by pressing the connect button. I then scrolled through the list of available services for my device. All with fairly simple naming convention. You can use the following [guide](https://www.bluetooth.com/specifications/assigned-numbers/) to figure out common UUID numbers used for commercial devices with BLE communication. 

<img src="https://github.com/n0psn0ps/n0psn0ps.github.io/blob/master/assets/nfsconnectWrite.png?raw=true" width="75%"/>

Using the key I built out before from the log file dump. I was able to turn off and on the light and change it to various colors using the nRF Connection application. All I needed to do was press the up arrow for the WRITE, WRITE NO RESPONSE and input the values seen in the screenshot below.

<img src="https://github.com/n0psn0ps/n0psn0ps.github.io/blob/master/assets/apolloOff.png?raw=true" width="75%"/>

## Controlling the Device

Additionally I wanted to prepare a script that would allow me to interact with the Apollo device just using my laptop bluetooth device. I found [gatttool](https://manpages.ubuntu.com/manpages/bionic/man1/gatttool.1.html) to be of particular help for this aspect of the project. So I created a short script below which is also hosted on my [GitHub](https://github.com/n0psn0ps/RE_ApolloLightStrip).

```
#!/bin/bash

echo "Changing the state of the Apollo strip light \n"
sleep 1

echo "Light on \n"
gatttool -i hci0 -b 92:15:B9:99:C6:2E --char-write-req -a 0x0009 -n cc2333 > /dev/null
sleep 1
echo "Purple"
gatttool -i hci0 -b 92:15:B9:99:C6:2E --char-write-req -a 0x0009 -n 564c005900f0aa > /dev/null
sleep 1
echo "Blue"
gatttool -i hci0 -b 92:15:B9:99:C6:2E --char-write-req -a 0x0009 -n 7800ffff00f0ee > /dev/null
sleep 1
echo "Red"
gatttool -i hci0 -b 92:15:B9:99:C6:2E --char-write-req -a 0x0009 -n 789f000000f0ee > /dev/null
sleep 1
echo "Dark Purple \n"
gatttool -i hci0 -b 92:15:B9:99:C6:2E --char-write-req -a 0x0009 -n 78ff00ff00f0ee > /dev/null
sleep 1
echo "Light off"
gatttool -i hci0 -b 92:15:B9:99:C6:2E --char-write-req -a 0x0009 -n cc2433 > /dev/null
```

[Demo Video](https://youtube.com/shorts/rgyljgQiLMA)

Clearly this is a simple BLE light so the impact is low on the severity scale. But it does bring up questions around what it would mean if a Bluetooth lock or any other smart device could be tampered with remotely. Especially if the remote device is capable of being controlled unauthenticated. 
