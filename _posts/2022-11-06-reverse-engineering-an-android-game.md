---
layout: post
title: Reverse Engineering an Android Game
---

I recently took a few weeks off from studying web and mobile related hacking. I was generally swamped with work. So I opted for taking a much needed break from personal hacking projects in my free time. But this week I was feeling the spark again and thought I would pick up on some various subjects related to mobile hacking. Specifically hacking Unity based games. I have never been a big gamer, but thought this is a great way to understand how games work.
I found myself landing on the subject of game reversing mostly out of interest in reverse engineering Android and iOS applications. So I plugged in my phone, started browsing the Play Store, decided on an app, and began digging into some code.
This application was pretty straight forward. You dig for gold underground and the player has various functionality that allows them to procure gold and other items. Ultimately my goal was to start the game with a high amount of money and then move on from there.
The default behavior is like most level based games you start on level 1 with a set amount of time to gain X number of points and then move on. I took the normal pentesting approach. Play with the application understand its functionality and then look into the file system and code. So I started playing with the game and used frida to bypass SSL pinning and see what was happening when the application was loaded on the android device. I was able to see the game communicating with the backend server and some analytics calls that were detailing information about my pixel device. 

<img src="https://github.com/n0psn0ps/n0psn0ps.github.io/blob/master/assets/burpAds.png?raw=true" width="75%"/>

Since some Unity applications communicate with a backend server and may use Firebase to pull game state data for the user I decided to start there. I have spent time testing applications like this before so I used pre-existing tools to enumerate the Firebase URL and Google API keys. After doing a quick dump of the APK and searching for strings I ended up empty handed both resulted in zero information. Which is a positive in terms of testing the overall integrity of how the application is deployed on the Android device.
So I decided to run the application again and see what was happening when I used adb logcat. I noticed somethin fairly interesting. The logs were showing that a file was created, loaded and saved in the application directory named gamedata.xml.

<img src="https://github.com/n0psn0ps/n0psn0ps.github.io/blob/master/assets/grepGame.png?raw=true" width="75%"/>

The next thing to do was load the application into objection. This allowed me the ability to look into the environment structure of the apk when it is deployed on the android device. The snapshot below gave me a quick indication of possible attack routes to explore.

<img src="https://github.com/n0psn0ps/n0psn0ps.github.io/blob/master/assets/androidFiles.png?raw=true" width="75%"/>

I started with the two xml files achievement.xml and gamedata.xml. Both appeared to be unique to the user, device and game state. So I started looking into the state of my application. Noticing that the entity money with the value 1120 which was the amount of money I ended with after closing my game state.

<img src="https://github.com/n0psn0ps/n0psn0ps.github.io/blob/master/assets/xmlFiles.png?raw=true" width="75%"/>

Ok, so I know the application is saving the game state and clearly the gamedata.xml may be the route I want to take to exploit the money state.  So I modified the money entity in the xml file saved the file and pushed it to the files directory under the game /data directory.

<img src="https://github.com/n0psn0ps/n0psn0ps.github.io/blob/master/assets/moneyValue.png?raw=true" width="75%"/>

I opened the saved state of the application and I got the response below.

<img src="https://github.com/n0psn0ps/n0psn0ps.github.io/blob/master/assets/modifyCoins.png?raw=true" width="75%"/>

Simple enough, changing the XML file entry allowed for the money amount to be modified in the game. Additionally, the level state could also change without any verification in the game player state or money amount! After playing with this parameters I decided to pivot and dig a bit further into why this was happening in the first place.

## XML Implementation in the Game Design 

Game states can be saved in mutliple ways in Unity. One way is through the Player Prefs in the Unity application this allows for only low values of data so can be insufficient if the game design require higher value integers. But generally this can be reverse engineered with specific tools which I will not cover here. Another way is using JSON and XML files which are easily readable and allow for quick modification. The idea behind these files is that they are easy to shared with game develoeprs working on the same product and allow for quick state modification. Though also not incredible secure and easier to modify as we just saw. The other option is binary. Please refer to this [article](https://blog.unity.com/technology/persistent-data-how-to-save-your-game-states-and-settings) for more details.


