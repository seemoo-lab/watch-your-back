# Watch Your Back PoC

Proof of concept for the Apple Watch impersonation attack presented in *Watch Your Back: Smartwatch Impersonation Attacks in Apple's iOS Ecosystem* published at NDSS 2027.

> [Warning!]  
> This is a proof of concept attack that extracts some information from a paired iPhone (iOS 18 or below). The code should therefore be considered malicious to some extent. Use with caution. All data obtained from the iPhone stays local and no destructive actions are performed.

> [Note!]  
> For the accompanying app to generate and scan watch pairing codes, refer to the [Magic Code repo](https://github.com/seemoo-lab/magiccode).

## Installation

### Bumble Script

Copy the bumble folder to your Raspberry Pi 3B. Then install bumble in a virtual python environment:

```bash
cd bumble
python -m venv .venv
source .venv/bin/activate
pip install bumble
```

### WatchWitchJava

Build the executable jar:

```bash
cd WatchWitchJava
./gradlew build
cp build/libs/WatchWitchJava-1.0-SNAPSHOT-all.jar WatchWitchJava-fresh.jar
```

Alternatively, use the pre-built `WatchWitchJava.jar`.


## Running

### iPhone

Make sure your iPhone is connected to the Internet and has Bluetooth enabled.

### Start Bumble

On your Raspberry Pi, run these commands:

```bash
# ensure no interference from system bluetooth stack
sudo hciconfig hci0 down
sudo systemctl stop bluetooth.service

# start bumble script
# note explicit python path due to sudo
sudo .venv/bin/python fakewatch.py applewatch.json hci-socket:0
```

### Start WatchWitchJava

Then start WatchWitchJava on your host machine:

```bash
sudo java --enable-native-access=ALL-UNNAMED -jar WatchWitchJava.jar <watchOS version> <bumble host IP>
```

This component requires root to set up a utun network interface. Feel free to run it in a VM etc. However, ensure that the Raspberry Pi running Bumble is reachable from the execution environment.

Options:
* Simulated watchOS version: `wos7, wos9, wos10, or wos11`. For iOS 14, choose `wos7`. For iOS 16.4-17.3.x, choose `wos9`. For iOS 17.4-18.3.x, choose `wos10`. For iOS 18.3.x-26.x, choose `wos11` (very limited support).
* Bumble host: Local IPv4 address of the Raspberry Pi running Bumble. Defaults to `127.0.0.1`.

For a live overview of extracted data, open `localhost:7070` in a browser.

You should see the following output:

```
[Main] starting watch impersonator with Watch OS 9.6.4
[Main] connecting to bumble host at 127.0.0.1
[WitchVpnConnection] tun interface created: tun0
[NRLPoverUDP] sent nrlp hello
[NRLPoverUDP] sent prelude 345445524d494e5553010a001304001000000000000000003d6586c6a25f4fd247f8
[NRLPoverUDP] received bluetooth OOB key: 723aa261d4f461d69d58d7e02c645abedb63def5e5d3ea3c19eb0304926719b1bb28
ready for commands
```

On your Raspberry Pi, you should see logs indicating the two components connected successfully:
```
got hello
UDP sending msg 3300723aa261d4f461d69d58d7e02c645abedb63def5e5d3ea3c19eb0304926719b1bb28
Got new prelude: 5445524d494e5553010a00130400100000000000000000e1dd14da555de2612e80
```

### Execute Attack

1. If you bring your victim iPhone very close to your Raspberry Pi, you should, after up to 10 seconds, see a pop-up asking you to pair a watch. Alternatively, navigate to the Watch app directly and tap 'Start Pairing'.

2. Choose 'Set Up for Myself'

3. Scan Magic Code or pair manually. You can generate a sutiable magic code for your watchOS version with the [Magic Code app](https://github.com/seemoo-lab/magiccode). For simplicity, however, we recommend using the fallback numeric comparison pairing. Tap 'pair manually' and choose 'Apple Watch 70815' from the list. After a short moment, the WatchWitchJava output should show a six-digit PIN. Enter the PIN on the iPhone.

4. Wait and move through the pairing setup when and if your iPhone asks you to. You should see a lot of activity in the WatchWitchJava output.

### What to expect

This is a complex attack with lots of moving pieces and opportunities for things to go wrong. In our tests, the attack is very sensitive to the Bluetooth chipset used. While we have success with the Raspberry Pi 3B, attack success rates drop significantly with newer iPhone models with Bluetooth chips that send more data faster, overwhelming the Pi's chipset and causing silent packet loss. You'll see this instability manifest in frequent `[NRLPoverUDP] NRLP disconnected` messages.

We had the most success with an iPhone 8 running iOS 14.8, and this is the only tested iPhone where we can reliably navigate through the entire pairing flow.

However, you should still see at least partial success with other models and versions! Here are some logging outputs to look out for:

* `[WatchState] idscc established` indicates the IKEv2 handshakes were successful and at least one encrypted data channel has been established  
* `[WatchState] alloy channel established (6/6)` indicates all data channels were established and the application-level watch setup is starting
* `[WatchState] sent PBBridge activation complete` indicates the first phase of the watch setup is completed
* General activity on `[WatchWitchAlloy]` shows application data is transferred and the setup is progressing

In a good run, you should see some extracted information being displayed on the website hosted at `localhost:7070`. This can include the device IMEI, Apple account e-mails, mobile network location, language settings, and WiFi credentials. Due to connection instability, you will typically not see all types of values in a single run. After WiFi credentials were sent, they may not be sent again until you add a new known WiFi network (or some time passes).  

If you're interested, you can check a log of all packets sent/received in the `.pcap` (plaintext traffic from within the IPSec tunnel) and `.idslog` (alloy messages) files created for each session. `idslog` files can be parsed and filtered using the [alloy parser](https://github.com/seemoo-lab/watchwitch-tools/).