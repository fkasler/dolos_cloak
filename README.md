Installation and Usage
============

* Perform default install of Kali ARM on Odroid C2. Check out the Blackhills writeup [here](https://www.blackhillsinfosec.com/how-to-build-your-own-penetration-testing-drop-box/).

```
ssh root@169.254.44.44
```

* Be sure to save this project to /root/tools/dolos_cloak
* Plug one external USB NIC into the Odroid and run dhclient to get internet access in order to install dependencies:

```
dhclient usbnet0
```

* Run the install script to get all the dependencies and make the Odroid performs the MitM on boot by default:

```
cd setup
./setup.sh
```

* You may want to install some other tools like 'host' that do not come standard on Kali ARM. Empire, enum4linux, and responder are also nice additions.
* Make sure you are able to ssh into the Odroid. Add your public key to /root/.ssh/authorized_keys for fast access.
* Modify config.yaml to meet your needs. You should make sure the interfaces match the default names that your Odroid is giving your USB dongles. Order does not matter here. You should leave client_ip, client_mac, gateway_ip, and gateway_mac blank unless you used a LAN tap to mine them. The script _should_ be able to figure this out for us. Set these options only if you know for sure their values. The management_int, domain_name, and dns_server options are placeholders for now but will be usefull very soon. For shells, you can set up a custom autorun command in the config.yaml to run when the man-in-middle attack has autoconfigured. You can also set up a cron job to send back shells.
* Connect two usb ethernet dongles and reboot the device (you need two because the built-in ethernet won't support promiscuous mode)
* Boot the device and wait a few seconds for autosniff.py to block the OUTPUT ethernet and IP chains. Then plug in the Odroid between a trusted device and the network.
* PWN N00BZ, get $$$, have fun, hack the planet

Tips
=====
* Mod and run ./scripts/upgrade_to_vpn.sh to turn a stealthy Empire agent into a full blown VPN tunnel
* Mod and run ./scripts/reverse_listener_setup.sh to set up a port for a reverse listener on the device.
* Run ./scripts/responder_setup.sh to allow control of the protocols that we capture for responder. You shoud run responder on the bridge interface:

```
responder -I mibr
```

* Be careful as some NAC solutions use port 445, 443, and 80 to periodically verify hosts. Working on a solution to this...
* Logs help when the autosniff.py misbehaves. The rc.local is set to store the current session logs in ./logs/session.log and logs in ./logs/history.log so we can reboot and still check the last session's log if need be. Log files have cool stuff in them like network info, error messages, and all bash commands to set up the NAT ninja magic.

Stealth
========

Use the radio_silence parameter to prevent any output originating from us.
This is for sniffing-only purpose.

WARNING!!! THE STUFF BELOW IS FROM THE ORIGIONAL(READ BROKEN) REPO. USE THE FILES IN THIS REPO AS CONFIGS OR WRITE YOUR OWN. THESE CONFIGS HAVE BEEN INCLUDED FOR LEARNING PURPOSES ONLY.
========

Hostapd
========

hostapd.conf

```
interface=wlan0
ssid=NothingToSeeHere
channel=1
#bridge=br0

# WPA and WPA2 configuration

macaddr_acl=0
auth_algs=3
ignore_broadcast_ssid=0
wpa=3
wpa_passphrase=hackallthethings
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP TKIP
rsn_pairwise=CCMP

# Hardware configuration

driver=rtl871xdrv
ieee80211n=1
hw_mode=g
device_name=RTL8192CU
manufacturer=Realtek

```

/etc/udhcpd-wlan0.conf

```
start      169.254.44.50
end        169.254.44.60
interface  wlan0
max_leases 1
option subnet 255.255.255.0
option router 169.254.44.44

```

License
=======

Just give me some credits if you build on this and keep it open source :) - @jkadijk

