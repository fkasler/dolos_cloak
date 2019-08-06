Dolos Cloak
============

Dolos Cloak is a python script designed to help network penetration testers and red teamers bypass 802.1x solutions by using an advanced man-in-the-middle attack. The tool is able to piggyback on the wired connection of a victim device that is already allowed on the target network without kicking the vicitim device off the network. It was designed to run on an Odroid C2 running Kali ARM and requires two external USB ethernet dongles. It should be possible to run the tool on other hardware and distros but it has only been tested on an Odroid C2 thus far.

How it Works
============

Dolos Cloak uses iptables, arptables, and ebtables NAT rules in order to spoof the MAC and IP addresses of a trusted network device and blend in with regular network traffic. On boot, the script disallows any outbound network traffic from leaving the Odroid in order to hide the MAC addresses of its network interfaces. 

Next, the script creates a bridge interface and adds the two external USB ethernet dongles to the bridge. All traffic, including any 802.1x authentication steps, is passed on the bridge between these two interfaces. In this state, the device is acting like a wire tap. Once the Odroid is plugged in between a trusted device (desktop, IP phone, printer, etc.) and the network, the script listens to the packets on the bridge interface in order to determine the MAC address and IP of the victim device.

Once the script determines the MAC address and IP of the victim device, it configures NAT rules in order to make all traffic on the OUTPUT and POSTROUTING chains look like it is coming from the victim device. At this point, the device is able to communicate with the network without being burned.

Once the Odroid is spoofing the MAC address and IP of the victim device, the script sends out a DHCP request in order to determine its default gateway, search domain, and name servers. It uses the response in order to configure its network settings so that the device can communicate with the rest of the network.

At this point, the Odroid is acting as a stealthy foothold on the network. Operators can connect to the Odroid over the built-in NIC eth0 in order to obtain network access. The device can also be configured to send out a reverse shell so that operators can utilize the device as a drop box and run commands on the network remotely. For example, the script can be configured to run an Empire python stager after running the man-in-the-middle attack. You can then use the Empire C2 connection to upgrade to a TCP reverse shell or VPN tunnel.

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

* Run the install script to get all the dependencies and set the Odroid to perform the MitM on boot by default. Keep in mind that this will make drastic changes to the device's network settings and disable Network Manager. You may want to download any additional tools before this step:

```
cd setup
./setup.sh
```

* You may want to install some other tools like 'host' that do not come standard on Kali ARM. Empire, enum4linux, and responder are also nice additions.
* Make sure you are able to ssh into the Odroid via the built-in NIC eth0. Add your public key to /root/.ssh/authorized_keys for fast access.
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

License
=======

This project is a major re-write of a tool written by @jkadijk and uses the class structure of the origional project. Per his request:

"Just give me some credits if you build on this and keep it open source :)" - @jkadijk

