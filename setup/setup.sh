#!/usr/bin/env bash
echo installing pip
apt-get install python-pip
echo installing python setuptools
pip install setuptools
echo installing basic project dependencies
apt-get install python-crypto python python-impacket python-pcapy libpcap0.8 bridge-utils ebtables arptables hostapd macchanger git
echo installing yaml python module
apt-get install python-yaml
echo installing scapy
apt-get install python-scapy
echo setting up network interfaces
cp ./interfaces /etc/network/interfaces
echo setting up startup script
cp ./rc.local /etc/rc.local
echo setting up ssh daemon config
cp ./sshd_config /etc/ssh/sshd_config
echo setting up udhacp config
cp ./udhcpd-eth0.conf /etc/udhcpd-eth0.conf
echo creating empty log files
touch ../logs/session.log
touch ../logs/history.log
echo All Done!
