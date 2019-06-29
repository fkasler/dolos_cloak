#!/bin/bash
/usr/sbin/openvpn /etc/openvpn/client.conf &
/sbin/ebtables -A OUTPUT -o tun0 -j ACCEPT
/sbin/iptables -A OUTPUT -o tun0 -j ACCEPT
/sbin/arptables -A OUTPUT -o tun0 -j ACCEPT
