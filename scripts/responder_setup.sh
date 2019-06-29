#!/bin/bash
#Any NetBIOS Name Resolution request
/sbin/iptables -t nat -A PREROUTING -i mibr -p tcp --dport 137 -j DNAT --to 169.254.66.77:137
/sbin/iptables -t nat -A PREROUTING -i mibr -p udp --dport 137 -j DNAT --to 169.254.66.77:137
#Any NetBIOS session packet
/sbin/iptables -t nat -A PREROUTING -i mibr -p tcp --dport 139 -j DNAT --to 169.254.66.77:139
/sbin/iptables -t nat -A PREROUTING -i mibr -p udp --dport 139 -j DNAT --to 169.254.66.77:139
#Any LLMNR Packet
/sbin/iptables -t nat -A PREROUTING -i mibr -p tcp --dport 5355 -j DNAT --to 169.254.66.77:5355
/sbin/iptables -t nat -A PREROUTING -i mibr -p udp --dport 5355 -j DNAT --to 169.254.66.77:5355
#Any SMB packet
/sbin/iptables -t nat -A PREROUTING -i mibr -p tcp --dport 445 -j DNAT --to 169.254.66.77:445
/sbin/iptables -t nat -A PREROUTING -i mibr -p udp --dport 445 -j DNAT --to 169.254.66.77:445

