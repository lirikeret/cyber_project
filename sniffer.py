from scapy.all import *
from arpspoofer import ArpSpoofer
class sniffer:

    def __init__(self):
        self.spoofer = ArpSpoofer.start()
