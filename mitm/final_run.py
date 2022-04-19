from mitm.sniffer import Sniffer
import threading

class FinalRun:
    def __init__(self, destinationMac, targetIP, gatewayIP, sourceMAC):
        self.sniffer = Sniffer(destinationMac, targetIP, gatewayIP, sourceMAC)

    def start(self):
        t_sniff = threading.Thread(target=self.sniffer.sniff_all)
        t_spoof = threading.Thread(target=self.sniffer.start_spoofing)
        t_spoof.start()
        t_sniff.start()
        print("started sniffing")



