from mitm.sniffer import Sniffer
import threading

class FinalRun:
    def __init__(self, targetIP, gatewayIP, do_before_adding_to_database):
        self.sniffer = Sniffer(targetIP, gatewayIP, do_before_adding_to_database)

    def start(self):
        t_sniff = threading.Thread(target=self.sniffer.sniff_all)
        t_spoof = threading.Thread(target=self.sniffer.start_spoofing)
        t_spoof.start()
        t_sniff.start()
        print("started sniffing")

    def stop(self):
        self.sniffer.spoofer.set_on('stop')
        self.sniffer.set_on('stop')
        self.sniffer.set_sendpac(False)

    def pause(self):
        self.sniffer.set_sendpac(False)

    def resume(self):
        self.sniffer.set_sendpac(True)