from mitm.sniffer import Sniffer
import threading
import time

class FinalRun:
    def __init__(self, targetIP, gatewayIP, do_before_adding_to_database):
        self.sniffer = Sniffer(targetIP, gatewayIP, do_before_adding_to_database)

    def start(self):
        """
        opens a thread foe sniffing and spoofing and runs them
        """
        t_sniff = threading.Thread(target=self.sniffer.sniff_all)
        t_spoof = threading.Thread(target=self.sniffer.start_spoofing)
        t_spoof.start()
        t_sniff.start()

    def stop(self):
        """
        stops the threads after closing the program
        """
        self.sniffer.spoofer.set_on('stop')
        self.sniffer.set_on(False)
        self.sniffer.set_sendpac(False)
        self.sniffer.db.set_db_on(False)

    def pause(self):
        """
        pauses the packet sending
        """
        self.sniffer.set_sendpac(False)

    def resume(self):
        """
        resumes the packet sending
        """
        self.sniffer.set_sendpac(True)

if __name__ == '__main__':
    x= FinalRun('192.168.0.110', '192.168.0.1', None)
    x.start()
