import sqlite3

from numpy.core import integer

connection = sqlite3.connect("project_db.db")
cursor = connection.cursor()

def access_to_router(packet_id, src_ip, dst_ip, req_type, req_params, headers, data, src_port, dst_port, src_mac, dst_mac):
    print (type(packet_id))
def access_to_router_changed(packet_id, src_ip, dst_ip, req_type, req_params, headers, data, src_port, dst_port, src_mac, dst_mac):
    pass
def access_to_victim(packet_id, src_ip, dst_ip, req_type, req_params, headers, data, src_port, dst_port, src_mac, dst_mac):
    pass
def access_to_victim_changed(packet_id, src_ip, dst_ip, req_type, req_params, headers, data, src_port, dst_port, src_mac, dst_mac):
    pass

access_to_router("a")
