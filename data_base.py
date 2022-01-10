import sqlite3

class data_base:

    def __init__(self):
        self.connection = sqlite3.connect("project_db.db")
        self.cursor = self.connection.cursor()

    def write_to_router(self,packet_id, src_ip, dst_ip, req_type, req_params, headers, data, src_port, dst_port, src_mac, dst_mac):
        self.cursor.execute(f"INSERT INTO router_db VALUES ({packet_id}, {src_ip}, {dst_ip}, {req_type}, {req_params}, {headers}"
                       f", {data}, {src_port}, {dst_port}, {src_mac}, {dst_mac})")


    def write_to_router_changed(self, packet_id, src_ip, dst_ip, req_type, req_params, headers, data, src_port, dst_port,
                                       src_mac, dst_mac):
        self.cursor.execute(f"INSERT INTO router_db_chnged VALUES ({packet_id}, {src_ip}, {dst_ip}, {req_type}, {req_params},"
                       f" {headers}, {data}, {src_port}, {dst_port}, {src_mac}, {dst_mac})")


    def write_to_victim(self,packet_id, src_ip, dst_ip, req_type, req_params, headers, data, src_port, dst_port, src_mac, dst_mac):
        self.cursor.execute(f"INSERT INTO victim_db VALUES ({packet_id}, {src_ip}, {dst_ip}, {req_type}, {req_params}, {headers}"
                       f", {data}, {src_port}, {dst_port}, {src_mac}, {dst_mac})")


    def write_to_victim_changed(self, packet_id, src_ip, dst_ip, req_type, req_params, headers, data, src_port, dst_port, src_mac,
                                dst_mac):
        self.cursor.execute(f"INSERT INTO victim_db_chnged VALUES ({packet_id}, {src_ip}, {dst_ip}, {req_type}, {req_params},"
                       f" {headers}, {data}, {src_port}, {dst_port}, {src_mac}, {dst_mac})")


    def get_from_router(self, packet_id=False, src_ip=False, dst_ip=False, req_type=False, req_params=False, headers=False,
                        data=False, src_port=False, dst_port=False, src_mac=False, dst_mac=False):
        try:
            rows = self.cursor.execute(f"SELECT {'packet_id, ' if packet_id else ''}{'src_ip' if src_ip else ''}"
                                  f"{'dst_ip' if dst_ip else ''}{'req_type' if req_type else ''}"
                                  f"{'req_params' if req_params else ''}{'req_params' if req_params else ''}"
                                  f"{'headers' if headers else ''}{'data' if data else ''}"
                                  f"{'src_port' if src_port else ''}{'dst_port' if dst_port else ''}"
                                  f"{'src_mac' if src_mac else ''}{'dst_mac' if dst_mac else ''}  FROM router_db").fetchall()
            return rows
        except:
            return ("ERROR: NOT GIVEN ENT PARAMETERS")

    def get_from_router_changed(self,packet_id=False, src_ip=False, dst_ip=False, req_type=False, req_params=False, headers=False,
                        data=False, src_port=False, dst_port=False, src_mac=False, dst_mac=False):
        try:
            rows = self.cursor.execute(f"SELECT {'packet_id, ' if packet_id else ''}{'src_ip' if src_ip else ''}"
                                  f"{'dst_ip' if dst_ip else ''}{'req_type' if req_type else ''}"
                                  f"{'req_params' if req_params else ''}{'req_params' if req_params else ''}"
                                  f"{'headers' if headers else ''}{'data' if data else ''}"
                                  f"{'src_port' if src_port else ''}{'dst_port' if dst_port else ''}"
                                  f"{'src_mac' if src_mac else ''}{'dst_mac' if dst_mac else ''}  FROM router_changed_db").fetchall()
            return rows
        except:
            return ("ERROR: NOT GIVEN ENT PARAMETERS")

    def get_from_victim(self,packet_id=False, src_ip=False, dst_ip=False, req_type=False, req_params=False, headers=False,
                        data=False, src_port=False, dst_port=False, src_mac=False, dst_mac=False):
        try:
            rows = self.cursor.execute(f"SELECT {'packet_id, ' if packet_id else ''}{'src_ip' if src_ip else ''}"
                                  f"{'dst_ip' if dst_ip else ''}{'req_type' if req_type else ''}"
                                  f"{'req_params' if req_params else ''}{'req_params' if req_params else ''}"
                                  f"{'headers' if headers else ''}{'data' if data else ''}"
                                  f"{'src_port' if src_port else ''}{'dst_port' if dst_port else ''}"
                                  f"{'src_mac' if src_mac else ''}{'dst_mac' if dst_mac else ''}  FROM victim_db").fetchall()
            return rows
        except:
            return ("ERROR: NOT GIVEN ENT PARAMETERS")

    def get_from_victim_changed(self,packet_id=False, src_ip=False, dst_ip=False, req_type=False, req_params=False, headers=False,
                        data=False, src_port=False, dst_port=False, src_mac=False, dst_mac=False):
        try:
            rows = self.cursor.execute(f"SELECT {'packet_id, ' if packet_id else ''}{'src_ip' if src_ip else ''}"
                                  f"{'dst_ip' if dst_ip else ''}{'req_type' if req_type else ''}"
                                  f"{'req_params' if req_params else ''}{'req_params' if req_params else ''}"
                                  f"{'headers' if headers else ''}{'data' if data else ''}"
                                  f"{'src_port' if src_port else ''}{'dst_port' if dst_port else ''}"
                                  f"{'src_mac' if src_mac else ''}{'dst_mac' if dst_mac else ''}  FROM victim_changed_db").fetchall()
            return rows
        except:
            return ("ERROR: NOT GIVEN ENT PARAMETERS")


