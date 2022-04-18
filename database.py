import sqlite3
import queue
import threading


class DataBase:

    def __init__(self):
        self.connection = sqlite3.connect("C:\\Users\\lirik\\Downloads\\sqlitestudio-3.3.3\\SQLiteStudio\\project_db.db")
        self.cursor = self.connection.cursor()
        self.missions = queue.Queue()
        self.on = True
        t = threading.Thread(target=self.start)
        t.start()

    def start(self):
        #self.connection = sqlite3.connect(
           # "C:\\Users\\lirik\\Downloads\\sqlitestudio-3.3.3\\SQLiteStudio\\project_db.db")
        #self.cursor = self.connection.cursor()
        while self.on:
            if not self.missions.empty():
                self.cursor.execute(*self.missions.get())
                self.connection.commit()
        self.close_connection()


    def write_to(self, table, packet_id, src_ip, dst_ip, req_type, req_params, data, src_port, dst_port):
        # line = f"INSERT INTO {table} VALUES ({packet_id}, '{src_ip}', '{dst_ip}', '{memoryview(req_type)}', "\
         #      f"'{memoryview(req_params)}', '{memoryview(data)}', {src_port}, {dst_port})"
        line2 = f"INSERT INTO {table} VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        print(line2)
        self.missions.put((line2, (packet_id, src_ip, dst_ip, req_type, req_params, data, src_port, dst_port)))

    def write_to_router(self, packet_id, src_ip, dst_ip, req_type, req_params, data, src_port, dst_port):
        self.write_to("router_db", packet_id, src_ip, dst_ip, req_type, req_params, data, src_port, dst_port)

    def write_to_router_changed(self, packet_id, src_ip, dst_ip, req_type, req_params, data, src_port, dst_port):
        self.write_to("router_db_changed", packet_id, src_ip, dst_ip, req_type, req_params, data, src_port, dst_port)

    def write_to_victim(self, packet_id, src_ip, dst_ip, req_type, req_params, data, src_port, dst_port):
        self.write_to("victim_db", packet_id, src_ip, dst_ip, req_type, req_params, data, src_port, dst_port)

    def write_to_victim_changed(self, packet_id, src_ip, dst_ip, req_type, req_params, data, src_port, dst_port):
        self.write_to("victim_db_changed", packet_id, src_ip, dst_ip, req_type, req_params, data, src_port, dst_port)

    def get_from_router(self, packet_id, src_ip=False, dst_ip=False, req_type=False, req_params=False,
                        data=False, src_port=False, dst_port=False):
        try:
            rows = self.cursor.execute(f"SELECT {'packet_id, '}{'src_ip, ' if src_ip else ''}"
                                       f"{'dst_ip, ' if dst_ip else ''}{'request_type, ' if req_type else ''}"
                                       f"{'request_parameters, ' if req_params else ''}{'data, ' if data else ''}"
                                       f"{'src_port, ' if src_port else ''}{'dst_port' if dst_port else ''}"
                                       f" FROM router_db WHERE packet_id={packet_id}").fetchall()
            return rows
        except:
            return ("ERROR: NOT GIVEN ENT PARAMETERS")

    def get_from_router_changed(self, packet_id, src_ip=False, dst_ip=False, req_type=False, req_params=False,
                                data=False, src_port=False, dst_port=False):
        try:
            rows = self.cursor.execute(f"SELECT {packet_id}{'src_ip' if src_ip else ''}"
                                       f"{'dst_ip' if dst_ip else ''}{'req_type' if req_type else ''}"
                                       f"{'req_params' if req_params else ''}{'req_params' if req_params else ''}"
                                       f"{'data' if data else ''}"
                                       f"{'src_port' if src_port else ''}{'dst_port' if dst_port else ''}"
                                       f" FROM router_changed_db WHERE packet_id={packet_id}").fetchall()
            return rows
        except:
            return ("ERROR: NOT GIVEN ENT PARAMETERS")

    def get_from_victim(self, packet_id, src_ip=False, dst_ip=False, req_type=False, req_params=False,
                        data=False, src_port=False, dst_port=False):
        try:
            rows = self.cursor.execute(f"SELECT {packet_id}{'src_ip' if src_ip else ''}"
                                       f"{'dst_ip' if dst_ip else ''}{'req_type' if req_type else ''}"
                                       f"{'req_params' if req_params else ''}{'req_params' if req_params else ''}"
                                       f"{'data' if data else ''}"
                                       f"{'src_port' if src_port else ''}{'dst_port' if dst_port else ''}"
                                       f" FROM victim_db WHERE packet_id={packet_id}").fetchall()
            return rows
        except:
            return ("ERROR: NOT GIVEN ENT PARAMETERS")

    def get_from_victim_changed(self, packet_id, src_ip=False, dst_ip=False, req_type=False, req_params=False,
                                data=False, src_port=False, dst_port=False):
        try:
            rows = self.cursor.execute(f"SELECT {packet_id}{'src_ip' if src_ip else ''}"
                                       f"{'dst_ip' if dst_ip else ''}{'req_type' if req_type else ''}"
                                       f"{'req_params' if req_params else ''}{'req_params' if req_params else ''}"
                                       f"{'data' if data else ''}"
                                       f"{'src_port' if src_port else ''}{'dst_port' if dst_port else ''}"
                                       f" FROM victim_changed_db WHERE packet_id={packet_id}").fetchall()
            return rows
        except:
            return ("ERROR: NOT GIVEN ENT PARAMETERS")

    def close_connection(self):
        self.cursor.close()

    def get_last(self):
        last_router = self.cursor.execute("SELECT packet_id AS last_id FROM router_db ORDER BY packet_id DESC LIMIT 1").fetchall()
        last_router = last_router[0] if len(last_router) > 0 else 0
        last_victim = self.cursor.execute("SELECT packet_id AS last_id FROM victim_db ORDER BY packet_id DESC LIMIT 1").fetchall()
        last_victim = last_victim[0] if len(last_victim) else 0
        maxi = max(last_router,last_victim)
        return maxi + 1 if maxi else maxi

