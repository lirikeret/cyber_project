import sqlite3
import queue
import threading

class DataBase:

    def __init__(self, do_before_adding_to_database=None):
        self.connection = sqlite3.connect("C:\\Users\\lirik\\Downloads\\sqlitestudio-3.3.3\\SQLiteStudio\\project_db.db")
        self.cursor = self.connection.cursor()
        self.missions = queue.Queue()
        self.do_before_adding_to_database = do_before_adding_to_database if do_before_adding_to_database else (lambda x: None)

    def start(self):
        """
        starts the func which sents the information to the right tables
        """
        self.on = True
        t = threading.Thread(target=self.start_missions)
        t.start()

    def start_missions(self):
        """
        while on=true, the func will execute all the lines from the mission Queue.
        """
        self.connection = sqlite3.connect(
            "C:\\Users\\lirik\\Downloads\\sqlitestudio-3.3.3\\SQLiteStudio\\project_db.db")
        self.cursor = self.connection.cursor()
        while self.on:
            if not self.missions.empty():
                self.cursor.execute(*self.missions.get())
                self.connection.commit()
        self.close_connection()

    def set_db_on(self, set):
        """
        :param set: false/true
        sets the var on
        """
        self.on = set

    def write_to(self, table, packet_id, src_ip, dst_ip, req_type, req_params, data, src_port, dst_port, flag=True):
        """
        :param flag: tells if the packect needs to be pronted to the screen or not
        puts the information recived to the missions queue
        """
        line2 = f"INSERT INTO {table} VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        info = (line2, (packet_id, src_ip, dst_ip, req_type, req_params, data, src_port, dst_port))
        if flag:
            self.do_before_adding_to_database((table, info[1]))
        self.missions.put(info)

    def write_to_router(self, packet_id, src_ip, dst_ip, req_type, req_params, data, src_port, dst_port):
        self.write_to("router_db", packet_id, src_ip, dst_ip, req_type, req_params, data, src_port, dst_port)

    def write_to_router_changed(self, packet_id, src_ip, dst_ip, req_type, req_params, data, src_port, dst_port):
        self.write_to("router_db_changed", packet_id, src_ip, dst_ip, req_type, req_params, data, src_port, dst_port, False)

    def write_to_victim(self, packet_id, src_ip, dst_ip, req_type, req_params, data, src_port, dst_port):
        self.write_to("victim_db", packet_id, src_ip, dst_ip, req_type, req_params, data, src_port, dst_port)

    def write_to_victim_changed(self, packet_id, src_ip, dst_ip, req_type, req_params, data, src_port, dst_port):
        self.write_to("victim_db_changed", packet_id, src_ip, dst_ip, req_type, req_params, data, src_port, dst_port, False)

    def get_from(self, table):
        self.missions.put(f"SELECT * FROM {table}")

    def get_from_router(self):
        self.get_from("router_db")

    def get_from_router_changed(self):
        self.get_from("router_db_changed")

    def get_from_victim(self):
        self.get_from("victim")

    def get_from_victim_changed(self):
        self.get_from("victim_db_changed")

    def close_connection(self):
        """
        closes the connection
        """
        self.cursor.close()

    def get_last(self):
        """
        takes all the last packet ids in the database, and compares them.
        :return: the new packet id neede to be used
        """
        last_router = self.cursor.execute("SELECT packet_id AS last_id FROM router_db "
                                          "ORDER BY packet_id DESC LIMIT 1").fetchall()
        last_router = last_router[0][0] if len(last_router) > 0 else 0
        last_victim = self.cursor.execute("SELECT packet_id AS last_id FROM victim_db "
                                          "ORDER BY packet_id DESC LIMIT 1").fetchall()
        last_victim = last_victim[0][0] if len(last_victim) else 0
        maxi = max(last_router,last_victim)
        return maxi + 1 if maxi else maxi

