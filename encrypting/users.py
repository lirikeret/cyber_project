import sqlite3
import hashlib
import uuid

class Users:
    def __init__(self):
        self.connection = sqlite3.connect(r"C:\Users\lirik\Downloads\sqlitestudio-3.3.3\SQLiteStudio\users_db.db")
        self.cursor = self.connection.cursor()

    def insert_user(self, username, pw):
        """
        recives pw and un, checks if the user exists. if it dosent exists, adds user to database.
        if exsists, returns exists.
        """
        salt, password = self.hash_pw(pw)
        if not self.u_exists(username):
            self.cursor.execute(f"INSERT INTO users (username,password,salt) VALUES (?,?,?)",
                                (username, password, salt))
            self.connection.commit()
        else:
            return "exists"

    def hash_pw(self, password):
        """
        encrypting the password using hash
        :return: salt and hashed password
        """
        password = password.encode()
        salt = uuid.uuid4().hex.encode()
        hashed_password = hashlib.sha256(password + salt).hexdigest()
        return salt, hashed_password

    def u_exists(self, un):
        """
        :param un: username
        :return: if the username Exsist
        """
        return len(self.cursor.execute(f"SELECT * FROM users WHERE username ='{un}'").fetchall()) > 0

    def close(self):
        """
        closes the connection with the db
        """
        self.cursor.close()

    def check_user(self, un, pw):
        """
        recives un and pw, checks if the user exsist and the password is correct
        :return: triue if exist, false otherwise
        """
        try:
            if self.u_exists(un):
                salt = self.cursor.execute(f"SELECT salt FROM users WHERE username ='{un}'").fetchall()
                salt = salt[0][0]
                pw = pw.encode()
                savedp = self.cursor.execute(f"SELECT password FROM users WHERE username ='{un}'").fetchall()[0][0]
                return hashlib.sha256(pw + salt).hexdigest() == savedp
            else:
                return False
        except sqlite3.DatabaseError:
            return False
