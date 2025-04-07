import mariadb

class DatabaseManager:
    
    def __init__(self, host="localhost", user="root", password="", database="red_activa"):
        try:
            self.conn = mariadb.connect(
                user = user,
                password = password,
                host = host,
                port = 3306,
                database = database
            )
            self.cursor = self.conn.cursor()
        except mariadb.Error as e:
            print(f"Error conectando a MariaDB: {e}")
            self.conn = None
    
    def insert_device(self, mac, ipv4, ipv6):
        try:
            self.cursor.execute(
                "INSERT INTO dispositivos (mac, ipv4, ipv6) VALUES (?, ?, ?)",
                (mac, ipv4, ipv6)
            )
            self.conn.commit()
        except mariadb.Error as e:
             print(f"Error insertando datos: {e}")

    def close(self):
        if self.conn:
            self.conn.close()