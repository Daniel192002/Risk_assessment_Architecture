import mariadb

class DatabaseManager:
    
    def __init__(self, host="localhost", user="root", password="", database="identified_assets"):
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
                "INSERT INTO assets (mac, ipv4, ipv6) VALUES (?, ?, ?)",
                (mac, ipv4, ipv6)
            )
            self.conn.commit()
        except mariadb.Error as e:
             print(f"Error insertando datos: {e}")
    
    def get_devices(self):
        query = "SELECT mac, ipv4, ipv6 FROM assets"
        self.cursor.execute(query)
        return self.cursor.fetchall()
    
    def insert_vulnerability(self, ipv4, cve):
        try:
            cursor = self.conn.cursor()
            query = "INSERT INTO vulnerabilities (ipv4, cve) VALUES (%s, %s)"
            cursor.execute(query, (ipv4, cve))
            self.conn.commit()
        except mariadb.Error as e:
            print(f"Error insertando vulnerabilidad: {e}")
    
    
    def cve_exists(self, ipv4, cve):
        cursor = self.conn.cursor()
        query = "SELECT 1 FROM vulnerabilities WHERE ipv4 = %s AND cve = %s LIMIT 1"
        cursor.execute(query, (ipv4, cve))
        return cursor.fetchone() is not None

    def close(self):
        if self.conn:
            self.conn.close()