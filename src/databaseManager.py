import mariadb
import json

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
        cursor = self.conn.cursor()
        query = "SELECT mac, ipv4, ipv6 FROM assets"
        cursor.execute(query)
        return cursor.fetchall()
    
    def get_vulnerabilities(self):
        cursor = self.conn.cursor()
        query = "SELECT ipv4, cve FROM vulnerabilities"
        cursor.execute(query)
        return cursor.fetchall()
    
    def get_classified_vulnerabilities(self):
        cursor = self.conn.cursor()
        query = "SELECT ipv4, cve_id, cvss_vector, stride, linddun FROM vul_classified"
        cursor.execute(query)
        return cursor.fetchall()
    
    def insert_vulnerability(self, mac, ipv4, cve, severity):
        try:
            cursor = self.conn.cursor()
            query = "INSERT INTO vulnerabilities (mac, ipv4, cve, severity) VALUES (%s, %s, %s, %s)"
            cursor.execute(query, (mac, ipv4, cve, severity))
            self.conn.commit()
        except mariadb.Error as e:
            print(f"Error insertando vulnerabilidad: {e}")
    
    def insert_vul_classified(self, ipv4, cve, cvss_vector, stride, linddun):
        try:
            cursor = self.conn.cursor()
            query = "INSERT INTO vul_classified (ipv4, cve_id, cvss_vector, stride, linddun) VALUES (%s, %s, %s, %s, %s)"
            cursor.execute(query, (ipv4, cve, cvss_vector, json.dumps(stride), json.dumps(linddun)))
            self.conn.commit()
        except mariadb.Error as e:
            print(f"Error insertando vulnerabilidad clasificada: {e}")
    
    def cve_exists(self, ipv4, cve):
        cursor = self.conn.cursor()
        query = "SELECT 1 FROM vulnerabilities WHERE ipv4 = %s AND cve = %s LIMIT 1"
        cursor.execute(query, (ipv4, cve))
        return cursor.fetchone() is not None
    
    def cve_classified_exists(self, ipv4, cve):
        cursor = self.conn.cursor()
        query = "SELECT 1 FROM vul_classified WHERE ipv4 = %s AND cve_id = %s LIMIT 1"
        cursor.execute(query, (ipv4, cve))
        return cursor.fetchone() is not None

    def close(self):
        if self.conn:
            self.conn.close()