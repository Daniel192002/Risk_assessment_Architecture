from databaseManager import DatabaseManager
import json

class ThreatRepository:
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        
    def get_classified_vulnerabilities(self):
        # Asegúrate de que los campos JSON se carguen si necesitas el objeto Python
        query = "SELECT ipv4, cve_id, cvss_vector, stride, linddun FROM vul_classified"
        results = self.db.execute_query(query)
        # Opcional: Deserializar los campos JSON si se necesitan como objetos Python
        # for row in results:
        #    row[3] = json.loads(row[3]) # stride
        #    row[4] = json.loads(row[4]) # linddun
        return results

    def insert_vul_classified(self, ipv4, cve, cvss_vector, stride, linddun):
        # Asegúrate de que stride y linddun sean strings JSON al insertarlos
        query = "INSERT INTO vul_classified (ipv4, cve_id, cvss_vector, stride, linddun) VALUES (%s, %s, %s, %s, %s)"
        self.db.execute_query(query, (ipv4, cve, cvss_vector, json.dumps(stride), json.dumps(linddun)))

    def cve_classified_exists(self, ipv4, cve):
        query = "SELECT 1 FROM vul_classified WHERE ipv4 = %s AND cve_id = %s LIMIT 1"
        return self.db.execute_query(query, (ipv4, cve), fetch_one=True) is not None