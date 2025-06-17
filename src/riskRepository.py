from databaseManager import DatabaseManager


class RiskRepository:
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        
    def insert_risk_value(self, ipv4, cve, risk_value, severity):
        query = "INSERT INTO risk_calculated (ipv4, cve, risk, severity) VALUES (%s, %s, %s, %s)"
        self.db.execute_query(query, (ipv4, cve, risk_value, severity))

    def vul_risk_calculated_exists(self, ipv4, cve):
        query = "SELECT 1 FROM risk_calculated WHERE ipv4 = %s AND cve = %s LIMIT 1"
        return self.db.execute_query(query, (ipv4, cve), fetch_one=True) is not None