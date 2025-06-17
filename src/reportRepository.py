from databaseManager import DatabaseManager

class ReportRepository:
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager

    def get_report_information(self):
        query = """
        SELECT
            a.mac, a.ipv4, a.ipv6,
            v.cve, v.nvt_name, v.severity, v.solution,
            vc.cvss_vector, vc.stride, vc.linddun,
            rc.risk, rc.severity
        FROM assets a
        LEFT JOIN vulnerabilities v ON a.ipv4 = v.ipv4
        LEFT JOIN vul_classified vc ON v.ipv4 = vc.ipv4 AND v.cve = vc.cve_id
        LEFT JOIN risk_calculated rc ON v.ipv4 = rc.ipv4 AND v.cve = rc.cve
        ORDER BY a.mac, v.cve;
        """