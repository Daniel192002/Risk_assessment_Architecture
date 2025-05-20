
from asset_controller import AssetController
from vulnerabilityScanner import VulnerabilityScanner
from threat_db import ExternalThreatDB
import  databaseManager


INTERFAZ = "eth1"

class RiskController:
    def __init__(self):
        self.asset_controller = AssetController()
        self.vulnerability_scanner = VulnerabilityScanner()
        self.threat_db = ExternalThreatDB()
        self.db = databaseManager.DatabaseManager(user="root", password="tfg2025", host="127.0.0.1")

    def execute_risk_analysis(self):
        devices = self.asset_controller.scan_network(INTERFAZ)
        existing_devices = self.db.get_devices()
        
        # INSERTAR DATOS EN LA BASE DE DATOS
        for mac, addrs in devices.items():
            ipv4 = addrs["IPv4"]
            ipv6 = addrs["IPv6"]
            if (mac, ipv4, ipv6) not in existing_devices:
                self.db.insert_device(mac, ipv4, ipv6)
                print(f"[+] Dispositivo nuevo detectado: {mac} - IPv4: {ipv4} - IPv6: {ipv6}")
            else:
                print(f"[-] Dispositivo ya existente (ignorando): {mac} - IPv4: {ipv4} - IPv6: {ipv6}")
        
        #ESCANEO DE VULNERABILIDADES
        for device in existing_devices:
            mac = device[0]
            ip = device[1]
            print(f"[+] Dispositivo nuevo detectado: {mac} - IPv4: {ip}")
            # if ip:
            #     cves = self.vulnerability_scanner.scan(ip)
            #     print(f"[+] CVES: {cves}")
            #     for cve, severity in cves:
            #         if not self.db.cve_exists(ipv4, cve):
            #             self.db.insert_vulnerability(ipv4, cve, severity)
            #             print(f"[+] Vulnerabilidad detectada: {cve} en {ipv4}")
            #         else:
            #             print(f"[-] Vulnerabilidad ya registrada (ignorando): {cve} en {ipv4}")
        
        
        #Buscar y clasificar vulnerabilidades
     
        cves = self.db.get_vulnerabilities()
        threads_classified = self.threat_db.classify_threats(cves)
        print(f"[+] Amenazas clasificadas: {threads_classified}")

        self.db.close()