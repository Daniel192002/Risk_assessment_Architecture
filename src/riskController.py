
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
        
        # # INSERTAR DATOS EN LA BASE DE DATOS
        # for mac, addrs in devices.items():
        #     ipv4 = addrs["IPv4"]
        #     ipv6 = addrs["IPv6"]
        #     if (mac, ipv4, ipv6) not in existing_devices:
        #         self.db.insert_device(mac, ipv4, ipv6)
        #         print(f"[+] Dispositivo nuevo detectado: {mac} - IPv4: {ipv4} - IPv6: {ipv6}")
        #     else:
        #         print(f"[-] Dispositivo ya existente (ignorando): {mac} - IPv4: {ipv4} - IPv6: {ipv6}")
        
        # #ESCANEO DE VULNERABILIDADES
        # for device in existing_devices:
        #     mac = device[0]
        #     ip = device[1]
        #     if ip:
        #         cves = self.vulnerability_scanner.scan(ip)
        #         print(f"[+] CVES: {cves}")
        #         for cve, severity in cves:
        #             if not self.db.cve_exists(ip, cve):
        #                 self.db.insert_vulnerability(mac, ip, cve, severity)
        #                 print(f"[+] Vulnerabilidad detectada: {cve} en {ip}")
        #             else:
        #                 print(f"[-] Vulnerabilidad ya registrada (ignorando): {cve} en {ip}")
        
        
        #Buscar y clasificar vulnerabilidades

        cves = self.db.get_vulnerabilities()
        for ipv4, cve in cves:
            if not self.db.cve_classified_exists(ipv4, cve):
                thread_classified = self.threat_db.classify_threat(ipv4, cve)
                thread = thread_classified[0]
                cvss_vector = thread["cvss_vector"]
                stride = thread["STRIDE"]
                linddun = thread["LINDDUN"]
                self.db.insert_vul_classified(ipv4,cve,cvss_vector,stride,linddun)
                print(f"[+] Amenazas clasificadas: {thread_classified}")
            else:
                print(f"[-] Amenaza ya clasificada (ignorando): {cve} en {ipv4}")
                continue
                
        
        self.db.close()