
from asset_controller import AssetController
from vulnerabilityScanner import VulnerabilityScanner
from threat_db import ExternalThreatDB
from riskCalculation import RiskCalculation
from reportGenerator import ReportGenerator
import  databaseManager
import atexit


INTERFAZ = "eth1"

class RiskController:
    def __init__(self):
        self.asset_controller = AssetController()
        self.vulnerability_scanner = VulnerabilityScanner()
        self.threat_db = ExternalThreatDB()
        self.risk_calculation = RiskCalculation()
        self.report_generator = ReportGenerator()
        self.db = databaseManager.DatabaseManager(user="root", password="tfg2025", host="127.0.0.1")
        atexit.register(self.db.close)  # Asegura que la conexión a la base de datos se cierre al salir del programa
    
    def scan_assets(self):
        print("[1] Escaneando dispositivos en la red ...")
        devices = self.asset_controller.scan_network(INTERFAZ)
        existing_devices = self.db.get_devices()
        for mac, addrs in devices.items():
            ipv4 = addrs["IPv4"]
            ipv6 = addrs["IPv6"]
            if (mac, ipv4, ipv6) not in existing_devices:
                self.db.insert_device(mac, ipv4, ipv6)
                print(f"[+] Dispositivo nuevo detectado: {mac} - IPv4: {ipv4} - IPv6: {ipv6}")
            else:
                print(f"[-] Dispositivo ya existente (ignorando): {mac} - IPv4: {ipv4} - IPv6: {ipv6}")
    def execute_vulnerability_scan(self):
        print("[2] Escaneando vulnerabilidades de los dispositivos ...")
        existing_devices = self.db.get_devices()
        for device in existing_devices:
            mac = device[0]
            ip = device[1]
            if ip:
                cves = self.vulnerability_scanner.scan(ip)
                print(f"[+] CVES: {cves}")
                for cve, severity, nvt_name, solution in cves:
                    if not self.db.cve_exists(ip, cve):
                        self.db.insert_vulnerability(mac, ip, cve, severity, nvt_name, solution)
                        print(f"[+] Vulnerabilidad detectada: {cve} en {ip}")
                    else:
                        print(f"[-] Vulnerabilidad ya registrada (ignorando): {cve} en {ip}")
        
        
    def classify_vulnerabilities(self):
        print("[3] Clasificando vulnerabilidades ...")
        cves = self.db.get_vulnerabilities()
        for ipv4, cve in cves:
            if not self.db.cve_classified_exists(ipv4, cve):
                thread_classified = self.threat_db.classify_threat(ipv4, cve)
                if thread_classified == None:
                    continue;
                else:
                    thread = thread_classified[0]
                    cvss_vector = thread["cvss_vector"]
                    stride = thread["STRIDE"]
                    linddun = thread["LINDDUN"]
                    self.db.insert_vul_classified(ipv4,cve,cvss_vector,stride,linddun)
                    print(f"[+] Amenazas clasificadas: {thread_classified}")
            else:
                print(f"[-] Amenaza ya clasificada (ignorando): {cve} en {ipv4}")
                continue
        
    def calculate_risk(self):
        print("[4] Calculando riesgo de las vulnerabilidades ...")
        cves_classified = self.db.get_classified_vulnerabilities()
        for ipv4, cve, cvss_vector, stride, linddun in cves_classified:
            if not self.db.vul_risk_calculated_exists(ipv4, cve):
                risk, severity = self.risk_calculation.calculate_risk(cvss_vector, stride, linddun)
                self.db.insert_risk_value(ipv4, cve, risk, severity)
                print(f"[+] Riesgo calculado: {risk}, con severidad {severity} para {ipv4} - {cve}")
            else:
                print(f"[-] Amenaza ya calculada (ignorando): {cve} en {ipv4}")
                continue
    
    def generate_report(self):
        print("[5] Generando reporte de vulnerabilidades ...")
        report_data = self.db.get_report_information()
        if not report_data:
            print("No se encontraron datos para generar el reporte.")
            return
        else:
            print("Datos obtenidos para el reporte:")
            self.report_generator.generate_report(report_data)
        
        
    def vulnerability_scan_complete(self):
            self.scan_assets()
            self.execute_vulnerability_scan()
            self.classify_vulnerabilities()
            self.calculate_risk()
            self.generate_report()
    
    def show_menu(self):
        print("\n====== MENÚ DE ANÁLISIS DE VULNERABILIDADES ======")
        print("1. Escanear activos")
        print("2. Analizar vulnerabilidades")
        print("3. Clasificar vulnerabilidades")
        print("4. Calcular riesgo")
        print("5. Generar reporte")
        print("6. Ejecutar proceso completo")
        print("0. Salir")
        print("===================================================")
            
        
    def main(self):
        while True:
            self.show_menu()
            choice = input("Seleccione una opción: ")
            if choice == "1":
                self.scan_assets()
            elif choice == "2":
                self.execute_vulnerability_scan()
            elif choice == "3":
                self.classify_vulnerabilities()
            elif choice == "4":
                self.calculate_risk()
            elif choice == "5":
                print("Generando reporte...")
                self.generate_report()
            elif choice == "6":
                self.vulnerability_scan_complete()
            elif choice == "0":
                print("Saliendo del programa...")
                break
            else:
                print("Opción no válida, por favor intente de nuevo.")
        
        
    
        
        