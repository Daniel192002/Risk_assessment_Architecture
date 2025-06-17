# risk_controller.py (Modificado)
from asset_detector import AssetDetector
from vulnerabilityScanner import VulnerabilityScanner
from threatClassifier import ThreatClassifier
from riskCalculation import RiskCalculation
from reportGenerator import ReportGenerator

# Importar los nuevos repositorios
from assetRepository import AssetRepository
from vulnerabilityRepository import VulnerabilityRepository
from reportRepository import ReportRepository

import psutil # Mantenemos psutil aquí, ya que es para la lógica de red, no de DB

class RiskController:
    def __init__(self,
                 asset_detector: AssetDetector,
                 vulnerability_scanner: VulnerabilityScanner,
                 threat_classifier: ThreatClassifier,
                 risk_calculation: RiskCalculation,
                 report_generator: ReportGenerator,
                 asset_repository: AssetRepository,
                 vulnerability_repository: VulnerabilityRepository,
                 report_repository: ReportRepository
                 ):
        # Módulos de lógica de negocio
        self.asset_detector = asset_detector
        self.vulnerability_scanner = vulnerability_scanner
        self.threat_classifier = threat_classifier
        self.risk_calculation = risk_calculation
        self.report_generator = report_generator

        # Repositorios para persistencia (inyectados)
        self.asset_repo = asset_repository
        self.vuln_repo = vulnerability_repository
        self.report_repo = report_repository

        # ¡ self.db y atexit.register(self.db.close) YA NO ESTÁN AQUÍ !

    def get_all_network_interfaces(self):
        interfaces = []
        for interface, addrs in psutil.net_if_addrs().items():
            if interface != "lo":
                interfaces.append(interface)
        return interfaces

    def scan_assets(self):
        print("[1] Escaneando dispositivos en la red ...")
        interfaces_to_scan = self.get_all_network_interfaces()
        if not interfaces_to_scan:
            print("[!] No se encontraron interfaces de red disponibles.")
            return
        print(f"[+] Escaneando en las siguientes interfaces: {', '.join(interfaces_to_scan)}")

        all_detected_devices = {}
        for interface in interfaces_to_scan:
            print(f"[+] Escaneando en la interfaz: {interface}")
            devices = self.asset_detector.scan_network(interface)
            all_detected_devices.update(devices)

        existing_devices = self.asset_repo.get_all_devices() # Usamos el AssetRepository
        # Convertir a un set para búsquedas eficientes (si tus tuplas de DB son hashable)
        existing_devices_set = set([(d[0], d[1], d[2]) for d in existing_devices])

        for mac, addrs in all_detected_devices.items():
            ipv4 = addrs.get("IPv4")
            ipv6 = addrs.get("IPv6")

            # Ahora la comprobación de existencia puede usar el set o un método del repo
            if (mac, ipv4, ipv6) not in existing_devices_set:
            # O podrías usar: if not self.asset_repo.device_exists(mac, ipv4, ipv6):
                self.asset_repo.insert_device(mac, ipv4, ipv6) # Usamos el AssetRepository
                print(f"[+] Dispositivo nuevo detectado: {mac} - IPv4: {ipv4} - IPv6: {ipv6}")
            else:
                print(f"[-] Dispositivo ya existente (ignorando): {mac} - IPv4: {ipv4} - IPv6: {ipv6}")

    def execute_vulnerability_scan(self):
        print("[2] Escaneando vulnerabilidades de los dispositivos ...")
        existing_devices = self.asset_repo.get_all_devices() # Usamos el AssetRepository
        for device in existing_devices:
            mac = device[0]
            ip = device[1]
            if ip:
                cves = self.vulnerability_scanner.scan(ip)
                print(f"[+] CVES: {cves}")
                for cve, severity, nvt_name, solution in cves:
                    # Usamos el VulnerabilityRepository
                    if not self.vuln_repo.cve_exists(ip, cve):
                        self.vuln_repo.insert_vulnerability(mac, ip, cve, severity, nvt_name, solution)
                        print(f"[+] Vulnerabilidad detectada: {cve} en {ip}")
                    else:
                        print(f"[-] Vulnerabilidad ya registrada (ignorando): {cve} en {ip}")

    def classify_vulnerabilities(self):
        print("[3] Clasificando vulnerabilidades ...")
        cves = self.vuln_repo.get_all_vulnerabilities() # Usamos el VulnerabilityRepository
        for ipv4, cve in cves:
            # Usamos el VulnerabilityRepository
            if not self.vuln_repo.cve_classified_exists(ipv4, cve):
                thread_classified = self.threat_classifier.classify_threat(ipv4, cve)
                if thread_classified is None: # Usar 'is None' en lugar de '== None'
                    continue
                else:
                    thread = thread_classified[0]
                    cvss_vector = thread["cvss_vector"]
                    stride = thread["STRIDE"]
                    linddun = thread["LINDDUN"]
                    self.vuln_repo.insert_vul_classified(ipv4, cve, cvss_vector, stride, linddun) # Usamos el VulnerabilityRepository
                    print(f"[+] Amenazas clasificadas: {thread_classified}")
            else:
                print(f"[-] Amenaza ya clasificada (ignorando): {cve} en {ipv4}")
                continue

    def calculate_risk(self):
        print("[4] Calculando riesgo de las vulnerabilidades ...")
        cves_classified = self.vuln_repo.get_classified_vulnerabilities() # Usamos el VulnerabilityRepository
        for ipv4, cve, cvss_vector, stride, linddun in cves_classified:
            # Usamos el VulnerabilityRepository
            if not self.vuln_repo.vul_risk_calculated_exists(ipv4, cve):
                risk, severity = self.risk_calculation.calculate_risk(cvss_vector, stride, linddun)
                self.vuln_repo.insert_risk_value(ipv4, cve, risk, severity) # Usamos el VulnerabilityRepository
                print(f"[+] Riesgo calculado: {risk}, con severidad {severity} para {ipv4} - {cve}")
            else:
                print(f"[-] Amenaza ya calculada (ignorando): {cve} en {ipv4}")
                continue

    def generate_report(self):
        print("[5] Generando reporte de vulnerabilidades ...")
        report_data = self.report_repo.get_report_information() # Usamos el ReportRepository
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
        # ... (código existente)
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