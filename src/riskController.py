# risk_controller.py
# Importar SOLO los módulos de lógica de negocio, NO los repositorios directamente aquí
from asset_detector import AssetDetector
from vulnerabilityScanner import VulnerabilityScanner
from threatClassifier import ThreatClassifier
from riskCalculation import RiskCalculation
from reportGenerator import ReportGenerator

import psutil # Todavía necesario para get_all_network_interfaces

class RiskController:
    # El constructor ahora solo recibe los módulos de negocio.
    def __init__(self,
                 asset_detector: AssetDetector,
                 vulnerability_scanner: VulnerabilityScanner,
                 threat_classifier: ThreatClassifier,
                 risk_calculation: RiskCalculation,
                 report_generator: ReportGenerator
                 ):
        self.asset_detector = asset_detector
        self.vulnerability_scanner = vulnerability_scanner
        self.threat_classifier = threat_classifier
        self.risk_calculation = risk_calculation
        self.report_generator = report_generator

        # ¡ self.asset_repo, self.vuln_repo, self.report_repo YA NO ESTÁN AQUÍ !

    def get_all_network_interfaces(self):
        # ... (Método auxiliar, no cambia)
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

        # El AssetDetector ahora maneja su propia persistencia.
        # RiskController solo le dice "escanea y encárgate".
        for interface in interfaces_to_scan:
            self.asset_detector.scan_network(interface) # El AssetDetector guarda los datos
        print("[+] Escaneo de activos completado y datos guardados por AssetDetector.")

    def execute_vulnerability_scan(self):
        print("[2] Escaneando vulnerabilidades de los dispositivos ...")
        # El RiskController SOLO LLAMA A LOS MÓDULOS DE NEGOCIO:
        self.vulnerability_scanner.execute_scan() # El VulnerabilityScanner se encarga de todo lo suyo.
        print("[+] Escaneo de vulnerabilidades completado y datos guardados por VulnerabilityScanner.")

    def classify_vulnerabilities(self):
        print("[3] Clasificando vulnerabilidades ...")
        # threat_classifier.classify_threats() (un nuevo método en ThreatClassifier que orqueste su lógica y persistencia)
        self.threat_classifier.classify_all_vulnerabilities() # Nuevo método
        print("[+] Clasificación de vulnerabilidades completada y datos guardados por ThreatClassifier.")

    def calculate_risk(self):
        print("[4] Calculando riesgo de las vulnerabilidades ...")
        # risk_calculation.calculate_all_risks() (un nuevo método en RiskCalculation)
        self.risk_calculation.calculate_all_risks() # Nuevo método
        print("[+] Cálculo de riesgo completado y datos guardados por RiskCalculation.")

    def generate_report(self):
        print("[5] Generando reporte de vulnerabilidades ...")
        self.report_generator.generate_full_report() # Nuevo método que se encarga de todo
        print("[+] Reporte generado con éxito.")

    def vulnerability_scan_complete(self):
        self.scan_assets()
        self.execute_vulnerability_scan()
        self.classify_vulnerabilities()
        self.calculate_risk()
        self.generate_report()

    def show_menu(self):
        # ... (método show_menu no cambia)
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