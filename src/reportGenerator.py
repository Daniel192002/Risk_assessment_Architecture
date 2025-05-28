
import csv
import xml.etree.ElementTree as ET
from collections import defaultdict

class ReportGenerator:
       
    def generate_report(self, report_data):
        print("\n¿En qué formato deseas generar el informe de vulnerabilidades?")
        print("1. CSV")
        print("2. XML")
        print("3. Ambos")
        print("0. Cancelar")
        
        choice = input("Seleccione una opción: ")
        if choice == "1":
            self.generate_csv_report(report_data)
        elif choice == "2":
            self.generate_xml_report(report_data)
        elif choice == "3":
            self.generate_csv_report(report_data)
            self.generate_xml_report(report_data)
        elif choice == "0":
            print("Operación cancelada.")
        else:
            print("Opción no válida, por favor intente de nuevo.")
    def generate_csv_report(self, report_data):
        
        filename = "vulnerability_report.csv"
        with open(filename, mode='w', newline='', encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(["MAC", "IPv4", "IPv6", "CVE", "NVT Name", "STRIDE", "LINDDUN", "Risk", "Solution"])
            
            # Ordenar por nivel de riesgo (asumiendo que Risk está en la posición 7)
            sorted_data = sorted(report_data, key=lambda x: float(x[7]) if x[7] is not None else 0.0, reverse=True)

            for row in sorted_data:
                # Limpiar STRIDE y LINDDUN si son listas como string
                row = list(row)
                row[5] = ", ".join(eval(row[5])) if row[5].startswith("[") else row[5]
                row[6] = ", ".join(eval(row[6])) if row[6].startswith("[") else row[6]
                writer.writerow(row)

        print(f"[✓] Informe CSV generado: {filename}")
    
    def generate_xml_report(self, report_data):
        
        print("[DEBUG] Generando informe XML...")
        filename = "vulnerability_report.xml"
        devices = defaultdict(list)
        for mac, ipv4, ipv6, cve, nvt, stride, linddun, risk, solucion in report_data:
            key = (mac, ipv4, ipv6)
            devices[key].append((cve, nvt, stride, linddun, risk, solucion))
        
        root = ET.Element("Devices")
        for (mac, ipv4, ipv6), vulnerabilities in devices.items():
            device_elem = ET.SubElement(root, "Device")
            ET.SubElement(device_elem, "MAC").text = mac
            ET.SubElement(device_elem, "IPv4").text = ipv4
            ET.SubElement(device_elem, "IPv6").text = ipv6
            
            for cve, nvt, stride, linddun, risk, solucion in vulnerabilities:
                vulnerability_elem = ET.SubElement(device_elem, "Vulnerability")
                ET.SubElement(vulnerability_elem, "CVE").text = cve
                ET.SubElement(vulnerability_elem, "NVT_Name").text = nvt
                ET.SubElement(vulnerability_elem, "STRIDE").text = stride
                ET.SubElement(vulnerability_elem, "LINDDUN").text = linddun
                ET.SubElement(vulnerability_elem, "Risk").text = risk
                ET.SubElement(vulnerability_elem, "Solution").text = solucion
        tree = ET.ElementTree(root)
        tree.write(filename, encoding="utf-8", xml_declaration=True)
        print(f"[✓] Informe XML generado: {filename}")

