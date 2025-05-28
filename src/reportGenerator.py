
import csv
import xml.etree.ElementTree as ET
import ast
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
                row = list(row)  # Convert tuple to list for mutability
                
                if isinstance(row[5], str) and row[5].startswith("["):
                    try:
                        row[5] = ", ".join(ast.literal_eval(row[5]))
                    except Exception:
                        pass
                if isinstance(row[6], str) and row[6].startswith("["):
                    try:
                        row[6] = ", ".join(ast.literal_eval(row[6]))
                    except Exception:
                        pass
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
            ET.SubElement(device_elem, "MAC").text = str(mac)
            ET.SubElement(device_elem, "IPv4").text = str(ipv4)
            ET.SubElement(device_elem, "IPv6").text = str(ipv6)
            
            for cve, nvt, stride, linddun, risk, solucion in vulnerabilities:
                vulnerability_elem = ET.SubElement(device_elem, "Vulnerability")
                ET.SubElement(vulnerability_elem, "CVE").text = str(cve)
                ET.SubElement(vulnerability_elem, "NVT_Name").text = str(nvt)

                # Limpiar STRIDE y LINDDUN si vienen como string tipo lista
                stride_str = ""
                if isinstance(stride, str) and stride.startswith("["):
                    try:
                        stride_str = ", ".join(ast.literal_eval(stride))
                    except:
                        stride_str = stride
                else:
                    stride_str = str(stride)
                ET.SubElement(vulnerability_elem, "STRIDE").text = stride_str

                linddun_str = ""
                if isinstance(linddun, str) and linddun.startswith("["):
                    try:
                        linddun_str = ", ".join(ast.literal_eval(linddun))
                    except:
                        linddun_str = linddun
                else:
                    linddun_str = str(linddun)
                ET.SubElement(vulnerability_elem, "LINDDUN").text = linddun_str

                ET.SubElement(vulnerability_elem, "Risk").text = str(risk) if risk is not None else "0"
                ET.SubElement(vulnerability_elem, "Solution").text = str(solucion)

        tree = ET.ElementTree(root)
        tree.write(filename, encoding="utf-8", xml_declaration=True)
        print(f"[✓] Informe XML generado: {filename}")

