import csv
import xml.etree.ElementTree as ET
import json
from collections import defaultdict
import ast # Todavía necesario para ast.literal_eval

# Importar el repositorio necesario
from reportRepository import ReportRepository

class ReportGenerator:
    # El constructor ahora recibe una instancia de ReportRepository
    def __init__(self, report_repository: ReportRepository):
        self.report_repo = report_repository
       
    def generate_full_report(self):
        """
        Orquesta la generación de informes, incluyendo la interacción con el usuario
        para seleccionar el formato y la obtención de datos del repositorio.
        """
        print("\n[5] ReportGenerator: Preparando para generar informes...")

        # 1. Obtener los datos completos del informe desde el ReportRepository
        # reportRepository.py::get_report_information devuelve:
        # a.mac, a.ipv4, a.ipv6, v.cve, v.nvt_name, v.severity(NVT), v.solution,
        # vc.cvss_vector, vc.stride, vc.linddun, rc.risk, rc.severity(FINAL)
        raw_report_data = self.report_repo.get_report_information()

        if not raw_report_data:
            print("[!] ReportGenerator: No se encontraron datos para generar el informe.")
            return

        # Mapear y reordenar los datos a la estructura esperada por los generadores de informes
        # Esperado: ["MAC", "IPv4", "IPv6", "CVE", "NVT Name", "STRIDE", "LINDDUN", "Risk", "severity", "Solution"]
        processed_report_data = []
        for row in raw_report_data:
            # Indices de raw_report_data:
            # 0: a.mac, 1: a.ipv4, 2: a.ipv6, 3: v.cve, 4: v.nvt_name, 5: v.severity (NVT),
            # 6: v.solution, 7: vc.cvss_vector, 8: vc.stride, 9: vc.linddun,
            # 10: rc.risk, 11: rc.severity (FINAL)
            
            # Reordenar y seleccionar solo los campos necesarios para el informe
            # Nota: Asegúrate de que los campos 'stride' y 'linddun' sean strings JSON en la DB
            # y los métodos de generación de informes los manejarán con ast.literal_eval
            # o json.loads si fueran necesarios como listas Python.
            cve_id = row[3] if row[3] else f"NOCVE-{row[4]}"  # Usa IP como identificador único

            final_severity = row[11] if row[3] else row[5]  # row[11] = rc.severity, row[5] = v.severity

            # Si no hay CVE, usar un riesgo genérico (si rc.risk también fuera NULL)
            final_risk = row[10] if row[10] is not None else 0.0
            processed_row = (
                row[0], # MAC
                row[1], # IPv4
                row[2], # IPv6
                cve_id, # CVE (usando IP como fallback si no hay CVE)
                row[3], # CVE
                row[4], # NVT Name
                row[8], # STRIDE (vc.stride)
                row[9], # LINDDUN (vc.linddun)
                final_risk,  # Risk (rc.risk)
                final_severity,  # Severity (rc.severity o v.severity)
                row[6]  # Solution (v.solution)
            )
            processed_report_data.append(processed_row)

        print("\n¿En qué formato deseas generar el informe de vulnerabilidades?")
        print("1. CSV")
        print("2. XML")
        print("3. JSON")
        print("4. Todos (CSV,XML y JSON)")
        print("0. Cancelar")
        
        choice = input("Seleccione una opción: ")
        
        if choice == "1":
            self.generate_csv_report(processed_report_data)
        elif choice == "2":
            self.generate_xml_report(processed_report_data)
        elif choice == "3":
            self.generate_json_report(processed_report_data)
        elif choice == "4":
            self.generate_csv_report(processed_report_data)
            self.generate_xml_report(processed_report_data)
            self.generate_json_report(processed_report_data)
        elif choice == "0":
            print("Operación cancelada.")
        else:
            print("Opción no válida, por favor intente de nuevo.")

    def generate_csv_report(self, report_data):
        
        filename = "vulnerability_report.csv"
        with open(filename, mode='w', newline='', encoding="utf-8") as file:
            writer = csv.writer(file, delimiter=';', quoting=csv.QUOTE_ALL)
            writer.writerow(["MAC", "IPv4", "IPv6", "CVE", "NVT Name", "STRIDE", "LINDDUN", "Risk", "Severity", "Solution"])
            
            # Ordenar por nivel de riesgo (asumiendo que Risk está en la posición 7)
            sorted_data = sorted(report_data, key=lambda x: float(x[7]) if x[7] is not None and str(x[7]).replace('.', '', 1).isdigit() else 0.0, reverse=True)

            for row in sorted_data:
                row_list = list(row)  # Convert tuple to list for mutability
                
                # Deserializar y unir STRIDE y LINDDUN si son cadenas JSON
                if isinstance(row_list[5], str) and row_list[5].startswith("["):
                    try:
                        row_list[5] = ", ".join(ast.literal_eval(row_list[5]))
                    except (ValueError, SyntaxError):
                        pass # Keep as is if not valid list string
                if isinstance(row_list[6], str) and row_list[6].startswith("["):
                    try:
                        row_list[6] = ", ".join(ast.literal_eval(row_list[6]))
                    except (ValueError, SyntaxError):
                        pass # Keep as is if not valid list string
                
                writer.writerow(row_list)
        print(f"[✓] Informe CSV generado: {filename}")
    
    def generate_xml_report(self, report_data):
        
        print("[DEBUG] Generando informe XML...")
        filename = "vulnerability_report.xml"
        devices = defaultdict(list)

        # report_data ahora contiene: MAC, IPv4, IPv6, CVE, NVT Name, STRIDE, LINDDUN, Risk, Severity, Solution
        for mac, ipv4, ipv6, cve, nvt, stride, linddun, risk, severity, solucion in report_data:
            key = (mac, ipv4, ipv6)
            devices[key].append((cve, nvt, stride, linddun, risk, severity, solucion))
        
        root = ET.Element("Devices")

        for (mac, ipv4, ipv6), vulnerabilities in devices.items():
            device_elem = ET.SubElement(root, "Device")
            ET.SubElement(device_elem, "MAC").text = str(mac) if mac is not None else "N/A"
            ET.SubElement(device_elem, "IPv4").text = str(ipv4) if ipv4 is not None else "N/A"
            ET.SubElement(device_elem, "IPv6").text = str(ipv6) if ipv6 is not None else "N/A"
            
            for cve, nvt, stride, linddun, risk, severity, solucion in vulnerabilities:
                vulnerability_elem = ET.SubElement(device_elem, "Vulnerability")
                ET.SubElement(vulnerability_elem, "CVE").text = str(cve) if cve is not None else "N/A"
                ET.SubElement(vulnerability_elem, "NVT_Name").text = str(nvt) if nvt is not None else "N/A"

                # Limpiar STRIDE y LINDDUN si vienen como string tipo lista JSON
                stride_list = self._clean_list_field(stride)
                ET.SubElement(vulnerability_elem, "STRIDE").text = ", ".join(stride_list) if stride_list else "N/A"

                linddun_list = self._clean_list_field(linddun)
                ET.SubElement(vulnerability_elem, "LINDDUN").text = ", ".join(linddun_list) if linddun_list else "N/A"

                ET.SubElement(vulnerability_elem, "Risk").text = str(risk) if risk is not None else "0.0"
                ET.SubElement(vulnerability_elem, "Severity").text = str(severity) if severity is not None else "N/A"
                ET.SubElement(vulnerability_elem, "Solution").text = str(solucion) if solucion is not None else "N/A"

        tree = ET.ElementTree(root)
        # Usar pretty_print para un XML más legible si es posible (Python 3.9+)
        try:
            ET.indent(tree, space="  ", level=0)
        except AttributeError:
            pass # ET.indent no está disponible en versiones anteriores
        tree.write(filename, encoding="utf-8", xml_declaration=True)
        print(f"[✓] Informe XML generado: {filename}")
        
    def generate_json_report(self, report_data):
        print("[DEBUG] Generando informe JSON...")
        filename = "vulnerability_report.json"
        devices = defaultdict(list)

        for mac, ipv4, ipv6, cve, nvt, stride, linddun, risk, severity, solucion in report_data:
            # Usar una clave que combine los identificadores del dispositivo
            device_key = f"{mac if mac is not None else 'N/A'}_{ipv4 if ipv4 is not None else 'N/A'}_{ipv6 if ipv6 is not None else 'N/A'}"
            
            entry = {
                "CVE": cve if cve is not None else "N/A",
                "NVT_Name": nvt if nvt is not None else "N/A",
                "STRIDE": self._clean_list_field(stride),
                "LINDDUN": self._clean_list_field(linddun),
                "Risk": float(risk) if risk is not None else 0.0,
                "Severity": str(severity) if severity is not None else "N/A",
                "Solution": solucion if solucion is not None else "N/A"
            }
            devices[device_key].append(entry)

        # Reestructurar como lista de objetos de dispositivo
        json_output = []
        for device_key, vulns in devices.items():
            # Descomponer la clave para obtener los identificadores originales del dispositivo
            parts = device_key.split("_")
            mac = parts[0] if parts[0] != "N/A" else None
            ipv4 = parts[1] if parts[1] != "N/A" else None
            ipv6 = parts[2] if parts[2] != "N/A" else None

            json_output.append({
                "MAC": mac,
                "IPv4": ipv4,
                "IPv6": ipv6,
                "Vulnerabilities": vulns
            })

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(json_output, f, indent=4, ensure_ascii=False)

        print(f"[✓] Informe JSON generado: {filename}")
    
    def _clean_list_field(self, field):
        """
        Intenta convertir una cadena JSON que representa una lista en una lista Python.
        Si ya es una lista o no se puede parsear, devuelve el campo tal cual o como lista de un elemento.
        """
        if isinstance(field, str) and (field.startswith("[") and field.endswith("]")):
            try:
                # Usar json.loads es más robusto para JSON
                parsed_list = json.loads(field)
                if isinstance(parsed_list, list):
                    return parsed_list
            except json.JSONDecodeError:
                pass # Fallback to ast.literal_eval if json.loads fails (e.g., single quotes)
            try:
                # ast.literal_eval puede manejar más formatos de string-list (e.g., con comillas simples)
                parsed_list = ast.literal_eval(field)
                if isinstance(parsed_list, list):
                    return parsed_list
            except (ValueError, SyntaxError):
                pass
        
        # Si ya es una lista, devolverla directamente
        if isinstance(field, list):
            return field
        # Si es None, devolver una lista vacía
        elif field is None:
            return []
        # Para cualquier otro tipo, convertir a string y devolver como una lista de un elemento
        else:
            return [str(field)]