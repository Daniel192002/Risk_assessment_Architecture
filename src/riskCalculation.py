import json # Necesario para parsear JSON de la DB

# Importar los repositorios necesarios
from threatRepository import ThreatRepository # Para obtener las vulnerabilidades clasificadas
from riskRepository import RiskRepository   # Para guardar y verificar los riesgos calculados

CVSS_V3_WEIGHTS = {
    'AV': {'N': 1.0, 'A': 0.8, 'L': 0.6, 'P': 0.4},
    'AC': {'L': 1.0, 'H': 0.5},
    'PR': {'N': 1.0, 'L': 0.6, 'H': 0.3},
    'UI': {'N': 1.0, 'R': 0.5},
    'S': {'U': 1.0, 'C': 1.2},
    'C': {'H': 1.0, 'L': 0.5, 'N': 0.0},
    'I': {'H': 1.0, 'L': 0.5, 'N': 0.0},
    'A': {'H': 1.0, 'L': 0.5, 'N': 0.0},
}

CVSS_V2_WEIGHTS = {
    'AV': {'N': 1.0, 'A': 0.8, 'L': 0.6},
    'AC': {'L': 1.0, 'M': 0.6, 'H': 0.3},
    'Au': {'N': 1.0, 'S': 0.5, 'M': 0.2},
    'C': {'C': 1.0, 'P': 0.5, 'N': 0.0},
    'I': {'C': 1.0, 'P': 0.5, 'N': 0.0},
    'A': {'C': 1.0, 'P': 0.5, 'N': 0.0},
}

STRIDE_TO_DREAD = {
    "Spoofing": {"Exploitability": 1, "Discoverability": 1},
    "Tampering": {"Damage": 1.5, "Reproducibility": 0.5},
    "Repudiation": {"Discoverability": 1},
    "Information Disclosure": {"Damage": 1.5, "AffectedUsers": 1},
    "Denial of Service": {"Damage": 1, "AffectedUsers": 1},
    "Elevation of Privilege": {"Exploitability": 1.5, "Damage": 1}
}

LINDDUN_TO_DREAD = {
    "Linkability": {"AffectedUsers": 1},
    "Identifiability": {"Damage": 1.5, "AffectedUsers": 1},
    "Non-repudiation": {"Discoverability": 1},
    "Detectability": {"Damage": 1, "Exploitability": 0.5 },
    "Disclosure of Information": {"Damage": 1.5, "AffectedUsers": 1, "Discoverability": 0.5},
    "Unawareness": {"Damage": 1, "Discoverability": 1},
    "Non-compliance": {"Damage": 1.5}
}


class RiskCalculation:
    """
    This class is responsible for calculating the risk of a given portfolio.
    It now also handles the retrieval of classified vulnerabilities and persistence of risk values.
    """
    
    # El constructor ahora recibe ambas instancias de repositorios relevantes
    def __init__(self, threat_repository: ThreatRepository, risk_repository: RiskRepository):
        self.threat_repo = threat_repository # Para obtener las vulnerabilidades clasificadas
        self.risk_repo = risk_repository     # Para manejar los riesgos calculados

    def detect_cvss_version(self, cvss_vector):
        """Detecta la versión de CVSS (v3 o v2) a partir del vector."""
        if cvss_vector.startswith("CVSS:3.1") or cvss_vector.startswith("CVSS:3.0"):
            return "v3"
        elif cvss_vector.startswith("AV:"):
            return "v2"
        return None
    
    def parse_cvss_vector(self, cvss_vector):
        """Parsea un string de vector CVSS en un diccionario de métricas."""
        parts = cvss_vector.split("/")
        metrics = {}
        for part in parts:
            if ":" in part:
                key, value = part.split(":")
                metrics[key] = value
        return metrics    
    
    def map_cvss_to_dread(self, cvss_vector):
        """Mapea un vector CVSS a las métricas DREAD iniciales."""
        version = self.detect_cvss_version(cvss_vector)
        metrics = self.parse_cvss_vector(cvss_vector)
        
        if version == "v3":
            weights = CVSS_V3_WEIGHTS
        elif version == "v2":
            weights = CVSS_V2_WEIGHTS
        else:
            print(f"[!] RiskCalculation: Versión de CVSS no soportada o vector inválido: {cvss_vector}")
            return {
                "Damage": 0.0, "Reproducibility": 0.0, "Exploitability": 0.0,
                "AffectedUsers": 0.0, "Discoverability": 0.0,
            }
        
        dread = {
            "Damage": 0.0,
            "Reproducibility": 0.0,
            "Exploitability": 0.0,
            "AffectedUsers": 0.0,
            "Discoverability": 0.0,
        }
        
        for impact in ["C", "I", "A"]:
            if impact in metrics and metrics[impact] in weights[impact]:
                dread["Damage"] += weights[impact][metrics[impact]] * 3.3
        dread["Damage"] = min(dread["Damage"], 10.0)

        if 'AC' in metrics:
            dread["Reproducibility"] = weights['AC'].get(metrics['AC'], 0.0) * 10
        
        if version == "v3":
            pr_score = weights['PR'].get(metrics.get('PR', 'N'), 0.0)
            ui_score = weights['UI'].get(metrics.get('UI', 'N'), 0.0)
            dread["Exploitability"] = (pr_score + ui_score) * 5
        elif version == "v2":
            dread["Exploitability"] = weights['Au'].get(metrics.get('Au', 'N'), 0.0) * 10
        
        if version == "v3":
            if 'S' in metrics:
                dread["AffectedUsers"] = weights['S'].get(metrics['S'], 0.0) * 10
        elif version == "v2":
            impact_total = 0
            for k in ["C", "I", "A"]:
                if k in metrics and metrics[k] in weights[k]:
                    impact_total += weights[k].get(metrics[k], 0.0)
            dread["AffectedUsers"] = min(impact_total * 3.3, 10)
        
        if 'AV' in metrics:
            dread["Discoverability"] = weights['AV'].get(metrics['AV'], 0.0) * 10
        
        return {k: round(v, 1) for k, v in dread.items()}
    
    
    def apply_stride_linddun_weights(self, dread: dict, stride: list, linddun: list):
        """Aplica pesos adicionales DREAD basados en las clasificaciones STRIDE y LINDDUN."""
        
        current_dread = dread.copy() 

        for category in stride:
            if category in STRIDE_TO_DREAD:
                for key, value in STRIDE_TO_DREAD[category].items():
                    current_dread[key] += value
        
        for category in linddun:
            if category in LINDDUN_TO_DREAD:
                for key, value in LINDDUN_TO_DREAD[category].items():
                    current_dread[key] += value
        
        for key in current_dread:
            current_dread[key] = min(current_dread[key], 10.0)
        
        return {k: round(v, 1) for k, v in current_dread.items()}
    
    def calculate_single_risk(self, cvss_vector: str, stride_str: str, linddun_str: str):
        """
        Calcula el riesgo para una única vulnerabilidad clasificada.
        Los inputs STRIDE y LINDDUN se esperan como cadenas JSON desde la DB.
        """
        try:
            # Parsear las cadenas JSON de STRIDE y LINDDUN a listas Python
            stride = json.loads(stride_str) if isinstance(stride_str, str) else stride_str
            linddun = json.loads(linddun_str) if isinstance(linddun_str, str) else linddun_str
            
            if not isinstance(stride, list): stride = []
            if not isinstance(linddun, list): linddun = []

        except (json.JSONDecodeError, ValueError) as e:
            print(f"Error al parsear cadenas STRIDE/LINDDUN: {e}. Usando listas vacías.")
            stride = []
            linddun = []

        dread_without_ponderation = self.map_cvss_to_dread(cvss_vector)
        
        dread_with_weights = self.apply_stride_linddun_weights(dread_without_ponderation, stride, linddun)
        
        dread_sum = (dread_with_weights["Damage"] + 
                     dread_with_weights["Reproducibility"] + 
                     dread_with_weights["Exploitability"] + 
                     dread_with_weights["AffectedUsers"] + 
                     dread_with_weights["Discoverability"])
        dread_final = dread_sum / 5.0

        severity = "Desconocido"
        if dread_final == 0.0 or dread_final < 5.0:
            severity = "Bajo"
        elif dread_final >= 5.0 and dread_final < 7.0:
            severity = "Medio"
        elif dread_final >= 7.0 and dread_final < 9.0:
            severity = "Alto"
        elif dread_final >= 9.0:
            severity = "Crítico"
        
        return round(dread_final, 1), severity

    def calculate_all_risks(self):
        """
        Orquesta el cálculo del riesgo para todas las vulnerabilidades
        previamente clasificadas que aún no tienen un riesgo calculado,
        y guarda los resultados.
        """
        print("[4] RiskCalculation: Iniciando cálculo de riesgo para todas las vulnerabilidades clasificadas...")
        
        # 1. Obtener las vulnerabilidades clasificadas desde el ThreatRepository
        # threat_repository.py::get_classified_vulnerabilities devuelve (ipv4, cve_id, cvss_vector, stride, linddun)
        classified_vulnerabilities = self.threat_repo.get_classified_vulnerabilities()

        if not classified_vulnerabilities:
            print("[!] RiskCalculation: No se encontraron vulnerabilidades clasificadas para calcular el riesgo.")
            return

        print(f"[+] RiskCalculation: Se encontraron {len(classified_vulnerabilities)} vulnerabilidades clasificadas para calcular el riesgo.")

        for vuln_info in classified_vulnerabilities:
            try:
                # Desempaquetar los datos según el orden de threat_repository.py::get_classified_vulnerabilities
                ipv4 = vuln_info[0]
                cve_id = vuln_info[1]
                cvss_vector = vuln_info[2]
                stride_json = vuln_info[3] # Es una cadena JSON
                linddun_json = vuln_info[4] # Es una cadena JSON

                # Verificar si el riesgo para esta vulnerabilidad ya ha sido calculado usando RiskRepository
                if self.risk_repo.vul_risk_calculated_exists(ipv4, cve_id):
                    print(f"[-] RiskCalculation: Riesgo para CVE {cve_id} en {ipv4} ya calculado. Saltando.")
                    continue

                print(f"[+] RiskCalculation: Calculando riesgo para CVE {cve_id} en {ipv4} (CVSS: {cvss_vector})...")
                
                # 2. Calcular el riesgo usando el método de cálculo individual
                risk_value, severity = self.calculate_single_risk(cvss_vector, stride_json, linddun_json)
                
                # 3. Guardar el resultado del cálculo de riesgo usando RiskRepository
                self.risk_repo.insert_risk_value(ipv4, cve_id, risk_value, severity)
                print(f"[✓] RiskCalculation: Riesgo para CVE {cve_id} en {ipv4} calculado ({risk_value}, {severity}) y guardado exitosamente.")

            except Exception as e:
                print(f"[!] RiskCalculation: Error al procesar CVE {vuln_info} para cálculo de riesgo: {e}")
        
        print("[+] RiskCalculation: Proceso de cálculo de riesgo completado.")