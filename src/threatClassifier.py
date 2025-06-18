import spacy
import nvdlib
import json # Necesario para serializar STRIDE/LINDDUN a JSON para la DB

# Importar los repositorios necesarios
from vulnerabilityRepository import VulnerabilityRepository # Para obtener las vulnerabilidades detectadas
from threatRepository import ThreatRepository # Para guardar y verificar las vulnerabilidades clasificadas

# Cargar el modelo de spaCy una sola vez al inicio del módulo
try:
    nlp = spacy.load("en_core_web_sm")
except OSError:
    print("Descargando modelo 'en_core_web_sm' de spaCy. Esto solo ocurre una vez.")
    spacy.cli.download("en_core_web_sm")
    nlp = spacy.load("en_core_web_sm")


STRIDE_CATEGORIES = {
    "Spoofing": ["impersonate", "spoof", "forged", "fake", "unauthorized access", "authentication bypass"],
    "Tampering": ["modify", "alter", "tamper", "change", "corrupt", "integrity", "data manipulation"],
    "Repudiation": ["repudiation", "undeniable", "logs", "non-repudiation", "audit trail"],
    "Information Disclosure": ["leak", "expose", "disclose", "information", "trace", "trace method", "sensitive data"],
    "Denial of Service": ["crash", "flood", "denial of service", "overload", "shutdown", "resource exhaustion"],
    "Elevation of Privilege": ["root", "admin", "execute", "privilege", "bypass", "remote code execution", "escalation"]
}

LINDDUN_CATEGORIES = {
    "Linkability": ["linked", "track", "connection", "associate", "correlation"],
    "Identifiability": ["identify", "reveal identity", "trace back", "deanonymize"],
    "Non-repudiation": ["proof", "logging", "non-repudiation", "digital signature"],
    "Detectability": ["detect", "monitor", "observed", "discovery", "visibility"],
    "Disclosure of Information": ["disclose", "leak", "expose", "information", "data", "confidentiality breach"],
    "Unawareness": ["unaware", "uninformed", "hidden", "implicit"],
    "Non-compliance": ["non-compliance", "regulation", "gdpr", "policy", "legal requirement"]
}

class ThreatClassifier:
    # El constructor ahora recibe ambas instancias de repositorios relevantes
    def __init__(self, vulnerability_repository: VulnerabilityRepository, threat_repository: ThreatRepository):
        self.vuln_repo = vulnerability_repository # Para obtener las vulnerabilidades sin clasificar
        self.threat_repo = threat_repository     # Para manejar las vulnerabilidades clasificadas
        nvdlib.read_timeout = 60 # Configurar timeout para nvdlib una vez

    def get_cve_description(self, cve_id):
        """
        Obtiene la descripción y el vector CVSS de un CVE desde NVD.
        Retorna (description, cvss_vector) o (None, None) en caso de error.
        """
        try:
            cve_results = nvdlib.searchCVE(cveId=cve_id, verbose=False)
            
            if not cve_results:
                print(f"[!] ThreatClassifier: CVE {cve_id} no encontrado en NVD.")
                return None, None
            
            cve = cve_results[0]
            
            description = cve.descriptions[0].value if cve.descriptions else None
            if not description:
                print(f"[!] ThreatClassifier: No se encontró descripción para CVE {cve_id}.")
                return None, None
            
            vector = "N/A"
            metrics = getattr(cve, 'metrics', {})
            
            if hasattr(metrics, 'cvssMetricV31') and metrics.cvssMetricV31:
                vector = metrics.cvssMetricV31[0].cvssData.vectorString
            elif hasattr(metrics, 'cvssMetricV30') and metrics.cvssMetricV30:
                vector = metrics.cvssMetricV30[0].cvssData.vectorString
            elif hasattr(metrics, 'cvssMetricV2') and metrics.cvssMetricV2:
                vector = metrics.cvssMetricV2[0].cvssData.vectorString
                
            return description, vector   
        except IndexError:
            print(f"[!] ThreatClassifier: CVE {cve_id} no encontrado o estructura inesperada de NVD.")
            return None, None
        except Exception as e:
            print(f"[!] ThreatClassifier: Error al obtener descripción/vector para CVE {cve_id}: {e}")
            return None, None
         
    
    def classify_cve_text(self, description: str, categories_map: dict):
        """
        Clasifica una descripción de CVE basándose en palabras clave para categorías dadas.
        """
        doc = nlp(description.lower())
        categories_found = set()
        for category, keywords in categories_map.items():
            for keyword in keywords:
                if keyword in description.lower():
                    categories_found.add(category)
        return list(categories_found)
    
    def classify_single_threat(self, ipv4: str, cve_id: str):
        """
        Clasifica una única amenaza (CVE) y devuelve los datos clasificados.
        Este es un método auxiliar llamado por classify_all_vulnerabilities.
        """
        
        description, vector = self.get_cve_description(cve_id)
        
        if description is None or vector is None:
            print(f"[-] ThreatClassifier: Saltando clasificación para CVE {cve_id} debido a datos faltantes.")
            return None # Retorna None si no hay datos para clasificar

        stride_categories = self.classify_cve_text(description, STRIDE_CATEGORIES)
        linddun_categories = self.classify_cve_text(description, LINDDUN_CATEGORIES)
        
        classified_data = {
            "ipv4": ipv4,
            "cve_id": cve_id,
            "cvss_vector": vector,
            "STRIDE": stride_categories,
            "LINDDUN": linddun_categories
        }
        return classified_data

    def classify_all_vulnerabilities(self):
        """
        Orquesta la clasificación de todas las vulnerabilidades detectadas
        que aún no han sido clasificadas y guarda los resultados.
        """
        print("[3] ThreatClassifier: Iniciando clasificación de vulnerabilidades...")

        # 1. Obtener vulnerabilidades detectadas (sin clasificar) del VulnerabilityRepository
        vulnerabilities_to_classify = self.vuln_repo.get_all_vulnerabilities() 

        if not vulnerabilities_to_classify:
            print("[!] ThreatClassifier: No se encontraron vulnerabilidades para clasificar.")
            return

        print(f"[+] ThreatClassifier: Se encontraron {len(vulnerabilities_to_classify)} vulnerabilidades candidatas para clasificación.")

        for vuln_info in vulnerabilities_to_classify:
            # Asegúrate que la tupla de vuln_info tiene los elementos en el orden correcto.
            # Según tu vulnerabilityRepository.py, get_all_vulnerabilities devuelve (ipv4, cve)
            ipv4 = vuln_info[0] 
            cve_id = vuln_info[1] 
            
            # Verificar si ya está clasificada usando ThreatRepository
            if self.threat_repo.cve_classified_exists(ipv4, cve_id):
                print(f"[-] ThreatClassifier: CVE {cve_id} para {ipv4} ya clasificado. Saltando.")
                continue
            
            print(f"[+] ThreatClassifier: Clasificando CVE {cve_id} para {ipv4}...")
            
            classified_data = self.classify_single_threat(ipv4, cve_id)
            
            if classified_data:
                # 2. Guardar la clasificación en el ThreatRepository
                try:
                    # Convertir listas a JSON strings para guardar en la DB
                    stride_json = classified_data["STRIDE"]
                    linddun_json = classified_data["LINDDUN"]
                    
                    self.threat_repo.insert_vul_classified(
                        ipv4,
                        cve_id,
                        classified_data["cvss_vector"],
                        stride_json, # threatRepository.py ya hace json.dumps interno
                        linddun_json # threatRepository.py ya hace json.dumps interno
                    )
                    print(f"[✓] ThreatClassifier: CVE {cve_id} para {ipv4} clasificado y guardado exitosamente.")
                except Exception as e:
                    print(f"[!] ThreatClassifier: Error al guardar la clasificación para CVE {cve_id} en {ipv4}: {e}")
            else:
                print(f"[-] ThreatClassifier: Clasificación fallida o incompleta para CVE {cve_id} en {ipv4}. No se guardará.")
            
            import time
            time.sleep(1) # Pequeña pausa para no saturar la API de NVD (si la usas mucho)
        
        print("[+] ThreatClassifier: Proceso de clasificación de vulnerabilidades completado.")