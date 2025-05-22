
import requests
import spacy
import nvdlib

nlp = spacy.load("en_core_web_sm")

STRIDE_CATEGORIES = {
    "Spoofing": ["impersonate", "spoof", "forged", "fake", "unauthorized access"],
    "Tampering": ["modify", "alter", "tamper", "change", "corrupt"],
    "Repudiation": ["repudiation", "undeniable", "logs", "non-repudiation"],
    "Information Disclosure": ["leak", "expose", "disclose", "information", "trace", "trace method"],
    "Denial of Service": ["crash", "flood", "denial of service", "overload", "shutdown"],
    "Elevation of Privilege": ["root", "admin", "execute", "privilege", "bypass", "remote code execution"]
}

LINDDUN_CATEGORIES = {
    "Linkability": ["linked", "track", "connection", "associate"],
    "Identifiability": ["identify", "reveal identity", "trace back"],
    "Non-repudiation": ["proof", "logging", "non-repudiation"],
    "Detectability": ["detect", "monitor", "observed", "discovery"],
    "Disclosure of Information": ["disclose", "leak", "expose", "information", "data"],
    "Unawareness": ["unaware", "uninformed", "hidden"],
    "Non-compliance": ["non-compliance", "regulation", "gdpr", "policy"]
}

class ExternalThreatDB:
    
    def get_cve_description(self, cve_id):
        try:
            nvdlib.read_timeout = 60
            cve = nvdlib.searchCVE(cveId=cve_id, verbose=True)[0]
            if not cve:
                print(f"Error: CVE {cve_id} not found.")
                return None, None
            print(f"CVE: {cve}")
            description = cve.descriptions[0].value
            vector = "N/A"
            metrics = getattr(cve, 'metrics', {})
            # nvdlib puede devolver un objeto, adaptamos acceso:
            if hasattr(metrics, 'cvssMetricV31') and metrics.cvssMetricV31:
                vector = metrics.cvssMetricV31[0].cvssData.vectorString
            elif hasattr(metrics, 'cvssMetricV3') and metrics.cvssMetricV3:
                vector = metrics.cvssMetricV3[0].cvssData.vectorString
            elif hasattr(metrics, 'cvssMetricV2') and metrics.cvssMetricV2:
                vector = metrics.cvssMetricV2[0].cvssData.vectorString
                
            return description, vector   
        except IndexError:
            print(f"Error: CVE {cve_id} not found.")
            return None,None
         
    
    def classify_cve(self, description, keywords):
        doc = nlp(description.lower())
        categories_found = set()
        for category, keyword in keywords.items():
            for token in doc:
                if any(kw in token.text for kw in keyword):
                    categories_found.add(category)
        return list(categories_found)
    
    def classify_threat(self,ipv4,cve_id):
        classified = []
        try:
            description, vector = self.get_cve_description(cve_id)
            print(f"Description: {description}")
            print(f"Vector: {vector}")
            if description is None or vector is None:
                print(f"Skipping classification for CVE {cve_id} due to missing data.")
                classified = None
                return classified
            stride_categorie = self.classify_cve(description, STRIDE_CATEGORIES)
            linddun_categorie = self.classify_cve(description, LINDDUN_CATEGORIES)
            classified.append({
                "ipv4": ipv4,
                "cve_id": cve_id,
                "cvss_vector": vector,
                "STRIDE": stride_categorie,
                "LINDDUN": linddun_categorie
            })
        except Exception as e:
            print(f"Error al clasificar CVE {cve_id}: {e}")
        return classified