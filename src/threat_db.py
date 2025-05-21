
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
    def __init__(self, api_key=None):
        self.api_key = '5ad9e6cf-d9a1-4c51-b8cc-c9f8d096757f'
        self.api_url = "https://services.nvd.nist.gov/rest/json/cve/2.0"
        self.headers = {"apiKey": self.api_key, "User-Agent": "Mozilla/5.0"}

    
    def get_cve_description(self, cve_id):
        try:
            url = f"{self.api_url}?cveId={cve_id}"
            response = requests.get(url, headers=self.headers)
            if response.status_code == 200:
                data = response.json()
                descriptions = data.get("vulnerabilities", [])[0]["cve"]["descriptions"]
                for desc in descriptions:
                    if desc["lang"] == "en":
                        return desc["value"]
            else:
                print(f"HTTP error: {response.status_code}")
        except Exception as e:
            print(f"Error al obtener la descripción de CVE {cve_id}: {e}")
        return None

    def classify_cve(self, description, keywords):
        doc = nlp(description.lower())
        categories_found = set()
        for category, keyword in keywords.items():
            for token in doc:
                if any(kw in token.text for kw in keyword):
                    categories_found.add(category)
        return list(categories_found)
    
    def classify_threats(self,cves):
        classified = []
        cve_ids = cves
        
        for ipv4, cve_id in cve_ids:
            try:
                description = self.get_cve_description(cve_id)
                stride_categorie = self.classify_cve(description, STRIDE_CATEGORIES)
                linddun_categorie = self.classify_cve(description, LINDDUN_CATEGORIES)
                classified.append({
                    "ipv4": ipv4,
                    "cve_id": cve_id,
                    "description": description,
                    "STRIDE": stride_categorie,
                    "LINDDUN": linddun_categorie
                })
            except Exception as e:
                print(f"Error al clasificar CVE {cve_id}: {e}")
        return classified