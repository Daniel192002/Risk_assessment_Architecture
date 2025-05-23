

CVSS_V3_WEIGHTS = {
    'AV': {'N': 1.0, 'A': 0.8, 'L': 0.6, 'P': 0.4},
    'AC': {'L': 1.0, 'H': 0.5},
    'PR': {'N': 1.0, 'L': 0.6, 'H': 0.2},
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
    """
    
    def detect_cvss_version(self, cvss_vector):

        if cvss_vector.startswith("CVSS:3.1") or cvss_vector.startswith("CVSS:3.0"):
            return "v3"
        elif cvss_vector.startswith("AV:"):
            return "v2"
        return None
    
    def parse_cvss_vector(self, cvss_vector):
        
        parts = cvss_vector.split("/")
        metrics = {}
        for part in parts:
            if ":" in part:
                key, value = part.split(":")
                metrics[key] = value
        return metrics    
    
    def map_cvss_to_dread(self, cvss_vector ):
        version = self.detect_cvss_version(cvss_vector)
        metrics = self.parse_cvss_vector(cvss_vector)
        if version == "v3":
            weights = CVSS_V3_WEIGHTS
        elif version == "v2":
            weights = CVSS_V2_WEIGHTS
        else:
            raise ValueError("Unsupported CVSS version")
        dread = {
            "Damage": 0.0,
            "Reproducibility": 0.0,
            "Exploitability": 0.0,
            "AffectedUsers": 0.0,
            "Discoverability": 0.0,
        }
        
        # Damage: Suma ponderada de impacto en C, I, A
        for impact in ["C", "I", "A"]:
            if impact in metrics and metrics[impact] in weights[impact]:
                dread["Damage"] += weights[impact][metrics[impact]] * 3.3
        dread["Damage"] = min(dread["Damage"], 10.0)

        # Reproducibility: 
        if 'AC' in metrics:
            dread["Reproducibility"] = weights['AC'].get(metrics['AC'], 0.0) * 10
        # Exploitability:
        if version == "v3":
            pr_score = weights['PR'].get(metrics.get('PR', ''), 0.0)
            ui_score = weights['UI'].get(metrics.get('UI', ''), 0.0)
            dread["Exploitability"] = (pr_score + ui_score) * 5
        elif version == "v2":
            dread["Exploitability"] = weights['Au'].get(metrics.get('Au', ''), 0.0) * 10
        # Affected Users:
        if version == "v3":
            if 'S' in metrics:
                dread["AffectedUsers"] = weights['S'].get(metrics['S'], 0.0) * 10
        elif version == "v2":
            impact_total = 0
            for k in ["C", "I", "A"]:
                if k in metrics:
                    impact_total += weights[k].get(metrics[k], 0.0)
            dread["AffectedUsers"] = min(impact_total * 3.3, 10)
        #Discoverability:
        if 'AV' in metrics:
            dread["Discoverability"] = weights['AV'].get(metrics['AV'], 0.0) * 10
        
        return {k: round(v, 1) for k, v in dread.items()}
    
    
    def apply_stride_linddun_weights(self, dread, stride, linddun):
        for category in stride:
            if category in STRIDE_TO_DREAD:
                for key, value in STRIDE_TO_DREAD[category].items():
                    dread[key] += value
        for category in linddun:
            if category in LINDDUN_TO_DREAD:
                for key, value in LINDDUN_TO_DREAD[category].items():
                    dread[key] += value
        for key in dread:
            dread[key] = min(dread[key], 10.0)
        
        return {k: round(v, 1) for k, v in dread.items()}
    
    def calculate_risk(self, cvss_vector, stride, linddun):

        dread = self.map_cvss_to_dread(cvss_vector)
        dread_with_weights = self.apply_stride_linddun_weights(dread, stride, linddun)
        print(f"[+] Riesgo calculado: {dread}")
        print(f"[+] Riesgo calculado: {dread_with_weights}")