import unittest
from riskCalculation import RiskCalculation

# Suponiendo que ExternalThreatDB está en otro archivo llamado threat_module.py
# from threat_module import ExternalThreatDB

# Si todo está en el mismo archivo puedes omitir la línea de import
class TestApplyStrideLinddunWeights(unittest.TestCase):
    def test_weights_application(self):
        etd = RiskCalculation()

        dread = {
            "Damage": 5.0,
            "Reproducibility": 4.0,
            "Exploitability": 6.0,
            "AffectedUsers": 3.0,
            "Discoverability": 2.5
        }

        stride = ["Information Disclosure", "Elevation of Privilege"]
        linddun = ["Linkability", "Disclosure of Information"]

        expected_result = {
            "Damage": 9.0,  # 5.0 + 1.5 + 1 + 1. 5= 9.2 → round 9.2
            "Reproducibility": 4.0,
            "Exploitability": 7.5,  # 6.0 + 1.5 = 7.5
            "AffectedUsers": 6.0, # 3.0 + 1 + 1 + 1 = 6.0
            "Discoverability": 3.0  # 2.5 + 0.5 = 3.0
        }

        result = etd.apply_stride_linddun_weights(dread.copy(), stride, linddun)
        self.assertEqual(result, {k: round(v, 1) for k, v in expected_result.items()})

if __name__ == '__main__':
    unittest.main()
