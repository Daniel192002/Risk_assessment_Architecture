
from riskController import RiskController
import subprocess

def set_permissions():
    try:
        subprocess.run(["chmod", "777", "/run/gvmd/gvmd.sock"], check=True)
        print("[+] Permisos modificados correctamente")
    except subprocess.CalledProcessError as e:
        print(f"[!] Error al modificar permisos: {e}")
if __name__ == "__main__":
    set_permissions()
    controller = RiskController()
    controller.execute_risk_analysis()