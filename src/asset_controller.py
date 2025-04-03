import subprocess
import re
import time

class AssetController:
    @staticmethod
    def execute_bettercap(interface):
        """Ejecuta Bettercap para obtener direcciones IPv4 y MACs."""
        try:
            command = f"sudo bettercap -iface {interface} -eval 'net.recon on; sleep 20; net.show; net.recon off'"
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            output, _ = process.communicate()
            return output
        except Exception as e:
            print("Error ejecutando Bettercap:", e)
            return ""

    @staticmethod
    def extract_ipv4_devices(output):
        """Extrae direcciones IPv4 y MACs de la salida de Bettercap."""
        devices = set()
        ipv4_pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+).*?([0-9A-Fa-f:]{17})")
        for line in output.split("\n"):
            match = ipv4_pattern.search(line)
            if match:
                devices.add((match.group(1), match.group(2)))
        return devices

    @staticmethod
    def scan_red_pasivo(interface):
        print("[+] Iniciando escaneo de red...")

        # Escaneo IPv4 con Bettercap
        print("[+] Escaneando direcciones IPv4...")
        ipv4_output = AssetController.execute_bettercap(interface)
        ipv4_devices = AssetController.extract_ipv4_devices(ipv4_output)

        # Mostrar resultados
        print("\n[+] Dispositivos detectados:")
        print("MAC Address\t\tIPv4")
        print("-" * 30)
        for ip, mac in ipv4_devices:
            print(f"{mac}\t{ip}")
        
        return ipv4_devices