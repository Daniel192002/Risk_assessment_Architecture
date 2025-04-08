import subprocess
import re
import time
import databaseManager

class AssetController:
    @staticmethod
    def execute_bettercap(interface):
        """Ejecuta Bettercap para obtener direcciones IPv4 y MACs."""
        try:
            command = f"sudo bettercap -iface {interface} -eval 'net.recon on; sleep 5; net.show; net.recon off; exit'"
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            output, _ = process.communicate()
            return output
        except Exception as e:
            print("Error ejecutando Bettercap:", e)
            return ""

    @staticmethod
    def execute_command(command):
        """Ejecuta un comando de shell y devuelve la salida."""
        try:
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            output, _ = process.communicate()
            return output
        except Exception as e:
            print("Error ejecutando comando:", e)
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
    def extract_ipv6_devices(output):
        """Extrae direcciones IPv6 y MACs de la salida del comando ip -6 neigh show."""
        devices = set()
        ipv6_pattern = re.compile(r"([a-fA-F0-9:]+)\s+dev\s+\S+\s+lladdr\s+([0-9A-Fa-f:]{17})")
        for line in output.split("\n"):
            match = ipv6_pattern.search(line)
            if match:
                devices.add((match.group(1), match.group(2)))
        return devices

    @staticmethod
    def scan_network(interface):
        print("[+] Iniciando escaneo de red...")

        # Escaneo IPv4 con Bettercap
        print("[+] Escaneando direcciones IPv4...")
        ipv4_output = AssetController.execute_bettercap(interface)
        ipv4_devices = AssetController.extract_ipv4_devices(ipv4_output)

        # Escaneo IPv6 con ip -6 neigh show
        print("[+] Escaneando direcciones IPv6...")
        ipv6_output = AssetController.execute_command("ip -6 neigh show")
        print("\n[DEBUG] Salida de IPv6:")
        print(ipv6_output)
        ipv6_devices = AssetController.extract_ipv6_devices(ipv6_output)

        # Unir resultados basados en la MAC
        active_devices = {}
        for ip, mac in ipv4_devices:
            active_devices[mac] = {"IPv4": ip, "IPv6": None}

        for ip, mac in ipv6_devices:
            if mac in active_devices:
                active_devices[mac]["IPv6"] = ip
            else:
                active_devices[mac] = {"IPv4": None, "IPv6": ip}

        # Mostrar resultados
        print("\n[+] Dispositivos detectados:")
        print("MAC Address\t\tIPv4\t\tIPv6")
        print("-" * 50)
        db = databaseManager.DatabaseManager.__init__(user="root", password="tfg2025", host="localhost")
        
        for mac, info in active_devices.items():
            db.insert_device(mac, info["IPv4"], info["IPv6"])
        
        db.close
        
        return active_devices
