import subprocess
import re
import time

class AssetController:
    @staticmethod
    def execute_bettercap(interface):
        """Ejecutar bettercap para obtener direcciones IPV4 y MACs."""
        try:
            command = "f sudo bettercap -iface {interface} -eval 'net.recon on; sleep 5; net.recon off'"
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            exit, _ = process.communicate()
            return exit
        except Exception as e:
            print("Error ejecutando Bettercap:", e)
            return ""
    @staticmethod
    def ejecutar_comando(command):
        """Ejecuta un comando de shell y devuelve la salida."""
        try:
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            exit, _ = process.communicate()            
            return exit
        except Exception as e:
            print("Error ejecutando comando:", e)
            return ""
    @staticmethod
    def extraer_dispositivos_ipv4(salida):
        """Extrae direcciones IPv4 y MACs de la salida de Bettercap."""
        dispositivos = set()
        patron_ipv4 = re.compile(r"(\d+\.\d+\.\d+\.\d+).*?([0-9A-Fa-f:]{17})")
        for linea in salida.split("\n"):
            match = patron_ipv4.search(linea)
            if match:
                dispositivos.add((match.group(1), match.group(2)))
        return dispositivos

    @staticmethod
    def extraer_dispositivos_ipv6(salida):
        """Extrae direcciones IPv6 y MACs de la salida del comando ip -6 neigh show."""
        dispositivos = set()
        patron_ipv6 = re.compile(r"([a-fA-F0-9:]+) +\w+ +([0-9A-Fa-f:]{17})")
        for linea in salida.split("\n"):
            match = patron_ipv6.search(linea)
            if match:
                dispositivos.add((match.group(1), match.group(2)))
        return dispositivos
    
    @staticmethod
    def scan_red_pasivo(interface):
        print("[+] Iniciando escaneo de red...")

        # Escaneo IPv4 con Bettercap
        print("[+] Escaneando direcciones IPv4...")
        salida_ipv4 = AssetController.execute_bettercap(interface)
        dispositivos_ipv4 = AssetController.extraer_dispositivos_ipv4(salida_ipv4)

        # Esperar antes del siguiente escaneo
        time.sleep(3)

        # Escaneo IPv6 con ip -6 neigh show
        print("[+] Escaneando direcciones IPv6...")
        salida_ipv6 = AssetController.ejecutar_comando("ip -6 neigh show dev eth1")
        dispositivos_ipv6 = AssetController.extraer_dispositivos_ipv6(salida_ipv6)

        # Unir resultados basados en la MAC
        activos = {}
        for ip, mac in dispositivos_ipv4:
            activos[mac] = {"IPv4": ip, "IPv6": None}

        for ip, mac in dispositivos_ipv6:
            if mac in activos:
                activos[mac]["IPv6"] = ip
            else:
                activos[mac] = {"IPv4": None, "IPv6": ip}

        # Mostrar resultados
        print("\n[+] Dispositivos detectados:")
        print("MAC Address\t\tIPv4\t\tIPv6")
        print("-" * 50)
        for mac, info in activos.items():
            print(f"{mac}\t{info['IPv4']}\t{info['IPv6']}")
        
        return activos