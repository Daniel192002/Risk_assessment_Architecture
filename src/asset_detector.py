import subprocess
import re
import time
# No necesitas importar databaseManager directamente aquí,
# ya que AssetRepository se encargará de interactuar con él.
# import databaseManager

from assetRepository import AssetRepository # Importa AssetRepository

class AssetDetector:
    # Ahora el constructor recibe una instancia de AssetRepository
    def __init__(self, assetRepository: AssetRepository):
        self.asset_repo = assetRepository

    @staticmethod # Este método puede seguir siendo estático o volverse de instancia si necesita self.asset_repo
    def execute_bettercap(interface):
        """Ejecuta Bettercap para obtener direcciones IPv4 y MACs."""
        try:
            # Comando modificado para ser más robusto y silenciar salida no deseada
            command = f"sudo bettercap -iface {interface} -eval 'net.recon on; sleep 5; net.show; net.recon off; exit'"
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
            output, _ = process.communicate() # Añadir un timeout para evitar bloqueos
            if process.returncode != 0:
                print(f"Error: Bettercap exited with code {process.returncode}")
                # Considera loggear o lanzar una excepción más específica
            return output
        except subprocess.TimeoutExpired:
            print(f"Error: Bettercap timed out after 30 seconds on interface {interface}.")
            process.kill()
            output, _ = process.communicate()
            return ""
        except Exception as e:
            print(f"Error ejecutando Bettercap en {interface}: {e}")
            return ""

    @staticmethod
    def execute_command(command):
        """Ejecuta un comando de shell y devuelve la salida."""
        try:
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            output, _ = process.communicate(timeout=10) # Añadir un timeout
            if process.returncode != 0:
                print(f"Error: Comando '{command}' exited with code {process.returncode}")
            return output
        except subprocess.TimeoutExpired:
            print(f"Error: Comando '{command}' timed out after 10 seconds.")
            process.kill()
            output, _ = process.communicate()
            return ""
        except Exception as e:
            print(f"Error ejecutando comando '{command}': {e}")
            return ""

    @staticmethod
    def extract_ipv4_devices(output):
        """Extrae direcciones IPv4 y MACs de la salida de Bettercap."""
        devices = set()
        # Patrón mejorado para capturar la MAC que suele estar cerca de la IP en bettercap
        # o en líneas adyacentes si net.show no la pone en la misma línea
        # Este patrón asume que la MAC está en la misma línea que la IP, lo cual es común con 'net.show'
        ipv4_mac_pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+.*?(\([0-9A-Fa-f:]{17}\))")
        for line in output.split("\n"):
            match = ipv4_mac_pattern.search(line)
            if match:
                # Group 1 is IP, Group 2 is MAC (with parentheses, remove them)
                devices.add((match.group(1), match.group(2).strip('()')))
        return devices

    @staticmethod
    def extract_ipv6_devices(output):
        """Extrae direcciones IPv6 y MACs de la salida del comando ip -6 neigh show."""
        devices = set()
        # Patrón para 'ip -6 neigh show', que suele tener IPv6 dev [interface] lladdr MAC
        ipv6_mac_pattern = re.compile(r"([a-fA-F0-9:]+)\s+dev\s+\S+\s+lladdr\s+([0-9A-Fa-f:]{17})")
        for line in output.split("\n"):
            match = ipv6_mac_pattern.search(line)
            if match:
                devices.add((match.group(1), match.group(2)))
        return devices

    # Este método ya no es estático porque necesita acceder a self.asset_repo
    def scan_network(self, interface):
        print(f"[+] AssetDetector: Iniciando escaneo de red en interfaz {interface}...")

        # Escaneo IPv4 con Bettercap
        print("[+] AssetDetector: Escaneando direcciones IPv4...")
        ipv4_output = self.execute_bettercap(interface)
        ipv4_devices = self.extract_ipv4_devices(ipv4_output)
        print(f"[+] AssetDetector: IPv4 encontrados: {len(ipv4_devices)}")


        # Escaneo IPv6 con ip -6 neigh show
        print("[+] AssetDetector: Escaneando direcciones IPv6...")
        # Nota: 'ip -6 neigh show' muestra entradas para todas las interfaces.
        # Si quieres filtrar por interfaz, el comando sería más complejo o tendrías que post-filtrar.
        # Para simplificar, lo dejamos así global por ahora.
        ipv6_output = self.execute_command("ip -6 neigh show")
        # print("\n[DEBUG] Salida de IPv6 para depuración:") # Descomenta para depurar la salida cruda
        # print(ipv6_output)
        ipv6_devices = self.extract_ipv6_devices(ipv6_output)
        print(f"[+] AssetDetector: IPv6 encontrados: {len(ipv6_devices)}")


        # Unir resultados basados en la MAC
        all_detected_devices_map = {} # Usamos un mapa MAC -> {IPv4, IPv6}
        for ip, mac in ipv4_devices:
            # Normalizar MAC a minúsculas y quitar posibles prefijos/sufijos extra
            normalized_mac = mac.lower().replace('-', ':')
            if normalized_mac not in all_detected_devices_map:
                all_detected_devices_map[normalized_mac] = {"IPv4": None, "IPv6": None}
            all_detected_devices_map[normalized_mac]["IPv4"] = ip

        for ip, mac in ipv6_devices:
            normalized_mac = mac.lower().replace('-', ':')
            if normalized_mac not in all_detected_devices_map:
                all_detected_devices_map[normalized_mac] = {"IPv4": None, "IPv6": None}
            all_detected_devices_map[normalized_mac]["IPv6"] = ip

        # --- Lógica de persistencia de datos (¡AHORA AQUÍ!) ---
        # Obtener los dispositivos ya existentes en la base de datos para evitar duplicados
        existing_devices_from_db = self.asset_repo.get_all_devices()
        # Convertir a un formato fácil de buscar, ej. un set de tuplas (mac, ipv4, ipv6)
        existing_devices_set = set()
        for dev_mac, dev_ipv4, dev_ipv6 in existing_devices_from_db:
            existing_devices_set.add((
                (dev_mac.lower() if dev_mac else None),
                (dev_ipv4 if dev_ipv4 else None),
                (dev_ipv6 if dev_ipv6 else None)
            ))

        print(f"[+] AssetDetector: Dispositivos detectados en la red: {len(all_detected_devices_map)}")
        print(f"[+] AssetDetector: Dispositivos existentes en la DB: {len(existing_devices_set)}")

        for mac, addrs in all_detected_devices_map.items():
            ipv4 = addrs.get("IPv4")
            ipv6 = addrs.get("IPv6")

            # Comprobar si la combinación exacta de MAC, IPv4 e IPv6 ya existe
            # Hay que ser cuidadoso con los None. `(mac, ipv4, ipv6)` funciona bien para `set`
            if (mac, ipv4, ipv6) not in existing_devices_set:
                try:
                    self.asset_repo.insert_device(mac, ipv4, ipv6)
                    print(f"[+] AssetDetector: Dispositivo nuevo detectado y guardado: MAC={mac}, IPv4={ipv4}, IPv6={ipv6}")
                except Exception as e:
                    print(f"[-] AssetDetector: Error al guardar dispositivo {mac}: {e}")
            else:
                print(f"[-] AssetDetector: Dispositivo ya existente (ignorando): MAC={mac}, IPv4={ipv4}, IPv6={ipv6}")
