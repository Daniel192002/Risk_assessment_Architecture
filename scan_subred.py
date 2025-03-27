import subprocess
import re

def scan_red_pasivo(interface):
    try:
        # Ejecutar bettercap en modo pasivo
        comando = f"sudo bettercap -iface {interface} -eval 'net.sniff on'"
        print(f"Ejecutando: {comando}")

        # Iniciar el proceso y capturar la salida en tiempo real
        proceso = subprocess.Popen(comando, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        dispositivos = set()  # Evitar duplicados

        # Leer la salida en tiempo real
        for linea in proceso.stdout:
            print(linea.strip())  # Mostrar la salida en vivo

            # Expresión regular para extraer IPs y MACs
            match = re.search(r"(\d+\.\d+\.\d+\.\d+).*?([0-9A-Fa-f:]{17})", linea)
            if match:
                ip, mac = match.groups()
                dispositivos.add((ip, mac))

        return list(dispositivos)
    
    except Exception as e:
        print("Error ejecutando Bettercap:", e)
        return []

# Definir la interfaz de red
INTERFAZ_KALI = "eth0"  # Cambia esto si usas otra interfaz

# Ejecutar escaneo pasivo
dispositivos = scan_red_pasivo(INTERFAZ_KALI)

# Mostrar los dispositivos detectados
if dispositivos:
    print("\nDispositivos detectados:")
    for ip, mac in dispositivos:
        print(f"IP: {ip}, MAC: {mac}")
else:
    print("\nNo se capturaron dispositivos en la red.")
