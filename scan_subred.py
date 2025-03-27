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

        patron_ipv4 = re.compile(r"(\d+\.\d+\.\d+\.\d+).*?([0-9A-Fa-f:]{17})")
        patron_ipv6 = re.compile(r"(([a-fA-F0-9:]+:+)+[a-fA-F0-9]+).*?([0-9A-Fa-f:]{17})")

        # Leer la salida en tiempo real
        for linea in proceso.stdout:
            print(linea.strip())  # Mostrar la salida en vivo

            match_ipv4 = patron_ipv4.search(linea)
            match_ipv6 = patron_ipv6.search(linea)

            if match_ipv4:
                ip, mac = match_ipv4.groups()
                dispositivos.add((ip, mac))
            
            if match_ipv6:
                ip, mac = match_ipv6.groups()
                dispositivos.add((ip, mac))


        return list(dispositivos)
    
    except Exception as e:
        print("Error ejecutando Bettercap:", e)
        return []

# Definir la interfaz de red
INTERFAZ_KALI = "eth1"  # Cambia esto si usas otra interfaz

# Ejecutar escaneo pasivo
dispositivos = scan_red_pasivo(INTERFAZ_KALI)

# Mostrar los dispositivos detectados
if dispositivos:
    print("\nDispositivos detectados:")
    for ip, mac in dispositivos:
        print(f"IP: {ip}, MAC: {mac}")
else:
    print("\nNo se capturaron dispositivos en la red.")
