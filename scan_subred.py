import subprocess
import re

def scan_subred(interface):
    try:
       # Ejecutar bettercap en modo no interactivo
        comando = f"sudo bettercap -iface {interface} -eval 'net.probe on; sleep 5; net.show; exit'"
        print(comando)
        resultado = subprocess.run(comando, shell=True, capture_output=True, text=True)
        #print(resultado)
        print(resultado.stdout)
        # Expresión regular para extraer IPs y MACs
        dispositivos = re.findall(r"(\d+\.\d+\.\d+\.\d+)\s*\│\s*([0-9A-Fa-f:]{17})", resultado.stdout)
        print(dispositivos)

        return dispositivos
    except Exception as e:
        print("Error ejecutando Bettercap:", e)
        return []

# Configura la interfaz de red de la VM (ajusta según tu sistema)
INTERFAZ_VM = "vboxnet0"

# Ejecuta el escaneo
dispositivos = scan_subred(INTERFAZ_VM)
print(dispositivos)

# Muestra los resultados
if dispositivos:
    print("Dispositivos encontrados:")
    for ip, mac in dispositivos:
        print(f"IP: {ip}, MAC: {mac}")
else:
    print("No se encontraron dispositivos en la subred.")