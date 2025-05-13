from asset_controller import AssetController
from vulnerabilityScanner import VulnerabilityScanner

INTERFAZ = "eth1"

if __name__ == "__main__":
    dispositivos = AssetController.scan_network(INTERFAZ)
    print("\n[DEBUG] Salida de IPv6:")
    print(dispositivos)
    if dispositivos:
        print("\nDispositivos detectados:")
        for mac, datos in dispositivos.items():
            print(f"MAC: {mac}, IPv4: {datos['IPv4']}, IPv6: {datos['IPv6']}")
    else:
        print("\nNo se capturaron dispositivos en la red.")

    scanner = VulnerabilityScanner()
    scanner.scan_devices_from_db()