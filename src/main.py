from asset_controller import AssetController

INTERFAZ_KALI = "eth1"

if __name__ == "__main__":
    dispositivos = AssetController.scan_network(INTERFAZ_KALI)

    if dispositivos:
        print("\nDispositivos detectados:")
        for mac, datos in dispositivos.items():
            print(f"MAC: {mac}, IPv4: {datos['IPv4']}, IPv6: {datos['IPv6']}")
    else:
        print("\nNo se capturaron dispositivos en la red.")
