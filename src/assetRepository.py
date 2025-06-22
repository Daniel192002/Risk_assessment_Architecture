from databaseManager import DatabaseManager

class AssetRepository:
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager # Recibe la instancia de DatabaseManager
        print(f"AssetRepository inicializado. Instancia de DatabaseManager: {self.db}")

    def get_all_devices(self):
        query = "SELECT mac, ipv4, ipv6 FROM assets"
        return self.db.execute_query(query)

    def insert_device(self, mac, ipv4, ipv6):
        query = "INSERT INTO assets (mac, ipv4, ipv6) VALUES (%s, %s, %s)"
        self.db.execute_query(query, (mac, ipv4, ipv6))
        # print(f"AssetRepository: Dispositivo {mac} insertado.") # Los prints de confirmación pueden ir en el RiskController o un logger

    def device_exists(self, mac, ipv4, ipv6): # Nuevo método si lo necesitas para la lógica en RiskController
        query = "SELECT 1 FROM assets WHERE mac = %s AND (ipv4 = %s OR ipv6 = %s) LIMIT 1"
        return self.db.execute_query(query, (mac, ipv4, ipv6), fetch_one=True) is not None
