import mariadb
import json

class DatabaseManager:

    def __init__(self, host="localhost", user="root", password="", database="identified_assets"):
        # Guardamos los parámetros de conexión para futuros reintentos
        self._db_config = {
            "host": host,
            "user": user,
            "password": password,
            "port": 3306,
            "database": database
        }

        self.conn = None
        self.connect()

    def connect(self):
        print(f"DatabaseManager: Intentando conectar a MariaDB en {self._db_config['host']} con usuario {self._db_config['user']} y DB {self._db_config['database']}...")
        try:
            self.conn = mariadb.connect(**self._db_config)
            print("DatabaseManager: ¡Conexión establecida exitosamente!")
        except mariadb.Error as e:
            print(f"DatabaseManager: ERROR al conectar a MariaDB: {e}")
            self.conn = None

    def execute_query(self, query, params=None, fetch_one=False):
        if self.conn is None:
            print("DatabaseManager: Error: No hay conexión a la base de datos para ejecutar la consulta.")
            return [] if not fetch_one else None

        # Verificamos que la conexión esté activa
        try:
            self.conn.ping()
        except mariadb.Error as e:
            print(f"DatabaseManager: Conexión perdida durante ping: {e}. Intentando reconectar...")
            self.connect()
            if self.conn is None:
                print("DatabaseManager: Reconexión fallida.")
                return [] if not fetch_one else None

        cursor = None
        try:
            cursor = self.conn.cursor()
            cursor.execute(query, params)

            if query.strip().upper().startswith(("INSERT", "UPDATE", "DELETE")):
                self.conn.commit()
                return cursor.rowcount
            else:
                return cursor.fetchone() if fetch_one else cursor.fetchall()

        except mariadb.Error as e:
            print(f"DatabaseManager: Error ejecutando consulta '{query}' con params {params}: {e}")
            self.conn.rollback()
            return [] if not fetch_one else None
        finally:
            if cursor:
                cursor.close()

    def close(self):
        if self.conn:
            try:
                self.conn.close()
                print("DatabaseManager: Conexión a la base de datos cerrada.")
            except mariadb.Error as e:
                print(f"DatabaseManager: Error al cerrar la conexión: {e}")
            except Exception as e:
                print(f"DatabaseManager: Error inesperado al cerrar la conexión: {e}")
        else:
            print("DatabaseManager: No hay conexión a la base de datos para cerrar.")
