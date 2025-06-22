import mariadb
import json

class DatabaseManager:
    
    def __init__(self, host="localhost", user="root", password="", database="identified_assets"):
        try:
            self.conn = mariadb.connect(
                user = user,
                password = password,
                host = host,
                port = 3306,
                database = database
            )
            self.cursor = self.conn.cursor()
        except mariadb.Error as e:
            print(f"Error conectando a MariaDB: {e}")
            self.conn = None
    
    def execute_query(self, query, params=None, fetch_one=False):
        if not self.conn is None:
            print("No hay conexión a la base de datos.")
            return [] if not fetch_one else None
        cursor = None
        try:
            cursor = self.conn.cursor()
            cursor.execute(query, params)

            # Detectar si es una operación de escritura para hacer commit
            if query.strip().upper().startswith(("INSERT", "UPDATE", "DELETE")):
                self.conn.commit()
                return cursor.rowcount # Retorna el número de filas afectadas
            else: # Operación de lectura (SELECT)
                if fetch_one:
                    return cursor.fetchone()
                return cursor.fetchall()
        except mariadb.Error as e:
            print(f"DatabaseManager: Error ejecutando consulta '{query}' con params {params}: {e}")
            self.conn.rollback() # Deshacer cambios en caso de error
            return [] if not fetch_one else None
        finally:
            if cursor:
                cursor.close() # Es buena práctica cerrar el cursor después de cada operación


    def close(self):
        if self.conn and self.conn.is_connected():
            self.conn.close()
            print("DatabaseManager: Conexión a la base de datos cerrada.")