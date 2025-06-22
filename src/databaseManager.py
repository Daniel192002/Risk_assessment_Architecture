import mariadb
import json

class DatabaseManager:

    def __init__(self, host="localhost", user="root", password="", database="identified_assets"):
        self.conn = None # Inicializa a None
        print(f"DatabaseManager: Intentando conectar a MariaDB en {host} con usuario {user} y DB {database}...") # Debug
        try:
            self.conn = mariadb.connect(
                user = user,
                password = password,
                host = host,
                port = 3306,
                database = database
            )
            print("DatabaseManager: ¡Conexión establecida exitosamente!") # Debug
        except mariadb.Error as e:
            print(f"DatabaseManager: ERROR al conectar a MariaDB: {e}") # Debug
            self.conn = None # Asegura que sea None si falla la conexión inicial

    def execute_query(self, query, params=None, fetch_one=False):
        if self.conn is None: # Si self.conn ES None, entonces no hay conexión
            print("DatabaseManager: Error: No hay conexión a la base de datos para ejecutar la consulta.") # Debug
            return [] if not fetch_one else None # Devolver [] para SELECTs que esperarían iterables

        try:
            self.conn.ping(reconnect=True) # Intenta un ping para asegurar que la conexión está viva y reconecta si es posible
        except mariadb.Error as e:
            print(f"DatabaseManager: Conexión perdida o inactiva durante ping: {e}. Por favor, verifique el servidor de la base de datos.") # Debug
            return [] if not fetch_one else None


        cursor = None
        try:
            cursor = self.conn.cursor() # Crea el cursor aquí
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
            print(f"DatabaseManager: Error ejecutando consulta '{query}' con params {params}: {e}") # Debug
            self.conn.rollback() # Deshacer cambios en caso de error
            return [] if not fetch_one else None # Devolver [] para SELECTs que esperarían iterables
        finally:
            if cursor:
                cursor.close()


    def close(self):
        if self.conn: # Si self.conn NO ES None (es decir, hay un objeto de conexión)
            try:
                self.conn.close()
                print("DatabaseManager: Conexión a la base de datos cerrada.") # Debug
            except mariadb.Error as e:
                print(f"DatabaseManager: Error al cerrar la conexión: {e}") # Debug
            except Exception as e:
                print(f"DatabaseManager: Error inesperado al cerrar la conexión: {e}") # Debug
        else:
            print("DatabaseManager: No hay conexión a la base de datos para cerrar.") # Debug