import mariadb
import json

class DatabaseManager:
    
    def __init__(self, host="localhost", user="root", password="", database="identified_assets"):
        self.conn = None # Inicializa a None
        try:
            self.conn = mariadb.connect(
                user = user,
                password = password,
                host = host,
                port = 3306,
                database = database
            )
            # Ya no crees self.cursor aquí. Créalo dentro de execute_query.
            # self.cursor = self.conn.cursor() 
            print("DatabaseManager: ¡Conexión establecida exitosamente!") # Mensaje de depuración
        except mariadb.Error as e:
            print(f"DatabaseManager: ERROR al conectar a MariaDB: {e}")
            self.conn = None # Asegura que sea None si falla la conexión inicial
    
    def execute_query(self, query, params=None, fetch_one=False):
        # LA CORRECCIÓN ESTÁ AQUÍ:
        if self.conn is None: # Si self.conn ES None, entonces no hay conexión
            print("DatabaseManager: Error: No hay conexión a la base de datos para ejecutar la consulta.")
            return [] if not fetch_one else None # Devolver [] para SELECTs que esperarían iterables
        
        # Elimina self.conn.is_connected() de aquí también. La librería mariadb no lo tiene.
        # Además, el ping() se usaría aquí si quieres verificar que la conexión sigue viva
        try:
            self.conn.ping(reconnect=True) # Intenta un ping para asegurar que la conexión está viva y reconecta si es posible
        except mariadb.Error as e:
            print(f"DatabaseManager: Conexión perdida o inactiva durante ping: {e}. Por favor, verifique el servidor de la base de datos.")
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
            print(f"DatabaseManager: Error ejecutando consulta '{query}' con params {params}: {e}")
            self.conn.rollback() # Deshacer cambios en caso de error
            return [] if not fetch_one else None # Devolver [] para SELECTs que esperarían iterables
        finally:
            if cursor:
                cursor.close()


    def close(self):
        # También corrige el close para eliminar el is_connected()
        if self.conn: # Si self.conn NO ES None (es decir, hay un objeto de conexión)
            try:
                self.conn.close()
                print("DatabaseManager: Conexión a la base de datos cerrada.")
            except mariadb.Error as e:
                print(f"DatabaseManager: Error al cerrar la conexión: {e}")
            except Exception as e:
                print(f"DatabaseManager: Error inesperado al cerrar la conexión: {e}")
        else:
            print("DatabaseManager: No hay conexión a la base de datos para cerrar.")