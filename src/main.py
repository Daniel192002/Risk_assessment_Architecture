import atexit

# Importar el DatabaseManager base
from databaseManager import DatabaseManager

# Importar los módulos de lógica de negocio
from asset_detector import AssetDetector
from vulnerabilityScanner import VulnerabilityScanner
from threatClassifier import ThreatClassifier
from riskCalculation import RiskCalculation
from reportGenerator import ReportGenerator # Asegúrate de que este nombre de archivo coincida

# Importar TODOS los repositorios
from assetRepository import AssetRepository
from vulnerabilityRepository import VulnerabilityRepository
from threatRepository import ThreatRepository
from riskRepository import RiskRepository     
from reportRepository import ReportRepository

# Importar el RiskController
from riskController import RiskController


if __name__ == "__main__":
    print("Iniciando la aplicación de Gestión de Riesgos...")

    # --- 1. Inicializar la única instancia del DatabaseManager ---
    # Aquí se configura la conexión a la base de datos
    db_manager = DatabaseManager(user="root", password="tfg2025", host="127.0.0.1")
    
    # Asegurarse de que la conexión se cierre limpiamente al finalizar el programa
    atexit.register(db_manager.close)

    # --- 2. Inicializar TODOS los Repositorios, inyectando el DatabaseManager ---
    # Cada repositorio es responsable de interactuar con una parte específica de la base de datos
    asset_repo = AssetRepository(db_manager=db_manager)
    vuln_repo = VulnerabilityRepository(db_manager=db_manager)
    threat_repo = ThreatRepository(db_manager=db_manager) # ¡Ahora se inicializa aquí!
    risk_repo = RiskRepository(db_manager=db_manager)     # ¡Ahora se inicializa aquí!
    report_repo = ReportRepository(db_manager=db_manager)

    # --- 3. Inicializar los Módulos de Lógica de Negocio, inyectando SUS dependencias de Repositorio ---
    # Estos módulos realizan las operaciones principales y conocen los repositorios que necesitan
    
    # AssetDetector ya no necesita repositorios directamente en su constructor si la gestión es en el Controller o si solo devuelve datos.
    # Si AssetDetector solo detecta y el Controller luego inserta, esta línea es correcta.
    # Si AssetDetector inserta directamente, necesitaría el asset_repo aquí. Revisa tu AssetDetector.py.
    # Basado en tu AssetDetector.py que tiene un constructor que acepta asset_repository, debería ser así:
    asset_detector_instance = AssetDetector(assetRepository=asset_repo)

    # VulnerabilityScanner necesita AssetRepository para obtener IPs y VulnerabilityRepository para guardar vulns
    vulnerability_scanner_instance = VulnerabilityScanner(
        asset_repository=asset_repo, 
        vulnerability_repository=vuln_repo
    )
    
    # ThreatClassifier necesita VulnerabilityRepository para obtener vulns y ThreatRepository para guardar clasificadas
    threat_classifier_instance = ThreatClassifier(
        vulnerability_repository=vuln_repo, 
        threat_repository=threat_repo
    )
    
    # RiskCalculation necesita ThreatRepository para obtener vulns clasificadas y RiskRepository para guardar riesgos
    risk_calculation_instance = RiskCalculation(
        threat_repository=threat_repo, 
        risk_repository=risk_repo
    )
    
    # ReportGenerator necesita ReportRepository para obtener los datos completos del informe
    report_generator_instance = ReportGenerator(
        report_repository=report_repo
    )

    # --- 4. Inicializar el RiskController, inyectando SÓLO las instancias de los módulos de Lógica de Negocio ---
    # El RiskController es el orquestador principal del flujo de la aplicación.
    # No necesita saber los detalles de los repositorios; solo se preocupa por qué "pasos" ejecutar.
    risk_controller_app = RiskController(
        asset_detector=asset_detector_instance,
        vulnerability_scanner=vulnerability_scanner_instance,
        threat_classifier=threat_classifier_instance,
        risk_calculation=risk_calculation_instance,
        report_generator=report_generator_instance,
        # ¡IMPORTANTE! Ya NO se inyectan los repositorios directamente en el RiskController aquí.
        # Los módulos de lógica de negocio ya los tienen.
    )

    # --- 5. Ejecutar el ciclo principal de la aplicación ---
    risk_controller_app.main() 

    print("Aplicación de Gestión de Riesgos finalizada.")