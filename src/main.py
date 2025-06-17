# main.py (Este archivo es el que ejecutarías para iniciar tu aplicación)
import atexit

# Importar el DatabaseManager base
from databaseManager import DatabaseManager

# Importar los módulos de lógica de negocio
from asset_detector import AssetDetector
from vulnerabilityScanner import VulnerabilityScanner
from threatClassifier import ThreatClassifier
from riskCalculation import RiskCalculation
from reportGenerator import ReportGenerator

# Importar los repositorios
from assetRepository import AssetRepository
from vulnerabilityRepository import VulnerabilityRepository
from reportRepository import ReportRepository

# Importar el RiskController
from riskController import RiskController


if __name__ == "__main__":
    print("Iniciando la aplicación de Gestión de Riesgos...")

    # --- 1. Inicializar la única instancia del DatabaseManager ---
    # Aquí se configura la conexión a la base de datos
    db_manager = DatabaseManager(user="root", password="tfg2025", host="127.0.0.1", database="identified_assets")
    
    # Asegurarse de que la conexión se cierre limpiamente al finalizar el programa
    atexit.register(db_manager.close)

    # --- 2. Inicializar los Repositorios, inyectando el DatabaseManager ---
    # Los repositorios son la capa que interactúa con el DatabaseManager
    asset_repo = AssetRepository(db_manager=db_manager)
    vuln_repo = VulnerabilityRepository(db_manager=db_manager)
    report_repo = ReportRepository(db_manager=db_manager)
    # Si tuvieras un ThreatRepository o RiskRepository separado, los inicializarías aquí también

    # --- 3. Inicializar los Módulos de Lógica de Negocio (sin dependencias de DB aquí) ---
    # Estos módulos realizan las operaciones principales sin preocuparse por la persistencia
    asset_detector_instance = AssetDetector()
    vulnerability_scanner_instance = VulnerabilityScanner()
    threat_classifier_instance = ThreatClassifier()
    risk_calculation_instance = RiskCalculation()
    report_generator_instance = ReportGenerator()

    # --- 4. Inicializar el RiskController, inyectando TODAS sus dependencias ---
    # El RiskController es el orquestador, recibe todo lo que necesita para operar
    risk_controller_app = RiskController(
        asset_detector=asset_detector_instance,
        vulnerability_scanner=vulnerability_scanner_instance,
        threat_classifier=threat_classifier_instance,
        risk_calculation=risk_calculation_instance,
        report_generator=report_generator_instance,
        asset_repository=asset_repo,             # Inyección del AssetRepository
        vulnerability_repository=vuln_repo,     # Inyección del VulnerabilityRepository
        report_repository=report_repo             # Inyección del ReportRepository
    )

    # --- 5. Ejecutar el ciclo principal de la aplicación ---
    risk_controller_app.main()

    print("Aplicación de Gestión de Riesgos finalizada.")