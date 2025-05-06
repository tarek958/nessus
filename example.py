from nessus_api import NessusAPI
import time
import json

def run_vulnerability_scan(target_network):
    """
    Exécute un scan de vulnérabilité sur le réseau cible.
    
    Args:
        target_network (str): Réseau cible (ex: 192.168.1.0/24)
        
    Returns:
        dict: Résultats du scan avec vulnérabilités
    """
    # Charger les paramètres de configuration
    with open('config.json', 'r') as f:
        config = json.load(f)
    
    # Initialiser l'API Nessus
    nessus = NessusAPI(
        url=config['nessus_url'],
        access_key=config['nessus_access_key'],
        secret_key=config['nessus_secret_key'],
        verify_ssl=config.get('verify_ssl', False)
    )
    
    # Créer un nouveau scan
    scan_name = f"Scan PICA - {time.strftime('%Y-%m-%d %H:%M:%S')}"
    scan_id = nessus.create_scan(name=scan_name, targets=target_network, template="basic")
    print(f"Scan créé: {scan_id}")
    
    # Lancer le scan
    nessus.launch_scan(scan_id)
    print("Scan lancé, en attente de la fin...")
    
    # Attendre la fin du scan
    nessus.wait_for_scan_completion(scan_id)
    print("Scan terminé")
    
    # Récupérer les résultats
    results = nessus.get_scan_results(scan_id)
    
    # Exporter un rapport
    report_file = nessus.export_report(scan_id, format="pdf")
    print(f"Rapport exporté: {report_file}")
    
    return {
        "scan_id": scan_id,
        "scan_name": scan_name,
        "vulnerabilities": results,
        "report_file": report_file
    }

if __name__ == "__main__":
    results = run_vulnerability_scan("192.168.1.0/24")
    print(f"Nombre de vulnérabilités trouvées: {len(results['vulnerabilities'])}") 