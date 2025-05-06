# PICA - Nessus API Integration

Ce module permet d'interagir avec l'API Nessus pour l'automatisation des scans de vulnérabilités dans le cadre du projet PICA (Plateforme Intégrée de Cybersécurité Automatisée).

## Prérequis

- Python 3.8+
- Nessus Professional ou Nessus Essentials (version gratuite)
- Postman (pour tester les API)

## Installation

```bash
pip install -r requirements.txt
```

## Configuration de Nessus

1. Installez Nessus à partir de [https://www.tenable.com/downloads/nessus](https://www.tenable.com/downloads/nessus)
2. Activez Nessus avec votre clé de licence ou créez un compte gratuit pour Nessus Essentials
3. Créez un utilisateur API dans Nessus via l'interface web (Settings > Users)
4. Notez votre API Key et Secret Key

## Utilisation de l'API Nessus avec Python

Le module `nessus_api.py` fournit une interface simplifiée pour interagir avec l'API Nessus.

### Exemple d'utilisation

```python
from nessus_api import NessusAPI

# Initialiser l'API
nessus = NessusAPI(
    url="https://localhost:8834",
    access_key="votre_access_key",
    secret_key="votre_secret_key",
    verify_ssl=False  # Mettre à True en production
)

# Lister les scans
scans = nessus.list_scans()
print(f"Scans disponibles: {scans}")

# Créer un nouveau scan
scan_id = nessus.create_scan(
    name="Scan Automatisé",
    targets="192.168.1.0/24",
    template="basic"
)
print(f"Nouveau scan créé avec ID: {scan_id}")

# Lancer un scan
nessus.launch_scan(scan_id)
print(f"Scan {scan_id} lancé")

# Vérifier le statut d'un scan
status = nessus.get_scan_status(scan_id)
print(f"Statut du scan: {status}")

# Récupérer les résultats d'un scan
results = nessus.get_scan_results(scan_id)
print(f"Vulnérabilités détectées: {len(results)}")

# Exporter un rapport au format PDF
report_file = nessus.export_report(scan_id, format="pdf")
print(f"Rapport exporté: {report_file}")
```

## Tests Postman pour l'API Nessus

Voici les requêtes Postman pour tester l'API Nessus. Vous pouvez importer la collection dans Postman.

### Collection Postman

```json
{
  "info": {
    "name": "Nessus API",
    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
  },
  "item": [
    {
      "name": "Authentification",
      "request": {
        "method": "POST",
        "header": [
          {
            "key": "Content-Type",
            "value": "application/json"
          }
        ],
        "body": {
          "mode": "raw",
          "raw": "{\n    \"username\": \"votre_utilisateur\",\n    \"password\": \"votre_mot_de_passe\"\n}"
        },
        "url": {
          "raw": "https://localhost:8834/session",
          "protocol": "https",
          "host": ["localhost"],
          "port": "8834",
          "path": ["session"]
        },
        "description": "Obtenir un token d'authentification (X-Cookie)"
      }
    },
    {
      "name": "Liste des scans",
      "request": {
        "method": "GET",
        "header": [
          {
            "key": "X-ApiKeys",
            "value": "accessKey=votre_access_key; secretKey=votre_secret_key"
          }
        ],
        "url": {
          "raw": "https://localhost:8834/scans",
          "protocol": "https",
          "host": ["localhost"],
          "port": "8834",
          "path": ["scans"]
        },
        "description": "Récupérer la liste des scans"
      }
    },
    {
      "name": "Créer un scan",
      "request": {
        "method": "POST",
        "header": [
          {
            "key": "X-ApiKeys",
            "value": "accessKey=votre_access_key; secretKey=votre_secret_key"
          },
          {
            "key": "Content-Type",
            "value": "application/json"
          }
        ],
        "body": {
          "mode": "raw",
          "raw": "{\n    \"uuid\": \"8d6f194d-8e9a-4b2f-9c9a-3dbb212e425d\",\n    \"settings\": {\n        \"name\": \"Scan Automatisé\",\n        \"text_targets\": \"192.168.1.0/24\",\n        \"enabled\": true\n    }\n}"
        },
        "url": {
          "raw": "https://localhost:8834/scans",
          "protocol": "https",
          "host": ["localhost"],
          "port": "8834",
          "path": ["scans"]
        },
        "description": "Créer un nouveau scan"
      }
    },
    {
      "name": "Lancer un scan",
      "request": {
        "method": "POST",
        "header": [
          {
            "key": "X-ApiKeys",
            "value": "accessKey=votre_access_key; secretKey=votre_secret_key"
          }
        ],
        "url": {
          "raw": "https://localhost:8834/scans/{{scan_id}}/launch",
          "protocol": "https",
          "host": ["localhost"],
          "port": "8834",
          "path": ["scans", "{{scan_id}}", "launch"]
        },
        "description": "Lancer un scan existant"
      }
    },
    {
      "name": "Statut d'un scan",
      "request": {
        "method": "GET",
        "header": [
          {
            "key": "X-ApiKeys",
            "value": "accessKey=votre_access_key; secretKey=votre_secret_key"
          }
        ],
        "url": {
          "raw": "https://localhost:8834/scans/{{scan_id}}",
          "protocol": "https",
          "host": ["localhost"],
          "port": "8834",
          "path": ["scans", "{{scan_id}}"]
        },
        "description": "Obtenir le statut d'un scan"
      }
    },
    {
      "name": "Résultats d'un scan",
      "request": {
        "method": "GET",
        "header": [
          {
            "key": "X-ApiKeys",
            "value": "accessKey=votre_access_key; secretKey=votre_secret_key"
          }
        ],
        "url": {
          "raw": "https://localhost:8834/scans/{{scan_id}}/hosts/{{host_id}}",
          "protocol": "https",
          "host": ["localhost"],
          "port": "8834",
          "path": ["scans", "{{scan_id}}", "hosts", "{{host_id}}"]
        },
        "description": "Récupérer les résultats d'un scan pour un hôte spécifique"
      }
    },
    {
      "name": "Exporter un rapport",
      "request": {
        "method": "POST",
        "header": [
          {
            "key": "X-ApiKeys",
            "value": "accessKey=votre_access_key; secretKey=votre_secret_key"
          },
          {
            "key": "Content-Type",
            "value": "application/json"
          }
        ],
        "body": {
          "mode": "raw",
          "raw": "{\n    \"format\": \"pdf\",\n    \"chapters\": \"vuln_hosts_summary;vuln_by_host\"\n}"
        },
        "url": {
          "raw": "https://localhost:8834/scans/{{scan_id}}/export",
          "protocol": "https",
          "host": ["localhost"],
          "port": "8834",
          "path": ["scans", "{{scan_id}}", "export"]
        },
        "description": "Exporter un rapport de scan"
      }
    },
    {
      "name": "Télécharger un rapport",
      "request": {
        "method": "GET",
        "header": [
          {
            "key": "X-ApiKeys",
            "value": "accessKey=votre_access_key; secretKey=votre_secret_key"
          }
        ],
        "url": {
          "raw": "https://localhost:8834/scans/{{scan_id}}/export/{{file_id}}/download",
          "protocol": "https",
          "host": ["localhost"],
          "port": "8834",
          "path": ["scans", "{{scan_id}}", "export", "{{file_id}}", "download"]
        },
        "description": "Télécharger un rapport exporté"
      }
    }
  ]
}
```

## Implémentation de l'API Python

Voici l'implémentation du module `nessus_api.py`:

```python
import requests
import time
import urllib3
import json
import os

# Désactiver les avertissements SSL pour les environnements de développement
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class NessusAPI:
    def __init__(self, url, access_key, secret_key, verify_ssl=False):
        """
        Initialise l'API Nessus.
        
        Args:
            url (str): URL de l'instance Nessus (ex: https://localhost:8834)
            access_key (str): Clé d'accès API
            secret_key (str): Clé secrète API
            verify_ssl (bool): Vérifier les certificats SSL
        """
        self.url = url.rstrip('/')
        self.access_key = access_key
        self.secret_key = secret_key
        self.verify_ssl = verify_ssl
        self.headers = {
            'X-ApiKeys': f'accessKey={access_key}; secretKey={secret_key}',
            'Content-Type': 'application/json'
        }
    
    def _request(self, method, endpoint, data=None, params=None, files=None):
        """
        Effectue une requête à l'API Nessus.
        
        Args:
            method (str): Méthode HTTP (GET, POST, etc.)
            endpoint (str): Point de terminaison API
            data (dict, optional): Données à envoyer
            params (dict, optional): Paramètres de requête
            files (dict, optional): Fichiers à envoyer
            
        Returns:
            dict: Réponse de l'API
        """
        url = f"{self.url}/{endpoint.lstrip('/')}"
        
        try:
            if method == "GET":
                response = requests.get(url, headers=self.headers, params=params, verify=self.verify_ssl)
            elif method == "POST":
                response = requests.post(url, headers=self.headers, json=data, params=params, files=files, verify=self.verify_ssl)
            elif method == "PUT":
                response = requests.put(url, headers=self.headers, json=data, params=params, verify=self.verify_ssl)
            elif method == "DELETE":
                response = requests.delete(url, headers=self.headers, json=data, params=params, verify=self.verify_ssl)
            else:
                raise ValueError(f"Méthode HTTP non prise en charge: {method}")
            
            response.raise_for_status()
            
            if response.headers.get('Content-Type') == 'application/octet-stream':
                return response.content
            
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Erreur lors de la requête à {url}: {e}")
            if hasattr(e, 'response') and e.response:
                print(f"Code de statut: {e.response.status_code}")
                print(f"Réponse: {e.response.text}")
            raise
    
    def list_scans(self):
        """
        Liste tous les scans.
        
        Returns:
            list: Liste des scans
        """
        response = self._request("GET", "/scans")
        return response.get('scans', [])
    
    def create_scan(self, name, targets, template="basic"):
        """
        Crée un nouveau scan.
        
        Args:
            name (str): Nom du scan
            targets (str): Cibles du scan (ex: "192.168.1.1, 192.168.1.2" ou "192.168.1.0/24")
            template (str): Template de scan (basic, advanced, etc.)
            
        Returns:
            int: ID du scan créé
        """
        # Récupérer l'UUID du template
        templates = self._request("GET", "/editor/scan/templates")
        template_uuid = None
        
        for t in templates.get('templates', []):
            if t.get('name', '').lower() == template.lower():
                template_uuid = t.get('uuid')
                break
        
        if not template_uuid:
            raise ValueError(f"Template de scan non trouvé: {template}")
        
        # Créer le scan
        data = {
            "uuid": template_uuid,
            "settings": {
                "name": name,
                "text_targets": targets,
                "enabled": True
            }
        }
        
        response = self._request("POST", "/scans", data=data)
        return response.get('scan', {}).get('id')
    
    def launch_scan(self, scan_id):
        """
        Lance un scan existant.
        
        Args:
            scan_id (int): ID du scan à lancer
            
        Returns:
            int: ID de la tâche de scan
        """
        response = self._request("POST", f"/scans/{scan_id}/launch")
        return response.get('scan_uuid')
    
    def get_scan_status(self, scan_id):
        """
        Obtient le statut d'un scan.
        
        Args:
            scan_id (int): ID du scan
            
        Returns:
            str: Statut du scan
        """
        response = self._request("GET", f"/scans/{scan_id}")
        return response.get('info', {}).get('status')
    
    def wait_for_scan_completion(self, scan_id, poll_interval=10, timeout=3600):
        """
        Attend la fin d'un scan.
        
        Args:
            scan_id (int): ID du scan
            poll_interval (int): Intervalle de vérification en secondes
            timeout (int): Délai d'attente maximum en secondes
            
        Returns:
            bool: True si le scan est terminé avec succès
        """
        start_time = time.time()
        
        while True:
            if time.time() - start_time > timeout:
                raise TimeoutError(f"Le scan {scan_id} n'a pas été terminé dans le délai imparti")
            
            status = self.get_scan_status(scan_id)
            
            if status == "completed":
                return True
            elif status in ["aborted", "failed", "canceled"]:
                raise Exception(f"Le scan {scan_id} a échoué avec le statut: {status}")
            
            time.sleep(poll_interval)
    
    def get_scan_results(self, scan_id):
        """
        Récupère les résultats d'un scan.
        
        Args:
            scan_id (int): ID du scan
            
        Returns:
            list: Liste des vulnérabilités
        """
        response = self._request("GET", f"/scans/{scan_id}")
        
        vulnerabilities = []
        hosts = response.get('hosts', [])
        
        for host in hosts:
            host_id = host.get('host_id')
            host_details = self._request("GET", f"/scans/{scan_id}/hosts/{host_id}")
            
            for vuln in host_details.get('vulnerabilities', []):
                vuln_details = self._request("GET", f"/scans/{scan_id}/hosts/{host_id}/plugins/{vuln.get('plugin_id')}")
                vulnerabilities.append({
                    "host": host.get('hostname'),
                    "ip": host.get('host_ip'),
                    "name": vuln.get('plugin_name'),
                    "severity": vuln.get('severity'),
                    "details": vuln_details
                })
        
        return vulnerabilities
    
    def export_report(self, scan_id, format="pdf", chapters="vuln_hosts_summary;vuln_by_host"):
        """
        Exporte un rapport de scan.
        
        Args:
            scan_id (int): ID du scan
            format (str): Format du rapport (pdf, csv, nessus, html)
            chapters (str): Chapitres à inclure
            
        Returns:
            str: Chemin du fichier exporté
        """
        # Démarrer l'exportation
        data = {
            "format": format,
            "chapters": chapters
        }
        
        response = self._request("POST", f"/scans/{scan_id}/export", data=data)
        file_id = response.get('file')
        
        if not file_id:
            raise Exception("Échec de l'exportation du rapport")
        
        # Attendre que l'exportation soit terminée
        while True:
            status_response = self._request("GET", f"/scans/{scan_id}/export/{file_id}/status")
            if status_response.get('status') == "ready":
                break
            time.sleep(1)
        
        # Télécharger le rapport
        content = self._request("GET", f"/scans/{scan_id}/export/{file_id}/download")
        
        # Enregistrer le fichier
        filename = f"nessus_scan_{scan_id}_{int(time.time())}.{format}"
        with open(filename, 'wb') as f:
            f.write(content)
        
        return filename
```

## Exemple d'utilisation dans un projet

```python
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
```

## Configuration

Créez un fichier `config.json` avec vos paramètres Nessus:

```json
{
    "nessus_url": "https://localhost:8834",
    "nessus_access_key": "votre_access_key",
    "nessus_secret_key": "votre_secret_key",
    "verify_ssl": false
}
```

## Dépendances

Créez un fichier `requirements.txt` avec les dépendances:

```
requests>=2.25.1
urllib3>=1.26.5
``` 