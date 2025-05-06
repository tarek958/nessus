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