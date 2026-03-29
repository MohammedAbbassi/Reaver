import json
import os
import re
from typing import Dict, List, Optional
from pathlib import Path


class CVEMatcher:
    def __init__(self, cve_cache_dir: str = './cve_cache'):
        self.cve_cache_dir = cve_cache_dir
        self.cve_db: Dict = {}
        self._ensure_cache_dir()
    
    def _ensure_cache_dir(self):
        os.makedirs(self.cve_cache_dir, exist_ok=True)
    
    def load_cve_data(self, cve_file: str = None) -> bool:
        if cve_file and os.path.exists(cve_file):
            try:
                with open(cve_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.cve_db = self._process_nvd_data(data)
                    print(f"[*] Loaded {len(self.cve_db)} CVEs from {cve_file}")
                    return True
            except Exception as e:
                print(f"[!] Error loading CVE data: {e}")
        
        lite_cve_file = os.path.join(self.cve_cache_dir, 'cve_lite.json')
        if os.path.exists(lite_cve_file):
            try:
                with open(lite_cve_file, 'r', encoding='utf-8') as f:
                    self.cve_db = json.load(f)
                    print(f"[*] Loaded {len(self.cve_db)} CVEs from cache")
                    return True
            except:
                pass
        
        return False
    
    def _process_nvd_data(self, data: Dict) -> Dict:
        cve_db = {}
        
        try:
            items = data.get('CVE_Items', [])
            for item in items:
                cve_id = item.get('cve', {}).get('CVE_data_meta', {}).get('ID', '')
                if not cve_id:
                    continue
                
                descriptions = item.get('cve', {}).get('description', {}).get('description_data', [])
                description = descriptions[0].get('value', '') if descriptions else ''
                
                impact = item.get('impact', {})
                base_metric_v3 = impact.get('baseMetricV3', {})
                base_metric_v2 = impact.get('baseMetricV2', {})
                
                cvss_v3 = base_metric_v3.get('cvssV3', {})
                cvss_v2 = base_metric_v2.get('cvssV2', {})
                
                severity = cvss_v3.get('baseSeverity') or cvss_v2.get('baseSeverity') or 'UNKNOWN'
                cvss = cvss_v3.get('baseScore') or cvss_v2.get('baseScore') or 0.0
                
                cve_db[cve_id] = {
                    'id': cve_id,
                    'description': description,
                    'severity': str(severity).upper(),
                    'cvss': float(cvss),
                    'affects': []
                }
                
                nodes = item.get('configurations', {}).get('nodes', [])
                for node in nodes:
                    for cpe in node.get('cpe', []):
                        affected = cpe.get('cpe22Uri', '')
                        if affected:
                            cve_db[cve_id]['affects'].append(affected)
        
        except Exception as e:
            print(f"[!] Error processing CVE data: {e}")
        
        return cve_db
    
    def match_cve(self, service_name: str, version: str = None, min_cvss: float = 7.0) -> List[Dict]:
        results = []
        
        service_normalized = self._normalize_service_name(service_name)
        
        for cve_id, cve_data in self.cve_db.items():
            if cve_data.get('cvss', 0) < min_cvss:
                continue
            
            description = cve_data.get('description', '').lower()
            affects = ' '.join(cve_data.get('affects', [])).lower()
            
            if not version:
                if service_normalized in description or service_normalized in affects:
                    results.append(self._format_cve_result(cve_data))
            else:
                version_normalized = self._normalize_version(version)
                
                if service_normalized in description or service_normalized in affects:
                    if self._version_in_range(version_normalized, description):
                        results.append(self._format_cve_result(cve_data))
        
        return results[:10]
    
    def _normalize_service_name(self, service: str) -> str:
        service = service.lower()
        
        mappings = {
            'apache': 'apache',
            'httpd': 'apache',
            'nginx': 'nginx',
            'openssh': 'ssh',
            'ssh': 'ssh',
            'ftp': 'ftp',
            'vsftpd': 'ftp',
            'proftpd': 'ftp',
            'mysql': 'mysql',
            'mariadb': 'mysql',
            'postgresql': 'postgresql',
            'postgres': 'postgresql',
            'redis': 'redis',
            'mongodb': 'mongodb',
            'elasticsearch': 'elasticsearch',
            'jenkins': 'jenkins',
            'git': 'git',
            'docker': 'docker',
            'kubernetes': 'kubernetes',
            'k8s': 'kubernetes',
            'php': 'php',
            'python': 'python',
            'django': 'django',
            'flask': 'flask',
            'express': 'express',
            'nodejs': 'node.js',
            'java': 'java',
            'tomcat': 'tomcat',
            'jboss': 'jboss',
            'weblogic': 'weblogic',
        }
        
        for key, value in mappings.items():
            if key in service:
                return value
        
        return service
    
    def _normalize_version(self, version: str) -> str:
        match = re.search(r'(\d+\.\d+(?:\.\d+)?)', version)
        if match:
            return match.group(1)
        return version
    
    def _version_in_range(self, version: str, text: str) -> bool:
        version_parts = version.split('.')
        if len(version_parts) < 2:
            return False
        
        text_with_version = f"{version_parts[0]}.{version_parts[1]}"
        
        patterns = [
            rf'{re.escape(text_with_version)}\.\d+',
            rf'before\s*{re.escape(text_with_version)}',
            rf'prior\s*to\s*{re.escape(text_with_version)}',
            rf'<{re.escape(text_with_version)}',
            rf'><{re.escape(text_with_version)}',
        ]
        
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        
        return True
    
    def _format_cve_result(self, cve_data: Dict) -> Dict:
        description = cve_data.get('description', '')
        
        vuln_types = []
        desc_lower = description.lower()
        if any(x in desc_lower for x in ['remote code execution', 'rce', 'code execution', 'exec']):
            vuln_types.append('RCE')
        if any(x in desc_lower for x in ['sql injection', 'sql injection']):
            vuln_types.append('SQLi')
        if any(x in desc_lower for x in ['cross-site scripting', 'xss']):
            vuln_types.append('XSS')
        if any(x in desc_lower for x in ['directory traversal', 'path traversal']):
            vuln_types.append('Traversal')
        if any(x in desc_lower for x in ['command injection', 'os command']):
            vuln_types.append('Command Injection')
        if any(x in desc_lower for x in ['authentication bypass', 'bypass authentication']):
            vuln_types.append('Auth Bypass')
        if any(x in desc_lower for x in ['denial of service', 'dos']):
            vuln_types.append('DoS')
        
        return {
            'cve': cve_data.get('id', ''),
            'severity': cve_data.get('severity', 'UNKNOWN'),
            'cvss': cve_data.get('cvss', 0),
            'type': vuln_types[0] if vuln_types else 'Other',
            'description': description[:200] + '...' if len(description) > 200 else description,
        }
    
    def save_cache(self):
        cache_file = os.path.join(self.cve_cache_dir, 'cve_lite.json')
        try:
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(self.cve_db, f)
            print(f"[*] CVE cache saved to {cache_file}")
        except Exception as e:
            print(f"[!] Error saving CVE cache: {e}")
    
    def build_service_cve_map(self, services: Dict[str, List[Dict]]) -> Dict:
        service_cve_map = {}
        
        for ip, service_list in services.items():
            service_cve_map[ip] = []
            
            for service in service_list:
                service_name = service.get('name', '')
                version = service.get('version', '')
                
                if not service_name:
                    continue
                
                cves = self.match_cve(service_name, version)
                
                if cves:
                    service_cve_map[ip].append({
                        'service': service_name,
                        'version': version,
                        'vulnerabilities': cves
                    })
        
        return service_cve_map
