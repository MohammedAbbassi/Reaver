import json
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional
from pathlib import Path


class NmapParser:
    @staticmethod
    def parse_xml(xml_file: str) -> Dict[str, Any]:
        result = {
            'hosts': []
        }
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            for host in root.findall('.//host'):
                host_data = {
                    'addresses': [],
                    'ports': [],
                    'hostnames': [],
                    'status': 'unknown'
                }
                
                for address in host.findall('address'):
                    addr = address.get('addr')
                    addrtype = address.get('addrtype')
                    if addr:
                        host_data['addresses'].append({
                            'addr': addr,
                            'type': addrtype
                        })
                
                for hostname in host.findall('.//hostname'):
                    name = hostname.get('name')
                    if name:
                        host_data['hostnames'].append(name)
                
                status = host.find('status')
                if status is not None:
                    host_data['status'] = status.get('state', 'unknown')
                
                for port in host.findall('.//port'):
                    port_data = {
                        'portid': port.get('portid'),
                        'protocol': port.get('protocol', 'tcp'),
                        'state': 'unknown',
                        'service': None
                    }
                    
                    state = port.find('state')
                    if state is not None:
                        port_data['state'] = state.get('state', 'unknown')
                    
                    service = port.find('service')
                    if service is not None:
                        port_data['service'] = {
                            'name': service.get('name'),
                            'product': service.get('product', ''),
                            'version': service.get('version', ''),
                            'extrainfo': service.get('extrainfo', ''),
                        }
                    
                    if port_data['state'] == 'open':
                        host_data['ports'].append(port_data)
                
                if host_data['ports']:
                    result['hosts'].append(host_data)
            
        except Exception as e:
            print(f"[!] Error parsing nmap XML: {e}")
        
        return result

    @staticmethod
    def extract_services(nmap_data: Dict) -> Dict[str, List[Dict]]:
        services = {}
        for host in nmap_data.get('hosts', []):
            for addr in host.get('addresses', []):
                if addr.get('type') == 'ipv4':
                    ip = addr.get('addr')
                    services[ip] = []
                    for port in host.get('ports', []):
                        if port.get('service'):
                            services[ip].append({
                                'port': port.get('portid'),
                                'protocol': port.get('protocol'),
                                'name': port['service'].get('name', ''),
                                'product': port['service'].get('product', ''),
                                'version': port['service'].get('version', ''),
                            })
        return services


class NucleiParser:
    @staticmethod
    def parse_json(json_file: str) -> List[Dict]:
        findings = []
        
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            data = json.loads(line)
                            findings.append({
                                'type': 'finding',
                                'severity': data.get('info', {}).get('severity', 'unknown'),
                                'title': data.get('info', {}).get('name', ''),
                                'target': data.get('matched-at', data.get('url', '')),
                                'source': 'nuclei',
                                'description': data.get('info', {}).get('description', ''),
                                'template': data.get('template-id', ''),
                            })
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            print(f"[!] Error parsing nuclei JSON: {e}")
        
        return findings


class CVEDataParser:
    @staticmethod
    def load_nvd_json(json_file: str) -> Dict:
        cve_db = {}
        
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                for item in data.get('CVE_Items', []):
                    cve_id = item.get('cve', {}).get('CVE_data_meta', {}).get('ID', '')
                    if not cve_id:
                        continue
                    
                    description = ''
                    desc_data = item.get('cve', {}).get('description', {}).get('description_data', [])
                    if desc_data:
                        description = desc_data[0].get('value', '')
                    
                    impact = item.get('impact', {})
                    base_metric_v3 = impact.get('baseMetricV3', {})
                    base_metric_v2 = impact.get('baseMetricV2', {})
                    
                    cvss_v3 = base_metric_v3.get('cvssV3', {})
                    cvss_v2 = base_metric_v2.get('cvssV2', {})
                    
                    severity = cvss_v3.get('baseSeverity') or cvss_v2.get('baseSeverity') or 'UNKNOWN'
                    cvss = cvss_v3.get('baseScore') or cvss_v2.get('baseScore') or 0
                    
                    cve_db[cve_id] = {
                        'id': cve_id,
                        'description': description,
                        'severity': severity.upper(),
                        'cvss': cvss,
                    }
        except Exception as e:
            print(f"[!] Error loading CVE data: {e}")
        
        return cve_db
