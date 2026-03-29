from typing import Dict, List, Any, Optional
from utils.normalizer import TargetNormalizer


class HostAggregator:
    def __init__(self):
        self.hosts: Dict[str, Dict] = {}
    
    def add_nmap_results(self, nmap_data: Dict):
        for host in nmap_data.get('hosts', []):
            ip = None
            hostname = None
            
            for addr in host.get('addresses', []):
                if addr.get('type') == 'ipv4':
                    ip = addr.get('addr')
            
            if host.get('hostnames'):
                hostname = host['hostnames'][0]
            
            if not ip:
                continue
            
            if ip not in self.hosts:
                self.hosts[ip] = {
                    'ip': ip,
                    'hostnames': [],
                    'ports': [],
                    'services': [],
                    'urls': [],
                    'technologies': [],
                    'endpoints': [],
                    'findings': [],
                    'cves': [],
                    'intelligence': []
                }
            
            if hostname and hostname not in self.hosts[ip]['hostnames']:
                self.hosts[ip]['hostnames'].append(hostname)
            
            for port in host.get('ports', []):
                port_entry = {
                    'port': port.get('portid'),
                    'protocol': port.get('protocol'),
                    'state': port.get('state'),
                }
                
                service = port.get('service')
                if service:
                    port_entry['service'] = service.get('name', '')
                    port_entry['product'] = service.get('product', '')
                    port_entry['version'] = service.get('version', '')
                
                if port_entry not in self.hosts[ip]['ports']:
                    self.hosts[ip]['ports'].append(port_entry)
                
                if service:
                    service_entry = {
                        'port': port.get('portid'),
                        'name': service.get('name', ''),
                        'product': service.get('product', ''),
                        'version': service.get('version', ''),
                    }
                    if service_entry not in self.hosts[ip]['services']:
                        self.hosts[ip]['services'].append(service_entry)
    
    def add_urls(self, ip: str, urls: List[str]):
        if ip in self.hosts:
            for url in urls:
                if url not in self.hosts[ip]['urls']:
                    self.hosts[ip]['urls'].append(url)
    
    def add_technologies(self, ip: str, tech: List[str]):
        if ip in self.hosts:
            for t in tech:
                if t not in self.hosts[ip]['technologies']:
                    self.hosts[ip]['technologies'].append(t)
    
    def add_endpoints(self, ip: str, endpoints: List[Dict]):
        if ip in self.hosts:
            for endpoint in endpoints:
                url = endpoint.get('url', '')
                if url:
                    self.hosts[ip]['endpoints'].append(endpoint)
    
    def add_findings(self, ip: str, findings: List[Dict]):
        if ip in self.hosts:
            for finding in findings:
                if finding not in self.hosts[ip]['findings']:
                    self.hosts[ip]['findings'].append(finding)
    
    def add_cves(self, ip: str, cves: List[Dict]):
        if ip in self.hosts:
            for cve_entry in cves:
                if cve_entry not in self.hosts[ip]['cves']:
                    self.hosts[ip]['cves'].append(cve_entry)
    
    def add_intelligence(self, ip: str, intel: str):
        if ip in self.hosts:
            if intel not in self.hosts[ip]['intelligence']:
                self.hosts[ip]['intelligence'].append(intel)
    
    def get_host(self, ip: str) -> Optional[Dict]:
        return self.hosts.get(ip)
    
    def get_all_hosts(self) -> Dict:
        return self.hosts
    
    def get_summary(self) -> Dict:
        return {
            'total_hosts': len(self.hosts),
            'hosts': list(self.hosts.keys())
        }
    
    def to_dict(self) -> Dict:
        return {
            'summary': self.get_summary(),
            'hosts': self.hosts
        }
