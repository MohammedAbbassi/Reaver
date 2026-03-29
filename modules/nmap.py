import subprocess
import os
import socket
import tempfile
import threading
import shutil
from typing import Dict, List, Optional
from pathlib import Path


class NmapScanner:
    def __init__(self, threads: int = 100, fast: bool = False):
        self.threads = threads
        self.fast = fast
        self.temp_dir = tempfile.mkdtemp()
        self.has_nmap = bool(shutil.which('nmap'))
    
    def scan(self, target: str, output_file: Optional[str] = None) -> Dict:
        if self.has_nmap:
            return self._nmap_scan(target, output_file)
        else:
            return self._socket_scan(target)

    def _nmap_scan(self, target: str, output_file: Optional[str] = None) -> Dict:
        print(f"[*] Running nmap scan on {target}...")
        
        if not output_file:
            output_file = os.path.join(self.temp_dir, f'nmap_{target}.xml')
            
        ports = "-F" if self.fast else "--top-ports 1000"
        cmd = [
            'nmap',
            '-sV',
            '-T4',
            ports,
            '-oX', output_file,
            target
        ]
        
        try:
            subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
            if os.path.exists(output_file):
                from utils.parser import NmapParser
                return NmapParser.parse_xml(output_file)
        except Exception as e:
            print(f"[!] Nmap scan failed: {e}")
            
        return self._socket_scan(target)

    def _socket_scan(self, target: str) -> Dict:
        print(f"[*] Fallback: Scanning common ports on {target} using sockets...")
        
        common_ports = [
            80, 443, 8080, 8000, 3000, 5000, 22, 21, 25, 3306, 
            5432, 27017, 6379, 11211, 9200, 8443, 53, 110, 143,
            445, 139, 135, 3389, 5900, 5901, 5902, 23, 111,
            2049, 1110, 496, 496, 69, 162, 514, 587, 8888
        ]
        
        if self.fast:
            common_ports = [80, 443, 8080, 22, 21, 3306, 5432, 3389]
        
        port_services = {
            80: 'http', 443: 'https', 8080: 'http-proxy', 8000: 'http',
            3000: 'http', 5000: 'http', 22: 'ssh', 21: 'ftp',
            25: 'smtp', 3306: 'mysql', 5432: 'postgresql', 27017: 'mongodb',
            6379: 'redis', 9200: 'elasticsearch', 8443: 'https',
            23: 'telnet', 445: 'smb', 3389: 'rdp', 5900: 'vnc',
            53: 'dns', 110: 'pop3', 143: 'imap', 8888: 'http'
        }
        
        open_ports = []
        
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            try:
                result = sock.connect_ex((target, port))
                if result == 0:
                    service = port_services.get(port, 'unknown')
                    open_ports.append({
                        'portid': str(port),
                        'protocol': 'tcp',
                        'state': 'open',
                        'service': {'name': service, 'product': '', 'version': ''}
                    })
            except:
                pass
            finally:
                sock.close()
        
        if open_ports:
            return {'hosts': [{'addresses': [{'addr': target, 'type': 'ipv4'}], 'ports': open_ports, 'hostnames': []}]}
        
        return {'hosts': []}
    
    def scan_multiple(self, targets: List[str]) -> Dict:
        all_results = {'hosts': []}
        
        for target in targets:
            result = self.scan(target)
            all_results['hosts'].extend(result.get('hosts', []))
        
        return all_results
    
    def cleanup(self):
        import shutil
        try:
            shutil.rmtree(self.temp_dir)
        except:
            pass
