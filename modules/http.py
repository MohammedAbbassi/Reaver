import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin
import socket
import ssl


class HTTPClient:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Reaver/1.0 (Reconnaissance Tool)'
        })
    
    def grab_headers(self, url: str) -> Dict:
        try:
            response = self.session.head(url, timeout=self.timeout, verify=False)
            return {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'server': response.headers.get('Server', 'Unknown'),
                'tech': self._detect_tech(response.headers),
            }
        except Exception as e:
            return {'error': str(e)}
    
    def detect_tech(self, url: str) -> List[str]:
        technologies = []
        
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            headers = response.headers
            
            server = headers.get('Server', '').lower()
            if 'nginx' in server:
                technologies.append('nginx')
            if 'apache' in server:
                technologies.append('apache')
            if 'iis' in server:
                technologies.append('iis')
            
            powered = headers.get('X-Powered-By', '').lower()
            if 'php' in powered:
                technologies.append('php')
            if 'asp.net' in powered:
                technologies.append('asp.net')
            if 'express' in powered:
                technologies.append('express')
            if 'django' in powered:
                technologies.append('django')
            if 'rails' in powered:
                technologies.append('rails')
            if 'laravel' in powered:
                technologies.append('laravel')
            
            cookies = headers.get('Set-Cookie', '').lower()
            if 'phpsessid' in cookies:
                technologies.append('php')
            if 'jsessionid' in cookies:
                technologies.append('java')
            if 'asp.net_sessionid' in cookies:
                technologies.append('asp.net')
            
            if response.headers.get('X-Generator'):
                technologies.append(response.headers.get('X-Generator'))
            
        except Exception:
            pass
        
        return list(set(technologies))
    
    def _detect_tech(self, headers: Dict) -> List[str]:
        tech = []
        server = headers.get('Server', '').lower()
        
        if 'nginx' in server:
            tech.append('nginx')
        if 'apache' in server:
            tech.append('apache')
        if 'iis' in server:
            tech.append('iis')
        if 'cloudflare' in server:
            tech.append('cloudflare')
        
        powered = headers.get('X-Powered-By', '').lower()
        if powered:
            tech.append(powered)
        
        return tech
    
    def detect_web_tech(self, url: str) -> Dict:
        result = {
            'tech': [],
            'cms': None,
            'framework': None,
            'server': None
        }
        
        try:
            response = self.session.get(url, timeout=5, verify=False, allow_redirects=True)
            headers = response.headers
            content = response.text.lower()
            
            server = headers.get('Server', '').lower()
            result['server'] = server
            
            if 'luci' in content or '/cgi-bin/luci' in content:
                result['tech'].append('luci')
                result['framework'] = 'luci'
            
            if 'openwrt' in content:
                result['tech'].append('openwrt')
            
            if 'nginx' in server:
                result['tech'].append('nginx')
            if 'apache' in server:
                result['tech'].append('apache')
            if 'nginx' in content or 'server: nginx' in content:
                result['tech'].append('nginx')
                
            if 'wordpress' in content:
                result['cms'] = 'wordpress'
                result['tech'].append('wordpress')
            if 'joomla' in content:
                result['cms'] = 'joomla'
                result['tech'].append('joomla')
            if 'drupal' in content:
                result['cms'] = 'drupal'
                result['tech'].append('drupal')
                
            if 'wp-content' in content:
                result['cms'] = 'wordpress'
                result['tech'].append('wordpress')
                
            if '/cgi-bin/' in content or 'cgi-bin' in content:
                result['tech'].append('cgi')
                
        except Exception as e:
            pass
        
        return result
    
    def check_login_page(self, url: str) -> bool:
        login_indicators = [
            'login', 'signin', 'password', 'username',
            'authenticate', 'sign in', 'log in'
        ]
        
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            content = response.text.lower()
            
            for indicator in login_indicators:
                if indicator in content:
                    return True
            
            if '<form' in content:
                form_inputs = response.text.count('<input')
                if form_inputs >= 2:
                    return True
            
        except Exception:
            pass
        
        return False
    
    def check_admin_panel(self, url: str) -> bool:
        admin_indicators = ['/admin', '/administrator', '/manage', '/backend']
        
        for path in admin_indicators:
            try:
                admin_url = urljoin(url, path)
                response = self.session.get(admin_url, timeout=self.timeout, verify=False)
                if response.status_code == 200:
                    return True
            except:
                continue
        
        return False


def generate_urls_from_ports(ip: str, ports: List[Dict]) -> List[str]:
    urls = []
    
    port_map = {
        80: 'http',
        443: 'https',
        8080: 'http',
        8443: 'https',
        8000: 'http',
        8888: 'http',
        3000: 'http',
        3001: 'http',
        5000: 'http',
        5001: 'https',
        9000: 'http',
    }
    
    for port_info in ports:
        port = int(port_info.get('port', 0))
        
        if port in port_map:
            protocol = port_map[port]
        elif port < 1024:
            protocol = 'http'
        else:
            protocol = 'http'
        
        url = f"{protocol}://{ip}:{port}"
        urls.append(url)
    
    return urls


def check_port_open(host: str, port: int, timeout: int = 3) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False
