import requests
from typing import List, Dict, Set
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed


class EndpointDiscovery:
    COMMON_PATHS = [
        '/admin',
        '/login',
        '/api',
        '/wp-admin',
        '/phpmyadmin',
        '/.git',
        '/.env',
        '/config',
        '/backup',
        '/api/v1',
        '/api/v2',
    ]
    
    FAST_PATHS = [
        '/admin',
        '/login',
        '/api',
    ]
    
    def __init__(self, threads: int = 20, timeout: int = 3, fast: bool = False):
        self.threads = threads
        self.timeout = timeout
        self.fast = fast
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Reaver/1.0'
        })
    
    def discover(self, base_url: str) -> List[Dict]:
        paths = self.FAST_PATHS if self.fast else self.COMMON_PATHS
        discovered = []
        
        def check_path(path: str) -> Dict:
            try:
                url = urljoin(base_url, path)
                response = self.session.head(url, timeout=self.timeout, allow_redirects=True)
                
                if response.status_code in [200, 301, 302, 403]:
                    return {
                        'path': path,
                        'url': url,
                        'status': response.status_code,
                        'type': self._classify_path(path)
                    }
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check_path, path): path for path in self.COMMON_PATHS}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    discovered.append(result)
        
        return discovered
    
    def discover_multiple(self, urls: List[str]) -> Dict[str, List[Dict]]:
        results = {}
        
        for url in urls:
            endpoints = self.discover(url)
            if endpoints:
                results[url] = endpoints
        
        return results
    
    def _classify_path(self, path: str) -> str:
        path_lower = path.lower()
        
        if any(x in path_lower for x in ['admin', 'manage', 'backend']):
            return 'admin'
        if any(x in path_lower for x in ['login', 'signin', 'auth']):
            return 'login'
        if any(x in path_lower for x in ['api', 'graphql', 'rest']):
            return 'api'
        if any(x in path_lower for x in ['.git', '.svn', '.env', 'config']):
            return 'sensitive'
        if any(x in path_lower for x in ['backup', 'db', 'database']):
            return 'backup'
        if any(x in path_lower for x in ['upload', 'file', 'images']):
            return 'upload'
        
        return 'other'
