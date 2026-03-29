import socket
import json
import os
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from modules.nmap import NmapScanner
from modules.nuclei import NucleiScanner
from modules.http import HTTPClient, generate_urls_from_ports
from modules.discovery import EndpointDiscovery
from modules.cve import CVEMatcher
from core.aggregator import HostAggregator
from core.intelligence import ReconIntelligence
from utils.parser import NmapParser
from utils.normalizer import TargetNormalizer


class ReconOrchestrator:
    def __init__(self, options: Dict = None):
        self.options = options or {}
        self.normalizer = TargetNormalizer()
        self.aggregator = HostAggregator()
        self.intelligence = ReconIntelligence()
        
        self.nmap_scanner = NmapScanner(
            threads=self.options.get('threads', 100),
            fast=self.options.get('fast', False)
        )
        self.nuclei_scanner = NucleiScanner(
            tags=self.options.get('nuclei_tags', 'exposure,misconfig,tech'),
            rate_limit=self.options.get('rate_limit', 150)
        )
        self.http_client = HTTPClient(timeout=self.options.get('timeout', 3))
        self.endpoint_discovery = EndpointDiscovery(
            threads=self.options.get('discovery_threads', 10),
            timeout=self.options.get('timeout', 2),
            fast=self.options.get('fast', False)
        )
        self.cve_matcher = CVEMatcher()
        
        self._load_cve_data()
    
    def _load_cve_data(self):
        cve_file = self.options.get('cve_file')
        if cve_file:
            self.cve_matcher.load_cve_data(cve_file)
    
    def run(self, targets: List[str] = None) -> Dict:
        if not targets and not self.options.get('targets'):
            print("[!] No targets provided to orchestrator")
            return self.aggregator.to_dict()
            
        targets = targets or self.options.get('targets', [])
        targets = self.normalizer.deduplicate_targets(targets)
        
        print(f"[*] Starting reconnaissance on {len(targets)} target(s)", flush=True)
        
        resolved_targets = self._resolve_targets(targets)
        print(f"[*] Resolved to {len(resolved_targets)} live host(s)", flush=True)
        
        if not resolved_targets:
            print("[!] No live hosts found", flush=True)
            return self.aggregator.to_dict()
        
        print(f"[*] [1/4] Scanning ports...", flush=True)
        self._scan_hosts(resolved_targets)
        
        print(f"[*] [2/4] Fingerprinting & discovering endpoints...", flush=True)
        
        print(f"[*] [3/4] Matching CVEs...", flush=True)
        self._match_cves(resolved_targets)
        
        print(f"[*] [4/4] Generating intelligence...", flush=True)
        
        results = self.aggregator.to_dict()
        results['intelligence'] = self._generate_intelligence()
        
        return results
    
    def _resolve_targets(self, targets: List[str]) -> List[str]:
        resolved = []
        
        for target in targets:
            target = self.normalizer.normalize_input(target)
            
            if self.normalizer.is_ip(target):
                if self._is_host_alive(target):
                    resolved.append(target)
            elif self.normalizer.is_domain(target):
                try:
                    ip = socket.gethostbyname(target)
                    if self._is_host_alive(ip):
                        resolved.append(ip)
                except socket.gaierror:
                    print(f"[!] Could not resolve {target}")
        
        return resolved
    
    def _is_host_alive(self, host: str) -> bool:
        return True
    
    def _scan_hosts(self, hosts: List[str]):
        print(f"[*] Running port scans on {len(hosts)} host(s)", flush=True)
        
        for host in hosts:
            print(f"  [*] Scanning {host}...")
            nmap_results = self.nmap_scanner.scan(host)
            self.aggregator.add_nmap_results(nmap_results)
            
            host_data = self.aggregator.get_host(host)
            if not host_data:
                print(f"[!] No results for {host}, skipping...")
                continue
            
            services = host_data.get('services', [])
            urls = generate_urls_from_ports(host, services)
            self.aggregator.add_urls(host, urls)
            
            if urls:
                self._fingerprint_web_services(host, urls)
        
        self._run_nuclei_scan(hosts)
        
        self._match_cves(hosts)
        
        for host in hosts:
            host_data = self.aggregator.get_host(host)
            if host_data:
                intel = self.intelligence.analyze_host(host_data)
                for item in intel:
                    self.aggregator.add_intelligence(host, item)
    
    def _fingerprint_web_services(self, host: str, urls: List[str]):
        all_endpoints = []
        
        for url in urls[:1]:
            try:
                headers = self.http_client.grab_headers(url)
                if 'error' not in headers:
                    tech = headers.get('tech', [])
                    self.aggregator.add_technologies(host, tech)
                    
                    server = headers.get('server', '').lower()
                    if 'luci' in server or 'openwrt' in server:
                        self.aggregator.add_technologies(host, ['luci', 'openwrt'])
                
                endpoints = self.endpoint_discovery.discover(url)
                all_endpoints.extend(endpoints)
                
                import requests
                requests.packages.urllib3.disable_warnings()
                r = requests.get(url, verify=False, timeout=3, allow_redirects=True)
                content = r.text.lower()
                
                if 'luci' in content or '/cgi-bin/luci' in content:
                    self.aggregator.add_technologies(host, ['luci', 'openwrt'])
                if 'openwrt' in content:
                    self.aggregator.add_technologies(host, ['openwrt'])
            except:
                pass
        
        if all_endpoints:
            self.aggregator.add_endpoints(host, all_endpoints)
    
    def _run_nuclei_scan(self, hosts: List[str]):
        all_urls = []
        
        for host in hosts:
            host_data = self.aggregator.get_host(host)
            if host_data:
                all_urls.extend(host_data.get('urls', []))
        
        if not all_urls:
            return
        
        print(f"[*] Running nuclei scan on {len(all_urls)} URL(s)")
        
        urls_file = 'temp_urls.txt'
        with open(urls_file, 'w') as f:
            for url in all_urls:
                f.write(f"{url}\n")
        
        try:
            findings = self.nuclei_scanner.scan(urls_file)
            
            for finding in findings:
                target = finding.get('target', '')
                if not target:
                    continue
                
                for host in hosts:
                    host_data = self.aggregator.get_host(host)
                    urls = host_data.get('urls', [])
                    
                    for url in urls:
                        if url in target or target in url:
                            self.aggregator.add_findings(host, [finding])
                            break
        except Exception as e:
            print(f"[!] Nuclei scan error: {e}")
        finally:
            if os.path.exists(urls_file):
                os.remove(urls_file)
    
    def _match_cves(self, hosts: List[str]):
        print(f"[*] Matching CVEs against discovered services")
        
        from modules.cve_db import lookup_cve
        
        for host in hosts:
            host_data = self.aggregator.get_host(host)
            if not host_data:
                continue
            
            services = host_data.get('services', [])
            technologies = host_data.get('technologies', [])
            
            all_cves = []
            seen_cves = set()
            
            service_dict = {host: services}
            cve_results = self.cve_matcher.build_service_cve_map(service_dict)
            cves = cve_results.get(host, [])
            if cves:
                all_cves.extend(cves)
            
            sources = [s.get('name', '') for s in services]
            sources += [s.get('product', '') for s in services]
            sources += technologies
            
            for source in sources:
                if not source:
                    continue
                    
                source_lower = source.lower()
                builtin_cves = lookup_cve(source_lower)
                
                for cve in builtin_cves:
                    cve_id = cve.get('cve', '')
                    if cve_id and cve_id not in seen_cves:
                        seen_cves.add(cve_id)
                        all_cves.append({
                            'service': source,
                            'version': '',
                            'vulnerabilities': [cve]
                        })
            
            if all_cves:
                self.aggregator.add_cves(host, all_cves)
    
    def _generate_intelligence(self) -> Dict:
        hosts_data = self.aggregator.get_all_hosts()
        return self.intelligence.rank_hosts(hosts_data)
    
    def cleanup(self):
        self.nmap_scanner.cleanup()
        self.nuclei_scanner.cleanup()
        self.cve_matcher.save_cache()
