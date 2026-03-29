from typing import Dict, List, Any
import json


class ReconIntelligence:
    @staticmethod
    def analyze_host(host_data: Dict) -> List[str]:
        intelligence = []
        
        services = host_data.get('services', [])
        urls = host_data.get('urls', [])
        endpoints = host_data.get('endpoints', [])
        findings = host_data.get('findings', [])
        cves = host_data.get('cves', [])
        
        for service in services:
            service_name = service.get('name', '').lower()
            product = service.get('product', '').lower()
            version = service.get('version', '')
            
            if version:
                if any(x in version.lower() for x in ['vulnerable', 'outdated', 'old']):
                    intelligence.append(f"Potentially outdated {product} {version}")
            
            if service_name in ['http', 'https', 'http-proxy']:
                intelligence.append("HTTP service exposed")
            
            if service_name in ['ssh', 'telnet', 'ftp']:
                intelligence.append(f"{service_name.upper()} login service detected")
            
            if service_name in ['smb', 'rpc']:
                intelligence.append("Windows/SMB service - enumerate shares/users")
            
            if service_name in ['rdp']:
                intelligence.append("RDP exposed - potential brute force target")
            
            if 'database' in product or service_name in ['mysql', 'postgresql', 'mongodb', 'redis']:
                intelligence.append("Database service - check for weak auth")
        
        for endpoint in endpoints:
            path_type = endpoint.get('type', '')
            path = endpoint.get('path', '')
            
            if path_type == 'admin':
                intelligence.append(f"Admin panel detected: {path}")
            elif path_type == 'login':
                intelligence.append(f"Login page detected: {path}")
            elif path_type == 'api':
                intelligence.append(f"API endpoint: {path}")
            elif path_type == 'sensitive':
                intelligence.append(f"Sensitive path exposed: {path}")
            elif path_type == 'upload':
                intelligence.append(f"File upload endpoint: {path}")
        
        for finding in findings:
            title = finding.get('title', '').lower()
            severity = finding.get('severity', '').upper()
            
            if severity in ['HIGH', 'CRITICAL']:
                intelligence.append(f"[{severity}] {finding.get('title', 'Finding')}")
            
            if any(x in title for x in ['exposed', 'debug', 'config', 'credential', 'password', 'token', 'api key']):
                intelligence.append(f"Exposure detected: {finding.get('title', '')}")
            
            if any(x in title for x in ['login', 'admin', 'panel']):
                intelligence.append("Administrative interface found")
        
        for cve_entry in cves:
            for vuln in cve_entry.get('vulnerabilities', []):
                vuln_type = vuln.get('type', '')
                severity = vuln.get('severity', '').upper()
                cve_id = vuln.get('cve', '')
                
                if severity in ['HIGH', 'CRITICAL'] or vuln_type == 'RCE':
                    intelligence.append(f"High severity: {cve_id} ({vuln_type}) - POTENTIAL RCE")
                elif severity == 'MEDIUM':
                    intelligence.append(f"Medium severity: {cve_id} ({vuln_type})")
        
        return list(set(intelligence))
    
    @staticmethod
    def rank_hosts(hosts_data: Dict) -> Dict:
        high_value = []
        interesting = []
        low_value = []
        
        for ip, host_data in hosts_data.items():
            score = 0
            reasons = []
            
            services = host_data.get('services', [])
            for service in services:
                product = service.get('product', '').lower()
                version = service.get('version', '')
                
                if any(x in product for x in ['apache', 'nginx', 'iis']):
                    score += 1
                if version and 'old' in version.lower():
                    score += 3
                    reasons.append(f"Outdated: {product} {version}")
            
            endpoints = host_data.get('endpoints', [])
            for endpoint in endpoints:
                path_type = endpoint.get('type', '')
                if path_type in ['admin', 'login', 'api']:
                    score += 3
                    reasons.append(f"{path_type} interface")
            
            findings = host_data.get('findings', [])
            for finding in findings:
                severity = finding.get('severity', '').upper()
                if severity in ['HIGH', 'CRITICAL']:
                    score += 5
                    reasons.append(f"Finding: {finding.get('title', '')}")
            
            cves = host_data.get('cves', [])
            for cve_entry in cves:
                for vuln in cve_entry.get('vulnerabilities', []):
                    if vuln.get('type') == 'RCE':
                        score += 10
                        reasons.append(f"RCE: {vuln.get('cve', '')}")
                    elif vuln.get('severity', '').upper() in ['HIGH', 'CRITICAL']:
                        score += 5
                        reasons.append(f"CVE: {vuln.get('cve', '')}")
            
            hostnames = host_data.get('hostnames', [])
            
            host_summary = {
                'ip': ip,
                'hostnames': hostnames,
                'reasons': reasons,
                'score': score
            }
            
            if score >= 10:
                high_value.append(host_summary)
            elif score >= 5:
                interesting.append(host_summary)
            else:
                low_value.append(host_summary)
        
        high_value.sort(key=lambda x: x['score'], reverse=True)
        interesting.sort(key=lambda x: x['score'], reverse=True)
        
        return {
            'high_value': high_value,
            'interesting': interesting,
            'low_value': low_value
        }
    
    @staticmethod
    def generate_recommendations(host_data: Dict) -> List[str]:
        recommendations = []
        
        services = host_data.get('services', [])
        hostnames = host_data.get('hostnames', [])
        cves = host_data.get('cves', [])
        
        for service in services:
            service_name = service.get('name', '')
            product = service.get('product', '').lower()
            
            if 'http' in service_name or product in ['apache', 'nginx', 'iis']:
                recommendations.append("Enumerate web directories and check for vulnerabilities")
            
            if service_name in ['ssh', 'ftp']:
                recommendations.append(f"Check for weak credentials on {service_name}")
        
        for cve_entry in cves:
            for vuln in cve_entry.get('vulnerabilities', []):
                if vuln.get('type') == 'RCE':
                    recommendations.append(f"Exploit {vuln.get('cve', '')} for potential RCE")
        
        return recommendations
