import re
import ipaddress
from typing import List, Set
from urllib.parse import urlparse


class TargetNormalizer:
    @staticmethod
    def normalize_input(target: str) -> str:
        target = target.strip()
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            target = parsed.netloc or parsed.path
        target = target.rstrip('/')
        return target

    @staticmethod
    def is_ip(target: str) -> bool:
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False

    @staticmethod
    def is_domain(target: str) -> bool:
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        )
        return bool(domain_pattern.match(target))

    @staticmethod
    def load_targets_from_file(filepath: str) -> List[str]:
        targets = set()
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    targets.add(TargetNormalizer.normalize_input(line))
        return list(targets)

    @staticmethod
    def deduplicate_targets(targets: List[str]) -> List[str]:
        return list(set(targets))

    @staticmethod
    def normalize_service_name(service: str) -> str:
        service_mapping = {
            'http': 'apache',
            'nginx': 'nginx',
            'apache': 'apache',
            'ssh': 'openssh',
            'ftp': 'vsftpd',
            'mysql': 'mysql',
            'postgresql': 'postgresql',
            'redis': 'redis',
            'mongodb': 'mongodb',
            'elasticsearch': 'elasticsearch',
            'jenkins': 'jenkins',
            'git': 'git',
            'docker': 'docker',
        }
        service_lower = service.lower()
        for key, value in service_mapping.items():
            if key in service_lower:
                return value
        return service.lower()

    @staticmethod
    def parse_version(version: str) -> str:
        match = re.search(r'(\d+\.\d+(?:\.\d+)?)', version)
        if match:
            return match.group(1)
        return version
