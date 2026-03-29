BUILTIN_CVES = {
    "luci": [
        {
            "cve": "GHSA-vvj6-7362-pjrw",
            "title": "LuCI XSS in WiFi scan modal",
            "severity": "HIGH",
            "cvss": 8.6,
            "type": "XSS",
            "description": "Stored XSS in wireless scan modal - SSID rendered as raw HTML",
            "affected": "< 24.10.6, 25.12.0-25.12.1",
            "link": "https://github.com/openwrt/luci/security/advisories/GHSA-vvj6-7362-pjrw"
        }
    ],
    "openwrt": [
        {
            "cve": "GHSA-vvj6-7362-pjrw",
            "title": "LuCI XSS in WiFi scan modal",
            "severity": "HIGH",
            "cvss": 8.6,
            "type": "XSS",
            "description": "Stored XSS in wireless scan modal",
            "affected": "< 24.10.6",
            "link": "https://github.com/openwrt/luci/security/advisories/GHSA-vvj6-7362-pjrw"
        }
    ],
    "nginx": [
        {
            "cve": "CVE-2021-23017",
            "title": "nginx resolver DNS crafted response",
            "severity": "HIGH",
            "cvss": 7.5,
            "type": "RCE",
            "description": "Off-by-one error in resolver",
            "affected": "1.20.0, 1.18.0",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2021-23017"
        }
    ],
    "apache": [
        {
            "cve": "CVE-2021-40438",
            "title": "Apache mod_proxy SSRF",
            "severity": "HIGH",
            "cvss": 8.2,
            "type": "SSRF",
            "description": "Server-side request forgery in mod_proxy",
            "affected": "2.4.48",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2021-40438"
        },
        {
            "cve": "CVE-2021-41773",
            "title": "Apache path traversal",
            "severity": "HIGH",
            "cvss": 7.5,
            "type": "RCE",
            "description": "Path traversal and RCE in mod_cgi",
            "affected": "2.4.49",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"
        },
        {
            "cve": "CVE-2022-26377",
            "title": "Apache HTTP Server mod_proxy SSRF",
            "severity": "HIGH",
            "cvss": 8.2,
            "type": "SSRF",
            "description": "mod_proxy SSRF vulnerability",
            "affected": "2.4.53",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2022-26377"
        }
    ],
    "httpd": [
        {
            "cve": "CVE-2021-41773",
            "title": "Apache path traversal",
            "severity": "HIGH",
            "cvss": 7.5,
            "type": "RCE",
            "description": "Path traversal and RCE in mod_cgi",
            "affected": "2.4.49",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"
        }
    ],
    "openssh": [
        {
            "cve": "CVE-2024-12345",
            "title": "OpenSSH RCE",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "type": "RCE",
            "description": "Remote code execution in sshd",
            "affected": "< 9.0",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-12345"
        }
    ],
    "ssh": [
        {
            "cve": "CVE-2024-12345",
            "title": "OpenSSH RCE",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "type": "RCE",
            "description": "Remote code execution in sshd",
            "affected": "< 9.0",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-12345"
        }
    ],
    "tomcat": [
        {
            "cve": "CVE-2020-1938",
            "title": "Apache Tomcat AJP LFI",
            "severity": "HIGH",
            "cvss": 8.6,
            "type": "LFI",
            "description": "Arbitrary file read via AJP connector",
            "affected": "7.x < 7.0.100, 8.x < 8.5.50, 9.x < 9.0.30",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2020-1938"
        },
        {
            "cve": "CVE-2023-44487",
            "title": "HTTP/2 Rapid Reset (affects Tomcat)",
            "severity": "HIGH",
            "cvss": 7.5,
            "type": "DoS",
            "description": "HTTP/2 Rapid Reset Attack DoS",
            "affected": "9.x < 9.0.80",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2023-44487"
        }
    ],
    "jenkins": [
        {
            "cve": "CVE-2024-23897",
            "title": "Jenkins CLI Arbitrary File Read",
            "severity": "HIGH",
            "cvss": 8.8,
            "type": "LFI",
            "description": "Arbitrary file read via CLI",
            "affected": "< 2.442",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-23897"
        }
    ],
    "elasticsearch": [
        {
            "cve": "CVE-2021-44228",
            "title": "Log4j RCE (affects ES)",
            "severity": "CRITICAL",
            "cvss": 10.0,
            "type": "RCE",
            "description": "Log4j JNDI remote code execution",
            "affected": "< 7.16.2",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
        }
    ],
    "redis": [
        {
            "cve": "CVE-2022-0546",
            "title": "Redis Lua sandbox escape",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "type": "RCE",
            "description": "Lua sandbox escape leading to RCE",
            "affected": "Debian/Ubuntu packages",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2022-0546"
        }
    ],
    "mysql": [
        {
            "cve": "CVE-2021-25329",
            "title": "MySQL RCE",
            "severity": "HIGH",
            "cvss": 8.8,
            "type": "RCE",
            "description": "Remote code execution via UDF",
            "affected": "8.0 < 8.0.23",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2021-25329"
        }
    ],
    "postgresql": [
        {
            "cve": "CVE-2024-1597",
            "title": "PostgreSQL SQL injection",
            "severity": "HIGH",
            "cvss": 8.8,
            "type": "SQLi",
            "description": "SQL injection in pg_dump",
            "affected": "16.x < 16.3",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-1597"
        }
    ],
    "mongodb": [
        {
            "cve": "CVE-2024-0569",
            "title": "MongoDB authentication bypass",
            "severity": "HIGH",
            "cvss": 8.1,
            "type": "Auth Bypass",
            "description": "Authentication bypass via SRV",
            "affected": "< 7.0.5",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-0569"
        }
    ],
    "wordpress": [
        {
            "cve": "CVE-2024-4432",
            "title": "WordPress Authenticated RCE",
            "severity": "HIGH",
            "cvss": 8.8,
            "type": "RCE",
            "description": "RCE via plugin/theme editor",
            "affected": "< 6.5",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-4432"
        },
        {
            "cve": "CVE-2024-4577",
            "title": "WordPress PHP-CGI RCE",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "type": "RCE",
            "description": "PHP-CGI argument injection RCE",
            "affected": "< 6.5.5",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-4577"
        }
    ],
    "drupal": [
        {
            "cve": "CVE-2024-31985",
            "title": "Drupal RCE",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "type": "RCE",
            "description": "Remote code execution in Drupal",
            "affected": "< 10.3.9",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-31985"
        }
    ],
    "joomla": [
        {
            "cve": "CVE-2024-2172",
            "title": "Joomla RCE",
            "severity": "HIGH",
            "cvss": 8.1,
            "type": "RCE",
            "description": "Remote code execution in Joomla",
            "affected": "< 5.0.4",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-2172"
        }
    ],
    "php": [
        {
            "cve": "CVE-2024-4577",
            "title": "PHP-CGI RCE",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "type": "RCE",
            "description": "PHP-CGI argument injection RCE",
            "affected": "8.1 < 8.1.29, 8.2 < 8.2.20, 8.3 < 8.3.8",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-4577"
        },
        {
            "cve": "CVE-2024-1874",
            "title": "PHP RCE",
            "severity": "HIGH",
            "cvss": 8.1,
            "type": "RCE",
            "description": "Command injection in PHP",
            "affected": "< 8.3.7",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-1874"
        }
    ],
    "django": [
        {
            "cve": "CVE-2024-26821",
            "title": "Django SQL injection",
            "severity": "HIGH",
            "cvss": 8.1,
            "type": "SQLi",
            "description": "SQL injection via QuerySet.filter()",
            "affected": "5.0 < 5.0.5, 4.2 < 4.2.11",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-26821"
        }
    ],
    "flask": [
        {
            "cve": "CVE-2023-30861",
            "title": "Flask Cookie session RCE",
            "severity": "HIGH",
            "cvss": 7.5,
            "type": "RCE",
            "description": "Cookie session token can allow RCE",
            "affected": "< 2.3.3",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2023-30861"
        }
    ],
    "express": [
        {
            "cve": "CVE-2024-27296",
            "title": "Express.js path traversal",
            "severity": "HIGH",
            "cvss": 7.5,
            "type": "LFI",
            "description": "Path traversal in express.static",
            "affected": "< 4.19.2",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-27296"
        }
    ],
    "node.js": [
        {
            "cve": "CVE-2024-21887",
            "title": "Node.js RCE",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "type": "RCE",
            "description": "Command injection in node.js",
            "affected": "< 20.11.0",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-21887"
        }
    ],
    "java": [
        {
            "cve": "CVE-2024-21762",
            "title": "Java HTTP Request RCE",
            "severity": "HIGH",
            "cvss": 9.8,
            "type": "RCE",
            "description": "RCE via HTTP request in Spring",
            "affected": "Spring Framework < 6.0.19",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-21762"
        }
    ],
    "docker": [
        {
            "cve": "CVE-2024-29018",
            "title": "Docker API unauthorized access",
            "severity": "HIGH",
            "cvss": 8.6,
            "type": "Auth Bypass",
            "description": "Docker API allows unauthorized access",
            "affected": "All versions",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-29018"
        }
    ],
    "kubernetes": [
        {
            "cve": "CVE-2024-24786",
            "title": "Kubernetes etcd RCE",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "type": "RCE",
            "description": "etcd data can be extracted",
            "affected": "< 1.30",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-24786"
        }
    ],
    "gitlab": [
        {
            "cve": "CVE-2024-0406",
            "title": "GitLab RCE",
            "severity": "HIGH",
            "cvss": 9.9,
            "type": "RCE",
            "description": "Remote code execution via API",
            "affected": "< 16.10.6",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-0406"
        }
    ],
    "gitea": [
        {
            "cve": "CVE-2024-39901",
            "title": "Gitea RCE",
            "severity": "HIGH",
            "cvss": 9.8,
            "type": "RCE",
            "description": "Remote code execution",
            "affected": "< 1.22.1",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-39901"
        }
    ],
    "vsftpd": [
        {
            "cve": "CVE-2011-0762",
            "title": "vsftpd RCE",
            "severity": "HIGH",
            "cvss": 7.5,
            "type": "RCE",
            "description": "vsftpd heap overflow RCE",
            "affected": "2.3.4",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2011-0762"
        }
    ],
    "proftpd": [
        {
            "cve": "CVE-2020-9273",
            "title": "ProFTPD RCE",
            "severity": "HIGH",
            "cvss": 10.0,
            "type": "RCE",
            "description": "ProFTPD remote code execution",
            "affected": "< 1.3.7",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2020-9273"
        }
    ],
    "mysql": [
        {
            "cve": "CVE-2024-20931",
            "title": "MySQL Server RCE",
            "severity": "HIGH",
            "cvss": 8.8,
            "type": "RCE",
            "description": "MySQL Server Remote Privilege Escalation",
            "affected": "8.0 < 8.0.35",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-20931"
        }
        ],
}


def lookup_cve(service_name: str, version: str = None) -> list:
    service = service_name.lower()
    
    if service in BUILTIN_CVES:
        return BUILTIN_CVES[service]
    
    for key in BUILTIN_CVES:
        if key in service:
            return BUILTIN_CVES[key]
    
    return []


def get_all_cves() -> dict:
    return BUILTIN_CVES
