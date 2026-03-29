#!/usr/bin/env python3

import argparse
import json
import sys
import os
import shutil
from pathlib import Path
from typing import Dict, List, Optional

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False

from core.orchestrator import ReconOrchestrator
from utils.normalizer import TargetNormalizer


USE_COLOR = sys.stdout.isatty() or HAS_COLORAMA

COLORS = {
    'reset': '\033[0m' if USE_COLOR else '',
    'red': '\033[91m' if USE_COLOR else '',
    'green': '\033[92m' if USE_COLOR else '',
    'yellow': '\033[93m' if USE_COLOR else '',
    'blue': '\033[94m' if USE_COLOR else '',
    'magenta': '\033[95m' if USE_COLOR else '',
    'cyan': '\033[96m' if USE_COLOR else '',
    'bold': '\033[1m' if USE_COLOR else '',
    'dim': '\033[2m' if USE_COLOR else '',
}


def colorize(text: str, color: str) -> str:
    return f"{COLORS.get(color, '')}{text}{COLORS['reset']}"


def print_banner():
    print("""
 ██▀███  ▓█████ ▄▄▄    ██▒   █▓▓█████  ██▀███  
▓██ ▒ ██▒▓█   ▀▒████▄ ▓██░   █▒▓█   ▀ ▓██ ▒ ██▒
▓██ ░▄█ ▒▒███  ▒██  ▀█▄▓██  █▒░▒███   ▓██ ░▄█ ▒
▒██▀▀█▄  ▒▓█  ▄░██▄▄▄▄██▒██ █░░▒▓█  ▄ ▒██▀▀█▄  
░██▓ ▒██▒░▒████▒▓█   ▓██▒▒▀█░  ░▒████▒░██▓ ▒██▒
░ ▒▓ ░▒▓░░░ ▒░ ░▒▒   ▓▒█░░ ▐░  ░░ ▒░ ░░ ▒▓ ░▒▓░
  ░▒ ░ ▒░ ░ ░  ░ ▒   ▒▒ ░░ ░░   ░ ░  ░  ░▒ ░ ▒░
  ░░   ░    ░    ░   ▒     ░░     ░     ░░   ░ 
   ░        ░  ░     ░  ░   ░     ░  ░   ░     
                           ░                                                    
    """)


def parse_args():
    parser = argparse.ArgumentParser(
        description='Reaver - Modular Reconnaissance Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py example.com
  python main.py 192.168.1.1
  python main.py example.com -o json
  python main.py -f targets.txt
  python main.py example.com --cve-file nvd.json
  python main.py example.com --nmap-only
        """
    )
    
    parser.add_argument('targets', nargs='*', help='Targets (domain or IP)')
    parser.add_argument('-t', '--target', type=str, help='Single target (domain or IP)')
    parser.add_argument('-f', '--file', type=str, help='File containing targets (one per line)')
    parser.add_argument('-o', '--output', type=str, choices=['json', 'text'], default='text',
                        help='Output format')
    parser.add_argument('--nmap-only', action='store_true', help='Run only nmap scan')
    parser.add_argument('--fast', action='store_true', help='Fast scan (top 100 ports)')
    parser.add_argument('--cve-file', type=str, help='Path to CVE data file (NVD JSON)')
    parser.add_argument('--nuclei-tags', type=str, default='exposure,misconfig,tech',
                        help='Nuclei tags to use (default: exposure,misconfig,tech)')
    parser.add_argument('--threads', type=int, default=100, help='Number of threads')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    
    return parser


def load_targets(args, parser):
    targets = []
    
    if args.targets:
        targets.extend(args.targets)
    
    if args.target:
        targets.append(args.target)
    
    if args.file:
        targets.extend(TargetNormalizer.load_targets_from_file(args.file))
    
    if not targets:
        print(colorize("[!] No targets specified. Use -t, -f, or provide targets directly", "red"))
        parser.print_help()
        sys.exit(1)
    
    return targets


def print_report(results: Dict, use_colors: bool = True):
    print("\n" + "=" * 60)
    print(colorize(" TARGET SUMMARY ", 'cyan') if use_colors else " TARGET SUMMARY ")
    print("=" * 60)
    
    summary = results.get('summary', {})
    print(f"\nTotal hosts scanned: {summary.get('total_hosts', 0)}")
    
    intelligence = results.get('intelligence', {})
    
    print("\n" + (colorize("[HIGH VALUE TARGETS]", 'red') if use_colors else "[HIGH VALUE TARGETS]"))
    print("-" * 40)
    
    high_value = intelligence.get('high_value', [])
    if not high_value:
        print("  None found")
    else:
        for host in high_value:
            name = host.get('hostnames', [])[0] if host.get('hostnames', []) else host.get('ip', 'unknown')
            print(f"\n  {colorize(name, 'bold' + 'red') if use_colors else name}")
            for reason in host.get('reasons', []):
                print(f"    - {reason}")
    
    print("\n" + (colorize("[INTERESTING]", 'yellow') if use_colors else "[INTERESTING]"))
    print("-" * 40)
    
    interesting = intelligence.get('interesting', [])
    if not interesting:
        print("  None found")
    else:
        for host in interesting:
            name = host.get('hostnames', [])[0] if host.get('hostnames', []) else host.get('ip', 'unknown')
            print(f"\n  {colorize(name, 'bold' + 'yellow') if use_colors else name}")
            for reason in host.get('reasons', [])[:3]:
                print(f"    - {reason}")
    
    print("\n" + (colorize("[LOW VALUE]", 'green') if use_colors else "[LOW VALUE]"))
    print("-" * 40)
    
    low_value = intelligence.get('low_value', [])
    if not low_value:
        print("  None found")
    else:
        for host in low_value[:5]:
            name = host.get('hostnames', [])[0] if host.get('hostnames', []) else host.get('ip', 'unknown')
            print(f"  - {name}")
    
    print("\n" + "=" * 60)
    print(colorize(" DETAILED FINDINGS ", 'cyan') if use_colors else " DETAILED FINDINGS ")
    print("=" * 60)
    
    hosts = results.get('hosts', {})
    for ip, host_data in hosts.items():
        hostnames = host_data.get('hostnames', [])
        display_name = hostnames[0] if hostnames else ip
        
        print(f"\n{colorize('>>> ', 'magenta') if use_colors else '>>> '}{display_name} ({ip})")
        
        services = host_data.get('services', [])
        if services:
            print(f"\n  Services ({len(services)}):")
            for svc in services[:5]:
                version = svc.get('version', '')
                ver_str = f" {version}" if version else ""
                print(f"    - {svc.get('name', 'unknown')}{ver_str} ({svc.get('product', '')})")
        
        urls = host_data.get('urls', [])
        if urls:
            print(f"\n  URLs ({len(urls)}):")
            for url in urls[:3]:
                print(f"    - {url}")
        
        endpoints = host_data.get('endpoints', [])
        if endpoints:
            print(f"\n  Discovered Endpoints ({len(endpoints)}):")
            for ep in endpoints[:5]:
                print(f"    - [{ep.get('type', 'other')}] {ep.get('path', '')}")
        
        findings = host_data.get('findings', [])
        if findings:
            print(f"\n  Nuclei Findings ({len(findings)}):")
            for finding in findings[:3]:
                sev = finding.get('severity', '').upper()
                color = 'red' if sev in ['HIGH', 'CRITICAL'] else 'yellow'
                sev_str = colorize(f"[{sev}]", color) if use_colors else f"[{sev}]"
                print(f"    {sev_str} {finding.get('title', '')}")
        
        cves = host_data.get('cves', [])
        if cves:
            print(f"\n  Potential CVEs:")
            for cve_entry in cves:
                service_name = cve_entry.get('service', '')
                version = cve_entry.get('version', '')
                for vuln in cve_entry.get('vulnerabilities', [])[:2]:
                    cve_id = vuln.get('cve', '')
                    vuln_type = vuln.get('type', '')
                    severity = vuln.get('severity', '')
                    link = vuln.get('link', '')
                    
                    rce_marker = colorize(" <<< RCE", 'red') if vuln_type == 'RCE' and use_colors else ""
                    
                    if link:
                        print(f"    - {cve_id} ({service_name} {version}) [{severity}] {vuln_type}{rce_marker}")
                        print(f"      Link: {link}")
                    else:
                        print(f"    - {cve_id} ({service_name} {version}) [{severity}] {vuln_type}{rce_marker}")
        
        intelligence_items = host_data.get('intelligence', [])
        if intelligence_items:
            print(f"\n  Intelligence:")
            for item in intelligence_items[:3]:
                print(f"    - {item}")
        
        print()
    
    print("=" * 60)


def check_environment():
    missing = []
    
    if not shutil.which('nuclei'):
        missing.append('nuclei')
        
    if missing:
        print(colorize(f"\n[!] Warning: Missing required tool(s): {', '.join(missing)}", "yellow"))
        print(colorize("[!] Some modules may not function correctly without these tools.\n", "yellow"))


def main():
    if not sys.stdout.isatty():
        for color in COLORS:
            COLORS[color] = ''
    
    print_banner()
    check_environment()
    
    parser = parse_args()
    args = parser.parse_args()
    
    if args.no_color:
        for color in COLORS:
            COLORS[color] = ''

    targets = load_targets(args, parser)
    
    options = {
        'threads': args.threads,
        'timeout': args.timeout,
        'nuclei_tags': args.nuclei_tags,
        'cve_file': args.cve_file,
        'fast': args.fast,
    }
    
    print(f"[*] Loaded {len(targets)} target(s)")
    
    orchestrator = ReconOrchestrator(options)
    
    try:
        results = orchestrator.run(targets)
        
        if args.output == 'json':
            print(json.dumps(results, indent=2))
        else:
            print_report(results, use_colors=not args.no_color)
        
        if args.file:
            output_file = 'reaver_results.json'
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\n[*] Results saved to {output_file}")
    
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(colorize(f"[!] Error: {e}", "red"))
        sys.exit(1)


if __name__ == "__main__":
    main()
