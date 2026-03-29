import subprocess
import os
import tempfile
from typing import List, Dict, Optional
from pathlib import Path


class NucleiScanner:
    def __init__(self, tags: str = 'exposure,misconfig,tech', rate_limit: int = 150):
        self.tags = tags
        self.rate_limit = rate_limit
        self.temp_dir = tempfile.mkdtemp()
    
    def scan(self, urls_file: str, output_file: Optional[str] = None) -> List[Dict]:
        if not os.path.exists(urls_file):
            print(f"[!] URLs file not found: {urls_file}")
            return []
        
        if not output_file:
            output_file = os.path.join(self.temp_dir, 'nuclei_results.json')
        
        cmd = [
            'nuclei',
            '-l', urls_file,
            '-json',
            '-tags', self.tags,
            '-rate-limit', str(self.rate_limit),
            '-o', output_file,
            '-silent'
        ]
        
        print(f"[*] Running nuclei scan on {urls_file}...")
        
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=1800
            )
            
            if os.path.exists(output_file):
                from utils.parser import NucleiParser
                return NucleiParser.parse_json(output_file)
            
        except subprocess.TimeoutExpired:
            print("[!] Nuclei scan timed out")
        except FileNotFoundError:
            print("[!] Nuclei not found. Please install nuclei.")
        except Exception as e:
            print(f"[!] Nuclei scan error: {e}")
        
        return []
    
    def scan_urls(self, urls: List[str]) -> List[Dict]:
        if not urls:
            return []
        
        urls_file = os.path.join(self.temp_dir, 'urls.txt')
        with open(urls_file, 'w') as f:
            for url in urls:
                f.write(f"{url}\n")
        
        return self.scan(urls_file)
    
    def cleanup(self):
        import shutil
        try:
            shutil.rmtree(self.temp_dir)
        except:
            pass
