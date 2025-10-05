import asyncio
import ssl
import socket
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional
import time
from datetime import datetime
import certifi

@dataclass
class SSLResult:
    domain: str
    port: int
    ssl_version: Optional[str] = None
    cipher: Optional[str] = None
    certificate_info: Dict = field(default_factory=dict)
    vulnerabilities: List[str] = field(default_factory=list)
    is_valid: bool = False
    expires_soon: bool = False

class AdvancedSSLScanner:
    def __init__(self, target: str, ports: List[int] = None, timeout: int = 10):
        self.target = target
        self.ports = ports or [443, 8443, 9443]
        self.timeout = timeout
        self.logger = self._setup_logger()
        self.results: List[SSLResult] = []
    
    def _setup_logger(self) -> logging.Logger:
        logger = logging.getLogger('SSLScanner')
        logger.setLevel(logging.INFO)
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        return logger
    
    async def scan_ssl(self, port: int) -> SSLResult:
        self.logger.info(f"Scanning SSL/TLS on {self.target}:{port}")
        result = SSLResult(domain=self.target, port=port)
        
        try:
            context = ssl.create_default_context(cafile=certifi.where())
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            loop = asyncio.get_event_loop()
            
            def sync_connect():
                sock = socket.create_connection((self.target, port), timeout=self.timeout)
                ssl_sock = context.wrap_socket(sock, server_hostname=self.target)
                
                result.ssl_version = ssl_sock.version()
                result.cipher = ssl_sock.cipher()[0] if ssl_sock.cipher() else None
                
                cert = ssl_sock.getpeercert()
                if cert:
                    result.is_valid = True
                    result.certificate_info = {
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'version': cert.get('version'),
                        'serialNumber': cert.get('serialNumber'),
                        'notBefore': cert.get('notBefore'),
                        'notAfter': cert.get('notAfter')
                    }
                    
                    not_after = cert.get('notAfter')
                    if not_after:
                        from datetime import datetime, timedelta
                        try:
                            expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                            days_until_expiry = (expiry - datetime.now()).days
                            if days_until_expiry < 30:
                                result.expires_soon = True
                                result.vulnerabilities.append(f"Certificate expires in {days_until_expiry} days")
                        except:
                            pass
                
                if result.cipher:
                    weak_ciphers = ['RC4', 'DES', 'MD5', 'NULL']
                    if any(weak in result.cipher for weak in weak_ciphers):
                        result.vulnerabilities.append(f"Weak cipher: {result.cipher}")
                
                if result.ssl_version:
                    old_versions = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']
                    if result.ssl_version in old_versions:
                        result.vulnerabilities.append(f"Old SSL/TLS version: {result.ssl_version}")
                
                ssl_sock.close()
                return result
            
            result = await loop.run_in_executor(None, sync_connect)
            
            self.logger.info(f"SSL/TLS {result.ssl_version} with {result.cipher}")
            if result.vulnerabilities:
                self.logger.warning(f"Vulnerabilities found: {', '.join(result.vulnerabilities)}")
            
        except ssl.SSLError as e:
            result.vulnerabilities.append(f"SSL Error: {str(e)}")
            self.logger.error(f"SSL Error on port {port}: {str(e)}")
        except socket.timeout:
            result.vulnerabilities.append("Connection timeout")
            self.logger.error(f"Timeout on port {port}")
        except Exception as e:
            result.vulnerabilities.append(f"Error: {str(e)}")
            self.logger.error(f"Error scanning port {port}: {str(e)}")
        
        return result
    
    async def scan_all_ports(self):
        self.logger.info(f"Starting SSL/TLS scan on {self.target}")
        tasks = [self.scan_ssl(port) for port in self.ports]
        self.results = await asyncio.gather(*tasks)
    
    def get_results(self) -> Dict:
        return {
            'target': self.target,
            'scan_date': time.strftime('%Y-%m-%d %H:%M:%S'),
            'results': [
                {
                    'port': r.port,
                    'ssl_version': r.ssl_version,
                    'cipher': r.cipher,
                    'is_valid': r.is_valid,
                    'expires_soon': r.expires_soon,
                    'certificate': r.certificate_info,
                    'vulnerabilities': r.vulnerabilities
                }
                for r in self.results if r.is_valid or r.vulnerabilities
            ]
        }

async def run(target: str, progress_manager):
    scanner = AdvancedSSLScanner(target=target, ports=[443, 8443, 9443], timeout=10)
    await scanner.scan_all_ports()
    
    timestamp = time.strftime('%Y%m%d_%H%M%S')
    output_dir = f"results/{target}"
    
    import os
    os.makedirs(output_dir, exist_ok=True)
    
    import json
    results = scanner.get_results()
    with open(f"{output_dir}/ssl_scan_{timestamp}.json", 'w') as f:
        json.dump(results, f, indent=2)
    
    return results