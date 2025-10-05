import asyncio
import aiohttp
from aiohttp import ClientSession, ClientTimeout, TCPConnector
from typing import List, Set, Dict, Optional
import dns.resolver
import logging
from dataclasses import dataclass, field
from collections import defaultdict
import time
import hashlib
import json

@dataclass
class SubdomainResult:
    subdomain: str
    ip_addresses: List[str]
    status_code: Optional[int] = None
    title: Optional[str] = None
    server: Optional[str] = None
    technologies: List[str] = field(default_factory=list)
    cdn: Optional[str] = None
    response_time: float = 0.0
    source: str = "active"
    content_length: int = 0

class AdvancedSubdomainEnumerator:
    def __init__(self, target: str, wordlist: Optional[List[str]] = None, mode: str = 'hybrid',
                 concurrency: int = 50, timeout: int = 5, wildcard_detection: bool = True):
        self.target = target.lower().strip()
        self.wordlist = wordlist or self._get_default_wordlist()
        self.mode = mode
        self.concurrency = concurrency
        self.timeout = timeout
        self.wildcard_detection = wildcard_detection
        self.subdomains: Dict[str, SubdomainResult] = {}
        self.semaphore = asyncio.Semaphore(concurrency)
        self.logger = self._setup_logger()
        self.dns_resolvers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1']
        self.resolver = self._setup_dns_resolver()
        self.wildcard_ips: Set[str] = set()
        self.stats = {'total_checked': 0, 'found': 0, 'active_scan': 0, 'passive_scan': 0, 
                     'filtered_wildcards': 0, 'dns_errors': 0}
    
    def _setup_logger(self) -> logging.Logger:
        logger = logging.getLogger('SubdomainEnumerator')
        logger.setLevel(logging.INFO)
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        return logger
    
    def _setup_dns_resolver(self) -> dns.resolver.Resolver:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = self.dns_resolvers
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout * 2
        return resolver
    
    def _get_default_wordlist(self) -> List[str]:
        return ['www', 'mail', 'ftp', 'smtp', 'pop', 'webmail', 'ns1', 'ns2', 'cpanel', 'admin',
                'dev', 'staging', 'test', 'api', 'mobile', 'm', 'cdn', 'static', 'db', 'monitor',
                'secure', 'vpn', 'portal', 'blog', 'shop', 'git', 'cloud']
    
    async def detect_wildcard(self):
        if not self.wildcard_detection:
            return
        self.logger.info("Detecting wildcard DNS...")
        random_tests = []
        for i in range(5):
            random_hash = hashlib.md5(f"{time.time()}{i}".encode()).hexdigest()[:12]
            random_tests.append(f"{random_hash}.{self.target}")
        wildcard_responses = []
        for test_subdomain in random_tests:
            ips = await self._resolve_dns(test_subdomain)
            if ips:
                wildcard_responses.append(set(ips))
        if len(wildcard_responses) >= 3:
            ip_counts = defaultdict(int)
            for ip_set in wildcard_responses:
                for ip in ip_set:
                    ip_counts[ip] += 1
            for ip, count in ip_counts.items():
                if count >= 3:
                    self.wildcard_ips.add(ip)
            if self.wildcard_ips:
                self.logger.warning(f"Wildcard DNS detected: {', '.join(self.wildcard_ips)}")
    
    async def _resolve_dns(self, domain: str) -> List[str]:
        ips = []
        try:
            answers = self.resolver.resolve(domain, 'A')
            ips.extend([str(rdata) for rdata in answers])
        except:
            pass
        return list(set(ips))
    
    async def _check_http(self, session: ClientSession, subdomain: str, ips: List[str]) -> SubdomainResult:
        start_time = time.time()
        for protocol in ['https', 'http']:
            try:
                url = f"{protocol}://{subdomain}"
                async with session.get(url, ssl=False, allow_redirects=True,
                                     timeout=aiohttp.ClientTimeout(total=self.timeout)) as response:
                    response_time = time.time() - start_time
                    content = await response.read()
                    title = None
                    try:
                        import re
                        title_match = re.search(b'<title[^>]*>(.*?)</title>', content, re.IGNORECASE)
                        if title_match:
                            title = title_match.group(1).decode('utf-8', errors='ignore').strip()[:200]
                    except:
                        pass
                    return SubdomainResult(subdomain=subdomain, ip_addresses=ips, status_code=response.status,
                                         title=title, server=response.headers.get('Server'),
                                         response_time=response_time, content_length=len(content))
            except:
                continue
        return SubdomainResult(subdomain=subdomain, ip_addresses=ips, response_time=time.time() - start_time)
    
    async def active_enumeration(self, session: ClientSession):
        self.logger.info(f"Starting active enumeration with {len(self.wordlist)} words...")
        
        async def check_subdomain(word: str):
            subdomain = f"{word}.{self.target}"
            async with self.semaphore:
                self.stats['total_checked'] += 1
                if self.stats['total_checked'] % 100 == 0:
                    self.logger.info(f"Progress: {self.stats['total_checked']}/{len(self.wordlist)}")
                ips = await self._resolve_dns(subdomain)
                if not ips:
                    return
                if self.wildcard_ips and set(ips).issubset(self.wildcard_ips):
                    self.stats['filtered_wildcards'] += 1
                    return
                result = await self._check_http(session, subdomain, ips)
                result.source = "active"
                self.subdomains[subdomain] = result
                self.stats['found'] += 1
                self.stats['active_scan'] += 1
                log_msg = f"[FOUND] {subdomain} -> {', '.join(ips)}"
                if result.status_code:
                    log_msg += f" [{result.status_code}]"
                self.logger.info(log_msg)
        
        batch_size = self.concurrency * 2
        for i in range(0, len(self.wordlist), batch_size):
            batch = self.wordlist[i:i + batch_size]
            tasks = [check_subdomain(word) for word in batch]
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def passive_enumeration(self):
        self.logger.info("Starting passive enumeration...")
        sources = [('crt.sh', self._query_crtsh)]
        all_found = set()
        for source_name, source_func in sources:
            try:
                self.logger.info(f"Querying {source_name}...")
                results = await source_func()
                all_found.update(results)
            except:
                pass
        if all_found:
            await self._verify_passive_results(all_found)
    
    async def _verify_passive_results(self, subdomains: Set[str]):
        connector = TCPConnector(limit=self.concurrency, ssl=False)
        timeout = ClientTimeout(total=self.timeout)
        async with ClientSession(connector=connector, timeout=timeout) as session:
            async def verify_subdomain(subdomain: str):
                if subdomain in self.subdomains:
                    return
                async with self.semaphore:
                    ips = await self._resolve_dns(subdomain)
                    if ips and not (self.wildcard_ips and set(ips).issubset(self.wildcard_ips)):
                        result = await self._check_http(session, subdomain, ips)
                        result.source = "passive"
                        self.subdomains[subdomain] = result
                        self.stats['found'] += 1
                        self.stats['passive_scan'] += 1
                        self.logger.info(f"[PASSIVE] {subdomain} -> {', '.join(ips)}")
            subdomain_list = list(subdomains)
            batch_size = self.concurrency * 2
            for i in range(0, len(subdomain_list), batch_size):
                batch = subdomain_list[i:i + batch_size]
                tasks = [verify_subdomain(sub) for sub in batch]
                await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _query_crtsh(self) -> Set[str]:
        url = f"https://crt.sh/?q=%.{self.target}&output=json"
        subdomains = set()
        try:
            async with ClientSession(timeout=ClientTimeout(total=30)) as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        for entry in data:
                            name_value = entry.get('name_value', '')
                            for name in name_value.split('\n'):
                                name = name.strip().lower()
                                if name.endswith(self.target) and '*' not in name:
                                    subdomains.add(name)
        except:
            pass
        return subdomains
    
    async def run(self):
        start_time = time.time()
        self.logger.info(f"Starting subdomain enumeration for: {self.target}")
        await self.detect_wildcard()
        connector = TCPConnector(limit=self.concurrency, ssl=False)
        timeout = ClientTimeout(total=self.timeout)
        async with ClientSession(connector=connector, timeout=timeout) as session:
            if self.mode in ['active', 'hybrid']:
                await self.active_enumeration(session)
            if self.mode in ['passive', 'hybrid']:
                await self.passive_enumeration()
        elapsed = time.time() - start_time
        self.logger.info(f"\nCompleted in {elapsed:.2f}s")
        self.logger.info(f"Total subdomains found: {self.stats['found']}")
    
    def get_results(self) -> Dict:
        alive = [s for s, r in self.subdomains.items() if r.status_code]
        return {
            'target': self.target,
            'statistics': {'total_found': self.stats['found'], 'alive': len(alive)},
            'subdomains': {s: {'ips': r.ip_addresses, 'status': r.status_code, 'title': r.title}
                          for s, r in sorted(self.subdomains.items())}
        }
    
    def export_results(self, filename: str, format: str = 'json'):
        results = self.get_results()
        if format == 'json':
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2)
        self.logger.info(f"Results exported to {filename}")

async def run(target: str, mode: str, progress_manager):
    enumerator = AdvancedSubdomainEnumerator(target=target, mode=mode)
    await enumerator.run()
    timestamp = time.strftime('%Y%m%d_%H%M%S')
    import os
    output_dir = f"results/{target}"
    os.makedirs(output_dir, exist_ok=True)
    enumerator.export_results(f"{output_dir}/subdomains_{timestamp}.json", 'json')
    return enumerator.get_results()