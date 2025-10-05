from aiohttp import ClientSession, ClientTimeout, TCPConnector
from aiohttp.client_exceptions import ClientError, ServerTimeoutError
import asyncio
import logging
from dataclasses import dataclass, field
from typing import List, Set, Optional, Dict, Tuple
from urllib.parse import urljoin, urlparse, quote
from collections import defaultdict
import time
import re
import hashlib

@dataclass
class ScanResult:
    url: str
    status: int
    size: int
    words: int = 0
    lines: int = 0
    redirect: Optional[str] = None
    response_time: float = 0.0
    headers: Dict[str, str] = field(default_factory=dict)
    content_type: Optional[str] = None
    server: Optional[str] = None
    interesting: bool = False
    checksum: Optional[str] = None

class AdvancedDirectoryBruteforcer:
    def __init__(self, target: str, wordlist: List[str], concurrency: int = 50,
                 extensions: Optional[List[str]] = None, timeout: int = 10):
        self.target = target.rstrip('/')
        self.wordlist = wordlist
        self.concurrency = concurrency
        self.extensions = extensions or []
        self.timeout = timeout
        self.results: List[ScanResult] = []
        self.visited: Set[str] = set()
        self.semaphore = asyncio.Semaphore(concurrency)
        self.logger = self._setup_logger()
        self.stats = {
            'total_requests': 0,
            'successful': 0,
            'filtered': 0,
            'errors': 0,
            'start_time': time.time()
        }
    
    def _setup_logger(self) -> logging.Logger:
        logger = logging.getLogger('DirectoryBruteforcer')
        logger.setLevel(logging.INFO)
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        return logger

    async def fetch(self, session: ClientSession, url: str) -> Optional[ScanResult]:
        if url in self.visited:
            return None
        self.visited.add(url)
        
        try:
            async with self.semaphore:
                start_time = time.time()
                async with session.get(url, allow_redirects=False, ssl=False) as response:
                    response_time = time.time() - start_time
                    self.stats['total_requests'] += 1
                    
                    if response.status == 404:
                        return None
                    
                    content = await response.read()
                    result = ScanResult(
                        url=url,
                        status=response.status,
                        size=len(content),
                        response_time=response_time,
                        headers=dict(response.headers),
                        content_type=response.headers.get('Content-Type'),
                        server=response.headers.get('Server')
                    )
                    
                    self.stats['successful'] += 1
                    self.results.append(result)
                    self.logger.info(f"[{response.status}] {url} - {len(content)}B")
                    return result
                    
        except (ServerTimeoutError, asyncio.TimeoutError):
            self.stats['errors'] += 1
        except (ClientError, Exception) as e:
            self.stats['errors'] += 1
        return None

    async def scan(self):
        connector = TCPConnector(limit=self.concurrency, ssl=False)
        timeout = ClientTimeout(total=self.timeout)
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        
        async with ClientSession(connector=connector, timeout=timeout, headers=headers) as session:
            self.logger.info(f"Starting scan on {self.target}")
            self.logger.info(f"Wordlist: {len(self.wordlist)} entries")
            
            tasks = []
            for word in self.wordlist:
                url = urljoin(self.target, word.strip())
                tasks.append(self.fetch(session, url))
                
                if self.extensions:
                    for ext in self.extensions:
                        ext_url = f"{url}.{ext.lstrip('.')}"
                        tasks.append(self.fetch(session, ext_url))
            
            await asyncio.gather(*tasks, return_exceptions=True)
            
            elapsed = time.time() - self.stats['start_time']
            self.logger.info(f"\nScan completed in {elapsed:.2f}s")
            self.logger.info(f"Found: {len(self.results)} endpoints")

def load_wordlist(file_path: str) -> List[str]:
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        raise FileNotFoundError(f"Wordlist not found: {file_path}")

async def run(target: str, wordlist: Optional[str], progress_manager):
    if wordlist:
        wordlist_data = load_wordlist(wordlist)
    else:
        wordlist_data = ['admin', 'login', 'api', 'backup', 'config', 'test', 'dev']
    
    scanner = AdvancedDirectoryBruteforcer(
        target=target,
        wordlist=wordlist_data,
        concurrency=50,
        extensions=['php', 'html', 'txt'],
        timeout=10
    )
    
    await scanner.scan()
    
    timestamp = time.strftime('%Y%m%d_%H%M%S')
    parsed_url = urlparse(target)
    output_dir = f"results/{parsed_url.netloc}"
    
    import os
    os.makedirs(output_dir, exist_ok=True)
    
    import json
    with open(f"{output_dir}/directories_{timestamp}.json", 'w') as f:
        json.dump({
            'target': target,
            'results': [{'url': r.url, 'status': r.status, 'size': r.size} for r in scanner.results]
        }, f, indent=2)
    
    return scanner.results