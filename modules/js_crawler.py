from aiohttp import ClientSession, ClientTimeout, TCPConnector
import asyncio
import re
import json
from typing import Set, Dict, List, Optional
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import logging
from dataclasses import dataclass
from collections import defaultdict
import time

@dataclass
class JSEndpoint:
    url: str
    endpoint_type: str
    method: Optional[str] = None
    source_file: str = None

class AdvancedJSCrawler:
    def __init__(self, target: str, max_depth: int = 3, concurrency: int = 20, timeout: int = 15):
        self.target = target.rstrip('/')
        self.max_depth = max_depth
        self.concurrency = concurrency
        self.timeout = timeout
        self.visited_js: Set[str] = set()
        self.endpoints: Dict[str, JSEndpoint] = {}
        self.secrets: Dict[str, List[str]] = defaultdict(list)
        self.semaphore = asyncio.Semaphore(concurrency)
        self.logger = self._setup_logger()
        
        self.patterns = {
            'api_endpoints': [
                r'["\']([/][a-zA-Z0-9_\-/{}:]+)["\']',
                r'["\']https?://[^"\']+/api[^"\']*["\']',
                r'fetch\(["\']([^"\']+)["\']'
            ],
            'secrets': {
                'api_key': r'(?i)api[_-]?key["\']?\s*[:=]\s*["\']([^"\']{20,})["\']',
                'aws_key': r'AKIA[0-9A-Z]{16}',
                'jwt': r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
            }
        }
    
    def _setup_logger(self) -> logging.Logger:
        logger = logging.getLogger('JSCrawler')
        logger.setLevel(logging.INFO)
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        return logger
    
    def _extract_endpoints(self, content: str, source: str):
        for pattern in self.patterns['api_endpoints']:
            matches = re.findall(pattern, content, re.MULTILINE | re.IGNORECASE)
            for match in matches:
                if not match or len(match) < 2:
                    continue
                if match.startswith('/'):
                    endpoint_url = urljoin(self.target, match)
                else:
                    endpoint_url = match
                endpoint = JSEndpoint(url=endpoint_url, endpoint_type='api', source_file=source)
                self.endpoints[endpoint_url] = endpoint
    
    def _extract_secrets(self, content: str, source: str):
        for secret_type, pattern in self.patterns['secrets'].items():
            matches = re.findall(pattern, content, re.MULTILINE)
            for match in matches:
                if match and len(match) > 10:
                    self.secrets[secret_type].append({'value': match[:50], 'source': source})
                    self.logger.warning(f"Potential {secret_type} found in {source}")
    
    async def fetch_js_file(self, session: ClientSession, url: str):
        if url in self.visited_js:
            return
        self.visited_js.add(url)
        
        try:
            async with self.semaphore:
                async with session.get(url) as response:
                    if response.status == 200:
                        js_content = await response.text()
                        self.logger.info(f"Analyzing: {url}")
                        self._extract_endpoints(js_content, url)
                        self._extract_secrets(js_content, url)
        except Exception as e:
            self.logger.debug(f"Error fetching JS {url}: {str(e)}")
    
    async def fetch_page(self, session: ClientSession, url: str) -> Optional[str]:
        try:
            async with self.semaphore:
                async with session.get(url) as response:
                    if response.status == 200:
                        html = await response.text()
                        soup = BeautifulSoup(html, 'html.parser')
                        for script in soup.find_all('script', src=True):
                            js_url = urljoin(url, script['src'])
                            await self.fetch_js_file(session, js_url)
                        return html
        except Exception as e:
            self.logger.debug(f"Error fetching page {url}: {str(e)}")
        return None
    
    async def crawl(self):
        connector = TCPConnector(limit=self.concurrency, ssl=False)
        timeout = ClientTimeout(total=self.timeout)
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        
        async with ClientSession(connector=connector, timeout=timeout, headers=headers) as session:
            await self.fetch_page(session, self.target)
    
    def get_results(self) -> Dict:
        return {
            'endpoints': {'total': len(self.endpoints), 'details': list(self.endpoints.values())},
            'secrets': dict(self.secrets),
            'statistics': {
                'js_files_analyzed': len(self.visited_js),
                'unique_endpoints': len(self.endpoints),
                'secrets_found': sum(len(v) for v in self.secrets.values())
            }
        }

async def run(target: str, progress_manager):
    crawler = AdvancedJSCrawler(target=target, max_depth=3, concurrency=20, timeout=15)
    await crawler.crawl()
    
    timestamp = time.strftime('%Y%m%d_%H%M%S')
    parsed_url = urlparse(target)
    output_dir = f"results/{parsed_url.netloc}"
    
    import os
    os.makedirs(output_dir, exist_ok=True)
    
    results = crawler.get_results()
    with open(f"{output_dir}/js_crawler_{timestamp}.json", 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    return results