import asyncio
import aiohttp
from aiohttp import ClientSession, ClientTimeout, TCPConnector
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import logging
from typing import Set, Dict, List, Optional
from dataclasses import dataclass, field
from collections import defaultdict
import re
import json
import time
from .evasion import EvasionTechniques

@dataclass
class CrawlResult:
    url: str
    status_code: int
    title: Optional[str] = None
    forms: List[Dict] = field(default_factory=list)
    links: List[str] = field(default_factory=list)
    inputs: List[Dict] = field(default_factory=list)
    comments: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    phone_numbers: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    hidden_params: List[str] = field(default_factory=list)
    cookies: Dict = field(default_factory=dict)
    headers: Dict = field(default_factory=dict)
    technologies: List[str] = field(default_factory=list)

class AdvancedWebCrawler:
    
    def __init__(self, target: str, max_depth: int = 3, concurrency: int = 10, 
                 timeout: int = 15, use_evasion: bool = True):
        self.target = target.rstrip('/')
        self.max_depth = max_depth
        self.concurrency = concurrency
        self.timeout = timeout
        self.use_evasion = use_evasion
        
        self.visited_urls: Set[str] = set()
        self.results: Dict[str, CrawlResult] = {}
        self.semaphore = asyncio.Semaphore(concurrency)
        self.logger = self._setup_logger()
        self.evasion = EvasionTechniques() if use_evasion else None
        
        self.session_cookies = {}
        
        self.patterns = {
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'phone': r'\b(?:\+?1[-.]?)?\(?([0-9]{3})\)?[-.]?([0-9]{3})[-.]?([0-9]{4})\b',
            'api_endpoint': r'(?:api|/v\d+)/[a-zA-Z0-9_\-/]+',
            'hidden_param': r'[?&]([a-zA-Z0-9_]+)=',
            'aws_key': r'AKIA[0-9A-Z]{16}',
            'api_key': r'(?i)api[_-]?key["\']?\s*[:=]\s*["\']([^"\']{20,})["\']',
            'jwt': r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
        }
        
        self.tech_signatures = {
            'WordPress': ['/wp-content/', '/wp-includes/', '/wp-admin/'],
            'Drupal': ['/sites/default/', '/modules/', '/themes/'],
            'Joomla': ['/components/', '/modules/', '/templates/'],
            'Laravel': ['laravel_session', 'XSRF-TOKEN'],
            'Django': ['csrftoken', 'sessionid'],
            'React': ['react', 'react-dom'],
            'Vue.js': ['vue', 'vuejs'],
            'Angular': ['ng-version', 'angular'],
            'jQuery': ['jquery'],
            'Bootstrap': ['bootstrap'],
        }
    
    def _setup_logger(self) -> logging.Logger:
        logger = logging.getLogger('AdvancedCrawler')
        logger.setLevel(logging.INFO)
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        return logger
    
    def _is_same_domain(self, url: str) -> bool:

        try:
            parsed = urlparse(url)
            target_parsed = urlparse(self.target)
            return parsed.netloc == target_parsed.netloc or parsed.netloc.endswith(f'.{target_parsed.netloc}')
        except:
            return False
    
    def _extract_forms(self, soup: BeautifulSoup, base_url: str) -> List[Dict]:

        forms = []
        for form in soup.find_all('form'):
            form_data = {
                'action': urljoin(base_url, form.get('action', '')),
                'method': form.get('method', 'get').upper(),
                'inputs': []
            }
            
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'type': input_tag.get('type', 'text'),
                    'name': input_tag.get('name'),
                    'value': input_tag.get('value', ''),
                    'required': input_tag.has_attr('required')
                }
                form_data['inputs'].append(input_data)
            
            forms.append(form_data)
        
        return forms
    
    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:

        links = set()
        
        for tag in soup.find_all(['a', 'link'], href=True):
            href = tag.get('href')
            if href:
                full_url = urljoin(base_url, href)
                if self._is_same_domain(full_url):
                    links.add(full_url.split('#')[0])
        
        for script in soup.find_all('script', src=True):
            src = script.get('src')
            if src:
                full_url = urljoin(base_url, src)
                if self._is_same_domain(full_url):
                    links.add(full_url)
        
        return list(links)
    
    def _extract_comments(self, soup: BeautifulSoup) -> List[str]:

        comments = []
        for comment in soup.find_all(string=lambda text: isinstance(text, str) and text.strip().startswith('<!--')):
            comments.append(comment.strip())
        return comments
    
    def _extract_patterns(self, content: str, pattern_name: str) -> List[str]:

        pattern = self.patterns.get(pattern_name)
        if pattern:
            matches = re.findall(pattern, content)
            return list(set(matches)) if matches else []
        return []
    
    def _detect_technologies(self, soup: BeautifulSoup, headers: Dict, content: str) -> List[str]:

        detected = set()
        
        content_lower = content.lower()
        for tech, signatures in self.tech_signatures.items():
            if any(sig.lower() in content_lower for sig in signatures):
                detected.add(tech)
        
        server = headers.get('Server', '')
        if 'nginx' in server.lower():
            detected.add('Nginx')
        elif 'apache' in server.lower():
            detected.add('Apache')
        elif 'cloudflare' in server.lower():
            detected.add('Cloudflare')
        
        powered_by = headers.get('X-Powered-By', '')
        if powered_by:
            detected.add(powered_by)
        
        return list(detected)
    
    async def fetch_url(self, session: ClientSession, url: str, depth: int = 0) -> Optional[CrawlResult]:

        if url in self.visited_urls or depth > self.max_depth:
            return None
        
        self.visited_urls.add(url)
        
        try:
            async with self.semaphore:
                if self.evasion and self.use_evasion:
                    self.evasion.add_random_delay(0.5, 2.0)
                    headers = self.evasion.get_random_headers(urlparse(self.target).netloc)
                    url = self.evasion.add_cache_buster(url)
                else:
                    headers = {'User-Agent': 'Mozilla/5.0'}
                
                async with session.get(url, headers=headers, ssl=False, allow_redirects=True) as response:
                    content = await response.text()
                    soup = BeautifulSoup(content, 'html.parser')
                    
                    title = soup.find('title')
                    title_text = title.string.strip() if title and title.string else None
                    
                    forms = self._extract_forms(soup, url)
                    links = self._extract_links(soup, url)
                    comments = self._extract_comments(soup)
                    
                    emails = self._extract_patterns(content, 'email')
                    phones = self._extract_patterns(content, 'phone')
                    api_endpoints = self._extract_patterns(content, 'api_endpoint')
                    hidden_params = self._extract_patterns(url, 'hidden_param')
                    
                    inputs = []
                    for input_tag in soup.find_all(['input', 'textarea']):
                        inputs.append({
                            'type': input_tag.get('type', 'text'),
                            'name': input_tag.get('name'),
                            'id': input_tag.get('id'),
                            'placeholder': input_tag.get('placeholder')
                        })
                    
                    technologies = self._detect_technologies(soup, dict(response.headers), content)
                    
                    result = CrawlResult(
                        url=url,
                        status_code=response.status,
                        title=title_text,
                        forms=forms,
                        links=links,
                        inputs=inputs,
                        comments=comments,
                        emails=emails,
                        phone_numbers=phones,
                        api_endpoints=api_endpoints,
                        hidden_params=hidden_params,
                        cookies=dict(response.cookies),
                        headers=dict(response.headers),
                        technologies=technologies
                    )
                    
                    self.results[url] = result
                    self.logger.info(f"[{response.status}] Crawled: {url} (Depth: {depth})")
                    
                    if depth < self.max_depth:
                        for link in links[:10]:
                            if link not in self.visited_urls:
                                await self.fetch_url(session, link, depth + 1)
                    
                    return result
                    
        except Exception as e:
            self.logger.debug(f"Error crawling {url}: {str(e)}")
        
        return None
    
    async def crawl(self):

        self.logger.info(f"Starting advanced crawl on {self.target}")
        self.logger.info(f"Max depth: {self.max_depth}, Concurrency: {self.concurrency}")
        self.logger.info(f"Evasion techniques: {'Enabled' if self.use_evasion else 'Disabled'}")
        
        connector = TCPConnector(limit=self.concurrency, ssl=False)
        timeout = ClientTimeout(total=self.timeout)
        
        async with ClientSession(connector=connector, timeout=timeout) as session:
            await self.fetch_url(session, self.target, depth=0)
        
        self.logger.info(f"\nCrawl completed!")
        self.logger.info(f"Total URLs crawled: {len(self.visited_urls)}")
        self.logger.info(f"Forms found: {sum(len(r.forms) for r in self.results.values())}")
        self.logger.info(f"Emails found: {sum(len(r.emails) for r in self.results.values())}")
        self.logger.info(f"API endpoints found: {sum(len(r.api_endpoints) for r in self.results.values())}")
    
    def get_results(self) -> Dict:

        all_forms = []
        all_emails = set()
        all_phones = set()
        all_api_endpoints = set()
        all_technologies = set()
        all_hidden_params = set()
        
        for result in self.results.values():
            all_forms.extend(result.forms)
            all_emails.update(result.emails)
            all_phones.update(result.phone_numbers)
            all_api_endpoints.update(result.api_endpoints)
            all_technologies.update(result.technologies)
            all_hidden_params.update(result.hidden_params)
        
        return {
            'target': self.target,
            'scan_date': time.strftime('%Y-%m-%d %H:%M:%S'),
            'statistics': {
                'urls_crawled': len(self.visited_urls),
                'forms_found': len(all_forms),
                'emails_found': len(all_emails),
                'phones_found': len(all_phones),
                'api_endpoints': len(all_api_endpoints),
                'technologies': list(all_technologies),
                'hidden_params': list(all_hidden_params)
            },
            'forms': all_forms,
            'emails': list(all_emails),
            'phones': list(all_phones),
            'api_endpoints': list(all_api_endpoints),
            'technologies': list(all_technologies),
            'urls': list(self.visited_urls)
        }

async def run(target: str, progress_manager):

    crawler = AdvancedWebCrawler(
        target=target,
        max_depth=3,
        concurrency=10,
        timeout=15,
        use_evasion=True
    )
    
    await crawler.crawl()
    
    timestamp = time.strftime('%Y%m%d_%H%M%S')
    parsed_url = urlparse(target)
    output_dir = f"results/{parsed_url.netloc}"
    
    import os
    os.makedirs(output_dir, exist_ok=True)
    
    results = crawler.get_results()
    with open(f"{output_dir}/advanced_crawl_{timestamp}.json", 'w') as f:
        json.dump(results, f, indent=2)
    
    return results