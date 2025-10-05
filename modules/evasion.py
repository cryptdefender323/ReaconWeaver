import random
import time
from typing import Dict, List, Optional
from urllib.parse import quote, unquote
import string

class EvasionTechniques:


    def __init__(self):
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (Android 14; Mobile; rv:121.0) Gecko/121.0 Firefox/121.0'
        ]
        
        self.accept_languages = [
            'en-US,en;q=0.9',
            'en-GB,en;q=0.9',
            'en-US,en;q=0.9,id;q=0.8',
            'id-ID,id;q=0.9,en;q=0.8',
            'en-US,en;q=0.9,ja;q=0.8',
            'en-US,en;q=0.9,zh-CN;q=0.8'
        ]
        
        self.referers = [
            'https://www.google.com/',
            'https://www.bing.com/',
            'https://www.yahoo.com/',
            'https://duckduckgo.com/',
            'https://www.baidu.com/',
            'https://search.brave.com/'
        ]
    
    def get_random_headers(self, target: str = None) -> Dict[str, str]:

        headers = {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': random.choice(self.accept_languages),
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': str(random.choice([0, 1])),
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': random.choice(['document', 'empty', 'iframe']),
            'Sec-Fetch-Mode': random.choice(['navigate', 'cors', 'no-cors']),
            'Sec-Fetch-Site': random.choice(['same-origin', 'same-site', 'cross-site', 'none']),
            'Cache-Control': random.choice(['max-age=0', 'no-cache', 'no-store'])
        }
        
        if random.random() > 0.5:
            headers['Referer'] = random.choice(self.referers)
        
        if target and random.random() > 0.3:
            headers['Referer'] = f'https://{target}/'
        
        return headers
    
    def add_random_delay(self, min_delay: float = 0.5, max_delay: float = 3.0):

        base_delay = random.uniform(min_delay, max_delay)
        jitter = random.uniform(-0.2, 0.5)
        delay = max(0.1, base_delay + jitter)
        time.sleep(delay)
    
    def encode_payload(self, payload: str, encoding: str = 'url') -> str:

        if encoding == 'url':
            return quote(payload)
        elif encoding == 'double_url':
            return quote(quote(payload))
        elif encoding == 'unicode':
            return ''.join(f'\\u{ord(c):04x}' for c in payload)
        elif encoding == 'hex':
            return ''.join(f'%{ord(c):02x}' for c in payload)
        elif encoding == 'mixed':
            result = []
            for c in payload:
                method = random.choice(['normal', 'url', 'hex'])
                if method == 'url':
                    result.append(quote(c))
                elif method == 'hex':
                    result.append(f'%{ord(c):02x}')
                else:
                    result.append(c)
            return ''.join(result)
        return payload
    
    def bypass_waf_path(self, path: str) -> List[str]:

        variations = [path]
        
        if not path.startswith('/'):
            path = '/' + path
        
        variations.extend([
            path,
            f'//{path.lstrip("/")}',
            f'/./{path.lstrip("/")}',
            f'/{path.lstrip("/")}/.',
            f'/{path.lstrip("/")}/',
            path.replace('/', '/./'),
            path.replace('/', '//'),
            path + '%00',
            path + '%20',
            path + '%09',
            path.upper(),
            path.lower(),
            self.case_swap(path)
        ])
        
        if '?' in path:
            base, query = path.split('?', 1)
            variations.extend([
                f'{base};{query}',
                f'{base}?{query}#',
                f'{base}%3f{query}',
                f'{base}?{query}&random={random.randint(1000,9999)}'
            ])
        
        return list(set(variations))
    
    def case_swap(self, text: str) -> str:

        return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in text)
    
    def obfuscate_parameter(self, param: str, value: str) -> List[tuple]:

        variations = [
            (param, value),
            (param.upper(), value),
            (param + '[]', value),
            (f'{param}[0]', value),
            (f' {param}', value),
            (f'{param} ', value),
            (f'{param}\t', value),
            (f'{param}\n', value),
        ]
        
        return variations
    
    def generate_random_string(self, length: int = 8) -> str:

        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    
    def get_timing_pattern(self, pattern: str = 'human') -> float:

        if pattern == 'human':
            return random.gauss(2.0, 1.0)
        elif pattern == 'bot_slow':
            return random.uniform(0.5, 1.5)
        elif pattern == 'bot_fast':
            return random.uniform(0.1, 0.5)
        else:
            return 1.0
    
    def rotate_proxy_headers(self) -> Dict[str, str]:

        return {
            'X-Forwarded-For': f'{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}',
            'X-Real-IP': f'{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}',
            'X-Originating-IP': f'{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}',
            'X-Remote-IP': f'{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}',
            'X-Remote-Addr': f'{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}'
        }
    
    def http_verb_tampering(self, method: str = 'GET') -> List[str]:

        return [
            method,
            method.lower(),
            method.upper(),
            f'{method}\r\n',
            f'{method}\n',
            f' {method}',
            f'{method} '
        ]
    
    def split_payload(self, payload: str, chunk_size: int = 3) -> List[str]:

        return [payload[i:i+chunk_size] for i in range(0, len(payload), chunk_size)]
    
    def add_cache_buster(self, url: str) -> str:

        separator = '&' if '?' in url else '?'
        busters = [
            f'_={int(time.time() * 1000)}',
            f'rand={self.generate_random_string()}',
            f'cb={random.randint(10000, 99999)}',
            f't={int(time.time())}'
        ]
        return f'{url}{separator}{random.choice(busters)}'