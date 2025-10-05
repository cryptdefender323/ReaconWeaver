import asyncio
import socket
from typing import List, Dict, Optional
from dataclasses import dataclass, field
import logging
import time
import re
from enum import Enum

class ScanTechnique(Enum):
    TCP_CONNECT = "tcp_connect"
    TCP_SYN = "tcp_syn"
    UDP = "udp"
    SERVICE_DETECTION = "service_detection"

@dataclass
class PortResult:
    port: int
    state: str
    service: str
    version: Optional[str] = None
    banner: Optional[str] = None
    protocol: str = "tcp"
    response_time: float = 0.0
    cpe: Optional[str] = None
    vulnerabilities: List[str] = field(default_factory=list)
    ssl_info: Optional[Dict] = None

@dataclass
class ServiceProbe:
    name: str
    probe_data: bytes
    patterns: List[tuple]
    ports: List[int]
    ssl: bool = False

class AdvancedPortScanner:
    def __init__(self, target: str, ports: Optional[List[int]] = None, port_range: str = "common",
                 concurrency: int = 100, timeout: float = 2.0, scan_technique: ScanTechnique = ScanTechnique.TCP_CONNECT,
                 service_detection: bool = True, banner_grabbing: bool = True, os_detection: bool = False, aggressive: bool = False):
        self.target = target
        self.port_range = port_range
        self.ports = ports or self._parse_port_range(port_range)
        self.concurrency = concurrency
        self.timeout = timeout
        self.scan_technique = scan_technique
        self.service_detection = service_detection
        self.banner_grabbing = banner_grabbing
        self.os_detection = os_detection
        self.aggressive = aggressive
        self.results: Dict[int, PortResult] = {}
        self.semaphore = asyncio.Semaphore(concurrency)
        self.logger = self._setup_logger()
        self.service_probes = self._load_service_probes()
        self.stats = {'open': 0, 'closed': 0, 'filtered': 0, 'errors': 0, 'total_scanned': 0, 'start_time': time.time()}
        self.common_services = self._load_common_services()
    
    def _setup_logger(self) -> logging.Logger:
        logger = logging.getLogger('AdvancedPortScanner')
        logger.setLevel(logging.INFO)
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        return logger
    
    def _parse_port_range(self, port_range: str) -> List[int]:
        if port_range == "common":
            return self._get_common_ports()
        elif port_range == "all":
            return list(range(1, 65536))
        elif port_range == "top100":
            return self._get_top_100_ports()
        elif port_range == "top1000":
            return self._get_top_1000_ports()
        elif "-" in port_range:
            start, end = map(int, port_range.split("-"))
            return list(range(start, end + 1))
        elif "," in port_range:
            return [int(p.strip()) for p in port_range.split(",")]
        else:
            return [int(port_range)]
    
    def _get_common_ports(self) -> List[int]:
        return [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
                993, 995, 1433, 1521, 1723, 3306, 3389, 5432, 5900, 6379, 8000, 8080,
                8443, 8888, 9000, 9200, 9300, 27017, 27018, 50000]
    
    def _get_top_100_ports(self) -> List[int]:
        return [7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
                113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465,
                513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995,
                1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000,
                2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009,
                5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001,
                6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000,
                32768, 49152, 49153, 49154, 49155, 49156, 49157]
    
    def _get_top_1000_ports(self) -> List[int]:
        base_ports = self._get_top_100_ports()
        additional = list(range(8000, 8100)) + list(range(9000, 9100))
        return sorted(list(set(base_ports + additional)))
    
    def _load_common_services(self) -> Dict[int, Dict]:
        return {
            20: {'name': 'ftp-data', 'protocol': 'tcp'},
            21: {'name': 'ftp', 'protocol': 'tcp', 'probes': [b'USER anonymous\r\n', b'HELP\r\n']},
            22: {'name': 'ssh', 'protocol': 'tcp'},
            23: {'name': 'telnet', 'protocol': 'tcp'},
            25: {'name': 'smtp', 'protocol': 'tcp', 'probes': [b'EHLO scanner\r\n']},
            53: {'name': 'dns', 'protocol': 'udp'},
            80: {'name': 'http', 'protocol': 'tcp', 'probes': [b'GET / HTTP/1.0\r\n\r\n']},
            110: {'name': 'pop3', 'protocol': 'tcp', 'probes': [b'USER test\r\n']},
            111: {'name': 'rpcbind', 'protocol': 'tcp'},
            135: {'name': 'msrpc', 'protocol': 'tcp'},
            139: {'name': 'netbios-ssn', 'protocol': 'tcp'},
            143: {'name': 'imap', 'protocol': 'tcp', 'probes': [b'A1 CAPABILITY\r\n']},
            443: {'name': 'https', 'protocol': 'tcp'},
            445: {'name': 'microsoft-ds', 'protocol': 'tcp'},
            465: {'name': 'smtps', 'protocol': 'tcp'},
            587: {'name': 'submission', 'protocol': 'tcp'},
            993: {'name': 'imaps', 'protocol': 'tcp'},
            995: {'name': 'pop3s', 'protocol': 'tcp'},
            1433: {'name': 'ms-sql-s', 'protocol': 'tcp'},
            1521: {'name': 'oracle', 'protocol': 'tcp'},
            1723: {'name': 'pptp', 'protocol': 'tcp'},
            3306: {'name': 'mysql', 'protocol': 'tcp'},
            3389: {'name': 'ms-wbt-server', 'protocol': 'tcp'},
            5432: {'name': 'postgresql', 'protocol': 'tcp'},
            5900: {'name': 'vnc', 'protocol': 'tcp'},
            6379: {'name': 'redis', 'protocol': 'tcp', 'probes': [b'PING\r\n', b'INFO\r\n']},
            8000: {'name': 'http-alt', 'protocol': 'tcp'},
            8080: {'name': 'http-proxy', 'protocol': 'tcp'},
            8443: {'name': 'https-alt', 'protocol': 'tcp'},
            9200: {'name': 'elasticsearch', 'protocol': 'tcp', 'probes': [b'GET / HTTP/1.0\r\n\r\n']},
            9300: {'name': 'elasticsearch-transport', 'protocol': 'tcp'},
            27017: {'name': 'mongodb', 'protocol': 'tcp'},
            27018: {'name': 'mongodb-shard', 'protocol': 'tcp'},
        }
    
    def _load_service_probes(self) -> List[ServiceProbe]:
        return [
            ServiceProbe(name='SSH', probe_data=b'', 
                        patterns=[(re.compile(rb'SSH-(\d\.\d+)-(.+)'), 'SSH'),
                                 (re.compile(rb'OpenSSH[_-](\S+)'), 'OpenSSH')], ports=[22]),
            ServiceProbe(name='HTTP', probe_data=b'GET / HTTP/1.0\r\nHost: %s\r\n\r\n',
                        patterns=[(re.compile(rb'Server:\s*(.+)'), 'HTTP Server'),
                                 (re.compile(rb'Apache/(\d+\.\d+\.\d+)'), 'Apache'),
                                 (re.compile(rb'nginx/(\d+\.\d+\.\d+)'), 'nginx')], ports=[80, 8000, 8080]),
            ServiceProbe(name='FTP', probe_data=b'HELP\r\n',
                        patterns=[(re.compile(rb'220.*ProFTPD\s+(\S+)'), 'ProFTPD')], ports=[21]),
            ServiceProbe(name='MySQL', probe_data=b'',
                        patterns=[(re.compile(rb'\x00\x00\x00\x0a(\d+\.\d+\.\d+)'), 'MySQL')], ports=[3306]),
            ServiceProbe(name='Redis', probe_data=b'PING\r\n',
                        patterns=[(re.compile(rb'\+PONG'), 'Redis')], ports=[6379])
        ]
    
    async def tcp_connect_scan(self, port: int) -> PortResult:
        start_time = time.time()
        try:
            async with self.semaphore:
                conn = asyncio.open_connection(self.target, port)
                reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
                response_time = time.time() - start_time
                service = self._get_service_name(port)
                version = None
                banner = None
                ssl_info = None
                if self.banner_grabbing:
                    banner = await self._grab_banner(reader, writer, port)
                if self.service_detection:
                    version = await self._detect_service_version(reader, writer, port, banner)
                writer.close()
                await writer.wait_closed()
                result = PortResult(port=port, state="open", service=service, version=version,
                                  banner=banner[:200] if banner else None, protocol="tcp",
                                  response_time=response_time, ssl_info=ssl_info)
                self.stats['open'] += 1
                log_msg = f"[OPEN] {port}/tcp - {service}"
                if version:
                    log_msg += f" ({version})"
                self.logger.info(log_msg)
                return result
        except asyncio.TimeoutError:
            self.stats['filtered'] += 1
            return PortResult(port=port, state="filtered", service="unknown")
        except (ConnectionRefusedError, OSError):
            self.stats['closed'] += 1
            return PortResult(port=port, state="closed", service="unknown")
        except Exception as e:
            self.stats['errors'] += 1
            return PortResult(port=port, state="error", service="unknown")
    
    async def _grab_banner(self, reader, writer, port: int) -> Optional[str]:
        try:
            service_info = self.common_services.get(port, {})
            probes = service_info.get('probes', [])
            banner_data = b''
            try:
                initial_data = await asyncio.wait_for(reader.read(2048), timeout=1.0)
                if initial_data:
                    banner_data += initial_data
            except asyncio.TimeoutError:
                pass
            if not banner_data and probes:
                for probe in probes:
                    try:
                        writer.write(probe)
                        await writer.drain()
                        response = await asyncio.wait_for(reader.read(2048), timeout=1.5)
                        if response:
                            banner_data += response
                            break
                    except:
                        continue
            if banner_data:
                return banner_data.decode('utf-8', errors='ignore').strip()
        except:
            pass
        return None
    
    async def _detect_service_version(self, reader, writer, port: int, banner: Optional[str]) -> Optional[str]:
        if banner:
            for probe in self.service_probes:
                if port in probe.ports:
                    for pattern, service_type in probe.patterns:
                        match = pattern.search(banner.encode())
                        if match:
                            try:
                                version = match.group(1).decode('utf-8', errors='ignore')
                                return f"{service_type} {version}"
                            except:
                                return service_type
        return None
    
    def _get_service_name(self, port: int) -> str:
        if port in self.common_services:
            return self.common_services[port]['name']
        try:
            return socket.getservbyport(port)
        except OSError:
            return "unknown"
    
    async def scan_ports(self):
        self.logger.info(f"Starting port scan on {self.target}")
        self.logger.info(f"Scanning {len(self.ports)} ports")
        sorted_ports = sorted(self.ports)
        batch_size = self.concurrency * 2
        for i in range(0, len(sorted_ports), batch_size):
            batch = sorted_ports[i:i + batch_size]
            tasks = [self.tcp_connect_scan(port) for port in batch]
            self.stats['total_scanned'] += len(batch)
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, PortResult):
                    self.results[result.port] = result
    
    def get_open_ports(self) -> List[PortResult]:
        return sorted([r for r in self.results.values() if r.state == "open"], key=lambda x: x.port)
    
    def get_statistics(self) -> Dict:
        elapsed = time.time() - self.stats['start_time']
        return {
            'target': self.target,
            'elapsed_time': round(elapsed, 2),
            'total_ports_scanned': self.stats['total_scanned'],
            'open_ports': self.stats['open'],
            'closed_ports': self.stats['closed']
        }
    
    def export_results(self, filename: str, format: str = 'json'):
        import json
        stats = self.get_statistics()
        open_ports = self.get_open_ports()
        if format == 'json':
            output = {'statistics': stats, 'open_ports': [{'port': r.port, 'state': r.state,
                     'service': r.service, 'version': r.version, 'banner': r.banner} for r in open_ports]}
            with open(filename, 'w') as f:
                json.dump(output, f, indent=2)
        self.logger.info(f"Results exported to {filename}")

async def run(target: str, ports: Optional[str], progress_manager):
    scanner = AdvancedPortScanner(target=target, port_range=ports or "common")
    await scanner.scan_ports()
    timestamp = time.strftime('%Y%m%d_%H%M%S')
    import os
    output_dir = f"results/{target}"
    os.makedirs(output_dir, exist_ok=True)
    scanner.export_results(f"{output_dir}/ports_{timestamp}.json", 'json')
    return scanner.get_statistics()