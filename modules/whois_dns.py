import asyncio
import whois
import dns.resolver
import dns.reversename
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass, field
import time
from datetime import datetime
import json

@dataclass
class DNSRecord:
    record_type: str
    values: List[str]
    ttl: Optional[int] = None

@dataclass
class WHOISInfo:
    domain: str
    registrar: Optional[str] = None
    creation_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None
    updated_date: Optional[datetime] = None
    name_servers: List[str] = field(default_factory=list)
    status: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)

@dataclass
class DNSAnalysis:
    domain: str
    records: Dict[str, DNSRecord]
    reverse_dns: Dict[str, List[str]]
    dns_security: Dict[str, bool]
    name_servers: List[str]
    mail_servers: List[Dict]

class AdvancedWHOISandDNS:
    def __init__(self, domain: str, timeout: int = 10):
        self.domain = domain.lower().strip()
        self.timeout = timeout
        self.logger = self._setup_logger()
        self.resolvers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1']
        self.resolver = self._setup_dns_resolver()
    
    def _setup_logger(self) -> logging.Logger:
        logger = logging.getLogger('WHOISandDNS')
        logger.setLevel(logging.INFO)
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        return logger
    
    def _setup_dns_resolver(self) -> dns.resolver.Resolver:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = self.resolvers
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout * 2
        return resolver
    
    async def fetch_whois(self) -> WHOISInfo:
        self.logger.info(f"Fetching WHOIS data for {self.domain}...")
        try:
            whois_data = await asyncio.to_thread(whois.whois, self.domain)
            
            creation_date = whois_data.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            expiration_date = whois_data.expiration_date
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            
            updated_date = whois_data.updated_date
            if isinstance(updated_date, list):
                updated_date = updated_date[0]
            
            name_servers = whois_data.name_servers or []
            if isinstance(name_servers, str):
                name_servers = [name_servers]
            name_servers = [ns.lower() for ns in name_servers]
            
            status = whois_data.status or []
            if isinstance(status, str):
                status = [status]
            
            emails = []
            if whois_data.emails:
                if isinstance(whois_data.emails, str):
                    emails = [whois_data.emails]
                else:
                    emails = list(whois_data.emails)
            
            whois_info = WHOISInfo(
                domain=self.domain,
                registrar=whois_data.registrar,
                creation_date=creation_date,
                expiration_date=expiration_date,
                updated_date=updated_date,
                name_servers=name_servers,
                status=status,
                emails=emails
            )
            
            self.logger.info("WHOIS data retrieved successfully")
            return whois_info
        except Exception as e:
            self.logger.error(f"WHOIS lookup failed: {str(e)}")
            return WHOISInfo(domain=self.domain)
    
    async def fetch_dns_records(self) -> Dict[str, DNSRecord]:
        self.logger.info(f"Fetching DNS records for {self.domain}...")
        records = {}
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']
        
        for record_type in record_types:
            try:
                answers = self.resolver.resolve(self.domain, record_type)
                values = []
                ttl = None
                
                for rdata in answers:
                    if record_type == 'MX':
                        values.append(f"{rdata.preference} {rdata.exchange}")
                    elif record_type == 'SOA':
                        values.append(f"mname={rdata.mname} rname={rdata.rname}")
                    else:
                        values.append(str(rdata))
                    
                    if ttl is None:
                        ttl = answers.rrset.ttl
                
                records[record_type] = DNSRecord(record_type=record_type, values=values, ttl=ttl)
                self.logger.info(f"Found {len(values)} {record_type} record(s)")
                
            except dns.resolver.NoAnswer:
                self.logger.debug(f"No {record_type} records found")
            except dns.resolver.NXDOMAIN:
                self.logger.error(f"Domain {self.domain} does not exist")
                break
            except Exception as e:
                self.logger.debug(f"Error querying {record_type}: {str(e)}")
        
        return records
    
    async def check_reverse_dns(self, records: Dict[str, DNSRecord]) -> Dict[str, List[str]]:
        self.logger.info("Performing reverse DNS lookups...")
        reverse_dns = {}
        ips = []
        if 'A' in records:
            ips.extend(records['A'].values)
        
        for ip in ips:
            try:
                reverse_name = dns.reversename.from_address(ip)
                answers = self.resolver.resolve(reverse_name, 'PTR')
                reverse_dns[ip] = [str(rdata) for rdata in answers]
                self.logger.info(f"Reverse DNS for {ip}: {', '.join(reverse_dns[ip])}")
            except Exception as e:
                self.logger.debug(f"Reverse DNS failed for {ip}: {str(e)}")
        
        return reverse_dns
    
    async def check_dns_security(self) -> Dict[str, bool]:
        self.logger.info("Checking DNS security features...")
        security = {'dnssec': False, 'spf': False, 'dmarc': False}
        
        try:
            self.resolver.resolve(self.domain, 'DNSKEY')
            security['dnssec'] = True
            self.logger.info("DNSSEC is enabled")
        except:
            self.logger.info("DNSSEC is not enabled")
        
        try:
            answers = self.resolver.resolve(self.domain, 'TXT')
            for rdata in answers:
                txt_value = str(rdata).strip('"')
                if txt_value.startswith('v=spf1'):
                    security['spf'] = True
                    self.logger.info(f"SPF record found")
                    break
        except:
            self.logger.info("No SPF record found")
        
        try:
            dmarc_domain = f"_dmarc.{self.domain}"
            answers = self.resolver.resolve(dmarc_domain, 'TXT')
            for rdata in answers:
                txt_value = str(rdata).strip('"')
                if txt_value.startswith('v=DMARC1'):
                    security['dmarc'] = True
                    self.logger.info(f"DMARC record found")
                    break
        except:
            self.logger.info("No DMARC record found")
        
        return security
    
    async def get_mail_servers(self, records: Dict[str, DNSRecord]) -> List[Dict]:
        mail_servers = []
        if 'MX' not in records:
            return mail_servers
        
        for mx_record in records['MX'].values:
            try:
                parts = mx_record.split()
                priority = int(parts[0])
                hostname = parts[1].rstrip('.')
                ips = []
                try:
                    answers = self.resolver.resolve(hostname, 'A')
                    ips = [str(rdata) for rdata in answers]
                except:
                    pass
                mail_servers.append({'priority': priority, 'hostname': hostname, 'ips': ips})
            except Exception as e:
                self.logger.debug(f"Error parsing MX record: {str(e)}")
        
        return sorted(mail_servers, key=lambda x: x['priority'])
    
    async def analyze(self) -> tuple:
        self.logger.info(f"Starting analysis for {self.domain}")
        start_time = time.time()
        
        whois_info = await self.fetch_whois()
        dns_records = await self.fetch_dns_records()
        reverse_dns = await self.check_reverse_dns(dns_records)
        dns_security = await self.check_dns_security()
        mail_servers = await self.get_mail_servers(dns_records)
        name_servers = dns_records.get('NS', DNSRecord('NS', [])).values
        
        dns_analysis = DNSAnalysis(
            domain=self.domain,
            records=dns_records,
            reverse_dns=reverse_dns,
            dns_security=dns_security,
            name_servers=name_servers,
            mail_servers=mail_servers
        )
        
        elapsed = time.time() - start_time
        self.logger.info(f"Analysis completed in {elapsed:.2f}s")
        
        return whois_info, dns_analysis

async def run(domain: str, progress_manager):
    analyzer = AdvancedWHOISandDNS(domain=domain, timeout=10)
    whois_info, dns_analysis = await analyzer.analyze()
    
    timestamp = time.strftime('%Y%m%d_%H%M%S')
    output_dir = f"results/{domain}"
    
    import os
    os.makedirs(output_dir, exist_ok=True)
    
    results = {
        'domain': domain,
        'scan_date': time.strftime('%Y-%m-%d %H:%M:%S'),
        'whois': {
            'registrar': whois_info.registrar,
            'creation_date': whois_info.creation_date.isoformat() if whois_info.creation_date else None,
            'expiration_date': whois_info.expiration_date.isoformat() if whois_info.expiration_date else None,
            'name_servers': whois_info.name_servers,
            'status': whois_info.status,
            'emails': whois_info.emails
        },
        'dns': {
            'records': {rec_type: {'values': rec.values, 'ttl': rec.ttl} for rec_type, rec in dns_analysis.records.items()},
            'reverse_dns': dns_analysis.reverse_dns,
            'security': dns_analysis.dns_security,
            'mail_servers': dns_analysis.mail_servers
        }
    }
    
    with open(f"{output_dir}/whois_dns_{timestamp}.json", 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    return results