import argparse
import json
import os
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    print("Warning: PyYAML not installed. YAML config file support disabled.")
    print("Install with: pip install PyYAML")

@dataclass
class ScanConfig:
    target: str
    mode: str = "hybrid"
    output_format: str = "json"
    concurrency: int = 50
    timeout: int = 10
    
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    proxy: Optional[str] = None
    rate_limit: float = 0.0
    max_retries: int = 3
    follow_redirects: bool = False
    verify_ssl: bool = False
    
    subdomain_enum: bool = False
    port_scan: bool = False
    dir_bruteforce: bool = False
    waf_detect: bool = False
    whois_dns: bool = False
    ssl_scan: bool = False
    js_crawler: bool = False
    
    subdomain_wordlist: Optional[str] = None
    subdomain_recursive: bool = False
    subdomain_permutation_level: int = 1
    
    port_range: str = "common"
    port_service_detection: bool = True
    port_banner_grab: bool = True
    
    dir_wordlist: Optional[str] = None
    dir_extensions: list = None
    dir_recursive: bool = False
    dir_max_depth: int = 3
    
    js_max_depth: int = 3
    js_extract_secrets: bool = True
    
    output_dir: str = "./results"
    save_raw: bool = False
    verbose: bool = False

class AdvancedConfigManager:
    def __init__(self):
        self.config: Optional[ScanConfig] = None
        self.config_paths = [
            Path.home() / ".webrecon" / "config.yaml",
            Path.cwd() / "config.yaml",
            Path.cwd() / ".webrecon.yaml"
        ]
    
    def parse_arguments(self) -> ScanConfig:
        parser = argparse.ArgumentParser(
            description="Advanced Web Reconnaissance Tool",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # Full scan with all features
  python main.py -t example.com --all
  
  # Subdomain enumeration only
  python main.py -t example.com --subdomain-enum -m hybrid
  
  # Port scan with service detection
  python main.py -t example.com --port-scan --service-detect
  
  # Directory brute force with custom wordlist
  python main.py -t example.com --dir-bruteforce -w /path/to/wordlist.txt
            """
        )
        
        parser.add_argument(
            "-t", "--target",
            required=True,
            help="Target domain atau IP address"
        )
        
        features = parser.add_argument_group("Features")
        features.add_argument("--all", action="store_true", help="Enable semua features")
        features.add_argument("--subdomain-enum", action="store_true", help="Subdomain enumeration")
        features.add_argument("--port-scan", action="store_true", help="Port scanning")
        features.add_argument("--dir-bruteforce", action="store_true", help="Directory bruteforce")
        features.add_argument("--waf-detect", action="store_true", help="WAF detection")
        features.add_argument("--whois-dns", action="store_true", help="WHOIS & DNS lookup")
        features.add_argument("--ssl-scan", action="store_true", help="SSL/TLS scanning")
        features.add_argument("--js-crawler", action="store_true", help="JavaScript crawler")
        
        global_opts = parser.add_argument_group("Global Options")
        global_opts.add_argument("-m", "--mode", choices=["passive", "active", "hybrid"], 
                                default="hybrid", help="Scan mode")
        global_opts.add_argument("-o", "--output-format", choices=["json", "csv", "html", "yaml"],
                                default="json", help="Output format")
        global_opts.add_argument("-c", "--concurrency", type=int, default=50,
                                help="Jumlah concurrent connections")
        global_opts.add_argument("--timeout", type=int, default=10,
                                help="Request timeout (seconds)")
        global_opts.add_argument("--proxy", help="Proxy URL (http://host:port)")
        global_opts.add_argument("--rate-limit", type=float, default=0.0,
                                help="Rate limit delay antar request (seconds)")
        global_opts.add_argument("--user-agent", help="Custom User-Agent")
        global_opts.add_argument("--config-file", help="Path ke config file")
        global_opts.add_argument("--output-dir", default="./results",
                                help="Output directory")
        global_opts.add_argument("-v", "--verbose", action="store_true",
                                help="Verbose output")
        
        subdomain_opts = parser.add_argument_group("Subdomain Enumeration")
        subdomain_opts.add_argument("--subdomain-wordlist", help="Custom wordlist untuk subdomain")
        subdomain_opts.add_argument("--subdomain-recursive", action="store_true",
                                   help="Recursive subdomain enumeration")
        subdomain_opts.add_argument("--subdomain-permutation", type=int, choices=[0,1,2],
                                   default=1, help="Permutation level (0-2)")
        
        port_opts = parser.add_argument_group("Port Scanning")
        port_opts.add_argument("--ports", help="Port range (ex: 1-1000, common, all)")
        port_opts.add_argument("--service-detect", action="store_true",
                              help="Enable service detection")
        port_opts.add_argument("--banner-grab", action="store_true",
                              help="Enable banner grabbing")
        port_opts.add_argument("--no-ping", action="store_true",
                              help="Skip ping check")
        
        dir_opts = parser.add_argument_group("Directory Bruteforce")
        dir_opts.add_argument("-w", "--wordlist", help="Wordlist file path")
        dir_opts.add_argument("-e", "--extensions", help="File extensions (comma-separated)")
        dir_opts.add_argument("--dir-recursive", action="store_true",
                             help="Recursive directory scanning")
        dir_opts.add_argument("--max-depth", type=int, default=3,
                             help="Maximum recursion depth")
        dir_opts.add_argument("--exclude-status", help="Status codes to exclude (comma-separated)")
        
        js_opts = parser.add_argument_group("JavaScript Crawler")
        js_opts.add_argument("--js-max-depth", type=int, default=3,
                            help="Maximum crawl depth")
        js_opts.add_argument("--extract-secrets", action="store_true",
                            help="Extract sensitive information")
        
        args = parser.parse_args()
        
        if args.config_file:
            file_config = self._load_config_file(args.config_file)
            if file_config:
                args = self._merge_configs(args, file_config)
        else:
            for path in self.config_paths:
                if path.exists():
                    file_config = self._load_config_file(str(path))
                    if file_config:
                        args = self._merge_configs(args, file_config)
                        break
        
        if args.all:
            args.subdomain_enum = True
            args.port_scan = True
            args.dir_bruteforce = True
            args.waf_detect = True
            args.whois_dns = True
            args.ssl_scan = True
            args.js_crawler = True
        
        extensions = []
        if hasattr(args, 'extensions') and args.extensions:
            extensions = [e.strip() for e in args.extensions.split(',')]
        
        exclude_status = []
        if hasattr(args, 'exclude_status') and args.exclude_status:
            exclude_status = [int(s.strip()) for s in args.exclude_status.split(',')]
        
        self.config = ScanConfig(
            target=args.target,
            mode=args.mode,
            output_format=args.output_format,
            concurrency=args.concurrency,
            timeout=args.timeout,
            user_agent=args.user_agent if hasattr(args, 'user_agent') and args.user_agent else ScanConfig.user_agent,
            proxy=args.proxy if hasattr(args, 'proxy') else None,
            rate_limit=args.rate_limit if hasattr(args, 'rate_limit') else 0.0,
            subdomain_enum=args.subdomain_enum,
            port_scan=args.port_scan,
            dir_bruteforce=args.dir_bruteforce,
            waf_detect=args.waf_detect,
            whois_dns=args.whois_dns,
            ssl_scan=args.ssl_scan,
            js_crawler=args.js_crawler,
            subdomain_wordlist=args.subdomain_wordlist if hasattr(args, 'subdomain_wordlist') else None,
            subdomain_recursive=args.subdomain_recursive if hasattr(args, 'subdomain_recursive') else False,
            subdomain_permutation_level=args.subdomain_permutation if hasattr(args, 'subdomain_permutation') else 1,
            port_range=args.ports if hasattr(args, 'ports') and args.ports else "common",
            port_service_detection=args.service_detect if hasattr(args, 'service_detect') else True,
            port_banner_grab=args.banner_grab if hasattr(args, 'banner_grab') else True,
            dir_wordlist=args.wordlist if hasattr(args, 'wordlist') else None,
            dir_extensions=extensions,
            dir_recursive=args.dir_recursive if hasattr(args, 'dir_recursive') else False,
            dir_max_depth=args.max_depth if hasattr(args, 'max_depth') else 3,
            js_max_depth=args.js_max_depth if hasattr(args, 'js_max_depth') else 3,
            js_extract_secrets=args.extract_secrets if hasattr(args, 'extract_secrets') else True,
            output_dir=args.output_dir if hasattr(args, 'output_dir') else "./results",
            verbose=args.verbose if hasattr(args, 'verbose') else False
        )
        
        self._validate_config()
        Path(self.config.output_dir).mkdir(parents=True, exist_ok=True)
        
        return self.config
    
    def _load_config_file(self, path: str) -> Optional[Dict[str, Any]]:
        try:
            file_path = Path(path)
            if not file_path.exists():
                return None
            
            with open(file_path, 'r') as f:
                if path.endswith(('.yaml', '.yml')):
                    if not YAML_AVAILABLE:
                        print(f"Warning: Cannot load YAML config '{path}' - PyYAML not installed")
                        return None
                    return yaml.safe_load(f)
                elif path.endswith('.json'):
                    return json.load(f)
        except Exception as e:
            print(f"Warning: Failed to load config file {path}: {e}")
        
        return None
    
    def _merge_configs(self, args, file_config: Dict[str, Any]):
        for key, value in file_config.items():
            if not hasattr(args, key) or getattr(args, key) is None:
                setattr(args, key, value)
        return args
    
    def _validate_config(self):
        if not self.config:
            raise ValueError("Config not initialized")
        
        if not self.config.target:
            raise ValueError("Target is required")
        
        if self.config.dir_wordlist and not Path(self.config.dir_wordlist).exists():
            raise FileNotFoundError(f"Directory wordlist not found: {self.config.dir_wordlist}")
        
        if self.config.subdomain_wordlist and not Path(self.config.subdomain_wordlist).exists():
            raise FileNotFoundError(f"Subdomain wordlist not found: {self.config.subdomain_wordlist}")
        
        if self.config.concurrency < 1:
            raise ValueError("Concurrency must be >= 1")
        
        if self.config.timeout < 1:
            raise ValueError("Timeout must be >= 1")
        
        features_enabled = any([
            self.config.subdomain_enum,
            self.config.port_scan,
            self.config.dir_bruteforce,
            self.config.waf_detect,
            self.config.whois_dns,
            self.config.ssl_scan,
            self.config.js_crawler
        ])
        
        if not features_enabled:
            raise ValueError("At least one feature must be enabled. Use --all or specify individual features.")
    
    def save_config(self, output_path: str):
        if not self.config:
            raise ValueError("No config to save")
        
        config_dict = asdict(self.config)
        
        path = Path(output_path)
        with open(path, 'w') as f:
            if output_path.endswith(('.yaml', '.yml')):
                if not YAML_AVAILABLE:
                    raise ImportError("PyYAML not installed. Cannot save YAML config.")
                yaml.dump(config_dict, f, default_flow_style=False)
            else:
                json.dump(config_dict, f, indent=2)
    
    def get_config(self) -> ScanConfig:
        if not self.config:
            raise ValueError("Config not initialized. Call parse_arguments() first.")
        return self.config

def parse_arguments() -> ScanConfig:
    manager = AdvancedConfigManager()
    return manager.parse_arguments()