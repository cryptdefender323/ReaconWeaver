# UltraWebRecon - A Professional Full-Stack Web Reconnaissance Toolkit

UltraWebRecon is a powerful and versatile web reconnaissance toolkit designed for penetration testers and security professionals. This toolkit provides a comprehensive set of features for conducting thorough web reconnaissance, including subdomain enumeration, port scanning, directory brute-forcing, WAF detection, WHOIS and DNS reconnaissance, SSL/TLS scanning, and JavaScript file crawling.

## Features

- **Subdomain Enumeration**: Perform passive and active subdomain enumeration with options for wildcard detection and duplicate filtering.
- **Port Scanning**: Conduct TCP/UDP port scans with service detection and banner grabbing, including stealth scanning options.
- **Directory and File Brute-Force**: Execute directory and file brute-force attacks with high concurrency and customizable output formats.
- **WAF and Firewall Detection**: Identify web application firewalls and firewalls using advanced fingerprinting techniques.
- **WHOIS and DNS Reconnaissance**: Retrieve WHOIS information and DNS records, detecting potential misconfigurations.
- **SSL/TLS Scanning**: Analyze SSL/TLS configurations, identifying weak ciphers and expired certificates.
- **JavaScript File Crawling**: Extract endpoints and sensitive information from JavaScript files on a target domain.
- **Real-Time Progress and Output**: Monitor the progress of operations with an interactive UI, displaying execution times and result counts.
- **Configuration and CLI Arguments**: Easily configure settings and options via command-line arguments or configuration files.
- **Error Handling and Safety**: Implement robust error handling, automatic retries, and rate limiting to ensure safe operations.

## Installation

To install UltraWebRecon, clone the repository and install the required dependencies:

```bash
git clone https://github.com/cryptdefender/UltraWebRecon.git
cd UltraWebRecon
pip install -r requirements.txt
```

## Usage

To run UltraWebRecon, use the following command:

```bash
python main.py --target <target_url> --mode <mode> --output <output_format>
```

Replace `<target_url>`, `<mode>`, and `<output_format>` with your desired values. For detailed usage instructions and available options, run:

python main.py --help
