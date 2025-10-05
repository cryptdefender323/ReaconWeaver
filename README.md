
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


## What does it detect?
<img width="563" height="366" alt="Tangkapan Layar 2025-10-05 pukul 18 06 31" src="https://github.com/user-attachments/assets/5862b423-5b2e-4cc8-b37c-6e32120befa5" />


## How do I use it?
<img width="1470" height="956" alt="Tangkapan Layar 2025-10-05 pukul 18 08 31" src="https://github.com/user-attachments/assets/23f64312-5706-4733-ad20-dbd6f7e2fdf3" />

## Installation

To install UltraWebRecon, clone the repository and install the required dependencies:

```bash
git clone https://github.com/cryptdefender323/UltraWebRecon.git
cd UltraWebRecon
pip install -r requirements.txt
```

## Usage

To run UltraWebRecon, use the following command:

```bash
python main.py --target <target_url> --mode <mode> --output <output_format>
example : python3 main.py -t http://testphp.vulnweb.com --port-scan --service-detect
```

Replace `<target_url>`, `<mode>`, and `<output_format>` with your desired values. For detailed usage instructions and available options, run:

python main.py --help
