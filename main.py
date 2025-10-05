import asyncio
import sys
from modules import (
    subdomain_enum,
    port_scan,
    dir_bruteforce,
    waf_detect,
    whois_dns,
    ssl_scan,
    js_crawler,
    advanced_crawler,
    progress,
    config,
    error_handling
)
from rich.console import Console
from rich.panel import Panel
from rich import print as rprint
import pyfiglet

console = Console()

def print_banner():

    banner = pyfiglet.figlet_format("UltraWebRecon", font="slant")
    console.print(f"[bold cyan]{banner}[/bold cyan]")
    console.print("[bold yellow]Advanced Web Reconnaissance Toolkit v1.0[/bold yellow]")
    console.print("[dim]By CryptDefender - Use responsibly and legally[/dim]\n")

async def main():
    try:
        print_banner()
        
        args = config.parse_arguments()
        progress_manager = progress.ProgressManager()
        
        console.print(Panel.fit(
            f"[bold green]Target:[/bold green] {args.target}\n"
            f"[bold green]Mode:[/bold green] {args.mode}\n"
            f"[bold green]Output:[/bold green] {args.output_dir}",
            title="Scan Configuration"
        ))
        
        if args.subdomain_enum:
            console.print("\n[bold cyan]>>> Starting Subdomain Enumeration[/bold cyan]")
            try:
                await subdomain_enum.run(args.target, args.mode, progress_manager)
                console.print("[bold green]✓ Subdomain enumeration completed[/bold green]")
            except Exception as e:
                console.print(f"[bold red]✗ Subdomain enumeration failed: {str(e)}[/bold red]")

        if args.port_scan:
            console.print("\n[bold cyan]>>> Starting Port Scan[/bold cyan]")
            try:
                await port_scan.run(args.target, args.port_range, progress_manager)
                console.print("[bold green]✓ Port scan completed[/bold green]")
            except Exception as e:
                console.print(f"[bold red]✗ Port scan failed: {str(e)}[/bold red]")

        if args.dir_bruteforce:
            console.print("\n[bold cyan]>>> Starting Directory Bruteforce[/bold cyan]")
            try:
                await dir_bruteforce.run(args.target, args.dir_wordlist, progress_manager)
                console.print("[bold green]✓ Directory bruteforce completed[/bold green]")
            except Exception as e:
                console.print(f"[bold red]✗ Directory bruteforce failed: {str(e)}[/bold red]")

        if args.waf_detect:
            console.print("\n[bold cyan]>>> Starting WAF Detection[/bold cyan]")
            try:
                await waf_detect.run(args.target, progress_manager)
                console.print("[bold green]✓ WAF detection completed[/bold green]")
            except Exception as e:
                console.print(f"[bold red]✗ WAF detection failed: {str(e)}[/bold red]")

        if args.whois_dns:
            console.print("\n[bold cyan]>>> Starting WHOIS & DNS Lookup[/bold cyan]")
            try:
                await whois_dns.run(args.target, progress_manager)
                console.print("[bold green]✓ WHOIS & DNS lookup completed[/bold green]")
            except Exception as e:
                console.print(f"[bold red]✗ WHOIS & DNS lookup failed: {str(e)}[/bold red]")

        if args.ssl_scan:
            console.print("\n[bold cyan]>>> Starting SSL/TLS Scan[/bold cyan]")
            try:
                await ssl_scan.run(args.target, progress_manager)
                console.print("[bold green]✓ SSL/TLS scan completed[/bold green]")
            except Exception as e:
                console.print(f"[bold red]✗ SSL/TLS scan failed: {str(e)}[/bold red]")

        if args.js_crawler:
            console.print("\n[bold cyan]>>> Starting JavaScript Crawler[/bold cyan]")
            try:
                await js_crawler.run(args.target, progress_manager)
                console.print("[bold green]✓ JavaScript crawler completed[/bold green]")
            except Exception as e:
                console.print(f"[bold red]✗ JavaScript crawler failed: {str(e)}[/bold red]")
        
        if args.advanced_crawl:
            console.print("\n[bold cyan]>>> Starting Advanced Deep Web Crawler[/bold cyan]")
            try:
                await advanced_crawler.run(args.target, progress_manager)
                console.print("[bold green]✓ Advanced crawler completed[/bold green]")
            except Exception as e:
                console.print(f"[bold red]✗ Advanced crawler failed: {str(e)}[/bold red]")
        
        progress_manager.finish()
        
        console.print(Panel.fit(
            f"[bold green]All scans completed![/bold green]\n"
            f"Results saved to: {args.output_dir}",
            title="Scan Complete"
        ))
        
    except KeyboardInterrupt:
        console.print("\n[bold yellow]⚠ Scan interrupted by user[/bold yellow]")
        sys.exit(0)
    except Exception as e:
        error_handling.handle_error(e)
        sys.exit(1)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Exiting...[/bold yellow]")
        sys.exit(0)