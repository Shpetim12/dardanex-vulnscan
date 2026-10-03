"""vulnscan - Network vulnerability scanner | Copyright (c) 2026 Shpetim / Dardanex | MIT License"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from scanner.cve_lookup import CVELookup, service_keyword
from scanner.dns_resolver import resolve_target, validate_target
from scanner.header_analyzer import fetch_and_analyze
from scanner.port_scanner import NmapUnavailableError, find_nmap_binary, scan_ports
from scanner.report import build_report, write_reports
from scanner import __author__, __version__

CONSOLE = Console()
WEB_SERVICES = {"http", "https", "http-alt", "http-proxy", "ssl/http", "https-alt"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Permission-gated network vulnerability scanner.")
    parser.add_argument("target", help="Authorized hostname or IP address to scan")
    parser.add_argument("--scan", choices=("quick", "default", "full"), default="default")
    parser.add_argument("--format", choices=("txt", "json", "both"), default="both")
    parser.add_argument("--output-dir", type=Path, default=Path("reports"))
    parser.add_argument("--no-cve", action="store_true", help="Skip NVD CVE lookup")
    parser.add_argument("--no-headers", action="store_true", help="Skip HTTP header analysis")
    parser.add_argument("--timeout", type=float, default=10.0, help="Network timeout in seconds")
    parser.add_argument("--i-have-permission", action="store_true", help="Confirm explicit authorization")
    parser.add_argument(
        "--version",
        action="version",
        version=f"vulnscan {__version__} - by {__author__} | Dardanex",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser.parse_args()


def confirm_permission(args: argparse.Namespace) -> bool:
    CONSOLE.print(Panel("[bold yellow]AUTHORIZED USE ONLY[/bold yellow]\nOnly scan systems you own or have explicit permission to test. Unauthorized scanning may be illegal.", title="vulnscan"))
    if args.i_have_permission:
        return True
    if not sys.stdin.isatty():
        CONSOLE.print("[red]Refusing to scan without --i-have-permission in a non-interactive session.[/red]")
        return False
    return input("I confirm I have permission to scan this target [y/N]: ").strip().lower() in {"y", "yes"}


def show_banner() -> None:
    """Display the project's identity before an authorized scan begins."""
    CONSOLE.print(Panel(f"[bold cyan]vulnscan v{__version__} - by {__author__} | Dardanex[/bold cyan]"))


def web_urls(ports: list[dict[str, Any]], target: str) -> list[str]:
    """Infer a bounded set of web endpoints from identified services."""
    urls: list[str] = []
    for port in ports:
        service, number = port.get("service", "").lower(), port["port"]
        if service not in WEB_SERVICES and number not in {80, 443, 8080, 8443, 8000, 8008}:
            continue
        scheme = "https" if number in {443, 8443} or "ssl" in service or "https" in service else "http"
        authority = target if (scheme, number) in {("http", 80), ("https", 443)} else f"{target}:{number}"
        urls.append(f"{scheme}://{authority}/")
    return list(dict.fromkeys(urls))


def run(args: argparse.Namespace) -> int:
    show_banner()
    if args.timeout <= 0:
        CONSOLE.print("[red]--timeout must be greater than zero.[/red]")
        return 2
    try:
        target = validate_target(args.target)
    except ValueError as exc:
        CONSOLE.print(f"[red]Invalid target: {exc}[/red]")
        return 2
    if not confirm_permission(args):
        return 1
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING, format="%(levelname)s %(message)s")
    try:
        nmap_binary = find_nmap_binary()
    except NmapUnavailableError as exc:
        CONSOLE.print(f"[red]{exc}[/red]")
        return 3
    data: dict[str, Any] = {"target": target, "timestamp": datetime.now(timezone.utc).isoformat(), "dns": {}, "ports": [], "cves": {}, "headers": []}
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=CONSOLE) as progress:
        task = progress.add_task("Resolving DNS…", total=None)
        data["dns"] = resolve_target(target, args.timeout)
        progress.update(task, description="Scanning ports and detecting services…")
        try:
            data["ports"] = scan_ports(target, args.scan, args.timeout, nmap_binary)
        except NmapUnavailableError as exc:
            CONSOLE.print(f"[red]{exc}[/red]")
            return 3
        except RuntimeError as exc:
            CONSOLE.print(f"[red]{exc}[/red]")
            return 4
        if not args.no_cve:
            progress.update(task, description="Looking up CVEs in NVD…")
            client = CVELookup(args.output_dir / ".nvd_cache.json", args.timeout)
            for service in data["ports"]:
                keyword = service_keyword(service)
                if keyword: data["cves"][keyword] = client.lookup(keyword)
        if not args.no_headers:
            progress.update(task, description="Analyzing HTTP security headers…")
            data["headers"] = [fetch_and_analyze(url, args.timeout) for url in web_urls(data["ports"], target)]
        progress.update(task, description="Writing report…")
    report = build_report(data)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    paths = write_reports(report, args.output_dir, args.format, f"scan_{target}_{stamp}")
    CONSOLE.print(f"[green]Scan complete.[/green] Open ports: {report['summary']['open_ports']}")
    for path in paths:
        CONSOLE.print(f"[cyan]Report: {path}[/cyan]")
    return 0


def main() -> int:
    """Run the console-script entry point without exposing raw tracebacks."""
    try:
        return run(parse_args())
    except KeyboardInterrupt:
        CONSOLE.print("\n[yellow]Scan cancelled.[/yellow]")
        return 130
    except Exception as exc:  # Last-resort CLI boundary: never expose a traceback by default.
        logging.getLogger(__name__).debug("Unexpected failure", exc_info=True)
        CONSOLE.print(f"[red]Unexpected error: {exc}[/red]")
        return 1


if __name__ == "__main__":
    sys.exit(main())
