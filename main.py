import sys
import argparse
from rich.console import Console
from rich.table import Table
from rich.progress import track
import questionary
from scanner import scan_targets, export_results
from rich.markdown import Markdown
import os

console = Console()

def interactive_menu():
    action = questionary.select(
        "Choose an action:",
        choices=[
            "Scan a single host",
            "Scan multiple hosts from file",
            "Exit"
        ]
    ).ask()
    if action == "Scan a single host":
        target = questionary.text("Enter domain or IP (optionally :port):").ask()
        results = scan_targets([target])
        display_results(results)
        export_prompt(results)
    elif action == "Scan multiple hosts from file":
        file_path = questionary.text("Enter path to file with targets:").ask()
        with open(file_path) as f:
            targets = [line.strip() for line in f if line.strip()]
        results = scan_targets(targets)
        display_results(results)
        export_prompt(results)
    else:
        sys.exit(0)

def display_results(results):
    table = Table(title="TLS/PKI Certificate Scan Results")
    table.add_column("Host", style="cyan")
    table.add_column("Expiry", style="magenta")
    table.add_column("Issuer", style="green", max_width=40, overflow="fold")
    table.add_column("Algorithm", style="yellow")
    table.add_column("Warnings", style="red")
    for r in results:
        issuer_short = r['issuer'].split(',')[0] if ',' in r['issuer'] else r['issuer']
        if len(issuer_short) > 38:
            issuer_short = issuer_short[:35] + '...'
        table.add_row(r['host'], r['expiry'], issuer_short, r['algorithm'], r['warnings'])
    console.print(table)
    # Show advanced details for each host after the table
    for r in results:
        console.print(f"[bold]{r['host']} details:[/bold]")
        console.print(f"  OCSP: {r['ocsp']}")
        console.print(f"  CRL: {r['crl']}")
        console.print(f"  Protocols: {r['protocols']}")
        console.print(f"  Ciphers: {r['ciphers']}")
        console.print(f"  Forward Secrecy: {r['forward_secrecy']}")
        console.print(f"  HSTS: {r['hsts']}")
        console.print(f"  HPKP: {r['hpkp']}")
        if r.get('chain'):
            if questionary.confirm(f"Show certificate chain for {r['host']}?").ask():
                for idx, cert in enumerate(r['chain'], 1):
                    console.print(f"[bold]Chain cert {idx} for {r['host']}:[/bold]\n{cert}")

def export_prompt(results):
    if questionary.confirm("Export results?").ask():
        fmt = questionary.select("Export format:", choices=["CSV", "JSON", "HTML", "Markdown"]).ask()
        path = questionary.text("Enter output file path:").ask()
        export_results(results, path, fmt.lower())
        console.print(f"[green]Results exported to {path}[/green]")

def export_results(results, path, fmt):
    import csv, json
    if fmt == 'csv':
        with open(path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)
    elif fmt == 'json':
        with open(path, 'w') as f:
            json.dump(results, f, indent=2)
    elif fmt == 'html':
        html = export_html(results)
        with open(path, 'w') as f:
            f.write(html)
    elif fmt == 'md':
        md = export_markdown(results)
        with open(path, 'w') as f:
            f.write(md)

def export_html(results):
    html = ["<html><head><meta charset='utf-8'><title>Certificate Scan Report</title></head><body>"]
    html.append("<h1>TLS/PKI Certificate Scan Report</h1>")
    html.append("<table border='1' cellpadding='5' cellspacing='0'>")
    html.append("<tr><th>Host</th><th>Expiry</th><th>Issuer</th><th>Algorithm</th><th>Warnings</th></tr>")
    for r in results:
        html.append(f"<tr><td>{r['host']}</td><td>{r['expiry']}</td><td>{r['issuer']}</td><td>{r['algorithm']}</td><td>{r['warnings']}</td></tr>")
    html.append("</table>")
    html.append("<h2>Details</h2>")
    for r in results:
        html.append(f"<h3>{r['host']}</h3><ul>")
        html.append(f"<li>OCSP: {r['ocsp']}</li>")
        html.append(f"<li>CRL: {r['crl']}</li>")
        html.append(f"<li>Protocols: {r['protocols']}</li>")
        html.append(f"<li>Ciphers: {r['ciphers']}</li>")
        html.append(f"<li>Forward Secrecy: {r['forward_secrecy']}</li>")
        html.append(f"<li>HSTS: {r['hsts']}</li>")
        html.append(f"<li>HPKP: {r['hpkp']}</li>")
        html.append("</ul>")
    html.append("</body></html>")
    return '\n'.join(html)

def export_markdown(results):
    md = ["# TLS/PKI Certificate Scan Report\n"]
    md.append("| Host | Expiry | Issuer | Algorithm | Warnings |")
    md.append("|------|--------|--------|-----------|----------|")
    for r in results:
        md.append(f"| {r['host']} | {r['expiry']} | {r['issuer']} | {r['algorithm']} | {r['warnings']} |")
    md.append("\n## Details\n")
    for r in results:
        md.append(f"### {r['host']}")
        md.append(f"- OCSP: {r['ocsp']}")
        md.append(f"- CRL: {r['crl']}")
        md.append(f"- Protocols: {r['protocols']}")
        md.append(f"- Ciphers: {r['ciphers']}")
        md.append(f"- Forward Secrecy: {r['forward_secrecy']}")
        md.append(f"- HSTS: {r['hsts']}")
        md.append(f"- HPKP: {r['hpkp']}")
        md.append("")
    return '\n'.join(md)

def main():
    parser = argparse.ArgumentParser(description="TLS/PKI Certificate Scanner and Analyzer")
    parser.add_argument('-t', '--target', help='Target domain/IP (optionally :port)')
    parser.add_argument('-f', '--file', help='File with list of targets')
    parser.add_argument('-e', '--export', help='Export results to file (CSV, JSON, HTML, or Markdown)')
    parser.add_argument('--format', choices=['csv', 'json', 'html', 'md'], help='Export format')
    args = parser.parse_args()

    if not any([args.target, args.file]):
        interactive_menu()
        return

    if args.target:
        targets = [args.target]
    elif args.file:
        with open(args.file) as f:
            targets = [line.strip() for line in f if line.strip()]
    else:
        console.print("[red]No targets specified.[/red]")
        sys.exit(1)

    results = scan_targets(targets)
    display_results(results)
    if args.export and args.format:
        export_results(results, args.export, args.format)
        console.print(f"[green]Results exported to {args.export}[/green]")

if __name__ == "__main__":
    main() 