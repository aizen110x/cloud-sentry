#!/usr/bin/env python3
"""Cloud-Sentry: AWS S3 Security Scanner v2.0"""
import argparse, asyncio, csv, json, os, platform, sys, time, webbrowser
from datetime import datetime, timezone
from typing import List, Dict, Any

try:
    import aiohttp
except ImportError:
    print("ERROR: aiohttp not installed. Run: pip install aiohttp")
    sys.exit(1)

try:
    from colorama import init, Fore, Style
except ImportError:
    print("ERROR: colorama not installed. Run: pip install colorama")
    sys.exit(1)

init(autoreset=True, convert=True)

class CloudSentry:
    def __init__(self, target: str, concurrent: int = 50, timeout: int = 10, verbose: bool = False, no_color: bool = False):
        self.target = target.lower().strip()
        self.concurrent = concurrent
        self.timeout = timeout
        self.verbose = verbose
        self.no_color = no_color
        self.total_checked = 0
        self.total_found = 0
        self.total_vulnerable = 0
        self.results = []
        self.total_buckets = 0
        self.scan_start_time = None
        self.scan_end_time = None
        self.semaphore = asyncio.Semaphore(concurrent)
    
    def generate_bucket_names(self) -> List[str]:
        bucket_names = []
        base = self.target.replace(' ', '-').replace('_', '-')
        prefixes = ['', 'www-', 'static-', 'cdn-', 'assets-', 'media-', 'images-', 'uploads-', 'downloads-', 'files-', 'data-', 'backup-', 'backups-', 'archive-', 'logs-', 'log-', 'dev-', 'test-', 'staging-', 'prod-', 'production-', 'admin-', 'api-', 'app-', 'web-', 'mobile-', 'public-', 'private-', 'internal-', 'external-', 'temp-', 'tmp-']
        suffixes = ['', '-www', '-static', '-cdn', '-assets', '-media', '-images', '-uploads', '-downloads', '-files', '-data', '-backup', '-backups', '-archive', '-logs', '-log', '-dev', '-test', '-staging', '-prod', '-production', '-admin', '-api', '-app', '-web', '-mobile', '-public', '-private', '-internal', '-external', '-temp', '-tmp', '-1', '-2', '-3', '-new', '-old', '-v1', '-v2']
        regions = ['', '-us-east-1', '-us-west-1', '-us-west-2', '-eu-west-1', '-eu-central-1', '-ap-southeast-1', '-ap-northeast-1']
        environments = ['', '-dev', '-test', '-staging', '-prod', '-production']
        base_variations = [base, base.replace('-', ''), base.replace('-', '_')]
        for base_var in base_variations:
            bucket_names.append(base_var)
            for p in prefixes: bucket_names.append(f"{p}{base_var}")
            for s in suffixes: bucket_names.append(f"{base_var}{s}")
            for r in regions: bucket_names.append(f"{base_var}{r}")
            for e in environments: bucket_names.append(f"{base_var}{e}")
        bucket_names.extend([f"{base}-bucket", f"{base}-s3", f"{base}-storage", f"{base}-files", f"s3-{base}", f"bucket-{base}", f"{base}.com", f"{base}.net", f"{base}.io"])
        return list(set(bucket_names))
    
    async def check_bucket(self, session: aiohttp.ClientSession, bucket_name: str) -> Dict[str, Any]:
        async with self.semaphore:
            url = f"https://{bucket_name}.s3.amazonaws.com"
            result = {'bucket_name': bucket_name, 'url': url, 'exists': False, 'accessible': False, 'listable': False, 'writable': False, 'risk_level': 'SAFE', 'timestamp': datetime.now(timezone.utc).isoformat()}
            try:
                async with session.head(url, timeout=aiohttp.ClientTimeout(total=self.timeout), allow_redirects=True) as response:
                    if response.status == 200:
                        result['exists'] = True
                        result['accessible'] = True
                        try:
                            async with session.get(url, timeout=aiohttp.ClientTimeout(total=self.timeout)) as list_response:
                                if list_response.status == 200:
                                    result['listable'] = True
                                    result['risk_level'] = 'CRITICAL'
                                    self.total_vulnerable += 1
                                    if self.verbose: self.print_finding(result, "CRITICAL - Publicly listable!")
                                elif list_response.status == 403:
                                    result['risk_level'] = 'LOW'
                                    if self.verbose: self.print_finding(result, "Exists but not listable")
                        except: pass
                        self.total_found += 1
                    elif response.status == 403:
                        result['exists'] = True
                        result['risk_level'] = 'LOW'
                        self.total_found += 1
                        if self.verbose: self.print_finding(result, "Exists (403 Forbidden)")
            except (asyncio.TimeoutError, aiohttp.ClientConnectorError): pass
            except Exception as e:
                if self.verbose: self.print_verbose(f"Error: {bucket_name}: {str(e)}")
            self.total_checked += 1
            if self.total_checked % 10 == 0: self.print_progress()
            return result
    
    async def scan_buckets(self, bucket_names: List[str]):
        connector = aiohttp.TCPConnector(limit=self.concurrent, limit_per_host=self.concurrent)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self.check_bucket(session, name) for name in bucket_names]
            results = await asyncio.gather(*tasks)
            self.results = [r for r in results if r['exists']]
    
    def print_banner(self, no_banner: bool = False):
        if no_banner: return
        if self.no_color:
            print("="*65 + "\nCLOUD-SENTRY v2.0\n" + "="*65)
        else:
            print(f"\n{Fore.CYAN}{'='*65}\n  {Fore.RED}CLOUD-SENTRY{Fore.CYAN} - AWS S3 Security Scanner v2.0\n{'='*65}{Style.RESET_ALL}\n")
    
    def print_progress(self):
        pct = (self.total_checked / self.total_buckets * 100) if self.total_buckets > 0 else 0
        msg = f"Progress: {self.total_checked}/{self.total_buckets} ({pct:.1f}%) | {self.total_found} found | {self.total_vulnerable} vulnerable"
        if self.no_color:
            print(msg)
        else:
            print(f"{Fore.BLUE}[*]{Style.RESET_ALL} {msg}", end='\r')
    
    def print_verbose(self, msg: str):
        print(f"[VERBOSE] {msg}")
    
    def print_finding(self, result: Dict, msg: str):
        colors = {'CRITICAL': Fore.RED, 'LOW': Fore.GREEN}
        c = colors.get(result['risk_level'], Fore.WHITE) if not self.no_color else ''
        r = Style.RESET_ALL if not self.no_color else ''
        print(f"{c}[{result['risk_level']}]{r} {result['bucket_name']}: {msg}")
    
    def print_summary(self):
        duration = f"{self.scan_end_time - self.scan_start_time:.2f}s" if self.scan_start_time and self.scan_end_time else ""
        rate = (self.total_found / self.total_checked * 100) if self.total_checked > 0 else 0
        print("\n\n" + ("="*65 if self.no_color else f"{Fore.CYAN}{'='*65}{Style.RESET_ALL}"))
        print("SCAN SUMMARY" if self.no_color else f"{Fore.CYAN}SCAN SUMMARY{Style.RESET_ALL}")
        print("="*65 if self.no_color else f"{Fore.CYAN}={'='*65}{Style.RESET_ALL}")
        print(f"Target: {self.target}")
        print(f"Total Checked: {self.total_checked}")
        print(f"Found: {self.total_found} ({rate:.1f}% rate)")
        print(f"Vulnerable: {self.total_vulnerable}")
        if duration: print(f"Duration: {duration}")
        print("="*65 if self.no_color else f"{Fore.CYAN}{'='*65}{Style.RESET_ALL}")
    
    def save_results(self, output_path: str):
        output_path = os.path.abspath(os.path.expanduser(output_path))
        os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
        data = {'scan_info': {'target': self.target, 'timestamp': datetime.now(timezone.utc).isoformat(), 'platform': platform.system(), 'python_version': platform.python_version(), 'total_checked': self.total_checked, 'total_found': self.total_found, 'total_vulnerable': self.total_vulnerable}, 'findings': self.results}
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Results saved to: {output_path}" if not self.no_color else f"[+] Results: {output_path}")
        except Exception as e:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Failed: {e}" if not self.no_color else f"ERROR: {e}")
    
    def save_html_report(self, output_path: str):
        output_path = os.path.abspath(os.path.expanduser(output_path))
        os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
        rate = round((self.total_found / self.total_checked * 100) if self.total_checked > 0 else 0, 1)
        findings = ""
        if self.results:
            for r in self.results:
                risk = r['risk_level'].lower()
                status = ', '.join([x for x in ['LISTABLE' if r['listable'] else '', 'ACCESSIBLE' if r['accessible'] else ''] if x]) or 'EXISTS (Private)'
                findings += f'<div class="finding-card {risk}"><div class="finding-title"><span>{r["bucket_name"]}</span><span class="risk-badge {risk}">{r["risk_level"]}</span></div><div class="finding-details">Status: {status}</div><div class="finding-url">Link: {r["url"]}</div></div>\n'
        else:
            findings = '<div class="no-findings">No vulnerable buckets found.</div>'
        try:
            with open('report_template.html', 'r', encoding='utf-8') as f:
                html = f.read()
            html = html.replace('{{TARGET}}', self.target).replace('{{TOTAL_CHECKED}}', str(self.total_checked)).replace('{{TOTAL_FOUND}}', str(self.total_found)).replace('{{TOTAL_VULNERABLE}}', str(self.total_vulnerable)).replace('{{SUCCESS_RATE}}', str(rate)).replace('{{PLATFORM}}', platform.system()).replace('{{SCAN_DATE}}', datetime.now(timezone.utc).strftime("%Y-%m-%d")).replace('{{SCAN_TIME}}', datetime.now(timezone.utc).strftime("%H:%M UTC")).replace('{{FINDINGS}}', findings)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html)
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} HTML saved: {output_path}" if not self.no_color else f"[+] HTML: {output_path}")
        except Exception as e:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} HTML failed: {e}" if not self.no_color else f"ERROR: {e}")
    
    def save_csv_report(self, output_path: str):
        output_path = os.path.abspath(os.path.expanduser(output_path))
        os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
        try:
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                if self.results:
                    w = csv.DictWriter(f, fieldnames=['bucket_name', 'url', 'exists', 'accessible', 'listable', 'writable', 'risk_level', 'timestamp'])
                    w.writeheader()
                    w.writerows(self.results)
                else:
                    csv.writer(f).writerow(['bucket_name', 'url', 'exists', 'accessible', 'listable', 'writable', 'risk_level', 'timestamp'])
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} CSV saved: {output_path}" if not self.no_color else f"[+] CSV: {output_path}")
        except Exception as e:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} CSV failed: {e}" if not self.no_color else f"ERROR: {e}")

def parse_arguments():
    p = argparse.ArgumentParser(description="Cloud-Sentry v2.0")
    p.add_argument("-t", "--target", required=True, help="Target company/keyword")
    p.add_argument("-o", "--output", default="results.json", help="JSON output")
    p.add_argument("--html", help="HTML report path")
    p.add_argument("--csv", help="CSV report path")
    p.add_argument("--timeout", type=int, default=10)
    p.add_argument("--concurrent", type=int, default=50)
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--no-banner", action="store_true")
    p.add_argument("--no-browser", action="store_true")
    return p.parse_args()

async def main():
    args = parse_arguments()
    scanner = CloudSentry(args.target, args.concurrent, args.timeout, args.verbose, args.no_color)
    scanner.print_banner(args.no_banner)
    print(f"[*] Generating names for: {args.target}")
    names = scanner.generate_bucket_names()
    scanner.total_buckets = len(names)
    print(f"[*] Generated {len(names)} names")
    print(f"[*] Starting scan...\n")
    scanner.scan_start_time = time.time()
    await scanner.scan_buckets(names)
    scanner.scan_end_time = time.time()
    scanner.print_summary()
    scanner.save_results(args.output)
    html_path = args.html if args.html else f"{args.target}_report.html"
    scanner.save_html_report(html_path)
    if not args.no_browser:
        try:
            webbrowser.open(f'file:///{os.path.abspath(html_path)}')
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Opening browser..." if not args.no_color else "[+] Opening browser...")
        except: pass
    if args.csv:
        scanner.save_csv_report(args.csv)

if __name__ == "__main__":
    try:
        if sys.version_info < (3, 7):
            print("ERROR: Python 3.7+ required")
            sys.exit(1)
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted")
    except Exception as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)

