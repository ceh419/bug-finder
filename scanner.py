#!/usr/bin/env python3
"""
Web Vulnerability Scanner - Main File
Ethical Hacking Tool for Pentesting
"""

import sys
import time
from colorama import init, Fore, Style
import requests
from urllib.parse import urlparse

# Import our modules
from xss_checker import XSSChecker
from sql_checker import SQLChecker
from headers_checker import HeadersChecker
from reporter import Reporter

# Initialize colorama for colored output
init(autoreset=True)

class WebVulnScanner:
    def __init__(self):
        self.url = ""
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def banner(self):
        """Display beautiful banner"""
        print(Fore.CYAN + """
╔══════════════════════════════════════════════════════════╗
║     Web Vulnerability Scanner - Ethical Hacking Tool    ║
║           For Pentesting & Security Research            ║
╚══════════════════════════════════════════════════════════╝
        """ + Style.RESET_ALL)
        print(Fore.YELLOW + "[!] Warning: Use only on authorized websites!" + Style.RESET_ALL)
        print()
    
    def validate_url(self, url):
        """Check if URL is valid and accessible"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        try:
            print(Fore.BLUE + f"[*] Checking URL: {url}" + Style.RESET_ALL)
            response = self.session.get(url, timeout=10, verify=False)
            if response.status_code == 200:
                print(Fore.GREEN + "[✓] URL is accessible!" + Style.RESET_ALL)
                return url, True
            else:
                print(Fore.RED + f"[✗] URL returned status code: {response.status_code}" + Style.RESET_ALL)
                return url, False
        except Exception as e:
            print(Fore.RED + f"[✗] Error: {str(e)}" + Style.RESET_ALL)
            return url, False
    
    def scan(self, url):
        """Main scanning function"""
        self.url, is_valid = self.validate_url(url)
        if not is_valid:
            return
        
        print(Fore.CYAN + "\n" + "="*60 + Style.RESET_ALL)
        print(Fore.CYAN + "           STARTING VULNERABILITY SCAN" + Style.RESET_ALL)
        print(Fore.CYAN + "="*60 + Style.RESET_ALL + "\n")
        
        # Initialize checkers
        xss_checker = XSSChecker(self.session)
        sql_checker = SQLChecker(self.session)
        headers_checker = HeadersChecker(self.session)
        
        # Run all checks
        print(Fore.YELLOW + "[*] Checking for XSS vulnerabilities..." + Style.RESET_ALL)
        xss_findings = xss_checker.scan(self.url)
        self.findings.extend(xss_findings)
        
        print(Fore.YELLOW + "\n[*] Checking for SQL Injection..." + Style.RESET_ALL)
        sql_findings = sql_checker.scan(self.url)
        self.findings.extend(sql_findings)
        
        print(Fore.YELLOW + "\n[*] Checking security headers..." + Style.RESET_ALL)
        headers_findings = headers_checker.scan(self.url)
        self.findings.extend(headers_findings)
        
        # Generate report
        print(Fore.CYAN + "\n" + "="*60 + Style.RESET_ALL)
        print(Fore.CYAN + "           SCAN COMPLETED" + Style.RESET_ALL)
        print(Fore.CYAN + "="*60 + Style.RESET_ALL + "\n")
        
        reporter = Reporter(self.url, self.findings)
        report_file = reporter.generate_report()
        
        # Show summary
        self.show_summary()
        print(Fore.GREEN + f"\n[✓] Report saved to: {report_file}" + Style.RESET_ALL)
    
    def show_summary(self):
        """Display scan summary"""
        print(Fore.MAGENTA + "\n📊 SCAN SUMMARY:" + Style.RESET_ALL)
        print(Fore.MAGENTA + "-"*30 + Style.RESET_ALL)
        
        if not self.findings:
            print(Fore.GREEN + "  No vulnerabilities found! 🎉" + Style.RESET_ALL)
        else:
            critical = len([f for f in self.findings if f['severity'] == 'Critical'])
            high = len([f for f in self.findings if f['severity'] == 'High'])
            medium = len([f for f in self.findings if f['severity'] == 'Medium'])
            low = len([f for f in self.findings if f['severity'] == 'Low'])
            
            print(f"  Total Findings: {len(self.findings)}")
            print(Fore.RED + f"  Critical: {critical}" + Style.RESET_ALL)
            print(Fore.RED + f"  High: {high}" + Style.RESET_ALL)
            print(Fore.YELLOW + f"  Medium: {medium}" + Style.RESET_ALL)
            print(Fore.GREEN + f"  Low: {low}" + Style.RESET_ALL)

def main():
    scanner = WebVulnScanner()
    scanner.banner()
    
    if len(sys.argv) > 1:
        url = sys.argv[1]
    else:
        url = input(Fore.CYAN + "Enter target URL: " + Style.RESET_ALL)
    
    scanner.scan(url)

if __name__ == "__main__":
    main()