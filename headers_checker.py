#!/usr/bin/env python3
"""
Security Headers Checker
"""

import requests

class HeadersChecker:
    def __init__(self, session):
        self.session = session
        self.findings = []
        
        # Important security headers
        self.security_headers = {
            'Strict-Transport-Security': 'HSTS header missing. This header enforces HTTPS connections.',
            'Content-Security-Policy': 'CSP header missing. This helps prevent XSS and data injection attacks.',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options header. Prevents MIME type sniffing.',
            'X-Frame-Options': 'Missing X-Frame-Options header. Page could be embedded in a frame (clickjacking risk).',
            'X-XSS-Protection': 'Missing X-XSS-Protection header. Enables browser XSS filtering.',
            'Referrer-Policy': 'Missing Referrer-Policy header. Controls how much referrer information is sent.',
            'Permissions-Policy': 'Missing Permissions-Policy header. Controls browser features.'
        }
        
        # Information disclosure checks
        self.info_disclosure = [
            'server',
            'x-powered-by',
            'x-aspnet-version',
            'x-aspnetmvc-version'
        ]
    
    def scan(self, url):
        """Main security headers scanning function"""
        print("[*] Checking security headers and configurations...")
        
        try:
            response = self.session.get(url, timeout=10)
            headers = response.headers
            
            # Check for missing security headers
            for header, description in self.security_headers.items():
                if header not in headers:
                    finding = {
                        'type': 'Missing Security Header',
                        'severity': 'Medium',
                        'location': 'HTTP Headers',
                        'header': header,
                        'description': description
                    }
                    self.findings.append(finding)
                    print(f"[!] Missing security header: {header}")
            
            # Check for information disclosure
            for header in self.info_disclosure:
                if header in headers:
                    finding = {
                        'type': 'Information Disclosure',
                        'severity': 'Low',
                        'location': 'HTTP Headers',
                        'header': header,
                        'value': headers[header],
                        'description': f'Server is revealing {header} header which may help attackers.'
                    }
                    self.findings.append(finding)
                    print(f"[!] Information disclosure: {header}: {headers[header]}")
            
            # Check HTTPS
            if not url.startswith('https://'):
                finding = {
                    'type': 'Insecure Connection',
                    'severity': 'High',
                    'location': 'Protocol',
                    'description': 'Website is not using HTTPS. All data is transmitted in plain text.'
                }
                self.findings.append(finding)
                print("[!] Website is not using HTTPS")
            
            # Check for cookies security
            if 'Set-Cookie' in headers:
                cookie = headers['Set-Cookie']
                if 'Secure' not in cookie:
                    finding = {
                        'type': 'Insecure Cookie',
                        'severity': 'Medium',
                        'location': 'Cookies',
                        'description': 'Cookies missing Secure flag - can be sent over HTTP'
                    }
                    self.findings.append(finding)
                
                if 'HttpOnly' not in cookie:
                    finding = {
                        'type': 'Insecure Cookie',
                        'severity': 'Medium',
                        'location': 'Cookies',
                        'description': 'Cookies missing HttpOnly flag - accessible to JavaScript'
                    }
                    self.findings.append(finding)
            
        except Exception as e:
            print(f"[-] Error checking headers: {str(e)}")
        
        return self.findings