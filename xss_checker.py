#!/usr/bin/env python3
"""
XSS (Cross-Site Scripting) Vulnerability Checker
"""

from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import requests

class XSSChecker:
    def __init__(self, session):
        self.session = session
        self.findings = []
        self.visited_urls = set()
        
        # Common XSS payloads
        self.payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "<ScRiPt>alert('XSS')</ScRiPt>"
        ]
    
    def scan(self, url):
        """Main XSS scanning function"""
        print("[*] Scanning for XSS vulnerabilities...")
        
        try:
            # Get all forms from the page
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all forms
            forms = soup.find_all('form')
            if forms:
                print(f"[+] Found {len(forms)} form(s) to test")
                for form in forms:
                    self.test_form(form, url)
            
            # Test URL parameters
            self.test_url_parameters(url)
            
            # Test for reflected XSS in common parameters
            self.test_reflected_xss(url)
            
        except Exception as e:
            print(f"[-] Error during XSS scan: {str(e)}")
        
        return self.findings
    
    def test_form(self, form, base_url):
        """Test a form for XSS vulnerabilities"""
        action = form.get('action', '')
        method = form.get('method', 'get').lower()
        form_url = urljoin(base_url, action)
        
        inputs = form.find_all('input')
        data = {}
        
        for input_tag in inputs:
            input_name = input_tag.get('name')
            input_type = input_tag.get('type', 'text')
            
            if input_name and input_type not in ['submit', 'button', 'image']:
                # Test with XSS payload
                data[input_name] = self.payloads[0]
        
        if data:
            if method == 'post':
                response = self.session.post(form_url, data=data, timeout=10)
            else:
                response = self.session.get(form_url, params=data, timeout=10)
            
            # Check if payload is reflected
            if self.payloads[0] in response.text:
                finding = {
                    'type': 'XSS (Cross-Site Scripting)',
                    'severity': 'High',
                    'location': form_url,
                    'method': method.upper(),
                    'parameter': list(data.keys())[0],
                    'payload': self.payloads[0],
                    'description': 'Form is vulnerable to XSS attack. An attacker can inject malicious scripts.'
                }
                self.findings.append(finding)
                print(f"[!] XSS vulnerability found in form at: {form_url}")
    
    def test_url_parameters(self, url):
        """Test URL parameters for XSS"""
        parsed = urlparse(url)
        if parsed.query:
            for payload in self.payloads[:3]:  # Test first 3 payloads
                test_url = f"{url}&test={payload}" if parsed.query else f"{url}?test={payload}"
                try:
                    response = self.session.get(test_url, timeout=10)
                    if payload in response.text:
                        finding = {
                            'type': 'Reflected XSS',
                            'severity': 'High',
                            'location': url,
                            'parameter': 'test',
                            'payload': payload,
                            'description': 'URL parameter is vulnerable to reflected XSS.'
                        }
                        self.findings.append(finding)
                        print(f"[!] Reflected XSS found in URL parameters")
                        break
                except:
                    pass
    
    def test_reflected_xss(self, url):
        """Test for reflected XSS in common parameters"""
        common_params = ['q', 'search', 'id', 'page', 'name', 'keyword', 's']
        
        for param in common_params:
            for payload in self.payloads[:2]:  # Test first 2 payloads
                test_url = f"{url}?{param}={payload}"
                if '?' in url:
                    test_url = f"{url}&{param}={payload}"
                
                try:
                    response = self.session.get(test_url, timeout=10)
                    if payload in response.text:
                        finding = {
                            'type': 'Reflected XSS',
                            'severity': 'High',
                            'location': url,
                            'parameter': param,
                            'payload': payload,
                            'description': f'Parameter "{param}" is vulnerable to reflected XSS.'
                        }
                        self.findings.append(finding)
                        print(f"[!] Reflected XSS found in parameter: {param}")
                        break
                except:
                    pass