#!/usr/bin/env python3
"""
SQL Injection Vulnerability Checker
"""

import requests
from urllib.parse import urlparse, urlencode, parse_qs

class SQLChecker:
    def __init__(self, session):
        self.session = session
        self.findings = []
        
        # SQL Injection payloads
        self.payloads = [
            "'",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "1' AND '1'='1",
            "1' AND '1'='2",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "admin' --",
            "admin' #"
        ]
        
        # Error patterns that indicate SQL injection
        self.error_patterns = [
            "SQL syntax",
            "mysql_fetch",
            "ORA-",
            "PostgreSQL",
            "SQLite",
            "ODBC",
            "Unclosed quotation mark",
            "Microsoft OLE DB",
            "Incorrect syntax near"
        ]
    
    def scan(self, url):
        """Main SQL injection scanning function"""
        print("[*] Scanning for SQL Injection vulnerabilities...")
        
        # Test URL parameters
        self.test_parameters(url)
        
        # Test forms (basic)
        self.test_forms(url)
        
        return self.findings
    
    def test_parameters(self, url):
        """Test URL parameters for SQL injection"""
        parsed = urlparse(url)
        
        if not parsed.query:
            # No parameters, add a test parameter
            test_params = {'id': '1'}
            test_url = f"{url}?{urlencode(test_params)}"
            self.test_single_url(test_url, 'id')
        else:
            # Parse existing parameters
            params = parse_qs(parsed.query)
            for param_name, param_value in params.items():
                if param_value:
                    test_url = self.create_test_url(url, param_name)
                    self.test_single_url(test_url, param_name)
    
    def test_single_url(self, url, param_name):
        """Test a single URL for SQL injection"""
        for payload in self.payloads:
            try:
                # Replace parameter value with payload
                test_url = url.replace(f"{param_name}=", f"{param_name}={payload}")
                response = self.session.get(test_url, timeout=10)
                
                # Check for error patterns
                for pattern in self.error_patterns:
                    if pattern.lower() in response.text.lower():
                        finding = {
                            'type': 'SQL Injection',
                            'severity': 'Critical',
                            'location': url,
                            'parameter': param_name,
                            'payload': payload,
                            'description': f'Parameter "{param_name}" is vulnerable to SQL injection. Error pattern: {pattern}'
                        }
                        self.findings.append(finding)
                        print(f"[!] SQL Injection found in parameter: {param_name}")
                        return
                
                # Check for boolean-based blind injection
                if self.check_boolean_blind(url, param_name, payload):
                    finding = {
                        'type': 'Blind SQL Injection',
                        'severity': 'High',
                        'location': url,
                        'parameter': param_name,
                        'payload': payload,
                        'description': f'Parameter "{param_name}" may be vulnerable to blind SQL injection.'
                    }
                    self.findings.append(finding)
                    print(f"[!] Possible blind SQL injection in parameter: {param_name}")
                    return
                    
            except Exception as e:
                continue
    
    def check_boolean_blind(self, url, param_name, payload):
        """Check for boolean-based blind SQL injection"""
        try:
            # Test with true condition
            true_payload = f"1' AND '1'='1"
            true_url = url.replace(f"{param_name}=", f"{param_name}={true_payload}")
            true_response = self.session.get(true_url, timeout=10)
            
            # Test with false condition
            false_payload = f"1' AND '1'='2"
            false_url = url.replace(f"{param_name}=", f"{param_name}={false_payload}")
            false_response = self.session.get(false_url, timeout=10)
            
            # If responses are different, might be blind injection
            if len(true_response.text) != len(false_response.text):
                return True
                
        except:
            pass
        return False
    
    def test_forms(self, url):
        """Test forms for SQL injection (basic)"""
        # This is a simplified version
        try:
            response = self.session.get(url, timeout=10)
            if "form" in response.text.lower() and "input" in response.text.lower():
                # Just a note that forms exist - full implementation would test them
                print("[*] Forms detected. Manual testing recommended for SQL injection.")
        except:
            pass
    
    def create_test_url(self, url, param_name):
        """Create a test URL with the given parameter"""
        if '?' in url:
            return url
        else:
            return f"{url}?{param_name}=test"