#!/usr/bin/env python3
"""
Report Generator for Vulnerability Scanner
"""

import datetime
import json
from urllib.parse import urlparse

class Reporter:
    def __init__(self, url, findings):
        self.url = url
        self.findings = findings
        self.domain = urlparse(url).netloc
        self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    
    def generate_report(self):
        """Generate a comprehensive report"""
        filename = f"scan_report_{self.domain}_{self.timestamp}.txt"
        
        with open(filename, 'w', encoding='utf-8') as f:
            self._write_header(f)
            self._write_summary(f)
            self._write_findings(f)
            self._write_recommendations(f)
            self._write_footer(f)
        
        # Also generate JSON for programmatic use
        self._generate_json()
        
        return filename
    
    def _write_header(self, f):
        """Write report header"""
        f.write("="*80 + "\n")
        f.write("WEB VULNERABILITY SCAN REPORT\n")
        f.write("="*80 + "\n\n")
        f.write(f"Target URL: {self.url}\n")
        f.write(f"Scan Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Scanner Version: 1.0\n")
        f.write("-"*80 + "\n\n")
    
    def _write_summary(self, f):
        """Write scan summary"""
        f.write("SCAN SUMMARY\n")
        f.write("-"*40 + "\n")
        
        if not self.findings:
            f.write("No vulnerabilities were detected.\n")
            f.write("The website appears to be secure against basic tests.\n")
        else:
            # Count by severity
            critical = len([f for f in self.findings if f.get('severity') == 'Critical'])
            high = len([f for f in self.findings if f.get('severity') == 'High'])
            medium = len([f for f in self.findings if f.get('severity') == 'Medium'])
            low = len([f for f in self.findings if f.get('severity') == 'Low'])
            
            f.write(f"Total Vulnerabilities Found: {len(self.findings)}\n\n")
            f.write(f"Critical: {critical}\n")
            f.write(f"High: {high}\n")
            f.write(f"Medium: {medium}\n")
            f.write(f"Low: {low}\n")
        
        f.write("\n" + "-"*80 + "\n\n")
    
    def _write_findings(self, f):
        """Write detailed findings"""
        if not self.findings:
            return
        
        f.write("DETAILED FINDINGS\n")
        f.write("="*40 + "\n\n")
        
        # Sort by severity
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
        sorted_findings = sorted(self.findings, 
                               key=lambda x: severity_order.get(x.get('severity', 'Low'), 4))
        
        for i, finding in enumerate(sorted_findings, 1):
            f.write(f"Finding #{i}\n")
            f.write("-"*20 + "\n")
            f.write(f"Type: {finding.get('type', 'Unknown')}\n")
            f.write(f"Severity: {finding.get('severity', 'Unknown')}\n")
            f.write(f"Location: {finding.get('location', 'Unknown')}\n")
            
            if 'parameter' in finding:
                f.write(f"Parameter: {finding['parameter']}\n")
            if 'payload' in finding:
                f.write(f"Test Payload: {finding['payload']}\n")
            if 'header' in finding:
                f.write(f"Header: {finding['header']}\n")
            
            f.write(f"\nDescription: {finding.get('description', 'No description')}\n")
            
            f.write("\n" + "-"*40 + "\n\n")
    
    def _write_recommendations(self, f):
        """Write recommendations based on findings"""
        f.write("RECOMMENDATIONS\n")
        f.write("="*40 + "\n\n")
        
        if not self.findings:
            f.write("No specific recommendations. Keep up the good security practices!\n")
            return
        
        # Group recommendations by vulnerability type
        vuln_types = set(f.get('type') for f in self.findings)
        
        for vuln_type in vuln_types:
            f.write(f"For {vuln_type}:\n")
            f.write("-"*20 + "\n")
            
            if 'XSS' in vuln_type:
                f.write("• Implement Content Security Policy (CSP)\n")
                f.write("• Validate and sanitize all user inputs\n")
                f.write("• Use output encoding when displaying user data\n")
                f.write("• Set X-XSS-Protection header\n")
            
            elif 'SQL' in vuln_type:
                f.write("• Use parameterized queries/prepared statements\n")
                f.write("• Implement input validation and sanitization\n")
                f.write("• Use an ORM framework\n")
                f.write("• Apply the principle of least privilege for database users\n")
            
            elif 'Header' in vuln_type:
                f.write("• Add missing security headers\n")
                f.write("• Remove information-disclosing headers\n")
                f.write("• Configure web server to hide version information\n")
            
            else:
                f.write("• Review and fix the identified issues\n")
                f.write("• Conduct regular security assessments\n")
                f.write("• Follow OWASP security guidelines\n")
            
            f.write("\n")
    
    def _write_footer(self, f):
        """Write report footer"""
        f.write("\n" + "="*80 + "\n")
        f.write("END OF REPORT\n")
        f.write("="*80 + "\n")
        f.write("\nDisclaimer: This report is generated by an automated tool.\n")
        f.write("Manual verification is recommended for confirmed vulnerabilities.\n")
        f.write("Always ensure you have proper authorization before testing.\n")
    
    def _generate_json(self):
        """Generate JSON report for programmatic use"""
        filename = f"scan_report_{self.domain}_{self.timestamp}.json"
        
        report_data = {
            'target_url': self.url,
            'scan_date': self.timestamp,
            'findings': self.findings,
            'total_vulnerabilities': len(self.findings)
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2)