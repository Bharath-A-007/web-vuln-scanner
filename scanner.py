import requests
from bs4 import BeautifulSoup
import ssl
import socket
from datetime import datetime
import os
import re
import time
from urllib.parse import urljoin, urlparse
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors

def check_security_headers(url, comprehensive=False):
    """Check for missing security headers"""
    try:
        response = requests.get(url, timeout=10, verify=False)
        headers = response.headers
        
        findings = []
        
        # Security header checks
        if 'X-Frame-Options' not in headers:
            findings.append("X-Frame-Options Missing - Prevents clickjacking attacks")
        else:
            findings.append("X-Frame-Options: " + headers.get('X-Frame-Options'))
            
        if 'X-Content-Type-Options' not in headers:
            findings.append("X-Content-Type-Options Missing - Prevents MIME sniffing attacks")
        else:
            findings.append("X-Content-Type-Options: " + headers.get('X-Content-Type-Options'))
            
        if url.startswith('https://') and 'Strict-Transport-Security' not in headers:
            findings.append("Strict-Transport-Security (HSTS) Missing - Enforces HTTPS security")
        elif url.startswith('https://'):
            findings.append("Strict-Transport-Security: " + headers.get('Strict-Transport-Security', 'Not found'))
            
        if 'Content-Security-Policy' not in headers:
            findings.append("Content-Security-Policy (CSP) Issues - Controls resource loading")
        else:
            findings.append("Content-Security-Policy: " + headers.get('Content-Security-Policy'))
            
        return findings
    except Exception as e:
        return [f"Could not check security headers: {str(e)}"]

def check_sql_injection(url, comprehensive=False):
    """Test for SQL Injection vulnerabilities"""
    try:
        response = requests.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(response.content, 'html.parser')
        forms = soup.find_all('form')
        
        if not forms:
            return ["No forms found for SQLi testing"]
        
        findings = []
        payloads = [
            "' OR '1'='1",  # Classic SQLi
            "admin'--",     # Comment-based
            "1' UNION SELECT null--",  # Union-based
            "1' AND SLEEP(5)--"  # Time-based (Blind SQLi)
        ]
        
        error_patterns = [
            'sql syntax', 'mysql_fetch', 'unclosed quotation',
            'sqlite3', 'postgresql', 'ora-', 'microsoft.*odbc', 
            'syntax error', 'mysql.*result'
        ]
        
        for form in forms:
            form_action = form.get('action', '')
            form_method = form.get('method', 'get').lower()
            
            inputs = {}
            for input_tag in form.find_all('input'):
                if input_tag.get('name') and input_tag.get('type') in ['text', 'password', 'search', 'email']:
                    inputs[input_tag['name']] = input_tag.get('value', 'test')
            
            for payload in payloads:
                test_data = {k: payload for k, v in inputs.items()}
                target_url = urljoin(url, form_action)
                
                try:
                    if form_method == 'post':
                        response = requests.post(target_url, data=test_data, timeout=8, verify=False)
                    else:
                        response = requests.get(target_url, params=test_data, timeout=8, verify=False)
                    
                    content_lower = response.text.lower()
                    
                    # Check for error patterns
                    if any(error in content_lower for error in error_patterns):
                        findings.append(f"SQLi vulnerability detected with payload: {payload}")
                        break
                        
                    # Check for time delays for blind SQLi
                    if 'SLEEP' in payload.upper() or 'WAITFOR' in payload.upper():
                        start_time = time.time()
                        if form_method == 'post':
                            requests.post(target_url, data=test_data, timeout=15, verify=False)
                        else:
                            requests.get(target_url, params=test_data, timeout=15, verify=False)
                        response_time = time.time() - start_time
                        
                        if response_time > 5:  # If response took more than 5 seconds
                            findings.append(f"Blind SQLi (time-based) detected")
                            break
                
                except requests.exceptions.Timeout:
                    findings.append(f"Possible blind SQLi (timeout) with payload: {payload}")
                    break
                except:
                    continue
        
        if not findings:
            findings.append("No SQL Injection vulnerabilities found")
            
        return findings
    except Exception as e:
        return [f"SQLi test failed: {str(e)}"]

def check_xss(url, comprehensive=False):
    """Test for XSS vulnerabilities"""
    try:
        response = requests.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(response.content, 'html.parser')
        forms = soup.find_all('form')
        links = soup.find_all('a', href=True)
        
        findings = []
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "\"><script>alert('XSS')</script>"
        ]
        
        # Test forms
        for form in forms:
            form_action = form.get('action', '')
            form_method = form.get('method', 'get').lower()
            
            inputs = {}
            for input_tag in form.find_all('input'):
                if input_tag.get('name') and input_tag.get('type') in ['text', 'password', 'search', 'email', 'url']:
                    inputs[input_tag['name']] = input_tag.get('value', 'test')
            
            for payload in payloads:
                test_data = {k: payload for k, v in inputs.items()}
                target_url = urljoin(url, form_action)
                
                try:
                    if form_method == 'post':
                        response = requests.post(target_url, data=test_data, timeout=8, verify=False)
                    else:
                        response = requests.get(target_url, params=test_data, timeout=8, verify=False)
                    
                    if payload in response.text:
                        findings.append(f"XSS vulnerability detected with payload: {payload}")
                        break
                
                except:
                    continue
        
        # Test URL parameters
        parsed_url = urlparse(url)
        if parsed_url.query:
            for param in parsed_url.query.split('&'):
                if '=' in param:
                    param_name = param.split('=')[0]
                    for payload in payloads:
                        test_url = url.replace(param, f"{param_name}={payload}")
                        try:
                            response = requests.get(test_url, timeout=8, verify=False)
                            if payload in response.text:
                                findings.append(f"Reflected XSS in parameter {param_name}")
                                break
                        except:
                            continue
        
        if not findings:
            findings.append("No XSS vulnerabilities found")
            
        return findings
    except Exception as e:
        return [f"XSS test failed: {str(e)}"]

def check_ssl_tls(url, comprehensive=False):
    """Check SSL/TLS configuration"""
    if not url.startswith('https://'):
        return ["Not using HTTPS - SSL/TLS checks skipped"]
    
    try:
        domain = url.split('//')[1].split('/')[0]
        context = ssl.create_default_context()
        
        findings = []
        
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                
                # Check certificate expiration
                expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_until_expiry = (expiry_date - datetime.now()).days
                
                if days_until_expiry < 30:
                    findings.append(f"SSL certificate expires in {days_until_expiry} days")
                else:
                    findings.append(f"SSL certificate valid for {days_until_expiry} days")
                
                # Check protocol
                protocol = ssock.version()
                if protocol in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                    findings.append(f"Weak protocol detected: {protocol}")
                else:
                    findings.append(f"Secure protocol: {protocol}")
                
                # Check cipher
                if cipher:
                    cipher_name = cipher[0]
                    weak_ciphers = ['RC4', 'DES', '3DES', 'NULL', 'EXP', 'MD5']
                    if any(weak in cipher_name for weak in weak_ciphers):
                        findings.append(f"Weak cipher detected: {cipher_name}")
                    else:
                        findings.append(f"Secure cipher: {cipher_name}")
        
        return findings
    except Exception as e:
        return [f"SSL/TLS check failed: {str(e)}"]

def check_general_vulnerabilities(url, comprehensive=False):
    """Check for general web vulnerabilities"""
    try:
        response = requests.get(url, timeout=10, verify=False)
        findings = []
        
        # Check for sensitive information in response
        sensitive_patterns = [
            'password', 'secret', 'key', 'token', 'api_key',
            'aws_access_key', 'database_password', 'config'
        ]
        
        content_lower = response.text.lower()
        for pattern in sensitive_patterns:
            if re.search(rf'\b{pattern}\b.*=.*[\'\"][^\'\"]+[\'\"]', content_lower):
                findings.append(f"Possible sensitive information exposure: {pattern}")
        
        # Check for directory listing
        if "index of /" in content_lower.lower():
            findings.append("Directory listing enabled")
        
        # Check for error messages
        error_indicators = ['stack trace', 'error in', 'exception', 'at line', 'warning:']
        for indicator in error_indicators:
            if indicator in content_lower:
                findings.append("Error messages exposed")
                break
                
        if not findings:
            findings.append("No general vulnerabilities detected")
            
        return findings
    except Exception as e:
        return [f"General vulnerability check failed: {str(e)}"]

def scan_website(url, comprehensive=False):
    """Main scanner function with categorized results"""
    print(f"🔍 Scanning: {url} ({'Comprehensive' if comprehensive else 'Quick'} mode)")
    
    results = {
        "Security Headers": check_security_headers(url, comprehensive),
        "SQL Injection": check_sql_injection(url, comprehensive),
        "XSS": check_xss(url, comprehensive),
        "SSL/TLS": check_ssl_tls(url, comprehensive),
        "General Vulnerabilities": check_general_vulnerabilities(url, comprehensive)
    }
    
    # Add severity levels to each finding
    for category, findings in results.items():
        for i, finding in enumerate(findings):
            if any(keyword in finding.lower() for keyword in ['vulnerability', 'exposure', 'weak', 'expires', 'missing']):
                if 'critical' in finding.lower() or 'expires' in finding.lower():
                    findings[i] = f"🚨 CRITICAL: {finding}"
                elif 'sql' in finding.lower() or 'xss' in finding.lower():
                    findings[i] = f"❌ HIGH: {finding}"
                else:
                    findings[i] = f"⚠️ MEDIUM: {finding}"
            elif 'failed' in finding.lower() or 'error' in finding.lower():
                findings[i] = f"ℹ️ INFO: {finding}"
            else:
                findings[i] = f"✅ {finding}"
    
    print(f"✅ Scan completed. Found {sum(len(v) for v in results.values())} results")
    return results

def generate_pdf_report(target_url):
    """Generate a comprehensive PDF report"""
    safe_url = target_url.replace('://', '_').replace('/', '_').replace(':', '_')
    filename = f"security_scan_report_{safe_url}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    filepath = os.path.join('reports', filename)
    
    # Create document
    doc = SimpleDocTemplate(filepath, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []
    
    # Title
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=16,
        spaceAfter=30,
        alignment=1  # Center aligned
    )
    story.append(Paragraph("Security Scan Report", title_style))
    
    # Scan details
    story.append(Paragraph(f"<b>Target URL:</b> {target_url}", styles["Normal"]))
    story.append(Paragraph(f"<b>Scan Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]))
    story.append(Spacer(1, 20))
    
    # Run the scan again for the report
    scan_results = scan_website(target_url, comprehensive=True)
    
    # Results summary
    story.append(Paragraph("<b>Scan Results Summary:</b>", styles["Heading2"]))
    
    # Create summary table
    summary_data = [['Category', 'Findings Count']]
    for category, findings in scan_results.items():
        critical = sum(1 for f in findings if '🚨 CRITICAL' in f)
        high = sum(1 for f in findings if '❌ HIGH' in f)
        medium = sum(1 for f in findings if '⚠️ MEDIUM' in f)
        info = sum(1 for f in findings if 'ℹ️ INFO' in f)
        secure = sum(1 for f in findings if '✅' in f)
        total = len(findings)
        
        summary_data.append([category, f"{total} findings ({critical} critical, {high} high, {medium} medium, {info} info, {secure} secure)"])
    
    summary_table = Table(summary_data, colWidths=[250, 250])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 20))
    
    # Detailed findings
    story.append(Paragraph("<b>Detailed Findings:</b>", styles["Heading2"]))
    
    for category, findings in scan_results.items():
        if findings:
            story.append(Paragraph(f"<b>{category}:</b>", styles["Heading3"]))
            
            for finding in findings:
                # Style based on severity
                if '🚨 CRITICAL' in finding:
                    story.append(Paragraph(f"• <font color='red'>{finding}</font>", styles["Normal"]))
                elif '❌ HIGH' in finding:
                    story.append(Paragraph(f"• <font color='darkorange'>{finding}</font>", styles["Normal"]))
                elif '⚠️ MEDIUM' in finding:
                    story.append(Paragraph(f"• <font color='orange'>{finding}</font>", styles["Normal"]))
                elif 'ℹ️ INFO' in finding:
                    story.append(Paragraph(f"• <font color='blue'>{finding}</font>", styles["Normal"]))
                else:
                    story.append(Paragraph(f"• <font color='green'>{finding}</font>", styles["Normal"]))
            
            story.append(Spacer(1, 10))
    
    # Recommendations
    story.append(Paragraph("<b>Security Recommendations:</b>", styles["Heading2"]))
    recommendations = [
        "Implement all missing security headers (CSP, HSTS, X-Frame-Options, etc.)",
        "Use parameterized queries to prevent SQL injection",
        "Validate and sanitize all user inputs to prevent XSS",
        "Ensure SSL/TLS is properly configured with strong protocols and ciphers",
        "Regularly update and patch all software components",
        "Implement proper error handling to avoid information disclosure",
        "Use a Web Application Firewall (WAF) for additional protection",
        "Conduct regular security scans and penetration tests"
    ]
    
    for rec in recommendations:
        story.append(Paragraph(f"• {rec}", styles["Normal"]))
    
    # Build PDF
    doc.build(story)
    return filepath

# Disable SSL warnings for testing
requests.packages.urllib3.disable_warnings()
