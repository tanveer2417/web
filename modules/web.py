"""
Web Reconnaissance Module
Performs web-based reconnaissance including technology detection and crawling
"""

import requests
import re
from urllib.parse import urljoin, urlparse
from datetime import datetime
import json

def run(args):
    """Execute web reconnaissance on the target domain"""
    domain = args.domain
    output_file = args.output
    
    print(f"[+] Starting web reconnaissance for: {domain}")
    print(f"[+] Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 60)
    
    results = {
        'domain': domain,
        'timestamp': datetime.now().isoformat(),
        'technologies': {},
        'headers': {},
        'directories': [],
        'forms': [],
        'links': [],
        'emails': [],
        'status_codes': {}
    }
    
    # Check both HTTP and HTTPS
    for scheme in ['https', 'http']:
        url = f"{scheme}://{domain}"
        print(f"\n[+] Analyzing {url}")
        
        try:
            response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
            
            # Store status code
            results['status_codes'][scheme] = response.status_code
            
            if response.status_code == 200:
                # Analyze headers
                print("  [+] Analyzing headers...")
                headers = analyze_headers(response.headers)
                results['headers'][scheme] = headers
                
                # Detect technologies
                print("  [+] Detecting technologies...")
                technologies = detect_technologies(response)
                results['technologies'][scheme] = technologies
                
                # Find forms
                print("  [+] Finding forms...")
                forms = find_forms(response.text, url)
                results['forms'].extend(forms)
                
                # Extract links
                print("  [+] Extracting links...")
                links = extract_links(response.text, url)
                results['links'].extend(links)
                
                # Find email addresses
                print("  [+] Finding email addresses...")
                emails = find_emails(response.text)
                results['emails'].extend(emails)
                
                # Directory bruteforce (basic)
                print("  [+] Checking common directories...")
                directories = check_directories(url)
                results['directories'].extend(directories)
                
                break  # Use the first successful connection
                
        except requests.RequestException as e:
            print(f"  [!] Error connecting to {url}: {str(e)}")
            results['status_codes'][scheme] = 'error'
    
    # Remove duplicates
    results['links'] = list(set(results['links']))
    results['emails'] = list(set(results['emails']))
    
    # Output results
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n[+] Results saved to: {output_file}")
    else:
        print_web_results(results)
    
    print(f"\n[+] Web reconnaissance completed for {domain}")

def analyze_headers(headers):
    """Analyze HTTP headers for security and technology information"""
    header_info = {}
    
    security_headers = [
        'strict-transport-security',
        'content-security-policy',
        'x-frame-options',
        'x-content-type-options',
        'x-xss-protection',
        'referrer-policy'
    ]
    
    tech_headers = [
        'server',
        'x-powered-by',
        'x-aspnet-version',
        'x-aspnetmvc-version',
        'x-generator'
    ]
    
    for header in security_headers + tech_headers:
        if header in headers:
            header_info[header] = headers[header]
    
    return header_info

def detect_technologies(response):
    """Detect web technologies from response"""
    technologies = []
    content = response.text.lower()
    headers = response.headers
    
    # Server header
    server = headers.get('server', '').lower()
    if 'apache' in server:
        technologies.append('Apache')
    elif 'nginx' in server:
        technologies.append('Nginx')
    elif 'iis' in server:
        technologies.append('IIS')
    
    # X-Powered-By header
    powered_by = headers.get('x-powered-by', '').lower()
    if 'php' in powered_by:
        technologies.append('PHP')
    elif 'asp.net' in powered_by:
        technologies.append('ASP.NET')
    
    # Content analysis
    if 'wordpress' in content or 'wp-content' in content:
        technologies.append('WordPress')
    if 'drupal' in content:
        technologies.append('Drupal')
    if 'joomla' in content:
        technologies.append('Joomla')
    if 'jquery' in content:
        technologies.append('jQuery')
    if 'bootstrap' in content:
        technologies.append('Bootstrap')
    if 'react' in content:
        technologies.append('React')
    if 'angular' in content:
        technologies.append('Angular')
    if 'vue' in content:
        technologies.append('Vue.js')
    
    return list(set(technologies))

def find_forms(content, base_url):
    """Find forms in HTML content"""
    forms = []
    form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.DOTALL | re.IGNORECASE)
    
    for match in form_pattern.finditer(content):
        form_html = match.group(0)
        
        # Extract form attributes
        action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        
        action = action_match.group(1) if action_match else ''
        method = method_match.group(1).upper() if method_match else 'GET'
        
        # Make action URL absolute
        if action:
            action = urljoin(base_url, action)
        
        # Find input fields
        input_pattern = re.compile(r'<input[^>]*>', re.IGNORECASE)
        inputs = []
        
        for input_match in input_pattern.finditer(form_html):
            input_html = input_match.group(0)
            name_match = re.search(r'name=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
            type_match = re.search(r'type=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
            
            if name_match:
                inputs.append({
                    'name': name_match.group(1),
                    'type': type_match.group(1) if type_match else 'text'
                })
        
        forms.append({
            'action': action,
            'method': method,
            'inputs': inputs
        })
    
    return forms

def extract_links(content, base_url):
    """Extract links from HTML content"""
    links = []
    link_pattern = re.compile(r'<a[^>]*href=["\']([^"\']*)["\']', re.IGNORECASE)
    
    for match in link_pattern.finditer(content):
        link = match.group(1)
        # Make link absolute
        absolute_link = urljoin(base_url, link)
        
        # Only include HTTP(S) links
        parsed = urlparse(absolute_link)
        if parsed.scheme in ['http', 'https']:
            links.append(absolute_link)
    
    return links

def find_emails(content):
    """Find email addresses in content"""
    email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    emails = email_pattern.findall(content)
    return emails

def check_directories(base_url):
    """Check for common directories"""
    common_dirs = [
        'admin', 'administrator', 'wp-admin', 'phpmyadmin', 'cpanel',
        'uploads', 'images', 'assets', 'css', 'js', 'fonts',
        'api', 'backup', 'config', 'tmp', 'test', 'dev'
    ]
    
    found_dirs = []
    
    for directory in common_dirs:
        url = f"{base_url.rstrip('/')}/{directory}"
        try:
            response = requests.head(url, timeout=5, verify=False, allow_redirects=False)
            if response.status_code in [200, 301, 302, 403]:
                found_dirs.append({
                    'directory': directory,
                    'url': url,
                    'status_code': response.status_code
                })
        except requests.RequestException:
            continue
    
    return found_dirs

def print_web_results(results):
    """Print formatted web reconnaissance results"""
    print("\n" + "="*60)
    print("WEB RECONNAISSANCE RESULTS")
    print("="*60)
    
    print(f"\nDomain: {results['domain']}")
    print(f"Timestamp: {results['timestamp']}")
    
    # Status codes
    if results['status_codes']:
        print("\n[Status Codes]")
        for scheme, status in results['status_codes'].items():
            print(f"  {scheme.upper()}: {status}")
    
    # Technologies
    if results['technologies']:
        print("\n[Detected Technologies]")
        for scheme, techs in results['technologies'].items():
            if techs:
                print(f"  {scheme.upper()}: {', '.join(techs)}")
    
    # Headers
    if results['headers']:
        print("\n[Important Headers]")
        for scheme, headers in results['headers'].items():
            if headers:
                print(f"  {scheme.upper()}:")
                for header, value in headers.items():
                    print(f"    {header}: {value}")
    
    # Forms
    if results['forms']:
        print(f"\n[Forms Found] ({len(results['forms'])})")
        for i, form in enumerate(results['forms'][:5], 1):
            print(f"  {i}. {form['method']} {form['action']}")
            if form['inputs']:
                inputs = [inp['name'] for inp in form['inputs']]
                print(f"     Inputs: {', '.join(inputs)}")
    
    # Directories
    if results['directories']:
        print(f"\n[Directories Found] ({len(results['directories'])})")
        for directory in results['directories']:
            print(f"  {directory['directory']} ({directory['status_code']})")
    
    # Emails
    if results['emails']:
        print(f"\n[Email Addresses] ({len(results['emails'])})")
        for email in results['emails'][:10]:
            print(f"  {email}")
    
    # Links summary
    if results['links']:
        print(f"\n[Links Found]: {len(results['links'])} total")
