"""
OSINT Module - Open Source Intelligence Gathering
Performs WHOIS lookups, Shodan queries, and other OSINT tasks
"""

import requests
import socket
import subprocess
import json
from datetime import datetime

def run(args):
    """Execute OSINT reconnaissance on the target domain"""
    domain = args.domain
    output_file = args.output
    
    print(f"[+] Starting OSINT reconnaissance for: {domain}")
    print(f"[+] Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 60)
    
    results = {
        'domain': domain,
        'timestamp': datetime.now().isoformat(),
        'whois': None,
        'dns': None,
        'shodan': None,
        'certificates': None
    }
    
    # WHOIS Lookup
    print("[+] Performing WHOIS lookup...")
    results['whois'] = perform_whois(domain)
    
    # DNS Information
    print("[+] Gathering DNS information...")
    results['dns'] = gather_dns_info(domain)
    
    # Certificate Transparency
    print("[+] Checking certificate transparency logs...")
    results['certificates'] = check_certificate_transparency(domain)
    
    # Shodan Information (mock implementation)
    print("[+] Gathering Shodan information...")
    results['shodan'] = gather_shodan_info(domain)
    
    # Output results
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"[+] Results saved to: {output_file}")
    else:
        print_results(results)
    
    print(f"\n[+] OSINT reconnaissance completed for {domain}")

def perform_whois(domain):
    """Perform WHOIS lookup"""
    try:
        result = subprocess.run(['whois', domain], capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            return result.stdout
        else:
            return f"WHOIS lookup failed: {result.stderr}"
    except subprocess.TimeoutExpired:
        return "WHOIS lookup timed out"
    except FileNotFoundError:
        return "WHOIS command not found"
    except Exception as e:
        return f"WHOIS lookup error: {str(e)}"

def gather_dns_info(domain):
    """Gather DNS information"""
    dns_info = {}
    
    try:
        # A Record
        try:
            ip = socket.gethostbyname(domain)
            dns_info['A'] = ip
            print(f"  A Record: {ip}")
        except socket.gaierror:
            dns_info['A'] = "Not found"
        
        # Try to get additional DNS records using dig if available
        for record_type in ['MX', 'NS', 'TXT', 'AAAA']:
            try:
                result = subprocess.run(['dig', '+short', record_type, domain], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0 and result.stdout.strip():
                    dns_info[record_type] = result.stdout.strip().split('\n')
                    print(f"  {record_type} Records: {dns_info[record_type]}")
                else:
                    dns_info[record_type] = "Not found"
            except (subprocess.TimeoutExpired, FileNotFoundError):
                dns_info[record_type] = "Could not query"
    
    except Exception as e:
        dns_info['error'] = str(e)
    
    return dns_info

def check_certificate_transparency(domain):
    """Check certificate transparency logs"""
    try:
        url = f"https://crt.sh/?q={domain}&output=json"
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            data = response.json()
            certificates = []
            for cert in data[:10]:  # Limit to first 10 results
                certificates.append({
                    'id': cert.get('id'),
                    'name_value': cert.get('name_value'),
                    'not_before': cert.get('not_before'),
                    'not_after': cert.get('not_after'),
                    'issuer_name': cert.get('issuer_name')
                })
            print(f"  Found {len(data)} certificate(s) in CT logs")
            return certificates
        else:
            return "Certificate transparency lookup failed"
    except requests.RequestException as e:
        return f"Certificate transparency error: {str(e)}"
    except Exception as e:
        return f"Certificate transparency error: {str(e)}"

def gather_shodan_info(domain):
    """Gather Shodan information (placeholder implementation)"""
    # This is a placeholder implementation
    # In a real scenario, you would use the Shodan API with proper authentication
    try:
        ip = socket.gethostbyname(domain)
        print(f"  Target IP: {ip}")
        print("  Shodan information would be queried here with proper API key")
        return {
            'ip': ip,
            'note': 'Shodan integration requires API key configuration'
        }
    except socket.gaierror:
        return "Could not resolve domain to IP"
    except Exception as e:
        return f"Shodan lookup error: {str(e)}"

def print_results(results):
    """Print formatted results"""
    print("\n" + "="*60)
    print("OSINT RECONNAISSANCE RESULTS")
    print("="*60)
    
    print(f"\nDomain: {results['domain']}")
    print(f"Timestamp: {results['timestamp']}")
    
    if results['dns']:
        print("\n[DNS Information]")
        for record_type, value in results['dns'].items():
            print(f"  {record_type}: {value}")
    
    if results['whois']:
        print("\n[WHOIS Information]")
        print(results['whois'][:500] + "..." if len(str(results['whois'])) > 500 else results['whois'])
    
    if results['certificates']:
        print("\n[Certificate Transparency]")
        if isinstance(results['certificates'], list):
            for cert in results['certificates'][:5]:  # Show first 5
                print(f"  Certificate: {cert.get('name_value', 'N/A')}")
        else:
            print(f"  {results['certificates']}")
    
    if results['shodan']:
        print("\n[Shodan Information]")
        print(f"  {results['shodan']}")
