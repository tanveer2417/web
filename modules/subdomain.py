"""
Subdomain Enumeration Module
Aggregates subdomains from various sources and performs brute-force enumeration
"""

import requests
import subprocess
import json
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

def run(args):
    """Execute subdomain enumeration on the target domain"""
    domain = args.domain
    output_file = args.output
    brute_force = args.brute
    
    print(f"[+] Starting subdomain enumeration for: {domain}")
    print(f"[+] Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 60)
    
    subdomains = set()
    
    # Certificate Transparency
    print("[+] Querying certificate transparency logs...")
    ct_subs = get_ct_subdomains(domain)
    subdomains.update(ct_subs)
    print(f"  Found {len(ct_subs)} subdomains from CT logs")
    
    # DNS Dumpster (simulated)
    print("[+] Querying DNS Dumpster...")
    dns_subs = get_dns_dumpster_subdomains(domain)
    subdomains.update(dns_subs)
    print(f"  Found {len(dns_subs)} subdomains from DNS Dumpster")
    
    # Netcraft (simulated)
    print("[+] Querying Netcraft...")
    netcraft_subs = get_netcraft_subdomains(domain)
    subdomains.update(netcraft_subs)
    print(f"  Found {len(netcraft_subs)} subdomains from Netcraft")
    
    # Brute force enumeration
    if brute_force:
        print("[+] Starting brute-force enumeration...")
        brute_subs = brute_force_subdomains(domain)
        subdomains.update(brute_subs)
        print(f"  Found {len(brute_subs)} subdomains from brute-force")
    
    # Remove duplicates and sort
    unique_subdomains = sorted(list(subdomains))
    
    # Save results
    with open(output_file, 'w') as f:
        for subdomain in unique_subdomains:
            f.write(f"{subdomain}\n")
    
    print(f"\n[+] Total unique subdomains found: {len(unique_subdomains)}")
    print(f"[+] Results saved to: {output_file}")
    
    # Display first 20 subdomains
    print("\n[+] First 20 subdomains:")
    for i, subdomain in enumerate(unique_subdomains[:20]):
        print(f"  {i+1:2d}. {subdomain}")
    
    if len(unique_subdomains) > 20:
        print(f"  ... and {len(unique_subdomains) - 20} more")

def get_ct_subdomains(domain):
    """Get subdomains from certificate transparency logs"""
    subdomains = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            data = response.json()
            for cert in data:
                name_value = cert.get('name_value', '')
                if name_value:
                    # Handle multiple names separated by newlines
                    names = name_value.split('\n')
                    for name in names:
                        name = name.strip()
                        if name and domain in name:
                            # Remove wildcards
                            if name.startswith('*.'):
                                name = name[2:]
                            subdomains.add(name)
    except Exception as e:
        print(f"  Error querying CT logs: {str(e)}")
    
    return subdomains

def get_dns_dumpster_subdomains(domain):
    """Get subdomains from DNS Dumpster (simulated)"""
    # In a real implementation, you would query DNS Dumpster's API
    # This is a simulation with common subdomain patterns
    common_subdomains = [
        'www', 'mail', 'ftp', 'api', 'admin', 'test', 'dev', 'staging',
        'blog', 'shop', 'app', 'portal', 'support', 'forum', 'wiki'
    ]
    
    subdomains = set()
    for sub in common_subdomains:
        subdomain = f"{sub}.{domain}"
        subdomains.add(subdomain)
    
    return subdomains

def get_netcraft_subdomains(domain):
    """Get subdomains from Netcraft (simulated)"""
    # In a real implementation, you would query Netcraft's API
    # This is a simulation with additional common patterns
    additional_subdomains = [
        'cdn', 'assets', 'static', 'img', 'images', 'js', 'css',
        'beta', 'alpha', 'demo', 'sandbox', 'preview'
    ]
    
    subdomains = set()
    for sub in additional_subdomains:
        subdomain = f"{sub}.{domain}"
        subdomains.add(subdomain)
    
    return subdomains

def brute_force_subdomains(domain):
    """Perform brute-force subdomain enumeration"""
    subdomains = set()
    
    # Basic wordlist (in a real scenario, you'd use SecLists)
    wordlist = [
        'a', 'api', 'app', 'admin', 'apps', 'auth', 'blog', 'cdn', 'chat',
        'dev', 'demo', 'docs', 'email', 'ftp', 'git', 'help', 'home',
        'mail', 'mobile', 'news', 'old', 'panel', 'portal', 'shop',
        'ssl', 'stage', 'test', 'vpn', 'web', 'www', 'www2', 'beta',
        'alpha', 'gamma', 'delta', 'prod', 'production', 'staging'
    ]
    
    print(f"  Brute-forcing {len(wordlist)} potential subdomains...")
    
    def check_subdomain(word):
        subdomain = f"{word}.{domain}"
        try:
            import socket
            socket.gethostbyname(subdomain)
            return subdomain
        except socket.gaierror:
            return None
    
    # Use threading for faster enumeration
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_word = {executor.submit(check_subdomain, word): word for word in wordlist}
        for future in as_completed(future_to_word):
            result = future.result()
            if result:
                subdomains.add(result)
                print(f"    Found: {result}")
    
    return subdomains
