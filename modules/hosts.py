"""
Live Hosts Detection Module
Checks the availability of discovered subdomains and identifies live hosts
"""

import socket
import subprocess
import requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

def run(args):
    """Execute live hosts detection"""
    domain = args.domain
    input_file = args.input
    output_file = args.output
    
    print(f"[+] Starting live hosts detection for: {domain}")
    print(f"[+] Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 60)
    
    # Get list of hosts to check
    hosts = []
    
    if input_file:
        try:
            with open(input_file, 'r') as f:
                hosts = [line.strip() for line in f if line.strip()]
            print(f"[+] Loaded {len(hosts)} hosts from {input_file}")
        except FileNotFoundError:
            print(f"[!] Input file {input_file} not found")
            return
    else:
        # Generate basic subdomains for the domain
        basic_subs = [
            'www', 'mail', 'ftp', 'api', 'admin', 'test', 'dev', 'blog',
            'app', 'portal', 'support', 'forum', 'wiki', 'cdn', 'assets'
        ]
        hosts = [f"{sub}.{domain}" for sub in basic_subs]
        hosts.append(domain)  # Include the main domain
        print(f"[+] Generated {len(hosts)} hosts to check")
    
    # Check live hosts
    print("[+] Checking host availability...")
    live_hosts = check_live_hosts(hosts)
    
    # Save results
    with open(output_file, 'w') as f:
        for host in live_hosts:
            f.write(f"{host['host']}\n")
    
    print(f"\n[+] Live hosts detection completed")
    print(f"[+] Found {len(live_hosts)} live hosts out of {len(hosts)} checked")
    print(f"[+] Results saved to: {output_file}")
    
    # Display results
    print("\n[+] Live hosts:")
    for i, host_info in enumerate(live_hosts, 1):
        host = host_info['host']
        ip = host_info.get('ip', 'N/A')
        status = host_info.get('status', 'N/A')
        print(f"  {i:2d}. {host:<30} [{ip}] - {status}")

def check_live_hosts(hosts):
    """Check which hosts are live using multiple methods"""
    live_hosts = []
    
    def check_host(host):
        """Check if a host is live using DNS resolution and HTTP probe"""
        result = {'host': host}
        
        # DNS Resolution
        try:
            ip = socket.gethostbyname(host)
            result['ip'] = ip
            result['dns_status'] = 'resolved'
        except socket.gaierror:
            result['ip'] = None
            result['dns_status'] = 'failed'
            return None  # Skip if DNS resolution fails
        
        # HTTP Probe
        http_status = probe_http(host)
        result['http_status'] = http_status
        
        # Determine overall status
        if result['dns_status'] == 'resolved':
            if http_status in ['200', '301', '302', '403', '404', '500']:
                result['status'] = 'live (HTTP)'
            else:
                result['status'] = 'live (DNS only)'
            return result
        
        return None
    
    print(f"  Checking {len(hosts)} hosts...")
    
    # Use threading for faster checking
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_host = {executor.submit(check_host, host): host for host in hosts}
        for future in as_completed(future_to_host):
            result = future.result()
            if result:
                live_hosts.append(result)
                print(f"    Live: {result['host']} [{result['ip']}]")
    
    return live_hosts

def probe_http(host):
    """Probe HTTP/HTTPS services on the host"""
    for scheme in ['https', 'http']:
        try:
            url = f"{scheme}://{host}"
            response = requests.get(url, timeout=5, verify=False, allow_redirects=False)
            return str(response.status_code)
        except requests.RequestException:
            continue
    
    return 'no_http'

def ping_host(host):
    """Ping a host to check if it's alive"""
    try:
        # Use ping command (works on most systems)
        result = subprocess.run(['ping', '-c', '1', '-W', '2', host], 
                              capture_output=True, text=True, timeout=5)
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False
