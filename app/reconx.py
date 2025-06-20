#!/usr/bin/env python3
"""
ReconX - A comprehensive reconnaissance tool for domain enumeration and OSINT
"""

import argparse
import sys
import os
from modules import osint, subdomain, hosts, web

def main():
    parser = argparse.ArgumentParser(
        description='ReconX - Domain Reconnaissance Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python reconx.py osint --domain example.com
  python reconx.py subdomain --domain example.com
  python reconx.py hosts --domain example.com
  python reconx.py web --domain example.com
        '''
    )
    
    subparsers = parser.add_subparsers(dest='module', help='Available modules')
    
    # OSINT module
    osint_parser = subparsers.add_parser('osint', help='OSINT reconnaissance module')
    osint_parser.add_argument('--domain', required=True, help='Target domain')
    osint_parser.add_argument('--output', help='Output file (optional)')
    
    # Subdomain module
    subdomain_parser = subparsers.add_parser('subdomain', help='Subdomain enumeration module')
    subdomain_parser.add_argument('--domain', required=True, help='Target domain')
    subdomain_parser.add_argument('--output', default='subdomains.txt', help='Output file')
    subdomain_parser.add_argument('--brute', action='store_true', help='Enable brute-force enumeration')
    
    # Hosts module
    hosts_parser = subparsers.add_parser('hosts', help='Live hosts detection module')
    hosts_parser.add_argument('--domain', required=True, help='Target domain')
    hosts_parser.add_argument('--input', help='Input file with subdomains')
    hosts_parser.add_argument('--output', default='live.txt', help='Output file')
    
    # Web module
    web_parser = subparsers.add_parser('web', help='Web reconnaissance module')
    web_parser.add_argument('--domain', required=True, help='Target domain')
    web_parser.add_argument('--output', help='Output file (optional)')
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    
    args = parser.parse_args()
    
    try:
        if args.module == 'osint':
            osint.run(args)
        elif args.module == 'subdomain':
            subdomain.run(args)
        elif args.module == 'hosts':
            hosts.run(args)
        elif args.module == 'web':
            web.run(args)
        else:
            parser.print_help()
            sys.exit(1)
    
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()
