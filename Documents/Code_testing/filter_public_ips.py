#!/usr/bin/env python3
"""
Filter public IP addresses from a CSV file.
Removes RFC 1918 private addresses, APIPA, and other non-routable IPs.
"""

import csv
import ipaddress
import sys

def is_public_ip(ip_str):
    """
    Check if an IP address is publicly routable.
    Returns True only for public IPs, False for private/reserved addresses.
    """
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        
        # Check if IP is global (publicly routable)
        # This excludes:
        # - RFC 1918 private addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
        # - APIPA/link-local (169.254.0.0/16)
        # - Loopback (127.0.0.0/8)
        # - Multicast (224.0.0.0/4)
        # - Reserved/special addresses
        return ip.is_global
        
    except ValueError:
        # Invalid IP address
        return False

def filter_public_ips(input_file, output_file):
    """
    Read IPs from input CSV, filter for public IPs, write to output CSV.
    Preserves all columns from the input file.
    """
    public_ip_rows = []
    fieldnames = None
    
    try:
        with open(input_file, 'r', newline='', encoding='utf-8') as infile:
            reader = csv.DictReader(infile)
            fieldnames = reader.fieldnames
            
            # Verify 'ip' column exists
            if 'ip' not in fieldnames:
                print(f"Error: 'ip' column not found in {input_file}")
                print(f"Available columns: {fieldnames}")
                sys.exit(1)
            
            # Filter for public IPs, keeping entire row
            for row in reader:
                ip = row['ip']
                if is_public_ip(ip):
                    public_ip_rows.append(row)
        
        # Write filtered rows to output file
        with open(output_file, 'w', newline='', encoding='utf-8') as outfile:
            writer = csv.DictWriter(outfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(public_ip_rows)
        
        print(f"Filtered {len(public_ip_rows)} public IP addresses")
        print(f"Output written to: {output_file}")
        
    except FileNotFoundError:
        print(f"Error: File '{input_file}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python filter_public_ips.py <input_csv> <output_csv>")
        print("Example: python filter_public_ips.py ips.csv public_ips.csv")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    filter_public_ips(input_file, output_file)
