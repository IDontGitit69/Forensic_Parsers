import re
import argparse
from datetime import datetime
from collections import Counter

def parse_log_date(date_str, year=None):
    """Parse log date in format 'mmm dd hh:mm:ss'"""
    try:
        parsed = datetime.strptime(date_str, '%b %d %H:%M:%S')
        if year:
            parsed = parsed.replace(year=year)
        return parsed
    except ValueError:
        return None

def extract_ip_from_dnsmasq(line):
    """Extract IP address from dnsmasq log line (after 'from')"""
    # Look for "from X.X.X.X" pattern
    match = re.search(r'from\s+((?:\d{1,3}\.){3}\d{1,3})\b', line)
    if match:
        return match.group(1)
    return None

def is_valid_ip(ip):
    """Validate IP address octets are 0-255"""
    try:
        octets = ip.split('.')
        return len(octets) == 4 and all(0 <= int(octet) <= 255 for octet in octets)
    except (ValueError, AttributeError):
        return False

def filter_logs_by_date(log_file, start_date, end_date, year=None):
    """
    Filter log entries by date range and extract unique IPs with counts
    
    Args:
        log_file: Path to log file
        start_date: Start date as string 'mmm dd' (e.g., 'Jan 15')
        end_date: End date as string 'mmm dd' (e.g., 'Jan 20')
        year: Optional year for date parsing (defaults to current year)
    
    Returns:
        Dictionary with IP addresses and their counts
    """
    if year is None:
        year = datetime.now().year
    
    start_parsed = datetime.strptime(start_date, '%b %d').replace(year=year)
    end_parsed = datetime.strptime(end_date, '%b %d').replace(year=year)
    
    # Handle year wraparound
    if end_parsed < start_parsed:
        end_parsed = end_parsed.replace(year=year + 1)
    
    ip_counts = Counter()
    lines_processed = 0
    lines_matched = 0
    
    try:
        with open(log_file, 'r') as f:
            for line in f:
                lines_processed += 1
                
                # Extract date from log line (first 15 characters: "mmm dd hh:mm:ss")
                if len(line) < 15:
                    continue
                
                date_str = line[:15]
                log_date = parse_log_date(date_str, year=year)
                
                if log_date is None:
                    continue
                
                # Handle potential year wraparound for logs
                if log_date < start_parsed and log_date.month == 12 and start_parsed.month == 1:
                    log_date = log_date.replace(year=year - 1)
                elif log_date > end_parsed and log_date.month == 1 and end_parsed.month == 12:
                    log_date = log_date.replace(year=year + 1)
                
                # Check if date is within range
                if start_parsed <= log_date <= end_parsed:
                    lines_matched += 1
                    # Extract IP from log message
                    ip = extract_ip_from_dnsmasq(line)
                    if ip and is_valid_ip(ip):
                        ip_counts[ip] += 1
    
    except FileNotFoundError:
        print(f"Error: File '{log_file}' not found")
        return None, lines_processed, lines_matched
    except Exception as e:
        print(f"Error reading file: {e}")
        return None, lines_processed, lines_matched
    
    return ip_counts, lines_processed, lines_matched

def main():
    parser = argparse.ArgumentParser(
        description='Filter log entries by date range and count unique IP addresses',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s /var/log/dnsmasq.log "Jul 19" "Jul 20"
  %(prog)s /var/log/dnsmasq.log "Jan 15" "Jan 20" --year 2024
  %(prog)s /var/log/dnsmasq.log "Dec 28" "Jan 5" --year 2024
        '''
    )
    
    parser.add_argument('log_file', help='Path to log file')
    parser.add_argument('start_date', help='Start date (format: "mmm dd", e.g., "Jan 15")')
    parser.add_argument('end_date', help='End date (format: "mmm dd", e.g., "Jan 20")')
    parser.add_argument('--year', type=int, help='Year for date parsing (default: current year)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show detailed processing information')
    
    args = parser.parse_args()
    
    print(f"Processing {args.log_file}...")
    print(f"Date range: {args.start_date} to {args.end_date}")
    if args.year:
        print(f"Year: {args.year}")
    print()
    
    ip_counts, lines_processed, lines_matched = filter_logs_by_date(
        args.log_file, 
        args.start_date, 
        args.end_date,
        args.year
    )
    
    if ip_counts is None:
        return 1
    
    if not ip_counts:
        print("No IP addresses found in specified date range")
        if args.verbose:
            print(f"\nLines processed: {lines_processed}")
            print(f"Lines in date range: {lines_matched}")
        return 0
    
    # Sort by count (descending)
    sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
    
    print(f"{'IP Address':<20} {'Count':<10}")
    print("-" * 30)
    for ip, count in sorted_ips:
        print(f"{ip:<20} {count:<10}")
    
    print(f"\nTotal unique IPs: {len(ip_counts)}")
    print(f"Total IP occurrences: {sum(ip_counts.values())}")
    
    if args.verbose:
        print(f"\nLines processed: {lines_processed}")
        print(f"Lines in date range: {lines_matched}")
    
    return 0

if __name__ == "__main__":
    exit(main())
