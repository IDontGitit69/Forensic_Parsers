import re
from datetime import datetime
from collections import Counter

def parse_log_date(date_str):
    """Parse log date in format 'mmm dd hh:mm:ss'"""
    try:
        return datetime.strptime(date_str, '%b %d %H:%M:%S')
    except ValueError:
        return None

def extract_ip(text):
    """Extract IP address from text"""
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    match = re.search(ip_pattern, text)
    return match.group(0) if match else None

def is_valid_ip(ip):
    """Validate IP address octets are 0-255"""
    octets = ip.split('.')
    return all(0 <= int(octet) <= 255 for octet in octets)

def filter_logs_by_date(log_file, start_date, end_date):
    """
    Filter log entries by date range and extract unique IPs with counts
    
    Args:
        log_file: Path to log file
        start_date: Start date as string 'mmm dd' (e.g., 'Jan 15')
        end_date: End date as string 'mmm dd' (e.g., 'Jan 20')
    
    Returns:
        Dictionary with IP addresses and their counts
    """
    start_parsed = datetime.strptime(start_date, '%b %d')
    end_parsed = datetime.strptime(end_date, '%b %d')
    
    ip_counts = Counter()
    
    try:
        with open(log_file, 'r') as f:
            for line in f:
                # Extract date from log line (first 12 characters: "mmm dd hh:mm:ss")
                if len(line) < 12:
                    continue
                
                date_str = line[:12]
                log_date = parse_log_date(date_str)
                
                if log_date is None:
                    continue
                
                # Compare only month and day
                log_month_day = log_date.replace(year=start_parsed.year)
                
                # Check if date is within range
                if start_parsed <= log_month_day <= end_parsed:
                    # Extract IP from log message
                    ip = extract_ip(line)
                    if ip and is_valid_ip(ip):
                        ip_counts[ip] += 1
    
    except FileNotFoundError:
        print(f"Error: File '{log_file}' not found")
        return {}
    except Exception as e:
        print(f"Error reading file: {e}")
        return {}
    
    return ip_counts

def main():
    # Configuration
    log_file = input("Enter log file path: ").strip()
    start_date = input("Enter start date (mmm dd, e.g., 'Jan 15'): ").strip()
    end_date = input("Enter end date (mmm dd, e.g., 'Jan 20'): ").strip()
    
    print(f"\nProcessing {log_file}...")
    print(f"Date range: {start_date} to {end_date}\n")
    
    ip_counts = filter_logs_by_date(log_file, start_date, end_date)
    
    if not ip_counts:
        print("No IP addresses found in specified date range")
        return
    
    # Sort by count (descending)
    sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
    
    print(f"{'IP Address':<20} {'Count':<10}")
    print("-" * 30)
    for ip, count in sorted_ips:
        print(f"{ip:<20} {count:<10}")
    
    print(f"\nTotal unique IPs: {len(ip_counts)}")
    print(f"Total IP occurrences: {sum(ip_counts.values())}")

if __name__ == "__main__":
    main()
