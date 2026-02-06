import sys
import glob
import orjson
from datetime import datetime

# Common cloud keywords to filter for
CLOUD_KEYWORDS = [
    "aws", "amazon", "azure", "google", "cloud", "googleapis",
    "amazonaws", "blob.core.windows.net", "s3", "cloudfront",
    "gcp", "dropbox", "box.com", "slack", "salesforce"
]

def is_cloud_destination(domain):
    if not domain:
        return False
    domain = domain.lower()
    return any(keyword in domain for keyword in CLOUD_KEYWORDS)

def process_logs(log_pattern):
    cloud_destinations = set()
    files = sorted(glob.glob(log_pattern))
    
    print(f"Processing {len(files)} files...")
    
    for file_path in files:
        # print(f"Reading {file_path}...")
        try:
            with open(file_path, 'rb') as f:
                for line in f:
                    try:
                        record = orjson.loads(line)
                        event_type = record.get('event_type')
                        
                        domain = None
                        
                        if event_type == 'tls':
                            tls = record.get('tls', {})
                            domain = tls.get('sni') or tls.get('subject')
                        elif event_type == 'dns':
                            dns = record.get('dns', {})
                            domain = dns.get('rrname')
                            
                        if is_cloud_destination(domain):
                            # Store tuple of (type, domain) to verify source
                            cloud_destinations.add((event_type, domain))
                            
                    except orjson.JSONDecodeError:
                        continue
        except Exception as e:
            print(f"Error reading {file_path}: {e}")

    return cloud_destinations

def main():
    if len(sys.argv) < 2:
        print("Usage: python analyze_cloud.py <log_pattern>")
        sys.exit(1)
        
    log_pattern = sys.argv[1]
    destinations = process_logs(log_pattern)
    
    print(f"\nFound {len(destinations)} unique cloud destinations:")
    
    # Sort by domain for cleaner output
    sorted_dest = sorted(list(destinations), key=lambda x: x[1] if x[1] else "")
    
    for event_type, domain in sorted_dest:
        print(f"[{event_type.upper()}] {domain}")

if __name__ == "__main__":
    main()
