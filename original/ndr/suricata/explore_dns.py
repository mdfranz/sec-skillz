import sys
import orjson
from collections import Counter

def main():
    if len(sys.argv) < 2:
        print("Usage: python explore_dns.py <log_file>")
        sys.exit(1)

    log_file = sys.argv[1]
    domain_counts = Counter()

    try:
        with open(log_file, 'rb') as f:
            for line in f:
                try:
                    event = orjson.loads(line)
                except orjson.JSONDecodeError:
                    continue

                if event.get('event_type') != 'dns':
                    continue

                dns = event.get('dns', {})
                rrname = dns.get('rrname')
                if rrname:
                    domain_counts[rrname] += 1
    
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

    print(f"Top 50 DNS Queries in {log_file}:")
    for domain, count in domain_counts.most_common(50):
        print(f"{count}: {domain}")

if __name__ == "__main__":
    main()
