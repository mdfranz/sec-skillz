import sys
import orjson

def main():
    if len(sys.argv) < 2:
        print("Usage: python extract_dns.py <log_file>")
        sys.exit(1)

    filename = sys.argv[1]
    dns_servers = set()

    try:
        with open(filename, 'rb') as f:
            for line in f:
                try:
                    event = orjson.loads(line)
                    # Check for event_type 'dns' or traffic to port 53
                    if event.get('event_type') == 'dns' or event.get('dest_port') == 53:
                        dest_ip = event.get('dest_ip')
                        if dest_ip:
                            dns_servers.add(dest_ip)
                except orjson.JSONDecodeError:
                    continue
    except FileNotFoundError:
        print(f"Error: File {filename} not found.")
        sys.exit(1)

    for ip in sorted(dns_servers):
        print(ip)

if __name__ == "__main__":
    main()
