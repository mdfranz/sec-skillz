import sys
import orjson
from collections import Counter

def analyze_logs(host, file_paths):
    outbound_ports = Counter()
    inbound_ports = Counter()
    protocols = Counter()
    sites = Counter()
    
    for file_path in file_paths:
        try:
            with open(file_path, 'rb') as f:
                for line in f:
                    try:
                        record = orjson.loads(line)
                    except orjson.JSONDecodeError:
                        continue
                        
                    if record.get("event_type") == "stats":
                        continue
                        
                    src_ip = record.get("src_ip")
                    dest_ip = record.get("dest_ip")
                    
                    if src_ip != host and dest_ip != host:
                        continue
                        
                    # Protocol
                    if "proto" in record:
                        protocols[record["proto"]] += 1
                        
                    # Ports
                    if src_ip == host:
                        # Outbound traffic, interested in where it's going
                        if "dest_port" in record:
                            outbound_ports[record["dest_port"]] += 1
                    else:
                        # Inbound traffic, interested in what port on host is being accessed
                        if "dest_port" in record:
                            inbound_ports[record["dest_port"]] += 1

                    # Sites
                    event_type = record.get("event_type")
                    if event_type == "dns" and "dns" in record:
                        if "rrname" in record["dns"]:
                            sites[record["dns"]["rrname"]] += 1
                    elif event_type == "tls" and "tls" in record:
                        if "sni" in record["tls"]:
                            sites[record["tls"]["sni"]] += 1
                    elif event_type == "quic" and "quic" in record:
                        if "sni" in record["quic"]:
                            sites[record["quic"]["sni"]] += 1
                    elif event_type == "http" and "http" in record:
                        if "hostname" in record["http"]:
                            sites[record["http"]["hostname"]] += 1

        except Exception as e:
            print(f"Error processing {file_path}: {e}", file=sys.stderr)

    print(f"Profile for Host: {host}")
    print("-" * 30)
    
    print("\nTop Protocols:")
    for proto, count in protocols.most_common(10):
        print(f"  {proto}: {count}")
        
    print("\nTop Outbound Ports (Remote Services Accessed):")
    for port, count in outbound_ports.most_common(10):
        print(f"  {port}: {count}")

    print("\nTop Inbound Ports (Services Hosted):")
    for port, count in inbound_ports.most_common(10):
        print(f"  {port}: {count}")

    print("\nTop Sites (Domains):")
    for site, count in sites.most_common(20):
        print(f"  {site}: {count}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python profile_host.py <host_ip> <log_file1> [log_file2 ...]")
        sys.exit(1)
    
    analyze_logs(sys.argv[1], sys.argv[2:])
