import sys
import orjson
import re
from collections import defaultdict, Counter
from ipaddress import ip_address, ip_network

# RFC 1918 Networks
NETWORKS = [
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16")
]

def is_rfc1918(ip_str):
    try:
        ip = ip_address(ip_str)
        return any(ip in net for net in NETWORKS)
    except ValueError:
        return False

# Indicators of Linux systems
LINUX_DOMAINS_REGEX = re.compile(r'(ubuntu.com|debian.org|centos.org|fedoraproject.org|archlinux.org|raspberrypi.org|kali.org|linuxmint.com|pop-os.org|canonical.com|pypi.org|pythonhosted.org|docker.io|quay.io|gcr.io|registry.npmjs.org|rubygems.org|snapcraft.io)$', re.IGNORECASE)
LINUX_UA_REGEX = re.compile(r'(linux|ubuntu|debian|fedora|arch|curl|wget|apt-http|pacman)', re.IGNORECASE)

def analyze_logs(file_paths):
    host_evidence = defaultdict(lambda: {"score": 0, "evidence": Counter()})
    
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
                    
                    if not src_ip or not is_rfc1918(src_ip):
                        continue

                    # Check HTTP User-Agent and Hostname
                    if record.get("event_type") == "http" and "http" in record:
                        http = record["http"]
                        if "http_user_agent" in http:
                            ua = http["http_user_agent"]
                            if LINUX_UA_REGEX.search(ua):
                                host_evidence[src_ip]["score"] += 1
                                host_evidence[src_ip]["evidence"][f"UA: {ua}"] += 1
                        
                        if "hostname" in http:
                            hostname = http["hostname"]
                            if LINUX_DOMAINS_REGEX.search(hostname):
                                host_evidence[src_ip]["score"] += 2 # Stronger signal
                                host_evidence[src_ip]["evidence"][f"Domain: {hostname}"] += 1

                    # Check TLS SNI
                    elif record.get("event_type") == "tls" and "tls" in record:
                        if "sni" in record["tls"]:
                            sni = record["tls"]["sni"]
                            if LINUX_DOMAINS_REGEX.search(sni):
                                host_evidence[src_ip]["score"] += 2
                                host_evidence[src_ip]["evidence"][f"Domain: {sni}"] += 1

                    # Check DNS Queries
                    elif record.get("event_type") == "dns" and "dns" in record:
                         if "rrname" in record["dns"]:
                            rrname = record["dns"]["rrname"]
                            if LINUX_DOMAINS_REGEX.search(rrname):
                                host_evidence[src_ip]["score"] += 1
                                host_evidence[src_ip]["evidence"][f"Domain: {rrname}"] += 1

        except Exception as e:
            print(f"Error processing {file_path}: {e}", file=sys.stderr)

    print("Likely Linux Hosts (RFC 1918) - Sorted by Confidence")
    print("=" * 60)

    # Sort by score descending
    sorted_hosts = sorted(host_evidence.items(), key=lambda x: x[1]["score"], reverse=True)

    for host, data in sorted_hosts:
        if data["score"] > 0:
            print(f"\nHost: {host} (Score: {data['score']})")
            print("  Evidence:")
            for ev, count in data["evidence"].most_common(5):
                print(f"    - {ev} ({count} times)")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python find_linux_hosts.py <log_file1> [log_file2 ...]")
        sys.exit(1)
    
    analyze_logs(sys.argv[1:])
