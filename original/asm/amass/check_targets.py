import socket
import requests
import concurrent.futures
import os
import ipaddress
import argparse
import urllib3
import sys

# Suppress insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def is_cidr(target):
    return '/' in target

def check_dns(target):
    try:
        # Only meaningful for hostnames
        ip_addr = socket.gethostbyname(target)
        return ip_addr
    except socket.error:
        return None

def check_http(target, port=80, protocol='http', timeout=2.0, verify_ssl=False):
    url = f"{protocol}://{target}:{port}" if port not in [80, 443] else f"{protocol}://{target}"
    try:
        response = requests.get(url, timeout=timeout, verify=verify_ssl, allow_redirects=True, stream=True)
        response.close() # Close connection immediately
        return response.status_code
    except requests.RequestException:
        return None

def analyze_target(target, timeout=2.0, verify_ssl=False):
    target = target.strip()
    if not target or is_cidr(target):
        return None

    result = {
        'target': target,
        'dns': None,
        'http': None,
        'https': None,
        'is_live': False
    }

    # 1. DNS Check (if it looks like a hostname)
    try:
        ipaddress.ip_address(target)
        # It's an IP, skip DNS resolution check (it resolves to itself)
        result['dns'] = target 
    except ValueError:
        # It's a hostname
        resolved_ip = check_dns(target)
        if resolved_ip:
            result['dns'] = resolved_ip
            result['is_live'] = True # DNS resolution implies existence

    # 2. HTTP Check
    http_status = check_http(target, protocol='http', timeout=timeout, verify_ssl=verify_ssl)
    if http_status:
        result['http'] = http_status
        result['is_live'] = True

    # 3. HTTPS Check
    https_status = check_http(target, protocol='https', timeout=timeout, verify_ssl=verify_ssl)
    if https_status:
        result['https'] = https_status
        result['is_live'] = True

    return result

def process_file(filepath, max_workers=10, timeout=2.0, verify_ssl=False):
    sys.stderr.write(f"Scanning targets in {filepath}...\n")
    
    with open(filepath, 'r') as f:
        targets = [line.strip() for line in f if line.strip()]

    # Filter out CIDRs for the count
    host_ip_targets = [t for t in targets if not is_cidr(t)]
    sys.stderr.write(f"Found {len(host_ip_targets)} individual hosts/IPs to check (skipped {len(targets) - len(host_ip_targets)} CIDRs).\n")

    live_count = 0
    # Print header to stdout
    print(f"Target | DNS IP | HTTP Status | HTTPS Status")
    print("-" * 60)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_target = {executor.submit(analyze_target, t, timeout, verify_ssl): t for t in host_ip_targets}
        for future in concurrent.futures.as_completed(future_to_target):
            data = future.result()
            if data and data['is_live']:
                live_count += 1

                dns_str = data['dns'] if data['dns'] else "N/A"
                http_str = str(data['http']) if data['http'] else "No"
                https_str = str(data['https']) if data['https'] else "No"

                print(f"{data['target']} | {dns_str} | {http_str} | {https_str}")
                # Optional: Print live targets to console as they are found (limited verbosity)
                # print(f"[+] Live: {data['target']}")

    sys.stderr.write(f"Finished {filepath}. Found {live_count} live targets. Output printed to stdout.\n")

def main():
    parser = argparse.ArgumentParser(description="Check an Amass targets file for live hosts.")
    parser.add_argument("targets_file", help="Path to the targets file to scan (targets_<session>.txt).")
    parser.add_argument("--threads", type=int, default=10, help="Number of concurrent threads (default: 10).")
    parser.add_argument("--timeout", type=float, default=2.0, help="Request timeout in seconds (default: 2.0).")
    parser.add_argument("--verify-ssl", action="store_true", help="Enable SSL verification (default: False).")
    
    args = parser.parse_args()

    if not os.path.isfile(args.targets_file):
        parser.error(f"File not found: {args.targets_file}")

    process_file(args.targets_file, max_workers=args.threads, timeout=args.timeout, verify_ssl=args.verify_ssl)

if __name__ == "__main__":
    main()
