import json
import os
import re
import ipaddress
import argparse
import sys

def is_valid_target(value):
    if not value or not isinstance(value, str):
        return False
    
    value = value.strip()

    # Explicit exclusions
    if value == '0.0.0.0' or value.startswith('0.0.0.0/'):
        return False
    if value.lower().endswith(".arpa"):
        return False
    if "://" in value or "email:" in value:
        return False
    
    # 1. Check for IP address or CIDR
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        pass
        
    # 2. Check for Hostname (Standard FQDN)
    # Regex allows alphanumeric, hyphens, underscores (subdomains), and dots.
    # Must contain at least one dot. TLD must be alpha.
    hostname_regex = r'(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-_]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)'
    if re.match(hostname_regex, value):
        return True
        
    return False

def clean_target(value):
    # More robust cleaning:
    # 1. If it contains a space, it might be "Type: Value". Take the last part.
    if " " in value:
        parts = value.split(" ")
        # Heuristic: the last part is usually the value
        potential_value = parts[-1]
        if is_valid_target(potential_value):
            return potential_value
            
    # 2. Original prefix stripping (still useful if no spaces but known prefix)
    # But the split above handles "DomainRecord: example.com"
    
    return value

def process_log_file(filepath):
    unique_targets = set()
    try:
        with open(filepath, 'r') as f:
            for line in f:
                try:
                    data = json.loads(line)
                    
                    # 1. Check direct 'fqdn'
                    if 'fqdn' in data:
                        unique_targets.add(data['fqdn'])
                        
                    # 2. Check 'ip' (sometimes present)
                    if 'ip' in data:
                        unique_targets.add(data['ip'])

                    # 3. Check relationships
                    if data.get('msg') == 'relationship discovered':
                        src = data.get('from')
                        dst = data.get('to')
                        
                        if src:
                            cleaned = clean_target(src)
                            if cleaned and is_valid_target(cleaned):
                                unique_targets.add(cleaned)
                        
                        if dst:
                            cleaned = clean_target(dst)
                            if cleaned and is_valid_target(cleaned):
                                unique_targets.add(cleaned)
                                
                except json.JSONDecodeError:
                    continue
        
        # Filter out anything that still doesn't look right or is empty
        final_targets = sorted([t for t in unique_targets if is_valid_target(t)])
        
        sys.stderr.write("Extracted targets:\n")
        for target in final_targets:
            print(target)
        
        sys.stderr.write(f"Processed {filepath}: Extracted {len(final_targets)} unique targets printed to stdout\n")

    except Exception as e:
        sys.stderr.write(f"Error processing {filepath}: {e}\n")

def main():
    parser = argparse.ArgumentParser(description="Extract targets from a single Amass session log.")
    parser.add_argument("log_file", help="Path to the session log (session-<id>.log).")
    args = parser.parse_args()

    if not os.path.isfile(args.log_file):
        parser.error(f"Log file not found: {args.log_file}")

    process_log_file(args.log_file)

if __name__ == "__main__":
    main()
