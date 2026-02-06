import json
import os
import argparse
import sys

def process_log_file(filepath, plugin_name='DNS'):
    unique_values = set()
    try:
        with open(filepath, 'r') as f:
            for line in f:
                try:
                    data = json.loads(line)
                    # We are looking for DNS relationships
                    if data.get('msg') == 'relationship discovered':
                        plugin = data.get('plugin', {})
                        if plugin.get('name') == plugin_name:
                            # Extract the 'to' value which represents the resolution
                            to_value = data.get('to')
                            if to_value:
                                unique_values.add(to_value)
                except json.JSONDecodeError:
                    continue
        
        sorted_values = sorted(unique_values)
        # Note: If this tool is intended to produce a clean list for piping, 
        # we might want to omit the header "dns_resolution_value". 
        # However, to avoid breaking potential downstream parsers expecting it, 
        # I will leave it or move it to stderr if it's considered metadata.
        # Given the instruction "Standardize Output... logs/metadata/summaries to stderr",
        # a header is kind of data, but often a nuisance in pipes.
        # I'll keep the header on stdout but remove the summary.
        print("dns_resolution_value")
        for value in sorted_values:
            print(value)
        
        sys.stderr.write(f"Processed {filepath}: Extracted {len(sorted_values)} unique values printed to stdout\n")

    except Exception as e:
        sys.stderr.write(f"Error processing {filepath}: {e}\n")

def main():
    parser = argparse.ArgumentParser(description="Extract DNS relationships from a single Amass session log.")
    parser.add_argument("log_file", help="Path to the session log (session-<id>.log).")
    parser.add_argument("--plugin", default="DNS", help="Plugin name to filter by (default: DNS).")
    args = parser.parse_args()

    if not os.path.isfile(args.log_file):
        parser.error(f"Log file not found: {args.log_file}")

    process_log_file(args.log_file, plugin_name=args.plugin)

if __name__ == "__main__":
    main()
