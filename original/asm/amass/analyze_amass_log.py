#!/usr/bin/env python3
import json
import sys
import collections
import argparse
from typing import Dict

def analyze_log(file_path: str, output_json: bool = False) -> None:
    """
    Reads an Amass JSON log file and prints a summary of event message types.
    """
    msg_counts: collections.Counter = collections.Counter()
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    msg = entry.get('msg', 'Unknown')
                    msg_counts[msg] += 1
                except json.JSONDecodeError:
                    continue # Skip invalid lines
    except FileNotFoundError:
        sys.stderr.write(f"Error: File not found: {file_path}\n")
        sys.exit(1)
    except Exception as e:
        sys.stderr.write(f"Error reading file: {e}\n")
        sys.exit(1)

    if output_json:
        print(json.dumps(dict(msg_counts), indent=2))
    else:
        sys.stderr.write(f"--- Analysis of {file_path} ---\n")
        print(f"{'Count':<8} | {'Message Type'}")
        print("-" * 50)
        
        for msg, count in msg_counts.most_common():
            print(f"{count:<8} | {msg}")

def main():
    parser = argparse.ArgumentParser(description="Analyze an Amass JSON log file and summarize event message types.")
    parser.add_argument("log_file", help="Path to the log file to analyze.")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format.")
    
    args = parser.parse_args()
    
    analyze_log(args.log_file, args.json)

if __name__ == "__main__":
    main()
