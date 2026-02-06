import sys
import orjson
from collections import defaultdict

def main():
    if len(sys.argv) < 2:
        print("Usage: python analyze_windows_dns.py <log_file>")
        sys.exit(1)

    log_file = sys.argv[1]
    
    # Domains strongly associated with Windows OS background services and telemetry
    windows_indicators = [
        "time.windows.com",
        "msftncsi.com",
        "msftconnecttest.com",
        "windowsupdate.com",
        "update.microsoft.com",
        "mp.microsoft.com", 
        "wdcp.microsoft.com", # Windows Defender
        "wdcpalt.microsoft.com",
        "displaycatalog.mp.microsoft.com",
        "sls.update.microsoft.com",
        "ctldl.windowsupdate.com",
        "download.windowsupdate.com",
        "tlu.dl.delivery.mp.microsoft.com",
        "settings-win.data.microsoft.com",
        "v10.events.data.microsoft.com",
        "watson.telemetry.microsoft.com",
        "login.live.com",
        "_msdcs", 
        "_ldap._tcp",
        "_kerberos._tcp"
    ]

    detected_systems = defaultdict(set)
    processed_lines = 0

    try:
        with open(log_file, 'rb') as f:
            for line in f:
                processed_lines += 1
                try:
                    event = orjson.loads(line)
                except orjson.JSONDecodeError:
                    continue

                if event.get('event_type') != 'dns':
                    continue

                dns = event.get('dns', {})
                
                queries_list = dns.get('queries', [])
                # Also check if rrname is directly in dns (older formats)
                if 'rrname' in dns:
                     queries_list.append({'rrname': dns['rrname']})

                for query_obj in queries_list:
                    rrname = query_obj.get('rrname', '').lower()
                    
                    is_windows = False
                    for indicator in windows_indicators:
                        if indicator in rrname:
                            is_windows = True
                            break
                    
                    if is_windows:
                        src_ip = event.get('src_ip')
                        if src_ip:
                            detected_systems[src_ip].add(rrname)

    except FileNotFoundError:
        print(f"Error: File {log_file} not found.")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)

    print(f"Analysis of {log_file}")
    print(f"Lines processed: {processed_lines}")
    print(f"Potential Windows Systems Identified: {len(detected_systems)}")
    print("-" * 40)
    
    for ip, queries in detected_systems.items():
        print(f"Source IP: {ip}")
        print(f"  Unique Windows-related Queries ({len(queries)}):")
        sorted_queries = sorted(list(queries))
        for q in sorted_queries[:15]:
            print(f"    - {q}")
        if len(sorted_queries) > 15:
            print(f"    - ... and {len(sorted_queries) - 15} more")
        print()

if __name__ == "__main__":
    main()
