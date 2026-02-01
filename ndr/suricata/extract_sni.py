import sys
import orjson

def main():
    if len(sys.argv) < 2:
        print("Usage: python extract_sni.py <log_file>")
        sys.exit(1)

    filename = sys.argv[1]
    unique_snis = set()

    try:
        with open(filename, 'rb') as f:
            for line in f:
                try:
                    event = orjson.loads(line)
                    if event.get('event_type') == 'tls':
                        tls_data = event.get('tls', {})
                        sni = tls_data.get('sni')
                        if sni:
                            unique_snis.add(sni)
                except orjson.JSONDecodeError:
                    continue
    except FileNotFoundError:
        print(f"Error: File {filename} not found.")
        sys.exit(1)

    for sni in sorted(unique_snis):
        print(sni)

if __name__ == "__main__":
    main()
