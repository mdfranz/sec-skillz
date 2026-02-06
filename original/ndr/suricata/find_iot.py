import sys
import glob
import orjson
from collections import defaultdict
import datetime

# IoT Keywords to search for in domains, SNIs, User-Agents
IOT_KEYWORDS = [
    "camera", "doorbell", "smart", "alexa", "echo", "nest", "google home",
    "tuya", "dahua", "hikvision", "amcrest", "foscam", "wyze", "ring",
    "roku", "samsung", "lg", "tv", "sonos", "tplink", "belkin", "wemo",
    "philips", "hue", "lifx", "xiaomi", "aqara", "eufy", "arlo",
    "ubiquiti", "unifi", "meross", "nanoleaf", "apple tv", "fire tv",
    "nvidia shield", "chromecast", "nintendo", "xbox", "playstation",
    "steam deck", "oculus", "quest", "yeelight", "sensibo", "tado",
    "netatmo", "withings", "fitbit", "garmin", "myq", "chamberlain",
    "august", "schlage", "yale", "kasa", "tapo", "reolink", "ezviz",
    "imou", "vivint", "simplisafe", "adt", "honeywell", "resideo",
    "ecobee", "sensi", "daikin", "mitsubishi", "fujitsu", "panasonic",
    "toshiba", "sharp", "hitachi", "sony", "bose", "denon", "marantz",
    "onkyo", "pioneer", "yamaha", "harman", "jbl", "ultimate ears",
    "bang olufsen", "bowers wilkins", "kepul", "tuya", "smartlife"
]

def is_iot_related(text):
    if not text:
        return False
    text = text.lower()
    for keyword in IOT_KEYWORDS:
        if keyword in text:
            return keyword
    return False

def analyze_logs(log_pattern):
    # Dictionary to store findings: src_ip -> set of (category, detail)
    devices = defaultdict(lambda: defaultdict(set))
    
    files = sorted(glob.glob(log_pattern))
    print(f"Scanning {len(files)} files...")

    for file_path in files:
        print(f"Processing {file_path}...")
        try:
            with open(file_path, 'rb') as f:
                for line in f:
                    try:
                        record = orjson.loads(line)
                    except orjson.JSONDecodeError:
                        continue
                    
                    event_type = record.get('event_type')
                    if event_type == 'stats':
                        continue

                    src_ip = record.get('src_ip')
                    # Basic filter for internal IPs (naive, usually 192.168.x.x, 10.x.x.x, 172.16-31.x.x)
                    # Adjust if needed, but for now we capture all src_ips that look like they originate traffic
                    if not src_ip:
                        continue

                    # DNS
                    if event_type == 'dns':
                        dns = record.get('dns', {})
                        query = dns.get('rrname') # or query match
                        if not query and 'query' in dns:
                             query = dns['query'][0].get('rrname')
                        
                        matched = is_iot_related(query)
                        if matched:
                            devices[src_ip]['dns'].add(f"{query} (match: {matched})")

                    # TLS
                    elif event_type == 'tls':
                        tls = record.get('tls', {})
                        sni = tls.get('sni')
                        matched = is_iot_related(sni)
                        if matched:
                            devices[src_ip]['tls'].add(f"{sni} (match: {matched})")
                        
                        subject = tls.get('subject')
                        matched_sub = is_iot_related(subject)
                        if matched_sub:
                            devices[src_ip]['tls_subject'].add(f"{subject} (match: {matched_sub})")

                    # QUIC
                    elif event_type == 'quic':
                        quic = record.get('quic', {})
                        sni = quic.get('sni')
                        matched = is_iot_related(sni)
                        if matched:
                            devices[src_ip]['quic'].add(f"{sni} (match: {matched})")

                    # HTTP
                    elif event_type == 'http':
                        http = record.get('http', {})
                        hostname = http.get('hostname')
                        matched_host = is_iot_related(hostname)
                        if matched_host:
                            devices[src_ip]['http_host'].add(f"{hostname} (match: {matched_host})")
                        
                        user_agent = http.get('http_user_agent')
                        matched_ua = is_iot_related(user_agent)
                        if matched_ua:
                            devices[src_ip]['http_ua'].add(f"{user_agent} (match: {matched_ua})")

        except Exception as e:
            print(f"Error reading {file_path}: {e}")

    # Output results
    output_filename = f"iot_analysis_results.txt"
    with open(output_filename, 'w') as out:
        for ip, categories in devices.items():
            out.write(f"Source IP: {ip}\n")
            for cat, details in categories.items():
                out.write(f"  Category: {cat}\n")
                for detail in details:
                    out.write(f"    - {detail}\n")
            out.write("\n")
    
    print(f"Analysis complete. Results saved to {output_filename}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python find_iot.py <log_pattern>")
        sys.exit(1)
    
    analyze_logs(sys.argv[1])
