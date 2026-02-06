import duckdb
import glob
import sys
import os
import datetime

# --- Constants & Keywords ---

CLOUD_KEYWORDS = [
    "aws", "amazon", "azure", "google", "cloud", "googleapis",
    "amazonaws", "blob.core.windows.net", "s3", "cloudfront",
    "gcp", "dropbox", "box.com", "salesforce"
]

WINDOWS_INDICATORS = [
    "time.windows.com", "msftncsi.com", "msftconnecttest.com",
    "windowsupdate.com", "update.microsoft.com", "mp.microsoft.com",
    "wdcp.microsoft.com", "wdcpalt.microsoft.com",
    "displaycatalog.mp.microsoft.com", "sls.update.microsoft.com",
    "ctldl.windowsupdate.com", "download.windowsupdate.com",
    "tlu.dl.delivery.mp.microsoft.com", "settings-win.data.microsoft.com",
    "v10.events.data.microsoft.com", "watson.telemetry.microsoft.com",
    "login.live.com", "_msdcs", "_ldap._tcp", "_kerberos._tcp"
]

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

LINUX_DOMAINS_REGEX = r'(ubuntu\.com|debian\.org|centos\.org|fedoraproject\.org|archlinux\.org|raspberrypi\.org|kali\.org|linuxmint\.com|pop-os\.org|canonical\.com|pypi\.org|pythonhosted\.org|docker\.io|quay\.io|gcr\.io|registry\.npmjs\.org|rubygems\.org|snapcraft\.io)$'
LINUX_UA_REGEX = r'(linux|ubuntu|debian|fedora|arch|curl|wget|apt-http|pacman)'

# --- Helper Functions ---

def get_parquet_file(argv):
    if len(argv) < 2:
        return None
    path = argv[1]
    if os.path.isdir(path):
        files = glob.glob(os.path.join(path, "*.parquet"))
        if not files:
            return None
        return sorted(files)[-1]
    if os.path.isfile(path) and path.endswith(".parquet"):
        return path
    return None

def build_like_clause(column, keywords):
    conditions = [f"{column} ILIKE '%{k}%'" for k in keywords]
    return f"({' OR '.join(conditions)})"

def run_query(con, query):
    try:
        return con.sql(query).fetchall()
    except Exception as e:
        print(f"Query Error: {e}")
        return []

def format_list_output(title, rows, limit=50):
    output = f"## {title}\n\n"
    if not rows:
        output += "No results found.\n"
    else:
        for row in rows[:limit]:
            output += f"- {', '.join(map(str, row))}\n"
        if len(rows) > limit:
            output += f"- ... ({len(rows) - limit} more)\n"
    output += "\n"
    return output

# --- Analysis Functions ---

def analyze_cloud(con, has_dns, has_tls):
    # Construct domain expression based on available columns
    parts = []
    if has_tls:
        parts.append("tls.sni")
        parts.append("tls.subject")
    if has_dns:
        parts.append("dns.queries[1].rrname")
        
    if not parts:
        return "## Cloud Destinations\n\nNo suitable columns (TLS/DNS) found.\n\n"
        
    domain_expr = f"COALESCE({', '.join(parts)})"
    
    query = f"""
    WITH candidates AS (
        SELECT 
            event_type, 
            {domain_expr} as domain
        FROM logs
        WHERE event_type IN ('tls', 'dns')
    )
    SELECT DISTINCT event_type, domain
    FROM candidates
    WHERE domain IS NOT NULL 
      AND {build_like_clause('domain', CLOUD_KEYWORDS)}
    ORDER BY domain
    """
    rows = run_query(con, query)
    return format_list_output("Cloud Destinations", rows)

def analyze_windows_dns(con):
    # Uses UNNEST(dns.queries)
    query = f"""
    SELECT src_ip, q.unnest.rrname, count(*) as count
    FROM logs, UNNEST(dns.queries) as q
    WHERE event_type = 'dns' 
      AND q.unnest.rrname IS NOT NULL
      AND {build_like_clause('q.unnest.rrname', WINDOWS_INDICATORS)}
    GROUP BY src_ip, q.unnest.rrname
    ORDER BY count DESC
    """
    rows = run_query(con, query)
    
    output = "## Windows DNS Analysis\n\n"
    if not rows:
        output += "No Windows activity found.\n"
    else:
        from collections import defaultdict
        grouped = defaultdict(list)
        for r in rows:
            grouped[r[0]].append(f"{r[1]} ({r[2]})")
        
        for ip, queries in grouped.items():
            output += f"### Source IP: {ip}\n"
            for q in queries[:15]:
                output += f"- {q}\n"
            if len(queries) > 15:
                output += f"- ... ({len(queries)-15} more)\n"
            output += "\n"
    return output

def explore_dns(con):
    query = """
    SELECT q.unnest.rrname, count(*) as cnt
    FROM logs, UNNEST(dns.queries) as q
    WHERE event_type = 'dns' AND q.unnest.rrname IS NOT NULL
    GROUP BY q.unnest.rrname
    ORDER BY cnt DESC
    LIMIT 50
    """
    rows = run_query(con, query)
    output = "## Top 50 DNS Queries\n\n"
    for r in rows:
        output += f"- {r[1]}: {r[0]}\n"
    output += "\n"
    return output

def extract_dns_servers(con):
    query = """
    SELECT DISTINCT dest_ip
    FROM logs
    WHERE (event_type = 'dns' OR dest_port = 53) 
      AND dest_ip IS NOT NULL
    ORDER BY dest_ip
    """
    rows = run_query(con, query)
    return format_list_output("DNS Servers (Dest IPs)", rows)

def extract_sni(con):
    query = """
    SELECT DISTINCT tls.sni
    FROM logs
    WHERE event_type = 'tls' 
      AND tls.sni IS NOT NULL
    ORDER BY tls.sni
    """
    rows = run_query(con, query)
    return format_list_output("Unique SNIs", rows)

def find_iot(con, has_http, has_dns, has_tls):
    iot_clauses = []
    
    if has_dns:
        iot_clauses.append(f"""
            SELECT src_ip, 'dns' as type, q.unnest.rrname as detail
            FROM logs, UNNEST(dns.queries) as q 
            WHERE event_type='dns' AND q.unnest.rrname IS NOT NULL 
              AND {build_like_clause('q.unnest.rrname', IOT_KEYWORDS)}
        """ )
    
    if has_tls:
        iot_clauses.append(f"""
            SELECT src_ip, 'tls_sni' as type, tls.sni as detail
            FROM logs 
            WHERE event_type='tls' AND tls.sni IS NOT NULL 
              AND {build_like_clause('tls.sni', IOT_KEYWORDS)}
        """ )
        iot_clauses.append(f"""
            SELECT src_ip, 'tls_subject' as type, tls.subject as detail
            FROM logs 
            WHERE event_type='tls' AND tls.subject IS NOT NULL 
              AND {build_like_clause('tls.subject', IOT_KEYWORDS)}
        """ )
    
    if has_http:
        iot_clauses.append(f"""
            SELECT src_ip, 'http_host' as type, http.hostname as detail
            FROM logs 
            WHERE event_type='http' AND http.hostname IS NOT NULL 
              AND {build_like_clause('http.hostname', IOT_KEYWORDS)}
        """ )
        iot_clauses.append(f"""
            SELECT src_ip, 'http_ua' as type, http.http_user_agent as detail
            FROM logs 
            WHERE event_type='http' AND http.http_user_agent IS NOT NULL 
              AND {build_like_clause('http.http_user_agent', IOT_KEYWORDS)}
        """ )
    
    if not iot_clauses:
        return "## IoT Device Analysis\n\nNo relevant columns (DNS/TLS/HTTP) found.\n\n"

    full_query = " UNION ALL ".join(iot_clauses)
    rows = run_query(con, full_query)
    
    output = "## IoT Device Analysis\n\n"
    if not rows:
        output += "No IoT devices found.\n"
    else:
        from collections import defaultdict
        grouped = defaultdict(list)
        for r in rows:
            if r[0]: 
                grouped[r[0]].append(f"[{r[1]}] {r[2]}")
        
        for ip, details in grouped.items():
            output += f"### Source IP: {ip}\n"
            unique_details = sorted(list(set(details)))
            for d in unique_details:
                output += f"- {d}\n"
            output += "\n"
    return output

def find_linux_hosts(con, has_http, has_dns, has_tls):
    clauses = []

    if has_http:
        clauses.append(f"""
            SELECT src_ip, 1 as score, http.http_user_agent as evidence
            FROM logs
            WHERE event_type = 'http'
              AND regexp_matches(http.http_user_agent, '(?i){LINUX_UA_REGEX}')
        """)
        clauses.append(f"""
            SELECT src_ip, 2 as score, http.hostname as evidence
            FROM logs
            WHERE event_type = 'http'
              AND regexp_matches(http.hostname, '(?i){LINUX_DOMAINS_REGEX}')
        """)

    if has_tls:
        clauses.append(f"""
            SELECT src_ip, 2 as score, tls.sni as evidence
            FROM logs
            WHERE event_type = 'tls'
              AND regexp_matches(tls.sni, '(?i){LINUX_DOMAINS_REGEX}')
        """)

    if has_dns:
        clauses.append(f"""
            SELECT src_ip, 1 as score, q.unnest.rrname as evidence
            FROM logs, UNNEST(dns.queries) as q
            WHERE event_type = 'dns'
              AND regexp_matches(q.unnest.rrname, '(?i){LINUX_DOMAINS_REGEX}')
        """)

    if not clauses:
         return "## Linux Host Analysis\n\nNo relevant columns found.\n\n"

    full_query = " UNION ALL ".join(clauses)

    query = f"""
    WITH scored_events AS (
        {full_query}
    )
    SELECT 
        src_ip, 
        SUM(score) as total_score,
        LIST(DISTINCT evidence) as evidences
    FROM scored_events
    WHERE src_ip IS NOT NULL 
      AND (
        src_ip LIKE '10.%'
        OR src_ip LIKE '192.168.%'
        OR (src_ip LIKE '172.%' AND try_cast(split_part(src_ip, '.', 2) as INTEGER) BETWEEN 16 AND 31)
      )
    GROUP BY src_ip
    ORDER BY total_score DESC
    """
    rows = run_query(con, query)
    output = "## Linux Host Analysis\n\n"
    if not rows:
        output += "No Linux hosts identified.\n"
    else:
        for r in rows:
            evidence_list = [e for e in r[2] if e] 
            output += f"### Host: {r[0]} (Score: {r[1]})\n"
            for ev in evidence_list[:10]:
                output += f"- {ev}\n"
            if len(evidence_list) > 10:
                output += f"- ... ({len(evidence_list)-10} more)\n"
            output += "\n"
    return output

def analyze_flow_pairs(con):
    base_filter = """
    FROM logs
    WHERE event_type = 'flow'
      AND src_ip IS NOT NULL
      AND dest_ip IS NOT NULL
      AND NOT (
        dest_ip LIKE '10.%'
        OR dest_ip LIKE '192.168.%'
        OR (dest_ip LIKE '172.%' AND try_cast(split_part(dest_ip, '.', 2) as INTEGER) BETWEEN 16 AND 31)
      )
    """

    top_query = f"""
    SELECT src_ip, dest_ip, count(*) as flow_count
    {base_filter}
    GROUP BY src_ip, dest_ip
    ORDER BY flow_count DESC, src_ip, dest_ip
    LIMIT 25
    """

    bottom_query = f"""
    SELECT src_ip, dest_ip, count(*) as flow_count
    {base_filter}
    GROUP BY src_ip, dest_ip
    ORDER BY flow_count ASC, src_ip, dest_ip
    LIMIT 25
    """

    top_rows = run_query(con, top_query)
    bottom_rows = run_query(con, bottom_query)

    output = "## Flow Pair Analysis (Public Dest IPs)\n\n"
    output += "### Top 25 Source/Dest Pairs\n\n"
    if not top_rows:
        output += "No flow pairs found.\n\n"
    else:
        for r in top_rows:
            output += f"- {r[0]} -> {r[1]} (flows: {r[2]})\n"
        output += "\n"

    output += "### Bottom 25 Source/Dest Pairs\n\n"
    if not bottom_rows:
        output += "No flow pairs found.\n\n"
    else:
        for r in bottom_rows:
            output += f"- {r[0]} -> {r[1]} (flows: {r[2]})\n"
        output += "\n"

    return output

def main():
    parquet_file = get_parquet_file(sys.argv)
    if not parquet_file:
        print("Usage: python duck_hunt.py <parquet_file_or_logs_dir>")
        print("Error: No .parquet file found in provided path.")
        sys.exit(1)
        
    print(f"Using data file: {parquet_file}")
    
    con = duckdb.connect(database=':memory:')
    con.execute(f"CREATE VIEW logs AS SELECT * FROM read_parquet('{parquet_file}')")
    
    # Check columns
    columns = [r[0] for r in con.execute("DESCRIBE logs").fetchall()]
    has_http = 'http' in columns
    has_dns = 'dns' in columns
    has_tls = 'tls' in columns
    
    print(f"Schema Check: HTTP={has_http}, DNS={has_dns}, TLS={has_tls}")
    
    now = datetime.datetime.now()
    report_filename = f"duckhunt-{now.strftime('%y-%m-%d-%H-%M')}.md"
    os.makedirs("example_reports", exist_ok=True)
    
    print(f"Running analyses and writing to {report_filename}...")
    
    with open(report_filename, 'w') as f:
        f.write(f"# Analyst Log - {now.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(f"Data Source: `{parquet_file}`\n\n")
        
        print("Running Cloud Analysis...")
        f.write(analyze_cloud(con, has_dns, has_tls))
        f.write("---\n\n")
        
        if has_dns:
            print("Running Windows DNS Analysis...")
            f.write(analyze_windows_dns(con))
            f.write("---\n\n")
            
            print("Running DNS Exploration...")
            f.write(explore_dns(con))
            f.write("---\n\n")
            
            print("Running DNS Server Extraction...")
            f.write(extract_dns_servers(con))
            f.write("---\n\n")
        else:
            f.write("## DNS Analysis skipped (No DNS data)\n\n")

        if has_tls:
            print("Running SNI Extraction...")
            f.write(extract_sni(con))
            f.write("---\n\n")
        else:
             f.write("## TLS Analysis skipped (No TLS data)\n\n")
        
        print("Running IoT Analysis...")
        f.write(find_iot(con, has_http, has_dns, has_tls))
        f.write("---\n\n")
        
        print("Running Linux Host Analysis...")
        f.write(find_linux_hosts(con, has_http, has_dns, has_tls))
        f.write("---\n\n")

        print("Running Flow Pair Analysis...")
        f.write(analyze_flow_pairs(con))
        f.write("---\n\n")
    
    print("Done.")

if __name__ == "__main__":
    main()
