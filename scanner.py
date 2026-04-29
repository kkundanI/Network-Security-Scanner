"""
Network Security Scanner
Author: Kundan Kumar
Description: Multi-threaded network scanner for open ports and vulnerability identification.
             For ethical/authorized use only.
"""

import socket
import threading
import concurrent.futures
import ipaddress
import argparse
import json
import datetime
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import List, Optional

# ──────────────────────────────────────────────
# DATA MODELS
# ──────────────────────────────────────────────

@dataclass
class PortResult:
    port: int
    state: str          # "open" | "closed" | "filtered"
    service: str
    banner: str = ""
    vulnerabilities: List[str] = field(default_factory=list)
    remediations: List[str] = field(default_factory=list)

@dataclass
class HostResult:
    ip: str
    hostname: str = ""
    is_alive: bool = False
    open_ports: List[PortResult] = field(default_factory=list)
    scan_time_sec: float = 0.0
    risk_level: str = "none"    # none | low | medium | high | critical

@dataclass
class ScanReport:
    scan_id: str
    target: str
    port_range: str
    thread_count: int
    start_time: str
    end_time: str = ""
    duration_sec: float = 0.0
    hosts: List[HostResult] = field(default_factory=list)
    total_open_ports: int = 0
    summary: str = ""


# ──────────────────────────────────────────────
# KNOWN SERVICES & VULNERABILITY DATABASE
# ──────────────────────────────────────────────

COMMON_SERVICES = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    135:  "MS-RPC",
    139:  "NetBIOS",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    993:  "IMAPS",
    995:  "POP3S",
    1433: "MSSQL",
    1521: "Oracle DB",
    2181: "Zookeeper",
    3306: "MySQL",
    3389: "RDP",
    4444: "Metasploit default",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    6443: "Kubernetes API",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "Jupyter Notebook",
    9200: "Elasticsearch",
    27017:"MongoDB",
}

# ──────────────────────────────────────────────
# STRUCTURED VULNERABILITY + REMEDIATION DATABASE
# Each entry: { "vulnerabilities": [...], "remediations": [...] }
# Remediations are actionable, step-by-step fix instructions.
# ──────────────────────────────────────────────

VULN_REMEDIATION_DB = {
    21: {
        "vulnerabilities": [
            "FTP may allow anonymous login (user: 'anonymous', any password)",
            "FTP transmits credentials and data in plaintext — MITM risk",
            "Outdated vsftpd/ProFTPD versions may have known RCE CVEs",
        ],
        "remediations": [
            "DISABLE anonymous FTP: in vsftpd.conf set 'anonymous_enable=NO'; "
            "in ProFTPD set 'Anonymous ~ { }' block removed or denied",
            "REPLACE FTP with SFTP (SSH File Transfer): install openssh-server, "
            "create an sftp-only group, and restrict with 'ForceCommand internal-sftp' in sshd_config",
            "If FTP must stay, enforce FTPS (FTP over TLS): in vsftpd.conf set "
            "'ssl_enable=YES', 'force_local_data_ssl=YES', 'force_local_logins_ssl=YES'",
            "UPDATE the FTP daemon: run 'apt upgrade vsftpd' or 'yum update proftpd'; "
            "check CVE database at https://nvd.nist.gov for your version",
            "FIREWALL: restrict FTP (port 21) to trusted IPs only using iptables or ufw: "
            "'ufw allow from 192.168.1.0/24 to any port 21'",
        ],
    },
    22: {
        "vulnerabilities": [
            "SSH password authentication enables brute-force attacks",
            "SSH version 1 protocol (if enabled) is vulnerable to MITM",
            "Unrestricted SSH access exposes all user accounts",
        ],
        "remediations": [
            "DISABLE password auth — use SSH keys only: in /etc/ssh/sshd_config set "
            "'PasswordAuthentication no', 'PubkeyAuthentication yes'; then 'systemctl restart sshd'",
            "GENERATE a key pair on your client: 'ssh-keygen -t ed25519 -C your@email.com'; "
            "copy to server: 'ssh-copy-id user@server'",
            "RESTRICT access in sshd_config: 'AllowUsers kundan admin', "
            "'PermitRootLogin no', 'Protocol 2' (disables SSHv1)",
            "CHANGE default port (optional hardening): set 'Port 2222' in sshd_config "
            "and update firewall rule — reduces automated scan noise",
            "INSTALL fail2ban to auto-ban repeated failures: "
            "'apt install fail2ban'; default config bans after 5 failed attempts",
            "ENABLE 2FA with Google Authenticator: "
            "'apt install libpam-google-authenticator'; run 'google-authenticator' as each user",
        ],
    },
    23: {
        "vulnerabilities": [
            "Telnet transmits ALL data (including passwords) in plaintext",
            "Telnet has no encryption — trivially intercepted on any shared network",
            "Telnet daemons are rarely patched and contain old vulnerabilities",
        ],
        "remediations": [
            "IMMEDIATELY disable Telnet: 'systemctl stop telnet.socket && "
            "systemctl disable telnet.socket'; or 'apt remove telnetd'",
            "REPLACE with SSH: 'apt install openssh-server && systemctl enable ssh'",
            "If a device only supports Telnet (e.g. old router/switch), "
            "create an SSH tunnel: 'ssh -L 2323:device_ip:23 jumphost' and connect via localhost:2323",
            "FIREWALL: block port 23 from all external traffic immediately: "
            "'ufw deny 23' or 'iptables -A INPUT -p tcp --dport 23 -j DROP'",
        ],
    },
    25: {
        "vulnerabilities": [
            "Open SMTP relay allows anyone to send email through your server (spam/phishing)",
            "Missing STARTTLS means email credentials and content travel in plaintext",
            "Mail header injection can enable phishing campaigns via your domain",
        ],
        "remediations": [
            "DISABLE open relay in Postfix: in /etc/postfix/main.cf set "
            "'smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject'",
            "ENFORCE STARTTLS in Postfix: add 'smtpd_tls_security_level = encrypt', "
            "'smtpd_tls_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem' to main.cf",
            "ENABLE SPF, DKIM, DMARC DNS records to prevent spoofing of your domain — "
            "check current config at https://mxtoolbox.com/SuperTool.aspx",
            "RESTRICT SMTP to authenticated users only: "
            "'smtpd_sasl_auth_enable = yes' and 'smtpd_sasl_security_options = noanonymous'",
            "MONITOR outbound email volume to detect abuse: "
            "install pflogsumm ('apt install pflogsumm') and review daily mail logs",
        ],
    },
    53: {
        "vulnerabilities": [
            "DNS zone transfer (AXFR) may expose your entire internal DNS structure",
            "Open DNS resolver can be abused for amplification DDoS attacks",
            "DNS cache poisoning if DNSSEC is not enabled",
        ],
        "remediations": [
            "RESTRICT zone transfers in BIND: in named.conf add "
            "'allow-transfer { none; };' globally, or specify trusted secondary IPs only",
            "DISABLE open recursive resolution: in named.conf set "
            "'allow-recursion { 127.0.0.1; 192.168.1.0/24; };' — limit to local networks only",
            "ENABLE DNSSEC on your zones: run 'dnssec-keygen -a ECDSAP256SHA256 -n ZONE yourdomain.com' "
            "and sign zones; verify at https://dnssec-analyzer.verisignlabs.com",
            "TEST for AXFR leak yourself: 'dig axfr yourdomain.com @your_dns_ip' — "
            "if it returns records, your zone transfer is open",
            "UPDATE BIND/dnsmasq regularly: 'apt upgrade bind9' — DNS daemons have had critical CVEs",
        ],
    },
    80: {
        "vulnerabilities": [
            "HTTP is unencrypted — login credentials and session tokens sent in plaintext",
            "Exposed admin panels (/admin, /phpmyadmin) are common attack targets",
            "Server version disclosure in headers aids targeted exploitation",
            "Directory listing may expose sensitive files",
        ],
        "remediations": [
            "FORCE HTTPS redirect: in Apache add 'Redirect permanent / https://yourdomain.com/' "
            "or in Nginx: 'return 301 https://$host$request_uri;'",
            "GET a free TLS certificate via Let's Encrypt: "
            "'apt install certbot python3-certbot-nginx && certbot --nginx -d yourdomain.com'",
            "HIDE server version: in Apache httpd.conf set 'ServerTokens Prod' and 'ServerSignature Off'; "
            "in Nginx set 'server_tokens off;'",
            "DISABLE directory listing: in Apache set 'Options -Indexes' in Directory block; "
            "in Nginx remove 'autoindex on;'",
            "RESTRICT admin panels by IP: in Nginx add 'allow 192.168.1.0/24; deny all;' "
            "inside the /admin location block",
            "ADD security headers: X-Frame-Options, X-Content-Type-Options, Content-Security-Policy — "
            "test current headers at https://securityheaders.com",
        ],
    },
    110: {
        "vulnerabilities": [
            "POP3 transmits email and login credentials in plaintext",
        ],
        "remediations": [
            "MIGRATE to POP3S (port 995): in Dovecot config set "
            "'ssl = required' in /etc/dovecot/conf.d/10-ssl.conf",
            "DISABLE plaintext POP3: in Dovecot set "
            "'disable_plaintext_auth = yes' to force TLS-only connections",
            "CONSIDER migrating to IMAPS (993) instead — IMAP supports server-side folders "
            "and is better suited for multi-device access",
            "FIREWALL: block port 110 externally: 'ufw deny 110'; allow 995 only",
        ],
    },
    135: {
        "vulnerabilities": [
            "MS-RPC exposed externally — enabled RCE exploits (e.g. MS03-026, Blaster worm)",
            "DCOM interfaces accessible over port 135 can be abused for lateral movement",
        ],
        "remediations": [
            "BLOCK port 135 at the perimeter firewall — it should NEVER be internet-facing",
            "On Windows: open Windows Firewall > Advanced Settings > Inbound Rules > "
            "disable or restrict 'Remote Procedure Call' rules to internal subnets only",
            "DISABLE DCOM if not needed: run 'dcomcnfg', navigate to "
            "Component Services > Computers > My Computer > Properties > Default Properties, "
            "uncheck 'Enable Distributed COM on this computer'",
            "APPLY all Windows security updates — MS03-026 is patched but unpatched systems remain vulnerable",
            "AUDIT with: 'netstat -an | findstr :135' to confirm if actively listening",
        ],
    },
    139: {
        "vulnerabilities": [
            "NetBIOS exposes machine name, workgroup, and share information",
            "Linked to EternalBlue SMB exploit chain — used by WannaCry ransomware",
        ],
        "remediations": [
            "DISABLE NetBIOS over TCP/IP: Network Adapter > Properties > IPv4 > Advanced > WINS tab > "
            "'Disable NetBIOS over TCP/IP'",
            "BLOCK ports 137-139 at firewall — never expose to internet",
            "DISABLE the Computer Browser service on Windows: "
            "'sc config browser start= disabled && net stop browser'",
            "See also port 445 (SMB) remediations — ports 139 and 445 are commonly exploited together",
        ],
    },
    143: {
        "vulnerabilities": [
            "IMAP plaintext — email content and credentials transmitted unencrypted",
        ],
        "remediations": [
            "ENFORCE IMAPS (port 993): in Dovecot set 'ssl = required' in 10-ssl.conf",
            "DISABLE plaintext IMAP: set 'disable_plaintext_auth = yes' in Dovecot",
            "CONFIGURE TLS certificate: set 'ssl_cert' and 'ssl_key' paths in Dovecot ssl config",
            "FIREWALL: block port 143 externally; allow 993 only: 'ufw deny 143 && ufw allow 993'",
        ],
    },
    443: {
        "vulnerabilities": [
            "Expired or self-signed TLS certificate triggers browser warnings and MITM risk",
            "Weak cipher suites (SSLv3, TLS 1.0/1.1, RC4) allow protocol downgrade attacks",
            "Heartbleed (CVE-2014-0160) on unpatched OpenSSL leaks server memory",
        ],
        "remediations": [
            "CHECK certificate expiry: 'echo | openssl s_client -connect yourdomain.com:443 2>/dev/null "
            "| openssl x509 -noout -dates'",
            "AUTO-RENEW with Let's Encrypt: 'certbot renew --dry-run'; add to cron: "
            "'0 3 * * * certbot renew --quiet'",
            "DISABLE weak protocols: in Nginx add 'ssl_protocols TLSv1.2 TLSv1.3;'; "
            "in Apache: 'SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1'",
            "SET strong cipher suites: 'ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;' "
            "in Nginx",
            "TEST your SSL configuration at https://www.ssllabs.com/ssltest/ — aim for grade A+",
            "UPDATE OpenSSL: 'apt upgrade openssl' — verify version is >= 1.0.1g to avoid Heartbleed",
        ],
    },
    445: {
        "vulnerabilities": [
            "SMBv1 is vulnerable to EternalBlue (MS17-010) — used by WannaCry and NotPetya ransomware",
            "Null session enumeration can expose user accounts and shares",
            "SMB brute-force attacks are common on internet-exposed systems",
        ],
        "remediations": [
            "DISABLE SMBv1 immediately on Windows: "
            "'Set-SmbServerConfiguration -EnableSMB1Protocol $false' in PowerShell (run as Admin)",
            "VERIFY SMBv1 is off: 'Get-SmbServerConfiguration | Select EnableSMB1Protocol' — should return False",
            "APPLY MS17-010 patch: ensure KB4012212 (Win7) or KB4012215 (Win8.1) or "
            "KB4013429 (Win10) is installed — check via 'wmic qfe list | findstr KB4012'",
            "BLOCK port 445 at perimeter firewall — SMB should NEVER be internet-facing",
            "DISABLE null sessions: in registry set "
            "'HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA\\RestrictAnonymous = 2'",
            "ENABLE Windows Defender / EDR to detect lateral movement via SMB",
        ],
    },
    1433: {
        "vulnerabilities": [
            "MSSQL exposed externally — brute-force and SQL injection attacks",
            "SA (System Administrator) account with weak password gives full DB access",
            "xp_cmdshell procedure allows OS command execution from SQL queries",
        ],
        "remediations": [
            "BIND to localhost only: in SQL Server Configuration Manager, "
            "set TCP/IP properties > IP Addresses > IPAll > TCP Port = 1433, "
            "and in Windows Firewall block inbound 1433 from external IPs",
            "DISABLE SA account: in SSMS run "
            "'ALTER LOGIN sa DISABLE;' — use a named admin account instead",
            "DISABLE xp_cmdshell: run "
            "'EXEC sp_configure \"xp_cmdshell\", 0; RECONFIGURE;' in SQL Server",
            "ENABLE SQL Server Audit: log all login attempts to detect brute-force",
            "USE Windows Authentication instead of SQL auth where possible — "
            "avoids credential exposure in connection strings",
        ],
    },
    3306: {
        "vulnerabilities": [
            "MySQL/MariaDB exposed externally — attackers can brute-force credentials",
            "Root account with no password or weak password gives full DB access",
            "Old MySQL versions have known privilege escalation CVEs",
        ],
        "remediations": [
            "BIND to localhost: in /etc/mysql/mysql.conf.d/mysqld.cnf set "
            "'bind-address = 127.0.0.1'; then 'systemctl restart mysql'",
            "SECURE the root account: run 'mysql_secure_installation' — "
            "sets root password, removes anonymous users, removes test DB",
            "CREATE per-app users with minimal privileges: "
            "'CREATE USER \"appuser\"@\"localhost\" IDENTIFIED BY \"StrongPass!\"; "
            "GRANT SELECT,INSERT,UPDATE ON appdb.* TO \"appuser\"@\"localhost\";'",
            "FIREWALL: block port 3306 externally: 'ufw deny 3306'",
            "UPDATE MySQL: 'apt upgrade mysql-server' — check for CVEs at https://www.mysql.com/support/",
            "If remote access is needed, use SSH tunnel: "
            "'ssh -L 3307:127.0.0.1:3306 user@server' and connect to localhost:3307",
        ],
    },
    3389: {
        "vulnerabilities": [
            "RDP is a top target for brute-force and credential stuffing attacks",
            "BlueKeep (CVE-2019-0708) allows unauthenticated RCE on Windows 7/Server 2008",
            "DejaBlue (CVE-2019-1181/1182) affects Windows 10 without NLA",
        ],
        "remediations": [
            "ENABLE Network Level Authentication (NLA): "
            "System Properties > Remote > 'Allow connections only from computers running "
            "Remote Desktop with NLA'",
            "APPLY BlueKeep patch: install KB4499175 (Win7/2008) or KB4499180 (Win2008 R2) — "
            "verify via 'wmic qfe list | findstr KB4499'",
            "CHANGE default RDP port (3389) to a non-standard port: "
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp > PortNumber",
            "RESTRICT access by IP in Windows Firewall: Inbound Rules > RDP > Scope > "
            "Remote IP = your office/VPN IP range only",
            "ENABLE Account Lockout Policy: gpedit.msc > "
            "Account Lockout Policy > set threshold to 5 attempts",
            "USE a VPN for RDP access instead of exposing port 3389 directly to the internet",
            "INSTALL RDP Gateway or Azure AD Application Proxy for enterprise environments",
        ],
    },
    4444: {
        "vulnerabilities": [
            "Port 4444 is the default Metasploit Framework reverse shell listener",
            "Open port 4444 strongly suggests an active backdoor or compromised service",
        ],
        "remediations": [
            "INVESTIGATE IMMEDIATELY: run 'netstat -tulnp | grep 4444' to identify the process",
            "KILL the suspicious process: 'kill -9 <PID>' after identifying it",
            "SCAN for malware: run ClamAV ('clamscan -r /') or Malwarebytes (Windows)",
            "CHECK crontab for persistence: 'crontab -l' and 'cat /etc/crontab'",
            "REVIEW recently modified files: 'find / -mtime -7 -type f 2>/dev/null | head -50'",
            "ISOLATE the host from the network and perform a full incident response procedure",
            "RESTORE from a known-clean backup after confirming the infection vector",
        ],
    },
    5432: {
        "vulnerabilities": [
            "PostgreSQL exposed externally — brute-force and SQL injection risk",
            "Default 'postgres' superuser with weak password gives full DB control",
        ],
        "remediations": [
            "BIND to localhost: in postgresql.conf set "
            "'listen_addresses = \"localhost\"'; then 'systemctl restart postgresql'",
            "CONFIGURE pg_hba.conf for strict access control: "
            "change 'host all all 0.0.0.0/0 md5' to "
            "'host all all 127.0.0.1/32 scram-sha-256'",
            "SET a strong password for postgres superuser: "
            "'psql -c \"ALTER USER postgres WITH PASSWORD \\'NewStrongPass!\\';\"'",
            "CREATE application-specific roles with least privilege: "
            "'CREATE ROLE appuser LOGIN PASSWORD \"pass\"; GRANT CONNECT ON DATABASE appdb TO appuser;'",
            "FIREWALL: block port 5432 externally: 'ufw deny 5432'",
            "USE SSL connections: set 'ssl = on' in postgresql.conf and provide ssl cert/key",
        ],
    },
    5900: {
        "vulnerabilities": [
            "VNC exposed — common target for brute-force attacks",
            "Many VNC implementations have no account lockout after failed attempts",
            "VNC traffic (screen content) may be transmitted unencrypted",
        ],
        "remediations": [
            "TUNNEL VNC over SSH instead of exposing it directly: "
            "'ssh -L 5901:localhost:5900 user@server' then connect VNC to localhost:5901",
            "BLOCK port 5900 at firewall entirely: 'ufw deny 5900'",
            "SET a strong VNC password (8+ chars): in TigerVNC run 'vncpasswd'",
            "CONFIGURE VNC to listen on localhost only: start vncserver with "
            "'-localhost' flag: 'vncserver -localhost :1'",
            "CONSIDER replacing VNC with a modern alternative: "
            "RustDesk (self-hosted, encrypted) or Guacamole (browser-based, SSH/RDP/VNC gateway)",
            "ENABLE fail2ban for VNC port to block repeated failed attempts",
        ],
    },
    6379: {
        "vulnerabilities": [
            "Redis with no authentication — CRITICAL: full server compromise possible",
            "Attackers can write SSH keys to authorized_keys via Redis CONFIG SET",
            "Attackers can schedule cron jobs via Redis to achieve code execution",
        ],
        "remediations": [
            "SET a strong password immediately: in /etc/redis/redis.conf add "
            "'requirepass YourVeryStrongPasswordHere'; then 'systemctl restart redis'",
            "BIND to localhost: in redis.conf set 'bind 127.0.0.1 ::1' — "
            "removes all external access",
            "DISABLE dangerous commands: in redis.conf add "
            "'rename-command CONFIG \"\"' and 'rename-command FLUSHALL \"\"'",
            "RUN Redis as a non-root user: 'User=redis' in the systemd service file",
            "ENABLE Redis ACL (Redis 6+): use 'ACL SETUSER' to create users with "
            "specific command and key permissions",
            "FIREWALL: block port 6379 from all external IPs: 'ufw deny 6379'",
            "CHECK if already compromised: look for unknown SSH keys in "
            "'~/.ssh/authorized_keys' and suspicious crontab entries",
        ],
    },
    8080: {
        "vulnerabilities": [
            "HTTP-Alt often runs development servers or unpatched app servers (Tomcat, Jenkins)",
            "May expose admin panels without authentication on default installs",
        ],
        "remediations": [
            "IDENTIFY the service: 'curl -I http://localhost:8080' to see server header",
            "If Apache Tomcat: change default credentials (admin/admin, tomcat/tomcat) — "
            "edit /etc/tomcat*/tomcat-users.xml immediately",
            "If Jenkins: ensure 'Enable security' is checked in Manage Jenkins > Configure Global Security; "
            "disable 'Allow users to sign up'",
            "PLACE behind a reverse proxy (Nginx/Apache) with HTTPS and access controls",
            "FIREWALL: block port 8080 externally if only used internally: 'ufw deny 8080'",
            "REDIRECT to HTTPS on port 443 for any production-facing service",
        ],
    },
    8888: {
        "vulnerabilities": [
            "Jupyter Notebook with no token/password = full remote code execution as the server user",
            "Any visitor can create a Terminal and run arbitrary OS commands",
        ],
        "remediations": [
            "SET a password immediately: run 'jupyter notebook password' — "
            "creates a hashed password in ~/.jupyter/jupyter_notebook_config.json",
            "BIND to localhost only: in jupyter_notebook_config.py set "
            "'c.NotebookApp.ip = \"127.0.0.1\"'",
            "ACCESS remotely via SSH tunnel only: "
            "'ssh -L 8888:localhost:8888 user@server' then open http://localhost:8888",
            "NEVER run Jupyter as root — create a dedicated user account",
            "CONSIDER JupyterHub for multi-user environments — provides proper auth and isolation",
            "FIREWALL: block port 8888 from all external access: 'ufw deny 8888'",
        ],
    },
    9200: {
        "vulnerabilities": [
            "Elasticsearch with no auth — all indexed data is publicly readable AND writable",
            "Attackers can delete all indices, inject data, or exfiltrate the entire database",
            "Thousands of Elasticsearch instances have been wiped and held for ransom",
        ],
        "remediations": [
            "ENABLE X-Pack Security (built-in since ES 6.8+): in elasticsearch.yml add "
            "'xpack.security.enabled: true'; then run 'elasticsearch-setup-passwords interactive'",
            "BIND to localhost: in elasticsearch.yml set 'network.host: 127.0.0.1'",
            "FIREWALL: block port 9200 and 9300 from all external IPs immediately: "
            "'ufw deny 9200 && ufw deny 9300'",
            "PLACE behind a reverse proxy (Nginx) with HTTP Basic Auth for any external access",
            "CHECK if data has been stolen: review index list via "
            "'curl http://localhost:9200/_cat/indices?v' — look for 'ransom' or unknown indices",
            "ENABLE audit logging: 'xpack.security.audit.enabled: true' in elasticsearch.yml",
        ],
    },
    27017: {
        "vulnerabilities": [
            "MongoDB with no auth — full read/write access to all databases",
            "Default install (pre-2.6) had no authentication enabled",
            "Hundreds of thousands of exposed MongoDB instances have been ransomed",
        ],
        "remediations": [
            "ENABLE authentication immediately: in /etc/mongod.conf set "
            "'security:\\n  authorization: enabled'; then 'systemctl restart mongod'",
            "CREATE an admin user first: in mongo shell run "
            "'use admin; db.createUser({user:\"admin\", pwd:\"StrongPass!\", roles:[\"root\"]})'",
            "BIND to localhost: in mongod.conf set 'net:\\n  bindIp: 127.0.0.1'",
            "FIREWALL: block port 27017 from all external access: 'ufw deny 27017'",
            "If remote access needed, use SSH tunnel: "
            "'ssh -L 27018:127.0.0.1:27017 user@server' and connect to localhost:27018",
            "CHECK for existing compromise: look for databases named 'README' or 'PWNED' — "
            "sign of ransomware that has already wiped your data",
            "ENABLE TLS for MongoDB connections: configure 'net.tls' in mongod.conf",
        ],
    },
}

def get_vuln_data(port: int):
    """Return (vulnerabilities, remediations) for a port."""
    entry = VULN_REMEDIATION_DB.get(port, {})
    return entry.get("vulnerabilities", []), entry.get("remediations", [])

RISK_WEIGHTS = {
    23: 10, 4444: 10, 6379: 9, 9200: 9, 27017: 9,
    445: 8, 3389: 8, 8888: 8,
    21: 6, 3306: 6, 5432: 6, 5900: 6,
    22: 3, 80: 2, 8080: 2,
}

def get_service(port: int) -> str:
    return COMMON_SERVICES.get(port, "unknown")

def compute_risk(open_ports: List[PortResult]) -> str:
    score = 0
    for p in open_ports:
        score += RISK_WEIGHTS.get(p.port, 1)
    if score == 0:    return "none"
    if score <= 3:    return "low"
    if score <= 8:    return "medium"
    if score <= 15:   return "high"
    return "critical"


# ──────────────────────────────────────────────
# BANNER GRABBING
# ──────────────────────────────────────────────

def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """Attempt to grab a service banner."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            # Send HTTP request for web ports
            if port in (80, 8080, 8443, 443):
                s.send(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
            banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
            # Return first meaningful line only
            first_line = banner.split("\n")[0][:120]
            return first_line
    except Exception:
        return ""


# ──────────────────────────────────────────────
# PORT SCANNER (C-style socket, single port)
# ──────────────────────────────────────────────

def scan_port(ip: str, port: int, timeout: float, grab_banners: bool) -> Optional[PortResult]:
    """
    Scan a single TCP port using raw socket.
    Returns PortResult if open, None if closed/filtered.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()

        if result == 0:
            service = get_service(port)
            banner = grab_banner(ip, port) if grab_banners else ""
            vulns, remeds = get_vuln_data(port)
            return PortResult(
                port=port,
                state="open",
                service=service,
                banner=banner,
                vulnerabilities=vulns,
                remediations=remeds,
            )
        return None
    except socket.error:
        return None


# ──────────────────────────────────────────────
# HOST SCANNER (thread pool per host)
# ──────────────────────────────────────────────

def is_host_alive(ip: str, timeout: float = 1.5) -> bool:
    """Quick liveness check — try connecting to port 80 or 443."""
    for port in (80, 443, 22, 3389):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            if sock.connect_ex((ip, port)) == 0:
                sock.close()
                return True
            sock.close()
        except Exception:
            pass
    # Fallback: try raw connect on port 1
    try:
        socket.setdefaulttimeout(timeout)
        socket.gethostbyaddr(ip)
        return True
    except Exception:
        pass
    return False


def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def scan_host(ip: str, ports: List[int], thread_count: int,
              timeout: float, grab_banners: bool,
              verbose: bool) -> HostResult:
    """Scan all ports on a single host using a thread pool."""
    host = HostResult(ip=ip)
    host.hostname = resolve_hostname(ip)
    t0 = time.time()

    if verbose:
        print(f"  [→] Scanning {ip} ({host.hostname or 'no rDNS'}) — {len(ports)} ports")

    open_ports = []
    lock = threading.Lock()

    def worker(port):
        result = scan_port(ip, port, timeout, grab_banners)
        if result:
            with lock:
                open_ports.append(result)
                if verbose:
                    print(f"      [OPEN] {ip}:{port:5d}  {result.service:20s}  {result.banner[:60]}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
        executor.map(worker, ports)

    host.open_ports = sorted(open_ports, key=lambda p: p.port)
    host.is_alive = len(open_ports) > 0 or is_host_alive(ip)
    host.scan_time_sec = round(time.time() - t0, 2)
    host.risk_level = compute_risk(host.open_ports)
    return host


# ──────────────────────────────────────────────
# IP RANGE PARSER
# ──────────────────────────────────────────────

def parse_targets(target_str: str) -> List[str]:
    """
    Parse target string into list of IP strings.
    Supports: single IP, CIDR, comma-separated list.
    Examples: 192.168.1.1 | 192.168.1.0/24 | 10.0.0.1,10.0.0.2
    """
    targets = []
    for part in target_str.split(","):
        part = part.strip()
        try:
            network = ipaddress.ip_network(part, strict=False)
            targets.extend(str(ip) for ip in network.hosts())
        except ValueError:
            print(f"[!] Invalid target: {part}")
    return targets


def parse_ports(port_str: str) -> List[int]:
    """
    Parse port string into list of ints.
    Supports: 80 | 80,443 | 1-1024 | top100
    """
    TOP_100 = [
        21,22,23,25,53,80,110,111,119,135,139,143,194,443,445,
        465,514,515,587,631,993,995,1025,1433,1434,1521,1720,
        1723,2049,2121,2181,3306,3389,4444,5432,5800,5900,6379,
        6443,7001,8008,8080,8443,8888,9000,9200,9300,27017,49152
    ]
    if port_str.lower() == "top100":
        return TOP_100
    ports = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


# ──────────────────────────────────────────────
# REPORT GENERATOR
# ──────────────────────────────────────────────

RISK_COLOR = {
    "none":     "  ",
    "low":      "LOW     ",
    "medium":   "MEDIUM  ",
    "high":     "HIGH    ",
    "critical": "CRITICAL",
}

# Priority label per risk level shown in remediation plan header
PRIORITY_LABEL = {
    "critical": "PRIORITY 1 — FIX IMMEDIATELY",
    "high":     "PRIORITY 2 — FIX WITHIN 24 HOURS",
    "medium":   "PRIORITY 3 — FIX WITHIN 1 WEEK",
    "low":      "PRIORITY 4 — FIX WITHIN 1 MONTH",
    "none":     "INFORMATIONAL",
}

def print_report(report: ScanReport):
    sep  = "═" * 70
    thin = "─" * 70

    print(f"\n{sep}")
    print(f"  NETWORK SECURITY SCAN REPORT")
    print(f"  Scan ID   : {report.scan_id}")
    print(f"  Target    : {report.target}")
    print(f"  Ports     : {report.port_range}")
    print(f"  Threads   : {report.thread_count}")
    print(f"  Started   : {report.start_time}")
    print(f"  Finished  : {report.end_time}")
    print(f"  Duration  : {report.duration_sec:.1f}s")
    print(sep)

    # ── Per-host findings ──────────────────────────────────────
    for host in report.hosts:
        if not host.is_alive and not host.open_ports:
            continue
        risk_label = RISK_COLOR.get(host.risk_level, "        ")
        print(f"\n  HOST: {host.ip}  ({host.hostname or 'no rDNS'})")
        print(f"  Risk Level : [{risk_label}]   Scan time: {host.scan_time_sec}s")
        print(f"  {thin}")

        if not host.open_ports:
            print("  No open ports found.")
            continue

        # Open ports table
        print(f"  {'PORT':<8} {'STATE':<10} {'SERVICE':<22} BANNER")
        print(f"  {'─'*6:<8} {'─'*8:<10} {'─'*20:<22} {'─'*20}")
        for p in host.open_ports:
            banner_short = p.banner[:35] + "…" if len(p.banner) > 35 else p.banner
            print(f"  {p.port:<8} {'open':<10} {p.service:<22} {banner_short}")

        # ── Vulnerability Findings ──────────────────────────
        has_vulns = any(p.vulnerabilities for p in host.open_ports)
        if has_vulns:
            print(f"\n  {'─'*70}")
            print(f"  VULNERABILITY FINDINGS")
            print(f"  {'─'*70}")
            for p in host.open_ports:
                if p.vulnerabilities:
                    print(f"\n  [Port {p.port} — {p.service}]")
                    for v in p.vulnerabilities:
                        print(f"    ⚠  {v}")

        # ── Remediation Plan ────────────────────────────────
        has_remeds = any(p.remediations for p in host.open_ports)
        if has_remeds:
            priority = PRIORITY_LABEL.get(host.risk_level, "")
            print(f"\n  {'═'*70}")
            print(f"  REMEDIATION PLAN  —  {priority}")
            print(f"  {'═'*70}")
            print(f"  The following steps will resolve the vulnerabilities found on {host.ip}.")
            print(f"  Work through them in order — highest-risk ports first.\n")

            # Sort ports by risk weight descending so most dangerous come first
            sorted_ports = sorted(
                [p for p in host.open_ports if p.remediations],
                key=lambda p: RISK_WEIGHTS.get(p.port, 1),
                reverse=True
            )
            for idx, p in enumerate(sorted_ports, start=1):
                port_risk = "CRITICAL" if RISK_WEIGHTS.get(p.port, 0) >= 9 else \
                            "HIGH"     if RISK_WEIGHTS.get(p.port, 0) >= 6 else \
                            "MEDIUM"   if RISK_WEIGHTS.get(p.port, 0) >= 3 else "LOW"
                print(f"  ┌─ [{idx}] Port {p.port} ({p.service})  [{port_risk}]")
                for step_num, step in enumerate(p.remediations, start=1):
                    # Word-wrap long lines at ~65 chars
                    words = step.split()
                    lines = []
                    current = ""
                    for word in words:
                        if len(current) + len(word) + 1 > 63:
                            lines.append(current)
                            current = word
                        else:
                            current = (current + " " + word).strip()
                    if current:
                        lines.append(current)
                    prefix = f"  │   Step {step_num}: "
                    indent = "  │            "
                    print(f"{prefix}{lines[0]}")
                    for line in lines[1:]:
                        print(f"{indent}{line}")
                print(f"  │")
                print(f"  └{'─'*67}")
                print()

    # ── Summary ───────────────────────────────────────────────
    print(f"\n{sep}")
    print(f"  SUMMARY")
    print(f"  Hosts scanned        : {len(report.hosts)}")
    alive = [h for h in report.hosts if h.open_ports]
    print(f"  Hosts with open ports: {len(alive)}")
    print(f"  Total open ports     : {report.total_open_ports}")

    risk_counts = {}
    for h in report.hosts:
        risk_counts[h.risk_level] = risk_counts.get(h.risk_level, 0) + 1
    for level in ["critical", "high", "medium", "low", "none"]:
        count = risk_counts.get(level, 0)
        if count:
            print(f"  {level.capitalize():<10} risk hosts : {count}")

    print(f"\n  {report.summary}")
    print(sep)


def save_json_report(report: ScanReport, filepath: str):
    """Save full report as structured JSON."""
    def default_serializer(obj):
        if hasattr(obj, '__dataclass_fields__'):
            return asdict(obj)
        return str(obj)

    with open(filepath, "w") as f:
        json.dump(asdict(report), f, indent=2, default=default_serializer)
    print(f"\n  [✓] JSON report saved: {filepath}")


def save_txt_report(report: ScanReport, filepath: str):
    """Save human-readable text report."""
    import io
    old_stdout = sys.stdout
    sys.stdout = buffer = io.StringIO()
    print_report(report)
    sys.stdout = old_stdout
    with open(filepath, "w") as f:
        f.write(buffer.getvalue())
    print(f"  [✓] Text report saved: {filepath}")


# ──────────────────────────────────────────────
# MAIN SCANNER ORCHESTRATOR
# ──────────────────────────────────────────────

def run_scan(target: str, port_str: str, threads: int,
             timeout: float, grab_banners: bool,
             output_json: str, output_txt: str,
             verbose: bool) -> ScanReport:

    targets = parse_targets(target)
    ports = parse_ports(port_str)

    scan_id = datetime.datetime.now().strftime("SCAN-%Y%m%d-%H%M%S")
    start_dt = datetime.datetime.now()

    report = ScanReport(
        scan_id=scan_id,
        target=target,
        port_range=port_str,
        thread_count=threads,
        start_time=start_dt.strftime("%Y-%m-%d %H:%M:%S"),
    )

    print(f"\n{'═'*70}")
    print(f"  Network Security Scanner  |  Kundan Kumar")
    print(f"  Scan ID  : {scan_id}")
    print(f"  Targets  : {len(targets)} host(s)")
    print(f"  Ports    : {len(ports)} port(s)  [{port_str}]")
    print(f"  Threads  : {threads}  |  Timeout: {timeout}s")
    print(f"  Banners  : {'yes' if grab_banners else 'no'}")
    print(f"{'═'*70}")

    if not targets:
        print("[!] No valid targets. Aborting.")
        return report

    # DISCLAIMER
    print("\n  [!] ETHICAL USE NOTICE: Only scan systems you own or have")
    print("      explicit written permission to test. Unauthorized scanning")
    print("      may violate laws including the Computer Fraud and Abuse Act.")
    print()

    t0 = time.time()
    all_hosts = []

    for ip in targets:
        host_result = scan_host(ip, ports, threads, timeout, grab_banners, verbose)
        all_hosts.append(host_result)

    report.hosts = all_hosts
    report.total_open_ports = sum(len(h.open_ports) for h in all_hosts)
    report.end_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report.duration_sec = round(time.time() - t0, 2)

    # Generate summary sentence
    alive_hosts = [h for h in all_hosts if h.open_ports]
    critical = [h for h in all_hosts if h.risk_level == "critical"]
    high = [h for h in all_hosts if h.risk_level == "high"]
    report.summary = (
        f"Found {report.total_open_ports} open port(s) across "
        f"{len(alive_hosts)}/{len(all_hosts)} host(s). "
        f"Critical risk: {len(critical)}, High risk: {len(high)}. "
        f"Immediate attention recommended for high/critical hosts."
    )

    print_report(report)

    if output_json:
        save_json_report(report, output_json)
    if output_txt:
        save_txt_report(report, output_txt)

    return report


# ──────────────────────────────────────────────
# CLI ENTRY POINT
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="scanner",
        description="Network Security Scanner — multi-threaded port scanner with vulnerability hints",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python scanner.py -t 192.168.1.1 -p top100
  python scanner.py -t 192.168.1.0/24 -p 22,80,443,3306 --threads 200
  python scanner.py -t 10.0.0.1 -p 1-1024 --banners --json report.json
  python scanner.py -t 192.168.1.1,192.168.1.2 -p 80,443 --verbose

NOTE: Only scan systems you own or have written permission to test.
        """
    )
    parser.add_argument("-t", "--target",  required=True,
                        help="Target IP, CIDR, or comma-separated list\n"
                             "e.g. 192.168.1.1 | 192.168.1.0/24 | 10.0.0.1,10.0.0.2")
    parser.add_argument("-p", "--ports",   default="top100",
                        help="Ports to scan: top100 | 80 | 22,80,443 | 1-1024\n(default: top100)")
    parser.add_argument("--threads",       type=int, default=100,
                        help="Number of concurrent threads (default: 100)")
    parser.add_argument("--timeout",       type=float, default=1.0,
                        help="Socket timeout per port in seconds (default: 1.0)")
    parser.add_argument("--banners",       action="store_true",
                        help="Attempt to grab service banners")
    parser.add_argument("--json",          metavar="FILE",
                        help="Save JSON report to FILE")
    parser.add_argument("--txt",           metavar="FILE",
                        help="Save text report to FILE")
    parser.add_argument("--verbose",       action="store_true",
                        help="Print open ports as they are discovered")

    args = parser.parse_args()

    run_scan(
        target=args.target,
        port_str=args.ports,
        threads=args.threads,
        timeout=args.timeout,
        grab_banners=args.banners,
        output_json=args.json,
        output_txt=args.txt,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    main()
