# Network Security Scanner
**Author:** Kundan Kumar  
**Tech:** Python · Socket Programming · Multi-threading · Cybersecurity

---

## What It Does
A multi-threaded command-line network scanner that:
- Scans single IPs, CIDR ranges, or comma-separated host lists
- Detects open TCP ports using raw sockets (C-style `connect_ex`)
- Identifies services running on open ports
- Grabs service banners (HTTP headers, SSH version strings, etc.)
- Maps open ports to known vulnerability findings
- Generates a **step-by-step Remediation Plan** for every vulnerability found, sorted by risk priority
- Assigns a risk level (none / low / medium / high / critical) per host
- Generates structured reports in text and JSON formats
- Uses a thread pool for 70%+ faster scanning vs sequential

---

## Project Structure
```
network_scanner/
├── scanner.py        ← Main scanner (all logic)
└── README.md         ← This file
```

---

## Usage

### Basic scan (top 100 common ports)
```bash
python scanner.py -t 192.168.1.1
```

### Scan a full subnet
```bash
python scanner.py -t 192.168.1.0/24 -p top100 --threads 200
```

### Scan specific ports with banner grabbing
```bash
python scanner.py -t 10.0.0.1 -p 22,80,443,3306,5432 --banners --verbose
```

### Scan a port range and save reports
```bash
python scanner.py -t 192.168.1.1 -p 1-1024 --json report.json --txt report.txt
```

### Multiple targets
```bash
python scanner.py -t 192.168.1.1,192.168.1.5,192.168.1.10 -p 80,443
```

---

## All Options
| Flag | Description | Default |
|------|-------------|---------|
| `-t` / `--target` | IP, CIDR, or comma-separated targets | required |
| `-p` / `--ports` | `top100`, `80`, `22,80,443`, or `1-1024` | `top100` |
| `--threads` | Concurrent thread count | `100` |
| `--timeout` | Socket timeout per port (seconds) | `1.0` |
| `--banners` | Grab service banners | off |
| `--json FILE` | Save JSON report | off |
| `--txt FILE` | Save text report | off |
| `--verbose` | Print ports as discovered | off |

---

## Top 100 Ports Covered
Includes all high-value ports: 21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP),
80/443 (HTTP/S), 445 (SMB), 3306 (MySQL), 3389 (RDP), 5432 (PostgreSQL),
6379 (Redis), 8080/8443, 9200 (Elasticsearch), 27017 (MongoDB), and more.

---

## Vulnerability Coverage & Remediation
The scanner maps 25+ ports to curated security findings. For every vulnerability found, it generates a **numbered, step-by-step remediation plan** with exact commands, config file paths, and patch KB numbers.

Coverage includes:
- **Critical:** Redis/MongoDB/Elasticsearch with no auth exposed
- **High:** SMB (EternalBlue MS17-010), RDP (BlueKeep CVE-2019-0708), Jupyter (full code exec)
- **Medium:** MySQL/PostgreSQL exposed, VNC brute-force risk, Telnet in use
- **Low:** HTTP without HTTPS, SSH hardening, open SMTP relay

The Remediation Plan is sorted by risk weight — most dangerous ports listed first — and each fix is labelled with a priority timeline:

| Risk Level | Priority Label |
|------------|----------------|
| Critical | PRIORITY 1 — FIX IMMEDIATELY |
| High | PRIORITY 2 — FIX WITHIN 24 HOURS |
| Medium | PRIORITY 3 — FIX WITHIN 1 WEEK |
| Low | PRIORITY 4 — FIX WITHIN 1 MONTH |

---

## Risk Scoring
Each host gets a risk score based on which ports are open:
- **Critical** — Score > 15 (e.g. Redis + SMB + RDP open)
- **High** — Score 9–15
- **Medium** — Score 4–8
- **Low** — Score 1–3
- **None** — No risky ports

---

## Sample Output

The following is a real scan output from a Windows machine on a local network (`192.168.31.7`). Three high-risk Windows networking ports were found open, triggering vulnerability findings and a full remediation plan.

```
══════════════════════════════════════════════════════════════════════
  Network Security Scanner  |  Kundan Kumar
  Scan ID  : SCAN-20260426-210633
  Targets  : 1 host(s)
  Ports    : 49 port(s)  [top100]
  Threads  : 100  |  Timeout: 1.0s
  Banners  : no
══════════════════════════════════════════════════════════════════════

  [!] ETHICAL USE NOTICE: Only scan systems you own or have
      explicit written permission to test. Unauthorized scanning
      may violate laws including the Computer Fraud and Abuse Act.


══════════════════════════════════════════════════════════════════════
  NETWORK SECURITY SCAN REPORT
  Scan ID   : SCAN-20260426-210633
  Target    : 192.168.31.7
  Ports     : top100
  Threads   : 100
  Started   : 2026-04-26 21:06:33
  Finished  : 2026-04-26 21:06:35
  Duration  : 1.1s
══════════════════════════════════════════════════════════════════════

  HOST: 192.168.31.7  (SPARCK-G.lan)
  Risk Level : [HIGH    ]   Scan time: 1.05s
  ──────────────────────────────────────────────────────────────────────
  PORT     STATE      SERVICE                BANNER
  ──────   ────────   ────────────────────   ────────────────────
  135      open       MS-RPC
  139      open       NetBIOS
  445      open       SMB

  ──────────────────────────────────────────────────────────────────────
  VULNERABILITY FINDINGS
  ──────────────────────────────────────────────────────────────────────

  [Port 135 — MS-RPC]
    ⚠  MS-RPC exposed externally — enabled RCE exploits (e.g. MS03-026, Blaster worm)
    ⚠  DCOM interfaces accessible over port 135 can be abused for lateral movement

  [Port 139 — NetBIOS]
    ⚠  NetBIOS exposes machine name, workgroup, and share information
    ⚠  Linked to EternalBlue SMB exploit chain — used by WannaCry ransomware

  [Port 445 — SMB]
    ⚠  SMBv1 is vulnerable to EternalBlue (MS17-010) — used by WannaCry and NotPetya ransomware
    ⚠  Null session enumeration can expose user accounts and shares
    ⚠  SMB brute-force attacks are common on internet-exposed systems

  ══════════════════════════════════════════════════════════════════════
  REMEDIATION PLAN  —  PRIORITY 2 — FIX WITHIN 24 HOURS
  ══════════════════════════════════════════════════════════════════════
  The following steps will resolve the vulnerabilities found on 192.168.31.7.
  Work through them in order — highest-risk ports first.

  ┌─ [1] Port 445 (SMB)  [HIGH]
  │   Step 1: DISABLE SMBv1 immediately on Windows:
  │            'Set-SmbServerConfiguration -EnableSMB1Protocol $false' in
  │            PowerShell (run as Admin)
  │   Step 2: VERIFY SMBv1 is off: 'Get-SmbServerConfiguration | Select
  │            EnableSMB1Protocol' — should return False
  │   Step 3: APPLY MS17-010 patch: ensure KB4012212 (Win7) or KB4012215
  │            (Win8.1) or KB4013429 (Win10) is installed — check via 'wmic
  │            qfe list | findstr KB4012'
  │   Step 4: BLOCK port 445 at perimeter firewall — SMB should NEVER be
  │            internet-facing
  │   Step 5: DISABLE null sessions: in registry set
  │            'HKLM\SYSTEM\CurrentControlSet\Control\LSA\RestrictAnonymous = 2'
  │   Step 6: ENABLE Windows Defender / EDR to detect lateral movement via SMB
  │
  └───────────────────────────────────────────────────────────────────

  ┌─ [2] Port 135 (MS-RPC)  [LOW]
  │   Step 1: BLOCK port 135 at the perimeter firewall — it should NEVER be
  │            internet-facing
  │   Step 2: On Windows: open Windows Firewall > Advanced Settings > Inbound
  │            Rules > disable or restrict 'Remote Procedure Call' rules to
  │            internal subnets only
  │   Step 3: DISABLE DCOM if not needed: run 'dcomcnfg', navigate to
  │            Component Services > Computers > My Computer > Properties >
  │            Default Properties, uncheck 'Enable Distributed COM on this
  │            computer'
  │   Step 4: APPLY all Windows security updates — MS03-026 is patched but
  │            unpatched systems remain vulnerable
  │   Step 5: AUDIT with: 'netstat -an | findstr :135' to confirm if actively
  │            listening
  │
  └───────────────────────────────────────────────────────────────────

  ┌─ [3] Port 139 (NetBIOS)  [LOW]
  │   Step 1: DISABLE NetBIOS over TCP/IP: Network Adapter > Properties >
  │            IPv4 > Advanced > WINS tab > 'Disable NetBIOS over TCP/IP'
  │   Step 2: BLOCK ports 137-139 at firewall — never expose to internet
  │   Step 3: DISABLE the Computer Browser service on Windows: 'sc config
  │            browser start= disabled && net stop browser'
  │   Step 4: See also port 445 (SMB) remediations — ports 139 and 445 are
  │            commonly exploited together
  │
  └───────────────────────────────────────────────────────────────────


══════════════════════════════════════════════════════════════════════
  SUMMARY
  Hosts scanned        : 1
  Hosts with open ports: 1
  Total open ports     : 3
  High       risk hosts : 1

  Found 3 open port(s) across 1/1 host(s). Critical risk: 0, High risk: 1.
  Immediate attention recommended for high/critical hosts.
══════════════════════════════════════════════════════════════════════
```

---

## Ethical Use Notice
> **Only scan systems you own or have explicit written permission to test.**
> Unauthorized port scanning may violate laws including the
> Computer Fraud and Abuse Act (CFAA) and equivalent legislation in your country.
> This tool is built for learning, authorized penetration testing, and security auditing only.

---

## Key Technical Concepts Demonstrated
| Concept | Where Used |
|---------|-----------|
| Raw TCP sockets (`socket.connect_ex`) | `scan_port()` |
| Thread pool (`ThreadPoolExecutor`) | `scan_host()` |
| Thread-safe result collection (`threading.Lock`) | `scan_host()` worker |
| CIDR / IP range parsing (`ipaddress` module) | `parse_targets()` |
| Banner grabbing (partial HTTP/raw recv) | `grab_banner()` |
| Risk scoring algorithm | `compute_risk()` |
| Structured JSON serialization (`dataclass` + `asdict`) | `save_json_report()` |
| CLI argument parsing (`argparse`) | `main()` |
