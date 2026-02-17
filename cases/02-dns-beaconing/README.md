# Case 02 — Malware Beaconing via DNS

![Wireshark](https://img.shields.io/badge/Wireshark-1679A7?style=for-the-badge&logo=wireshark&logoColor=white)
![Zeek](https://img.shields.io/badge/Zeek-777BB4?style=for-the-badge&logo=zeek&logoColor=white)
![AbuseIPDB](https://img.shields.io/badge/AbuseIPDB-CC0000?style=for-the-badge&logo=abuseipdb&logoColor=white)
![VirusTotal](https://img.shields.io/badge/VirusTotal-394EFF?style=for-the-badge&logo=virustotal&logoColor=white)

---

## 📋 Case Summary

| Field | Details |
|---|---|
| **Case ID** | SOC-2024-002 |
| **Date** | 2024-04-02 |
| **Severity** | 🔴 High |
| **Status** | Closed — Confirmed Incident |
| **Analyst** | Camilo Castellote |
| **MITRE ATT&CK** | T1071.004, T1041, T1568.002, T1027 |

---

## 🚨 Alert Triggered

> **SIEM Rule:** Unusual DNS query volume from single internal host  
> **Source:** Zeek DNS logs — dns.log  
> **Time:** 2024-04-02 09:44:00 UTC  

```
Alert: DNS Query Spike — Threshold exceeded
Host: ACCOUNTING-PC-09
Internal IP: 10.10.8.15
Total DNS queries: 847 in 60 minutes (baseline: ~30/hr)
Unique domains contacted: 312
Query pattern: Randomized subdomains, consistent parent domain
```

---

## 🔍 Investigation Process

### Step 1 — Alert Triage & Validation

**Goal:** Confirm the alert and eliminate false positives (CDN, software updates, browsers).

I first checked if this could be legitimate traffic — Windows Update, antivirus updates, or a browser caching DNS aggressively:

```bash
# Check Zeek dns.log for this host over the alert window
cat dns.log | zeek-cut ts id.orig_h query qtype_name answers \
| grep "10.10.8.15" \
| sort -k3 \
| head -50
```

**Sample of DNS Queries Observed:**

```
09:44:03  10.10.8.15  a7f3k2.updates-cdn77.com      A  [no answer]
09:44:09  10.10.8.15  bx92mq.updates-cdn77.com      A  [no answer]
09:44:15  10.10.8.15  zt18rp.updates-cdn77.com      A  [no answer]
09:44:21  10.10.8.15  kd03yw.updates-cdn77.com      A  [no answer]
09:44:27  10.10.8.15  nv55xj.updates-cdn77.com      A  [no answer]
09:45:03  10.10.8.15  qp77lc.updates-cdn77.com      A  [no answer]
```

**What stands out:**
- All queries share **the same parent domain** (`updates-cdn77.com`)
- Subdomains are **random alphanumeric strings** (not typical CDN naming)
- Queries arrive in a **regular 6-second interval** — consistent beaconing
- Most queries return **no answer (NXDOMAIN)** — typical of DNS tunneling/exfiltration
- ✅ Confirmed **True Positive** — clear beaconing pattern

---

### Step 2 — DNS Pattern Analysis

**Goal:** Measure the regularity and entropy of the queries to confirm beaconing.

```bash
# Extract timestamps and calculate intervals between queries
cat dns.log | zeek-cut ts query \
| grep "10.10.8.15" \
| grep "updates-cdn77.com" \
| awk '{print $1}' \
| awk 'NR>1{printf "%.2f\n", $1-prev} {prev=$1}' \
| sort | uniq -c | sort -rn | head -10
```

**Interval Analysis:**

| Interval (seconds) | Count | % of Total |
|---|---|---|
| 6.00 | 401 | 47.3% |
| 6.01 | 198 | 23.4% |
| 5.99 | 187 | 22.1% |
| 6.02 | 55 | 6.5% |
| Other | 6 | 0.7% |

> ⚠️ **93% of all DNS queries arrive within ±0.01s of a 6-second interval. This is machine-generated beaconing, not human browsing.**

**Subdomain Entropy Check:**

```python
import math, collections

subdomains = ["a7f3k2", "bx92mq", "zt18rp", "kd03yw", "nv55xj", "qp77lc"]
for sub in subdomains:
    freq = collections.Counter(sub)
    entropy = -sum((c/len(sub)) * math.log2(c/len(sub)) for c in freq.values())
    print(f"{sub}: entropy = {entropy:.2f}")

# Output:
# a7f3k2: entropy = 2.58
# bx92mq: entropy = 2.58
# zt18rp: entropy = 2.58
# All subdomains: entropy ~2.58 (high randomness = algorithmically generated)
```

High entropy + regular intervals = **Domain Generation Algorithm (DGA)** behavior.

---

### Step 3 — PCAP Analysis with Wireshark

**Goal:** Inspect the raw packets to look for data being embedded in DNS queries (DNS tunneling).

```bash
# Filter DNS traffic in Wireshark/tshark to the suspicious domain
tshark -r capture.pcap \
  -Y "dns && dns.qry.name contains updates-cdn77.com" \
  -T fields \
  -e frame.time \
  -e ip.src \
  -e dns.qry.name \
  -e dns.resp.name \
  -e frame.len
```

**Packet-Level Findings:**

| Observation | Normal DNS | This Traffic |
|---|---|---|
| Query length | 10–40 bytes | **48–62 bytes** |
| Subdomain length | 3–15 chars | **Exactly 6 chars** |
| Response | IP address | **NXDOMAIN** |
| Interval | Irregular | **Exactly 6s** |
| TXT record queries | Rare | **Present** |

**Suspicious TXT Query Found:**

```
Query: cmQgL2V0Yy9wYXNzd3Jk.updates-cdn77.com TXT
         ^^^^^^^^^^^^^^^^^^^^
         Base64 encoded: "rd /etc/passwd"
```

> ⚠️ **Attacker is encoding stolen data as Base64 in DNS subdomain queries — classic DNS exfiltration technique.**

---

### Step 4 — Endpoint Investigation

**Goal:** Find the malware responsible for the beaconing on ACCOUNTING-PC-09.

Pivoting to Sysmon logs on the infected host:

```spl
index=sysmon host=ACCOUNTING-PC-09 EventCode=3
earliest="2024-04-02T09:40:00" latest="2024-04-02T11:00:00"
| table _time, Image, QueryName, Protocol, Initiated
| sort _time
```

**Process Making DNS Calls:**

```
Process:  C:\Users\patricia\AppData\Roaming\Microsoft\Windows\svcupdate.exe
PID:      4821
Parent:   WINWORD.EXE  ← Microsoft Word spawned the malware
DNS Dest: updates-cdn77.com (repeated)
Started:  2024-04-02 09:43:11 UTC
```

**Parent Process — Word spawned malware:**

```spl
index=sysmon EventCode=1 host=ACCOUNTING-PC-09
ParentImage="*WINWORD.EXE"
| table _time, ParentCommandLine, Image, CommandLine
```

```
ParentCommandLine:  "WINWORD.EXE" /n "Q1_Invoices_Final.docm"
Child Process:       cmd.exe /c powershell -w hidden -ep bypass [encoded]
Grandchild:          svcupdate.exe (dropped to AppData\Roaming\Microsoft\Windows\)
```

> ⚠️ **User opened a malicious macro-enabled Word document (`.docm`). The macro ran a hidden PowerShell command which dropped and executed the DNS beaconing malware.**

---

### Step 5 — IOC Enrichment

**Malicious Domain — `updates-cdn77.com`**

| Field | Value |
|---|---|
| **Registered** | 2024-03-29 (4 days before attack) |
| **Registrar** | Namecheap (privacy protected) |
| **VirusTotal** | 38/90 vendors — DNS Tunneling / C2 |
| **OTX Pulses** | Linked to DNScat2 C2 infrastructure |
| **Hosting IP** | 94.102.49.190 (Netherlands) |

**Malicious File — `svcupdate.exe`**

| Field | Value |
|---|---|
| **MD5** | `c1d2e3f4a5b6789012abcdef34567890` |
| **SHA256** | `cafebabe1234...9876fedc` |
| **VirusTotal** | 61/72 — **DNScat2 client / DNS RAT** |
| **Size** | 156 KB |
| **Packer** | UPX packed (obfuscation) |

**Original Document — `Q1_Invoices_Final.docm`**

| Field | Value |
|---|---|
| **MD5** | `ff00ee11dd22cc33bb44aa5566778899` |
| **VirusTotal** | 49/65 — Macro Dropper |
| **Macro Language** | VBA |
| **Author (metadata)** | `user1` (generic, likely spoofed) |

---

### Step 6 — Exfiltration Scope Assessment

**Goal:** Estimate what data may have been sent over DNS.

```bash
# Calculate total bytes encoded in DNS subdomains
cat dns.log | grep "10.10.8.15" | grep "updates-cdn77.com" \
| awk '{print length($3)-length("updates-cdn77.com")-1}' \
| awk '{sum += $1} END {print "Total exfil bytes (est):", sum}'

# Result: Total exfil bytes (est): 24,822 bytes (~24 KB)
```

```bash
# Decode captured subdomains to identify exfiltrated content
echo "cmQgL2V0Yy9wYXNzd3Jk" | base64 -d
# Output: rd /etc/passwd

echo "aG9zdG5hbWU=" | base64 -d  
# Output: hostname

echo "aXBjb25maWc=" | base64 -d  
# Output: ipconfig
```

**Exfiltrated Data Includes:** hostname, IP configuration, and file directory listings — **reconnaissance data, not sensitive files yet.**

---

### Step 7 — Attack Timeline

```
09:31:04  patricia@ACCOUNTING-PC-09 receives phishing email
           Attachment: "Q1_Invoices_Final.docm"

09:43:01  Patricia opens document — Word macro executes
           Macro runs: powershell -w hidden -ep bypass -EncodedCommand [...]

09:43:11  svcupdate.exe dropped to AppData and executed

09:43:17  First DNS beacon: a7f3k2.updates-cdn77.com (hostname exfil)

09:43:23  Second beacon: bx92mq.updates-cdn77.com (ipconfig exfil)

09:44:00  SIEM alert fires — 847 DNS queries in 60 minutes

09:44:03  Regular 6-second beaconing continues (DGA subdomain pattern)

11:02:00  Host isolated — beaconing stops
```

---

## 🔴 Findings & Impact

| Category | Finding |
|---|---|
| **Initial Access** | Phishing email with malicious `.docm` attachment |
| **Execution** | VBA macro → hidden PowerShell dropper |
| **C2 Channel** | DNS beaconing via DGA subdomains (T1071.004) |
| **Exfiltration** | ~24KB of recon data via DNS TXT/A queries (T1041) |
| **Obfuscation** | Base64 encoded data in subdomain queries (T1027) |
| **Affected Hosts** | ACCOUNTING-PC-09 |
| **Affected Users** | patricia |
| **Data Exfiltrated** | Hostname, IP config, directory listing (no PII confirmed) |

---

## 🛡️ Containment & Recommendations

- [x] Isolated ACCOUNTING-PC-09 from network
- [x] Blocked `updates-cdn77.com` and `94.102.49.190` at DNS/firewall
- [x] Removed `svcupdate.exe` and re-imaged endpoint
- [x] Quarantined `Q1_Invoices_Final.docm` in email gateway
- [x] Notified patricia — phishing awareness follow-up scheduled
- [ ] **Recommend:** Disable macros in Office via GPO for all non-developer users
- [ ] **Recommend:** Deploy DNS filtering (Cisco Umbrella / Cloudflare Gateway) to block DGA domains
- [ ] **Recommend:** Alert on high-volume NXDOMAIN responses from single host
- [ ] **Recommend:** Monitor for Base64 patterns in DNS query strings

---

## 📎 Evidence Files

| File | Description |
|---|---|
| `logs/dns_queries.txt` | Sanitized Zeek dns.log for ACCOUNTING-PC-09 |
| `logs/pcap_analysis.txt` | tshark output — packet-level DNS inspection |
| `logs/sysmon_processes.txt` | Process tree from Sysmon (Word → cmd → svcupdate.exe) |
| `iocs.txt` | All IOCs (domain, IP, file hashes) |

---

## 🗂️ MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Initial Access | Phishing: Spearphishing Attachment | T1566.001 |
| Execution | User Execution: Malicious File | T1204.002 |
| Execution | Command & Scripting: PowerShell | T1059.001 |
| Command & Control | Application Layer Protocol: DNS | T1071.004 |
| Command & Control | Dynamic Resolution: DGA | T1568.002 |
| Exfiltration | Exfiltration Over C2 Channel | T1041 |
| Defense Evasion | Obfuscated Files: Encoding | T1027 |
