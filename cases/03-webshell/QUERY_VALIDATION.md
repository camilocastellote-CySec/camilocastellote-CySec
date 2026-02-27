---

## 🔍 Query Validation Notes

### Environment Assumptions

**SIEM Platform:** Elastic Security (Elasticsearch + Kibana)  
**Data Sources:**
- Apache access logs (via Filebeat)
- Linux auth logs (via Filebeat)
- Auditd process logs (via Auditbeat)

**Field Name Assumptions:**

| Query Field | Standard Name | Alternative Names |
|---|---|---|
| `process.parent.name` | Parent process name | `process.parent.executable`, `parent_process`, `ppid_name` |
| `process.name` | Process name | `process.executable`, `proc_name`, `command` |
| `source.ip` | Source IP address | `src_ip`, `client_ip`, `remote_addr`, `http.request.headers.x-forwarded-for` |
| `http.request.url.path` | URL path | `url.path`, `request_path`, `url` |
| `user.name` | Unix username | `user`, `username`, `uid_name` |

---

### Query 1: Detect Web Server Spawning Shell

**Query (Elastic KQL):**
```kql
process.parent.name: "apache2"
AND process.name: ("bash" OR "sh" OR "python3" OR "wget" OR "curl" OR "find")
```

**Validation Steps:**

1. **Check if process fields exist:**
```kql
   event.dataset: "process"
   | fields process.name, process.parent.name
```
   **Expected:** Both fields populated in results

2. **Verify parent process name format:**
```kql
   process.parent.name: *
   | stats count by process.parent.name
```
   Look for: `apache2`, `/usr/sbin/apache2`, `httpd`

3. **Test specific detection:**
```kql
   process.parent.name: "apache2"
   AND process.name: "bash"
   AND @timestamp >= "2024-05-21T14:30:00"
```
   **Expected:** Should return the `whoami` execution at 14:32:07

**Common Issues & Fixes:**

| Issue | Fix |
|---|---|
| Parent name includes full path | Use wildcards: `process.parent.name: *apache*` |
| Process name case differences | KQL is case-insensitive by default, but verify |
| Different web server (nginx, httpd) | Expand: `process.parent.name: (*apache* OR *httpd* OR *nginx*)` |
| Process name includes args | Use `process.executable` instead of `process.name` |

**Alternative Query:**
```kql
process.parent.executable: (*apache* OR *httpd* OR *nginx*)
AND process.executable: (*bash OR *sh OR */bin/python*)
AND NOT process.parent.args: (*logrotate* OR *cron*)
```

---

### Query 2: Web Shell POST Requests

**Query (Elastic KQL):**
```kql
http.request.url.path: "/uploads/img_cache/thumb_resize.php"
AND NOT http.request.method: "GET"
| sort @timestamp asc
```

**Validation Steps:**

1. **Check HTTP log field names:**
```kql
   event.dataset: "apache.access"
   | fields http.*, url.*, source.ip
```
   **Expected:** Shows available HTTP-related fields

2. **Verify path field format:**
```kql
   http.request.url.path: *
   | stats count by http.request.url.path
   | limit 20
```
   Look for: Full paths like `/uploads/img_cache/thumb_resize.php`

3. **Test method filter:**
```kql
   http.request.url.path: "/uploads/img_cache/thumb_resize.php"
   | stats count by http.request.method
```
   **Expected:** POST count should be 16 (from case timeline)

**Common Issues & Fixes:**

| Issue | Fix |
|---|---|
| `url.path` vs `http.request.url.path` | Try both, depends on Filebeat module version |
| Method field is lowercase | Use `http.request.method: "post"` |
| Path includes query string | Use `url.path: "/uploads/*" AND url.query: "cmd=*"` |
| Different log format (nginx) | Fields may be `nginx.access.url`, `nginx.access.method` |

**Alternative Query (for nginx or custom Apache format):**
```kql
log.file.path: "/var/log/apache2/access.log"
AND message: "*POST /uploads/img_cache/thumb_resize.php*"
| rex field=message "(?<method>\w+) (?<path>/\S+)"
| where path="/uploads/img_cache/thumb_resize.php" AND method="POST"
```

---

### Query 3: Privilege Escalation via sudo

**Query (auth.log via Filebeat):**
```kql
event.dataset: "system.auth"
AND process.name: "sudo"
AND user.name: "www-data"
AND message: *COMMAND*
```

**Validation Steps:**

1. **Check if auth logs are ingested:**
```kql
   event.dataset: "system.auth"
   | stats count by @timestamp
```
   **Expected:** Recent auth log events

2. **Verify sudo events format:**
```kql
   process.name: "sudo"
   | limit 10
```
   Look for fields: `user.name`, `process.args`, `message`

3. **Test for specific sudo command:**
```kql
   event.dataset: "system.auth"
   AND message: "*sudo*www-data*find*"
   AND @timestamp >= "2024-05-21T14:43:00"
```
   **Expected:** Should return the `sudo find` escalation at 14:43:07

**Common Issues & Fixes:**

| Issue | Fix |
|---|---|
| Auth logs not parsed | Check Filebeat system module is enabled |
| User field not extracted | Parse from message: `message: "*www-data*"` |
| Sudo command in different field | Check `system.auth.sudo.command` or `process.command_line` |

**Alternative Query (raw message parsing):**
```kql
log.file.path: "/var/log/auth.log"
AND message: "*sudo*www-data*"
| rex field=message "sudo:\s+(?<sudo_user>\S+)\s+:.*USER=(?<target_user>\w+)\s+; COMMAND=(?<command>.*)"
| where sudo_user="www-data" AND target_user="root"
```

---

### Query 4: File Upload Detection

**Query (Apache access logs):**
```kql
http.request.url.path: "/upload.php"
AND source.ip: "203.0.113.88"
AND @timestamp >= "2024-05-21T14:20:00"
| fields @timestamp, source.ip, http.request.method, http.response.status_code
```

**Validation Steps:**

1. **Verify response codes are captured:**
```kql
   http.request.url.path: "/upload.php"
   | stats count by http.response.status_code
```
   **Expected:** Mix of 200, 403 status codes

2. **Check timestamp format:**
```kql
   http.request.url.path: "/upload.php"
   | eval formatted_time=formatdate(@timestamp, "yyyy-MM-dd HH:mm:ss")
   | limit 5
```
   Verify time matches case timeline (14:25:17, 14:25:49, 14:28:03)

3. **Test IP filter:**
```kql
   source.ip: "203.0.113.88"
   | stats count by http.request.url.path
```
   **Expected:** Should show all attacker requests

**Common Issues & Fixes:**

| Issue | Fix |
|---|---|
| IP in different field | Try `client.ip`, `http.request.headers.x-forwarded-for` |
| Status code as string | Use quotes: `http.response.status_code: "403"` |
| Time zone differences | Convert: `@timestamp >= "2024-05-21T14:20:00Z"` (UTC) |

---

### Query 5: Database Exfiltration Detection (auditd)

**Query (auditd process logs):**
```kql
process.name: ("mysqldump" OR "curl")
AND user.name: "root"
AND @timestamp >= "2024-05-21T14:45:00"
AND @timestamp <= "2024-05-21T14:47:00"
```

**Validation Steps:**

1. **Check auditd data ingestion:**
```kql
   event.module: "auditd"
   | stats count by process.name
   | sort count desc
   | limit 20
```

2. **Verify process arguments are captured:**
```kql
   process.name: "mysqldump"
   | fields process.name, process.args, process.command_line
```
   **Expected:** Should show full command with database name

3. **Test time-based correlation:**
```kql
   (process.name: "mysqldump" OR process.name: "curl")
   AND @timestamp >= "2024-05-21T14:44:00"
   | sort @timestamp asc
```
   **Expected:** mysqldump at 14:45:18, curl at 14:46:03 (ordered)

**Common Issues & Fixes:**

| Issue | Fix |
|---|---|
| Auditd not logging exec calls | Check auditd rules: `auditctl -l` |
| Process args truncated | Use `process.command_line` for full command |
| User name format differs | May be `uid` (numeric) instead of username |

---

### Apache Access Log Parsing (Manual)

**Query (bash):**
```bash
cat /var/log/apache2/access.log | grep "203.0.113.88" | grep "POST"
```

**Validation Steps:**

1. **Check log format:**
```bash
   head -5 /var/log/apache2/access.log
```
   **Expected:** Common Log Format or Combined Log Format

2. **Verify IP appears in logs:**
```bash
   grep -c "203.0.113.88" /var/log/apache2/access.log
```
   **Expected:** Should match 19 total requests from case timeline

3. **Test POST filtering:**
```bash
   grep "203.0.113.88" /var/log/apache2/access.log | grep -c "POST"
```
   **Expected:** 16 POST requests (from Evidence Files section)

**Common Issues & Fixes:**

| Issue | Fix |
|---|---|
| IP behind load balancer | Check X-Forwarded-For: `grep "X-Forwarded-For.*203.0.113.88"` |
| Different log file location | Try `/var/log/httpd/access_log` (RHEL) |
| Compressed logs | Use `zcat access.log.1.gz | grep ...` |

**Alternative (awk for structured parsing):**
```bash
awk '$1 == "203.0.113.88" && $6 ~ /POST/ {print $4, $6, $7, $9}' /var/log/apache2/access.log
```

---

### Linux Auth Log Analysis (Manual)

**Query (bash):**
```bash
grep "2024-05-21T14:[3-5]" /var/log/auth.log | grep -E "sudo|su |COMMAND"
```

**Validation Steps:**

1. **Check auth log format:**
```bash
   head -10 /var/log/auth.log
```
   **Expected:** Syslog format with timestamps

2. **Verify timestamp format:**
```bash
   grep "sudo" /var/log/auth.log | head -1
```
   **Expected:** Format like `May 21 14:43:07` or ISO format

3. **Test sudo detection:**
```bash
   grep "sudo.*www-data" /var/log/auth.log | wc -l
```
   **Expected:** 4 entries (3 denied, 1 allowed)

**Common Issues & Fixes:**

| Issue | Fix |
|---|---|
| Timestamp format differs | Use: `grep "May 21 14:4" /var/log/auth.log` |
| auth.log location varies | Try `/var/log/secure` (RHEL) or `/var/log/messages` |
| Need to check rotated logs | Include: `zgrep "sudo" /var/log/auth.log*` |

---

### Verification Checklist

- [ ] Confirmed Elastic field mappings match ECS (Elastic Common Schema)
- [ ] Verified Filebeat modules are enabled (apache, system)
- [ ] Tested Auditbeat is capturing process executions
- [ ] Checked Apache log format (Common vs Combined)
- [ ] Validated time zone consistency (UTC vs local)
- [ ] Tested queries return expected event counts from case timeline
- [ ] Confirmed IP address fields (source.ip vs client.ip)

---

### Testing in Real Environment

**Option 1: Elastic Security Free Trial**
- Download: https://www.elastic.co/downloads/elasticsearch
- Pre-configured with Filebeat + Auditbeat
- Ingest sample Apache logs

**Option 2: Home Lab Setup**
```bash
# Install Elastic Stack
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
sudo apt update && sudo apt install elasticsearch kibana filebeat auditbeat

# Configure Filebeat for Apache
sudo filebeat modules enable apache system
sudo filebeat setup
sudo systemctl start filebeat

# Configure Auditbeat for process monitoring
sudo auditbeat setup
sudo systemctl start auditbeat
```

**Option 3: TryHackMe Labs**
- "Investigating with ELK" series
- Pre-configured Elastic stack with web attack scenarios

---

### Common Elastic Query Pitfalls

| Mistake | Consequence | Fix |
|---|---|---|
| Using `=` instead of `:` | Syntax error | KQL uses `:` for matching |
| Forgetting wildcards on paths | No matches | Use `*apache*` not `apache` |
| Not escaping special chars | Query errors | Escape: `\/uploads\/` |
| Mixing Lucene and KQL syntax | Unexpected results | Stick to one query language |
| Case-sensitive field names | No results | Field names ARE case-sensitive: `process.name` not `Process.Name` |
