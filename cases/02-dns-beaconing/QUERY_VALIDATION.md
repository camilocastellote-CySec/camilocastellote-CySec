---

## 🔍 Query Validation Notes

### Environment Assumptions

**SIEM Platform:** Splunk Enterprise Security  
**Data Sources:**
- Zeek DNS logs (dns.log)
- Sysmon logs (EventID 1, 3, 22)
- Windows Event Logs

**Field Name Assumptions:**

| Query Field | Standard Name | Alternative Names |
|---|---|---|
| `QueryName` | DNS query | `query`, `dns.qry.name`, `question.name`, `dns_query` |
| `Image` | Process executable | `process.name`, `ProcessName`, `process.executable` |
| `ParentImage` | Parent process | `process.parent.name`, `ParentProcessName` |
| `ProcessId` | Process ID | `PID`, `process.pid`, `process_id` |

---

### Query 1: DNS Query Volume Detection (Sysmon EventID 22)

**Query:**
```spl
index=sysmon host=ACCOUNTING-PC-09 EventCode=22
QueryName="*updates-cdn77.com"
| stats count by QueryName
| sort - count
```

**Validation Steps:**

1. **Verify Sysmon DNS logging is enabled:**
```spl
   index=sysmon EventCode=22
   | stats count by host
```
   **Expected:** ACCOUNTING-PC-09 appears in results

2. **Check QueryName field format:**
```spl
   index=sysmon EventCode=22
   | table *
   | head 1
```
   Look for: `QueryName`, `query`, `dns.question.name`

3. **Test wildcard matching:**
```spl
   index=sysmon EventCode=22 QueryName="*updates-cdn77.com"
   | stats count
```
   **Expected:** 847 total queries (from case timeline)

**Common Issues & Fixes:**

| Issue | Fix |
|---|---|
| EventID 22 not available | Sysmon DNS logging not enabled in config |
| QueryName field missing | Field may be `query` or in nested JSON format |
| Wildcard not working | Try `QueryName IN ("*updates-cdn77.com")` or use `match()` |
| Case sensitivity issues | Use `| search QueryName="*updates-cdn77.com"` (case-insensitive) |

**Alternative Query:**
```spl
index=sysmon EventCode=22 Computer=ACCOUNTING-PC-09
| search QueryName="*updates-cdn77.com"
| stats count by QueryName, QueryStatus
| sort - count
```

---

### Query 2: Process Creating DNS Queries

**Query:**
```spl
index=sysmon host=ACCOUNTING-PC-09 EventCode=3
earliest="2024-04-02T09:40:00" latest="2024-04-02T11:00:00"
| table _time, Image, QueryName, Protocol, Initiated
| sort _time
```

**Validation Steps:**

1. **Verify EventID 3 captures DNS:**
```spl
   index=sysmon EventCode=3 dest_port=53
   | stats count by Image
```
   **Expected:** Various processes making DNS queries

2. **Check if DNS queries are in EventID 3 or EventID 22:**
   - EventID 3 = Network connection (includes DNS as port 53)
   - EventID 22 = DNS query (dedicated event, more detail)
   
   **Note:** The case uses EventID 22, not EventID 3. Correct query:
```spl
   index=sysmon host=ACCOUNTING-PC-09 EventCode=22
   earliest="2024-04-02T09:40:00" latest="2024-04-02T11:00:00"
   | table _time, Image, ProcessId, QueryName, QueryStatus
   | sort _time
```

3. **Test for specific process:**
```spl
   index=sysmon EventCode=22 Image="*svcupdate.exe"
   QueryName="*updates-cdn77.com"
```
   **Expected:** All 847 queries should be from this single process

**Common Issues & Fixes:**

| Issue | Fix |
|---|---|
| EventID 3 doesn't show DNS details | Use EventID 22 instead |
| QueryName field in EventID 3 | Only available in EventID 22 |
| Image shows full path | Use wildcards: `Image="*\\svcupdate.exe"` |

**Corrected Query:**
```spl
index=sysmon host=ACCOUNTING-PC-09 EventCode=22
earliest="2024-04-02T09:40:00" latest="2024-04-02T11:00:00"
QueryName="*updates-cdn77.com"
| table _time, Image, ProcessId, QueryName, QueryStatus
| sort _time
```

---

### Query 3: Process Tree Analysis (Parent Process)

**Query:**
```spl
index=sysmon EventCode=1 ProcessId=4821
| table _time, ParentImage, ParentCommandLine, Image, CommandLine
```

**Validation Steps:**

1. **Verify PID field format:**
```spl
   index=sysmon EventCode=1
   | table ProcessId, ProcessGuid
   | head 5
```
   **Expected:** ProcessId is numeric (4821), ProcessGuid is GUID format

2. **Check if PID is unique across time:**
   - PIDs can be reused by Windows
   - Add time filter to ensure correct process:
```spl
   index=sysmon EventCode=1 ProcessId=4821
   earliest="2024-04-02T09:43:00" latest="2024-04-02T09:44:00"
```

3. **Test parent-child relationship:**
```spl
   index=sysmon EventCode=1 Image="*svcupdate.exe"
   | table _time, ParentImage, Image, User
```
   **Expected:** ParentImage should be `*powershell.exe`

**Common Issues & Fixes:**

| Issue | Fix |
|---|---|
| Multiple processes with same PID | Add time range filter |
| ProcessId is string, not number | Use `ProcessId="4821"` (quotes) |
| ParentImage missing | Some Sysmon versions use `ParentProcessName` |

**Alternative Query (using ProcessGuid instead of PID):**
```spl
index=sysmon EventCode=1
ProcessGuid="{4A3B2C1D-E5F6-7890-ABCD-EF1234567890}"
| table _time, ParentImage, ParentCommandLine, ParentProcessGuid, Image, CommandLine, ProcessGuid
```

---

### Zeek DNS Log Analysis

**Query (bash):**
```bash
cat dns.log | zeek-cut ts id.orig_h query qtype_name answers
| grep "10.10.8.15"
| grep "updates-cdn77.com"
```

**Validation Steps:**

1. **Check Zeek log format version:**
```bash
   head -10 dns.log | grep "^#"
```
   **Expected:** Shows field names like `ts`, `id.orig_h`, `query`, etc.

2. **Verify field names match Zeek version:**
   - Zeek 3.x: `id.orig_h`, `id.resp_h`
   - Zeek 4.x+: May use different field names

3. **Test field extraction:**
```bash
   zeek-cut -h | grep query
```
   **Expected:** Shows `query` is available field

**Common Issues & Fixes:**

| Issue | Fix |
|---|---|
| Different Zeek version | Check field names: `grep "^#fields" dns.log` |
| zeek-cut not installed | Use `awk -F'\t' '{print $1, $3, $10}' dns.log` |
| Logs in JSON format | Use `jq '.query | select(. | contains("updates-cdn77.com"))' dns.log` |

**Alternative (awk version):**
```bash
awk -F'\t' '($3 == "10.10.8.15" || $5 == "10.10.8.15") && $10 ~ /updates-cdn77\.com/ {print $1, $3, $10, $16}' dns.log
```

---

### Query 4: Interval Analysis (Beacon Detection)

**Query (bash):**
```bash
cat dns.log | zeek-cut ts query
| grep "updates-cdn77.com"
| awk '{print $1}'
| awk 'NR>1{printf "%.2f\n", $1-prev} {prev=$1}'
| sort | uniq -c | sort -rn
```

**Validation Steps:**

1. **Test timestamp extraction:**
```bash
   cat dns.log | zeek-cut ts | head -5
```
   **Expected:** Unix timestamps like `1712047380.112`

2. **Verify awk math:**
```bash
   echo -e "1712047380.112\n1712047386.118" | awk 'NR>1{print $1-prev} {prev=$1}'
```
   **Expected:** `6.006` (6-second interval)

3. **Check sorting logic:**
```bash
   # Should show most common interval first
   echo -e "6.00\n6.00\n6.01\n5.99" | sort | uniq -c | sort -rn
```
   **Expected:** 
```
   2 6.00
   1 6.01
   1 5.99
```

**Common Issues & Fixes:**

| Issue | Fix |
|---|---|
| Timestamps in different format | Convert to Unix time first |
| Precision issues in intervals | Use `printf "%.3f"` for more decimal places |
| Large dataset performance | Filter to specific host first: `grep "10.10.8.15"` before processing |

---

### Entropy Calculation (Python)

**Script:**
```python
import math, collections

subdomain = "a7f3k2"
freq = collections.Counter(subdomain)
entropy = -sum((c/len(subdomain)) * math.log2(c/len(subdomain)) for c in freq.values())
print(f"Entropy: {entropy:.2f}")
```

**Validation Steps:**

1. **Test with known values:**
```python
   # Low entropy (repeated characters)
   test1 = "aaaaaa"  # Expected: ~0.0
   
   # High entropy (random)
   test2 = "a7f3k2"  # Expected: ~2.58
   
   # Calculate both and compare
```

2. **Verify math:**
   - "aaaaaa" → 1 unique char → entropy = 0
   - "abcdef" → 6 unique chars → entropy = log2(6) ≈ 2.58
   - "a7f3k2" → 6 unique chars → entropy ≈ 2.58

3. **Check against online calculator:**
   - Use https://planetcalc.com/2476/ to verify

**Common Issues & Fixes:**

| Issue | Fix |
|---|---|
| Division by zero | Add check: `if len(subdomain) == 0: return 0` |
| Negative entropy | Ensure using absolute values in log |
| Different entropy values | Check if using log2 vs log10 vs ln |

---

### Verification Checklist

- [ ] Confirmed Sysmon EventID 22 (DNS query) is logged
- [ ] Tested Zeek dns.log field names match version
- [ ] Verified ProcessId vs ProcessGuid usage
- [ ] Checked time zone (Zeek logs are UTC)
- [ ] Validated entropy calculation with known values
- [ ] Tested interval analysis on sample data

---

### Testing in Real Environment

**Option 1: TryHackMe**
- Room: "Investigating with Splunk" or "DNS Tunneling"
- Pre-configured logs with DNS beaconing patterns

**Option 2: Generate Test Traffic**
```bash
# Simulate DNS beaconing (for lab use only)
while true; do
  dig $(head /dev/urandom | tr -dc a-z0-9 | head -c 6).test-domain.com
  sleep 6
done
```

**Option 3: Public Datasets**
- Malware Traffic Analysis: https://malware-traffic-analysis.net
- Download PCAP with DNS tunneling
- Extract dns.log with Zeek
