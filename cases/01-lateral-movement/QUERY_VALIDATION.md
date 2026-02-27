# Query Validation Notes



##  Environment Assumptions

**SIEM Platform:** Splunk Enterprise Security  
**Data Sources:**
- Windows Security Event Logs (EventID 4624, 4625, 4648)
- Sysmon logs (EventID 1, 3, 13)
- Network traffic logs (Zeek conn.log format)

**Field Name Assumptions:**

| Query Field | Standard Name | Alternative Names in Other Environments |
|---|---|---|
| `src_ip` | Source IP Address | `Source_Network_Address`, `IpAddress`, `source.ip`, `clientIP` |
| `user` | Username | `TargetUserName`, `Account_Name`, `user_name`, `SubjectUserName` |
| `Logon_Type` | Logon Type Code | `LogonType`, `logon_type`, `EventData.LogonType` |
| `LogonId` | Logon Session ID | `Logon_ID`, `TargetLogonId`, `logon_id` |
| `host` | Hostname | `Computer`, `ComputerName`, `dest_host`, `hostname` |

---

## Query 1: Baseline Behavior Check

**Query:**
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4624
user=jsmith
| stats count by src_ip, host, Logon_Type
| sort - count
```

**Validation Steps:**

1. **Check if field names exist:**
   ```spl
   index=windows sourcetype=WinEventLog:Security EventCode=4624
   | table *
   | head 1
   ```
   Look for fields containing: `user`, `ip`, `logon`, `type`

2. **Test with known event:**
   - Known login: jsmith from 10.10.5.22 on 2024-03-13 08:44:21
   ```spl
   index=windows EventCode=4624 user=jsmith
   earliest="2024-03-13T08:44:00" latest="2024-03-13T08:45:00"
   ```
   **Expected:** At least 1 result

3. **Verify Logon Type values:**
   ```spl
   index=windows EventCode=4624
   | stats count by Logon_Type
   ```
   **Expected:** Types 2, 3, 7, 10, etc. (standard Windows logon types)

**Common Issues & Fixes:**

| Issue | Symptom | Fix |
|---|---|---|
| **Wrong field name** | 0 results | Use `Source_Network_Address` instead of `src_ip` |
| **Case sensitivity** | Partial results | Windows fields are case-insensitive, but check your Splunk config |
| **Missing sourcetype** | 0 results | Try `sourcetype="WinEventLog:Security"` or `sourcetype=XmlWinEventLog:Security` |
| **Time zone mismatch** | Wrong results | Add timezone modifier: `earliest="2024-03-13T08:44:00Z"` (UTC) |

**Alternative Query (if field names differ):**
```spl
index=windows EventCode=4624 TargetUserName=jsmith
| stats count by Source_Network_Address, Computer, LogonType
| sort - count
```

---

## Query 2: Brute Force Detection

**Query:**
```spl
index=windows sourcetype=WinEventLog:Security
(EventCode=4625 OR EventCode=4624) src_ip=185.220.101.47
| table _time, EventCode, user, src_ip, host, Logon_Type, Failure_Reason
| sort _time
```

**Validation Steps:**

1. **Verify both EventIDs return data:**
   ```spl
   index=windows EventCode=4625 OR EventCode=4624
   | stats count by EventCode
   ```
   **Expected:** Both EventCode 4624 and 4625 have counts > 0

2. **Check Failure_Reason field exists:**
   ```spl
   index=windows EventCode=4625
   | table *
   | head 1
   ```
   Look for: `Failure_Reason`, `FailureReason`, `SubStatus`, or `Status`

3. **Test IP filter logic:**
   ```spl
   index=windows EventCode=4625 src_ip=185.220.101.47
   | stats count
   ```
   **Expected:** Should match the 23 failed attempts mentioned in the case

**Common Issues & Fixes:**

| Issue | Fix |
|---|---|
| `Failure_Reason` field missing | Use `SubStatus` or `Status` instead |
| IP field is nested | Try `source.ip` or extract with `rex` |
| No results for specific IP | Verify IP format (some logs use hex notation) |

**Alternative Query:**
```spl
index=windows sourcetype=WinEventLog:Security
(EventCode=4625 OR EventCode=4624) Source_Network_Address=185.220.101.47
| eval Failure_Info=if(EventCode=4625, SubStatus, "Success")
| table _time, EventCode, TargetUserName, Source_Network_Address, Computer, LogonType, Failure_Info
| sort _time
```

---

## Query 3: Process Execution Analysis (Sysmon)

**Query:**
```spl
index=sysmon EventCode=1 host=WORKSTATION-04
earliest="2024-03-14T02:17:43" latest="2024-03-14T03:00:00"
| table _time, user, ParentImage, Image, CommandLine
| sort _time
```

**Validation Steps:**

1. **Verify Sysmon data exists:**
   ```spl
   index=sysmon EventCode=1
   | stats count by host
   ```
   **Expected:** WORKSTATION-04 should appear in results

2. **Check field names for process data:**
   ```spl
   index=sysmon EventCode=1
   | table *
   | head 1
   ```
   Look for: `Image`, `CommandLine`, `ParentImage`, `User`, `ParentCommandLine`

3. **Test time range accuracy:**
   ```spl
   index=sysmon EventCode=1 host=WORKSTATION-04
   earliest="2024-03-14T02:17:00" latest="2024-03-14T02:18:00"
   Image="*cmd.exe"
   ```
   **Expected:** Should return the `whoami /all` command at 02:18:05

**Common Issues & Fixes:**

| Issue | Fix |
|---|---|
| Sysmon logs in different index | Check `index=winlogbeat` or `index=endpoint` |
| Image field shows full path only | Use wildcards: `Image="*\\powershell.exe"` |
| User field format differs | May be `DOMAIN\\user` vs just `user` |
| Time is in local, not UTC | Confirm timezone with `| eval local_time=strftime(_time, "%Y-%m-%d %H:%M:%S %Z")` |

**Alternative Query (expanded field names):**
```spl
index=sysmon EventCode=1 Computer=WORKSTATION-04
_index_earliest=1710379063 _index_latest=1710382800
| table _time, User, ParentImage, ParentCommandLine, Image, CommandLine, ProcessId, ParentProcessId
| sort _time
```

---

## Query 4: Network Connection Correlation (Sysmon EventID 3)

**Query:**
```spl
index=sysmon EventCode=3 host=WORKSTATION-04
dest_ip=185.220.101.47
| table _time, Image, dest_ip, dest_port, src_port
```

**Validation Steps:**

1. **Check network event data exists:**
   ```spl
   index=sysmon EventCode=3
   | stats count by host
   ```

2. **Verify destination IP field:**
   ```spl
   index=sysmon EventCode=3
   | table *
   | head 1
   ```
   Look for: `DestinationIp`, `dest_ip`, `destination.ip`, `DestinationAddress`

3. **Test known connection:**
   - Known: PowerShell to 185.220.101.47:8080 at 02:19:12
   ```spl
   index=sysmon EventCode=3 Image="*powershell.exe"
   earliest="2024-03-14T02:19:00" latest="2024-03-14T02:20:00"
   ```

**Alternative Query:**
```spl
index=sysmon EventCode=3 Computer=WORKSTATION-04
DestinationIp=185.220.101.47
| table _time, Image, User, DestinationIp, DestinationPort, SourcePort, Initiated
| sort _time
```

---

## Zeek Network Traffic Query

**Query (bash):**
```bash
cat conn.log | zeek-cut ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration orig_bytes resp_bytes conn_state
| grep "185.220.101.47"
```

**Validation Steps:**

1. **Verify Zeek log format:**
   ```bash
   head -20 conn.log
   ```
   **Expected:** Tab-separated values with header showing field names

2. **Check if zeek-cut is available:**
   ```bash
   which zeek-cut
   ```
   **Expected:** `/usr/local/zeek/bin/zeek-cut` or similar

3. **Test field extraction:**
   ```bash
   zeek-cut -h
   ```
   **Expected:** Shows available fields

**Common Issues & Fixes:**

| Issue | Fix |
|---|---|
| `zeek-cut: command not found` | Install Zeek or use `awk` to extract columns |
| Field names differ in Zeek version | Check header: `grep "^#fields" conn.log` |
| Log is JSON format, not TSV | Use `jq` instead: `jq 'select(.id.resp_h=="185.220.101.47")' conn.log` |

**Alternative (awk version):**
```bash
awk -F'\t' '$5 == "185.220.101.47" || $3 == "185.220.101.47" {print $1, $3, $5, $6, $8, $9}' conn.log
```

---

## Verification Checklist

Before using these queries in a real environment:

- [ ] Confirmed index names: `index=windows`, `index=sysmon`
- [ ] Tested field names with `| table *` command
- [ ] Verified at least 1 known event returns results
- [ ] Checked time zone settings (UTC vs local)
- [ ] Validated boolean logic with simple test cases
- [ ] Confirmed EventID formats (numeric vs string)
- [ ] Tested on a non-production Splunk instance first

---

## Additional Resources

**To validate in a test environment:**

1. **Use Boss of the SOC datasets:**
   - Download: https://github.com/splunk/botsv3
   - Contains realistic Windows Security + Sysmon logs
   - Test queries against known attack patterns

2. **TryHackMe Splunk Labs:**
   - "Investigating with Splunk" room
   - Pre-configured Splunk instance
   - Validate query syntax and logic

3. **Build home lab:**
   - Install Splunk Free (developer license)
   - Configure Sysmon on Windows VM
   - Generate test traffic and ingest logs

**Query troubleshooting guide:**
- If 0 results → Check field names, index, sourcetype
- If too many results → Add more filters, check time range
- If slow performance → Add index-time filters first, use `tstats` for large datasets
