# 🔐 SOC Analyst Portfolio

This portfolio contains **three fictional but realistic incident investigations** demonstrating my SOC analyst capabilities:

- **Investigation methodology** - Real SOC workflows
- **Tools and queries** - Actual Splunk/Elastic syntax
- **MITRE ATT&CK mapping** - Correct technique classification
- **IOCs and log samples** - Synthetic data for educational purposes

**Note:** IOCs (IP addresses, file hashes) are fictional and will not return results in threat intelligence platforms. This is intentional to avoid legal/ethical issues with distributing real malware indicators. The value of this portfolio lies in demonstrating **investigation process, analytical thinking, and technical documentation skills** rather than real threat data.

---

## 🛠️ Tools Used

### SIEM
![Splunk](https://img.shields.io/badge/Splunk-000000?style=for-the-badge&logo=splunk&logoColor=white)
![Elastic](https://img.shields.io/badge/Elastic-005571?style=for-the-badge&logo=elastic&logoColor=white)

### Network Analysis
![Wireshark](https://img.shields.io/badge/Wireshark-1679A7?style=for-the-badge&logo=wireshark&logoColor=white)
![Zeek](https://img.shields.io/badge/Zeek-777BB4?style=for-the-badge&logo=zeek&logoColor=white)

### Endpoint & Logs
![Windows](https://img.shields.io/badge/Windows_Event_Logs-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![Linux](https://img.shields.io/badge/Linux_Auth_Logs-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![Sysmon](https://img.shields.io/badge/Sysmon-0078D4?style=for-the-badge&logo=microsoft&logoColor=white)

### Threat Intelligence
![VirusTotal](https://img.shields.io/badge/VirusTotal-394EFF?style=for-the-badge&logo=virustotal&logoColor=white)
![AbuseIPDB](https://img.shields.io/badge/AbuseIPDB-CC0000?style=for-the-badge&logo=abuseipdb&logoColor=white)
![OTX](https://img.shields.io/badge/AlienVault_OTX-4A90D9?style=for-the-badge&logoColor=white)

---

## 📜 Certificates

![CompTIA Security+](https://img.shields.io/badge/CompTIA-Security%2B-FF0000?style=for-the-badge&logo=comptia&logoColor=white)
![TryHackMe SAL1](https://img.shields.io/badge/TryHackMe-SOC_Level_1_Analyst-212C42?style=for-the-badge&logo=tryhackme&logoColor=white)
![Google Coursera](https://img.shields.io/badge/Coursera-Bits_and_Bytes_of_Computer_Networking-0056D2?style=for-the-badge&logo=coursera&logoColor=white)
![Google Coursera](https://img.shields.io/badge/Coursera-Technical_Support_Fundamentals-0056D2?style=for-the-badge&logo=coursera&logoColor=white)

---

## 💡 Skills Demonstrated

| Category | Skills |
|---|---|
| **Detection** | Alert triage, log correlation, anomaly detection |
| **Analysis** | Windows/Linux/Web log analysis, PCAP review |
| **SIEM** | Splunk SPL queries, Elastic KQL filtering |
| **Threat Intel** | IOC enrichment, malware triage, pivot analysis |
| **Documentation** | Incident reports, escalation write-ups |

---

## 🔍 Investigation Methodology
```
[Alert Triggered]
      ↓
  Auth Logs → Validate identity anomalies
      ↓
  Process Logs → Suspicious executions / parent-child chains
      ↓
  Network Logs → C2 beaconing, exfil, lateral movement
      ↓
  Persistence Checks → Registry, scheduled tasks, startup
      ↓
  Timeline → Chronological reconstruction of events
      ↓
  [Incident Report / Escalation]
```

---

## 📁 Projects

| # | Case | Type | Tools | Write-up |
|---|---|---|---|---|
| 01 | Suspicious Login & Lateral Movement | IR | Splunk, Sysmon | [View →](./cases/01-lateral-movement/) |
| 02 | Malware Beaconing via DNS | Malware | Wireshark, Zeek | [View →](./cases/02-dns-beaconing/) |
| 03 | Web Shell Detection | Web | Elastic, Auth logs | [View →](./cases/03-webshell/) |

