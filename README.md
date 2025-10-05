Malware Analysis Report — Fake Software Download Site

**Analyst:** SOC Analyst (Student Project)  
**Category:** Network Forensics & Malware Traffic Analysis  
**Tools Used:** Zeek, Wireshark, CyberChef, VirusTotal, ELK Stack

---

##  Executive Summary

This report analyzes malicious traffic from a **fake software download website**.  
The infected host downloaded **PowerShell payloads** and communicated with **C2 servers** via HTTP.  
Network logs show data **exfiltration (~10 MB)** to an external IP.  

---

##  Table of Contents
1. Investigation Overview
2. Key Artifacts & IOCs
3. Network Analysis
4. File Analysis
5. MITRE ATT&CK Mapping
6. Detection & Response in ELK
7. Reproduction Steps
8. Summary Visuals
9. License & Attribution

---

##  Investigation Overview

| Field | Details |
|-------|----------|
| Victim Host | 10.1.17.215 |
| Hostname | DESKTOP-L8C5GSJ |
| Domain | bluemoontuesday.com |
| Controller | WIN-GSH54QLW48D (10.1.17.2) |
| Malicious IPs | 5[.]252[.]153.[]241, 45[.]125[.]66[.]32, 45[.]125[.]66[.]252 |
| Suspicious Domain | authenticatoor[.]org |


---

##  Key Artifacts & IOCs

| Type | Value | Description |
|------|--------|-------------|
| Filename | pas.ps1 | PowerShell loader script |
| Filename | 29842.ps1 | Secondary PowerShell payload |
| Filename | 1517096937(464) | Numeric C2 file |
| SHA256 | b8ce40900788ea26b9e4c9af7efab533e8d39ed1370da09b93fcf72a16750ded | 29842.ps1 |
| SHA256 | a833f27c2bb4cad31344e70386c44b5c221f031d7cd2f2a6b8601919e790161e | pas.ps1 |
| SHA256 | d63f0163a727b8bc2abe6d35b56468c5ac048b15c63c3faeba1dca054c3704bc | 1517096937(464) |

---

##  Network Analysis

**Observations:**
- HTTP GET requests fetched obfuscated PowerShell scripts (`pas.ps1`, `29842.ps1`) from 5[.]252[.]153[.]241  
- Numeric-path polling (`/1517096937`) suggested beaconing activity  
- Large (~10 MB) outbound traffic to 45[.]125[.]66[.]32 indicates **data exfiltration**

### Visuals
![Zeek HTTP Log](images/zeek_httplogs.png)
![Wireshark HTTP Exfiltration](images/exfiltration.png)

---

##  File Analysis

**Extracted HTTP Artifacts:**
- `pas.ps1` — Loader PowerShell script  
- `29842.ps1` — Stage 2 payload  
- `1517096937(464)` — Numeric beacon file

### Sandbox Findings
- `.ps1` files flagged as **malicious** on VirusTotal / Any.Run  
- Execution: PowerShell (T1059.001)  
- C2 over HTTP (T1071.001)  
- Exfiltration & persistence traces detected  

### Visuals
![hash of .ps1 files](images/hash.png)
![pas.ps1 VirusTotal](images/hash_ps1_vir.png)
![29842.ps1 VirusTotal](images/virus298.png)
![Numeric File 1517096937](images/wireshark_http_exp.png)

---

##  MITRE ATT&CK Mapping

| Technique ID | Technique | Tactic |
|---------------|------------|---------|
| T1059.001 | PowerShell (Command Interpreter) | Execution |
| T1071.001 | Web Protocols (C2 over HTTP) | Command & Control |
| T1041 | Exfiltration Over C2 Channel | Exfiltration |
| T1189 | Drive-by Compromise | Initial Access |
| T1204 | User Execution | Execution |

### Visuals
![pas.ps1 file content](images/contents_ps1.png)
![MITRE Mapping Table](images/mitre_mapping_table.png)

---

##  Detection & Response in ELK

###  ElastAlert Rules
- Detects HTTP GET to `/1517096937`
- Detects `.ps1` downloads with PowerShell User‑Agent  
File: [`elastalert_rules.yaml`](elastalert_rules.yaml)

![ElastAlert Rule](images/elk_alert_rule.png)

---

###  Elasticsearch Watcher
Triggers alert on outbound > 5 MB from internal hosts  
File: [`elasticsearch_watcher_large_exfil.json`](elasticsearch_watcher_large_exfil.json)

![Watcher Config](images/elk_watcher_config.png)

---

###  Kibana Dashboard
Import: [`kibana_saved_objects.ndjson`](kibana_saved_objects.ndjson)  
Suggested visualizations:
- Top External IPs by Bytes Out  
- HTTP Requests with Suspicious URIs  
- PowerShell Download Trends  

![Kibana Dashboard](images/kibana_dashboard.png)

---

##  Reproduction Steps

```bash
# 1. Run Zeek
zeek -r malware-analysis-exercise.pcap

# 2. Inspect Connections
cat conn.log | zeek-cut id.orig_h id.resp_h proto service duration

# 3. Inspect HTTP Logs
cat http.log | zeek-cut id.orig_h id.resp_h method uri status_code

# 4. Extract Objects in Wireshark
File > Export Objects > HTTP > Save all 
```
![Zeek Parse](images/zeek_parse.png)
![Zeek conn.log](images/zeek_conn1_log.png)
![Zeek http log](images/zeek_httplogs.png)
![Wireshark export http objects](images/wireshark_httpps1.png)
---

##  Summary Visuals
![Overall Summary](images/summary_visual.png)

---

##  License & Attribution

**License:** MIT  
**Author:** SOC Analyst (Student Project)  
**Dataset:** [malware‑traffic‑analysis.net (2025‑01‑22)](https://www.malware-traffic-analysis.net/2025/01/22/index.html)

---
**End of Report**

