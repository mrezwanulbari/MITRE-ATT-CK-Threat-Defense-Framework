# Threat Hunting — Proactive Cyber Defense & Detection Engineering

![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-v14-red?style=for-the-badge)
![Sigma](https://img.shields.io/badge/Sigma-Rules-blue?style=for-the-badge)
![YARA](https://img.shields.io/badge/YARA-Rules-orange?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green.svg)

> A comprehensive threat hunting toolkit featuring Sigma detection rules, YARA malware signatures, SPL/KQL hunting queries, structured hunting playbooks, and MITRE ATT&CK technique mappings for proactive cyber defense operations.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Threat Hunting Methodology](#threat-hunting-methodology)
- [Repository Structure](#repository-structure)
- [Sigma Detection Rules](#sigma-detection-rules)
- [YARA Rules](#yara-rules)
- [Hunting Queries (SPL)](#hunting-queries-spl)
- [Hunting Queries (KQL)](#hunting-queries-kql)
- [Hunting Playbooks](#hunting-playbooks)
- [MITRE ATT&CK Coverage](#mitre-attck-coverage)
- [Detection Engineering](#detection-engineering)
- [Contributing](#contributing)

---

## Overview

**Threat hunting** is the proactive, hypothesis-driven practice of searching through networks and datasets to identify threats that evade automated security controls. This repository provides battle-tested detection content and structured methodologies for security operations teams.

### What's Included

| Category | Count | Description |
|---|---|---|
| **Sigma Rules** | 25+ | Vendor-agnostic detection rules covering Windows, Linux, Cloud |
| **YARA Rules** | 15+ | Malware and tool identification signatures |
| **SPL Queries** | 20+ | Splunk hunting queries for enterprise SIEM |
| **KQL Queries** | 15+ | Microsoft Sentinel / Defender hunting queries |
| **Playbooks** | 8+ | Structured hypothesis-driven hunting procedures |
| **ATT&CK Mappings** | Full | Coverage matrix across all 14 tactics |

### Who Is This For?

- **SOC Analysts** seeking proactive detection content
- **Threat Hunters** building hypothesis-driven hunt programs
- **Detection Engineers** developing and tuning detection rules
- **Security Architects** assessing detection coverage gaps
- **CISO/Security Leaders** evaluating ATT&CK coverage metrics

---

## Threat Hunting Methodology

### The Hunting Loop

```
┌──────────────────────────────────────────────────────────┐
│                    THREAT HUNTING LOOP                     │
│                                                           │
│    ┌──────────────┐                                       │
│    │  1. GENERATE  │ ◄── Threat Intel, ATT&CK, Gaps      │
│    │  HYPOTHESIS   │                                       │
│    └──────┬───────┘                                       │
│           │                                               │
│    ┌──────▼───────┐                                       │
│    │ 2. DEVELOP   │ ◄── SPL, KQL, Sigma, YARA            │
│    │ ANALYTICS    │                                       │
│    └──────┬───────┘                                       │
│           │                                               │
│    ┌──────▼───────┐                                       │
│    │ 3. EXECUTE   │ ◄── Search data, correlate findings   │
│    │ HUNT         │                                       │
│    └──────┬───────┘                                       │
│           │                                               │
│    ┌──────▼───────┐     ┌──────────────┐                  │
│    │ 4. ANALYZE   │────►│ 5. AUTOMATE  │                  │
│    │ FINDINGS     │     │ (New Rules)  │                  │
│    └──────┬───────┘     └──────────────┘                  │
│           │                                               │
│    ┌──────▼───────┐                                       │
│    │ 6. DOCUMENT  │ ──── Report, Lessons Learned          │
│    │ & SHARE      │                                       │
│    └──────────────┘                                       │
└──────────────────────────────────────────────────────────┘
```

### Hunting Maturity Model (HMM)

| Level | Name | Description | Capabilities |
|---|---|---|---|
| HM0 | Initial | Primarily reactive, no formal hunting | IOC-based searches only |
| HM1 | Minimal | Ad-hoc hunting with basic tools | Manual log searches, basic queries |
| HM2 | Procedural | Documented hunting procedures | Playbooks, repeatable hunts |
| HM3 | Innovative | Custom analytics, hypothesis-driven | ML-assisted, advanced correlation |
| HM4 | Leading | Automated hunting, continuous improvement | Full ATT&CK coverage, proactive R&D |

---

## Repository Structure

```
threat-hunting/
├── README.md
├── sigma-rules/
│   ├── windows/
│   │   ├── process-creation/
│   │   │   ├── win-susp-powershell-encoded-cmd.yml
│   │   │   ├── win-susp-lolbin-execution.yml
│   │   │   ├── win-credential-dumping-lsass.yml
│   │   │   └── win-susp-scheduled-task-creation.yml
│   │   ├── registry/
│   │   │   ├── win-persistence-run-key.yml
│   │   │   └── win-disable-defender-registry.yml
│   │   ├── authentication/
│   │   │   ├── win-pass-the-hash.yml
│   │   │   └── win-kerberoasting.yml
│   │   └── network/
│   │       └── win-rdp-lateral-movement.yml
│   ├── linux/
│   │   ├── linux-reverse-shell.yml
│   │   ├── linux-privilege-escalation-suid.yml
│   │   ├── linux-cron-persistence.yml
│   │   └── linux-ssh-authorized-keys-modified.yml
│   └── cloud/
│       ├── aws-root-account-usage.yml
│       └── azure-ad-suspicious-signin.yml
├── yara-rules/
│   ├── malware/
│   │   ├── cobalt-strike-beacon.yar
│   │   ├── mimikatz-indicators.yar
│   │   ├── webshell-generic.yar
│   │   └── ransomware-indicators.yar
│   ├── tools/
│   │   └── hacking-tool-indicators.yar
│   ├── documents/
│   │   └── malicious-macro-indicators.yar
│   └── README.md
├── hunting-queries/
│   ├── splunk/
│   │   ├── initial-access/
│   │   │   └── phishing-detection.spl
│   │   ├── execution/
│   │   │   └── suspicious-process-execution.spl
│   │   ├── persistence/
│   │   │   └── persistence-mechanisms.spl
│   │   ├── credential-access/
│   │   │   └── credential-harvesting.spl
│   │   ├── lateral-movement/
│   │   │   └── lateral-movement-detection.spl
│   │   ├── exfiltration/
│   │   │   └── data-exfiltration.spl
│   │   └── command-and-control/
│   │       └── c2-detection.spl
│   └── kql/
│       ├── identity-hunting.kql
│       ├── endpoint-hunting.kql
│       └── network-hunting.kql
├── playbooks/
│   ├── 01-initial-access-hunting.md
│   ├── 02-persistence-hunting.md
│   ├── 03-lateral-movement-hunting.md
│   ├── 04-credential-access-hunting.md
│   ├── 05-c2-communication-hunting.md
│   ├── 06-data-exfiltration-hunting.md
│   ├── 07-ransomware-precursor-hunting.md
│   └── 08-insider-threat-hunting.md
├── mitre-attack/
│   ├── coverage-matrix.md
│   ├── technique-to-detection-map.json
│   └── gap-analysis-template.md
├── detection-engineering/
│   ├── detection-development-lifecycle.md
│   ├── rule-testing-framework.md
│   ├── false-positive-tuning-guide.md
│   └── detection-metrics.md
└── docs/
    ├── hunting-program-guide.md
    ├── threat-intel-integration.md
    └── reporting-template.md
```

---

## Sigma Detection Rules

### Windows — Suspicious PowerShell Encoded Command

```yaml
title: Suspicious PowerShell Encoded Command Execution
id: f1e2d3c4-b5a6-7890-1234-567890abcdef
status: stable
level: high
description: |
    Detects PowerShell execution with encoded commands, commonly
    used by attackers to obfuscate malicious scripts.
author: Shakil Md. Rezwanul Bari
logsource:
    category: process_creation
    product: windows
detection:
    selection_encoded:
        CommandLine|contains:
            - '-enc '
            - '-EncodedCommand'
            - '-ec '
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
    selection_bypass:
        CommandLine|contains:
            - '-nop'
            - '-WindowStyle Hidden'
            - '-ep bypass'
    condition: selection_encoded and selection_bypass
falsepositives:
    - Legitimate admin scripts using encoded commands
    - Configuration management tools (SCCM, Ansible)
tags:
    - attack.execution
    - attack.t1059.001
    - attack.defense_evasion
    - attack.t1027
```

### Windows — LSASS Credential Dumping

```yaml
title: LSASS Memory Access for Credential Dumping
id: a2b3c4d5-e6f7-8901-2345-678901bcdef0
status: stable
level: critical
description: |
    Detects attempts to access LSASS process memory, commonly used
    by Mimikatz, ProcDump, and comsvcs.dll to dump credentials.
author: Shakil Md. Rezwanul Bari
logsource:
    category: process_access
    product: windows
detection:
    selection_target:
        TargetImage|endswith: '\lsass.exe'
    selection_access:
        GrantedAccess|contains:
            - '0x1010'
            - '0x1038'
            - '0x1F0FFF'
    filter_legitimate:
        SourceImage|endswith:
            - '\MsMpEng.exe'
            - '\csrss.exe'
            - '\wmiprvse.exe'
    condition: selection_target and selection_access and not filter_legitimate
tags:
    - attack.credential_access
    - attack.t1003.001
```

### Windows — Kerberoasting Detection

```yaml
title: Kerberoasting - Service Ticket Request
id: b3c4d5e6-f7a8-9012-3456-789012cdef01
status: stable
level: high
description: |
    Detects Kerberoasting attacks where service tickets are requested
    with weak RC4 encryption for offline password cracking.
author: Shakil Md. Rezwanul Bari
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4769
        TicketEncryptionType: '0x17'
        TicketOptions: '0x40810000'
    filter_machine:
        ServiceName|endswith: '$'
    filter_builtin:
        ServiceName:
            - 'krbtgt'
            - 'kadmin'
    condition: selection and not filter_machine and not filter_builtin
tags:
    - attack.credential_access
    - attack.t1558.003
```

### Linux — Reverse Shell Detection

```yaml
title: Linux Reverse Shell Execution
id: d5e6f7a8-b9c0-1234-5678-901234ef0123
status: stable
level: critical
description: |
    Detects common reverse shell patterns on Linux including bash,
    Python, Perl, nc/netcat techniques.
author: Shakil Md. Rezwanul Bari
logsource:
    category: process_creation
    product: linux
detection:
    selection_bash:
        CommandLine|contains:
            - 'bash -i >& /dev/tcp/'
            - 'bash -c "sh -i >& /dev/tcp/'
    selection_python:
        CommandLine|contains:
            - 'python -c "import socket,subprocess,os'
            - 'python3 -c "import socket,subprocess,os'
    selection_netcat:
        CommandLine|contains:
            - 'nc -e /bin/sh'
            - 'nc -e /bin/bash'
            - 'ncat -e /bin/sh'
    condition: selection_bash or selection_python or selection_netcat
tags:
    - attack.execution
    - attack.t1059.004
    - attack.command_and_control
    - attack.t1071.001
```

---

## YARA Rules

### Cobalt Strike Beacon Detection

```yara
rule CobaltStrike_Beacon_Indicators
{
    meta:
        author = "Shakil Md. Rezwanul Bari"
        description = "Detects Cobalt Strike Beacon payloads"
        severity = "critical"
        mitre_attack = "T1071.001, T1573.002"

    strings:
        $pipe1 = "\\\\.\\pipe\\msagent_" ascii wide
        $pipe2 = "\\\\.\\pipe\\MSSE-" ascii wide
        $pipe3 = "\\\\.\\pipe\\postex_" ascii wide
        $str1 = "beacon.dll" ascii wide
        $str2 = "beacon.x64.dll" ascii wide
        $str3 = "%02d/%02d/%02d %02d:%02d:%02d" ascii
        $c2_1 = "/submit.php?id=" ascii
        $c2_2 = "__cfduid=" ascii

    condition:
        uint16(0) == 0x5A4D and (2 of ($pipe*) or 2 of ($str*))
}
```

### Mimikatz Indicators

```yara
rule Mimikatz_Indicators
{
    meta:
        author = "Shakil Md. Rezwanul Bari"
        description = "Detects Mimikatz credential dumping tool"
        severity = "critical"
        mitre_attack = "T1003.001"

    strings:
        $cmd1 = "sekurlsa::logonpasswords" ascii wide nocase
        $cmd2 = "lsadump::dcsync" ascii wide nocase
        $cmd3 = "kerberos::golden" ascii wide nocase
        $cmd4 = "privilege::debug" ascii wide nocase
        $str1 = "gentilkiwi" ascii wide
        $str2 = "Benjamin DELPY" ascii wide
        $str3 = "mimikatz" ascii wide nocase

    condition:
        (3 of ($cmd*)) or (2 of ($str*) and any of ($cmd*))
}
```

### Web Shell Detection

```yara
rule WebShell_Generic
{
    meta:
        author = "Shakil Md. Rezwanul Bari"
        description = "Detects common web shell patterns"
        severity = "high"
        mitre_attack = "T1505.003"

    strings:
        $php1 = "<?php eval(" ascii nocase
        $php2 = "<?php system(" ascii nocase
        $php3 = "<?php shell_exec(" ascii nocase
        $php4 = "$_GET['cmd']" ascii nocase
        $php5 = "$_POST['cmd']" ascii nocase
        $asp1 = "wscript.shell" ascii nocase
        $asp2 = "cmd.exe /c" ascii nocase
        $jsp1 = "Runtime.getRuntime().exec(" ascii nocase

    condition:
        filesize < 500KB and (2 of ($php*) or ($asp1 and $asp2) or $jsp1)
}
```

### Ransomware Indicators

```yara
rule Ransomware_Generic_Indicators
{
    meta:
        author = "Shakil Md. Rezwanul Bari"
        description = "Detects generic ransomware behavioral indicators"
        severity = "critical"
        mitre_attack = "T1486, T1490"

    strings:
        $shadow1 = "vssadmin delete shadows" ascii wide nocase
        $shadow2 = "wmic shadowcopy delete" ascii wide nocase
        $shadow3 = "bcdedit /set {default} recoveryenabled no" ascii wide nocase
        $note1 = "Your files have been encrypted" ascii wide nocase
        $note2 = "decrypt your files" ascii wide nocase
        $kill1 = "taskkill /f /im sqlservr.exe" ascii wide nocase
        $kill2 = "net stop" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and (2 of ($shadow*) or (any of ($shadow*) and any of ($kill*)))
}
```

---

## Hunting Queries (SPL)

### Persistence Mechanisms

```spl
| tstats count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name=schtasks.exe
  AND (Processes.process="*create*")
  AND (Processes.process="*powershell*" OR Processes.process="*cmd*"
       OR Processes.process="*wscript*" OR Processes.process="*mshta*")
  by Processes.dest Processes.user Processes.process
  | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
  | sort -count
```

### Command and Control — DNS Beaconing

```spl
index=dns sourcetype=stream:dns OR sourcetype=dns
| where query_type="A"
| eval query_length=len(query)
| where query_length > 30
| bucket _time span=5m
| stats count as beacon_count, dc(_time) as time_intervals,
  stdev(_time) as time_stdev by query
| eval regularity=round(time_stdev, 2)
| where beacon_count > 50 AND regularity < 300
| sort -beacon_count
```

### Data Exfiltration — Unusual Outbound Volume

```spl
index=firewall OR index=proxy action=allowed
| where src_zone="internal" AND dest_zone="external"
| stats sum(bytes_out) as total_bytes by src_ip, user
| eval gb_out=round(total_bytes/1073741824, 2)
| where gb_out > 1
| sort -gb_out
```

### Lateral Movement — RDP Brute Force

```spl
index=win sourcetype=WinEventLog:Security EventCode=4625
  Logon_Type=10
| stats count as failures dc(Source_Network_Address) as src_count
  values(Source_Network_Address) as src_ips by Account_Name, ComputerName
| where failures > 10
| join Account_Name ComputerName [
    search index=win EventCode=4624 Logon_Type=10
    | stats latest(_time) as success_time by Account_Name, ComputerName
  ]
| where isnotnull(success_time)
| sort -failures
```

---

## Hunting Queries (KQL)

### Identity — Impossible Travel

```kql
SigninLogs
| where TimeGenerated >= ago(24h)
| where ResultType == "0"
| project TimeGenerated, UserPrincipalName, IPAddress,
    Lat = tostring(LocationDetails.geoCoordinates.latitude),
    Lon = tostring(LocationDetails.geoCoordinates.longitude),
    City = tostring(LocationDetails.city)
| sort by UserPrincipalName, TimeGenerated asc
| extend PrevTime = prev(TimeGenerated, 1),
    PrevLat = todouble(prev(Lat, 1)),
    PrevLon = todouble(prev(Lon, 1)),
    PrevUser = prev(UserPrincipalName, 1)
| where UserPrincipalName == PrevUser
| extend TimeDiffMin = datetime_diff('minute', TimeGenerated, PrevTime),
    DistKm = geo_distance_2points(todouble(Lon), todouble(Lat), PrevLon, PrevLat) / 1000
| where TimeDiffMin < 120 and DistKm > 500
```

### Endpoint — Suspicious Process Chains

```kql
DeviceProcessEvents
| where TimeGenerated >= ago(24h)
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe")
| where FileName in~ ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "certutil.exe", "rundll32.exe", "regsvr32.exe")
| project TimeGenerated, DeviceName, AccountName,
    ParentProcess = InitiatingProcessFileName,
    ChildProcess = FileName,
    CommandLine = ProcessCommandLine
| sort by TimeGenerated desc
```

---

## Hunting Playbooks

### Playbook 07: Ransomware Precursor Hunting

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  HUNTING PLAYBOOK: Ransomware Precursors
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

OBJECTIVE: Identify ransomware operator activity BEFORE encryption

PRECURSOR TIMELINE:

  Phase 1: Initial Compromise (Days -30 to -14)
  • Cobalt Strike / Brute Ratel beaconing
  • IcedID / QakBot initial payload delivery
  • Unusual RDP/VPN from new geolocations

  Phase 2: Reconnaissance (Days -14 to -7)
  • AdFind.exe or BloodHound AD enumeration
  • Network scanning (Advanced IP Scanner, nmap)
  • nltest /dclist: (domain controller discovery)
  • net group "Domain Admins" /domain

  Phase 3: Credential Theft (Days -7 to -3)
  • LSASS access (Mimikatz, ProcDump)
  • DCSync attacks (replication requests)
  • Kerberoasting / AS-REP Roasting

  Phase 4: Lateral Movement (Days -3 to -1)
  • PsExec / WMIC remote execution
  • RDP to multiple servers in sequence
  • SMB file shares accessed in bulk

  Phase 5: Data Exfiltration (Days -2 to 0)
  • Rclone or MegaSync upload activity
  • Large archive file creation (7z, rar)
  • Unusual outbound to cloud storage

  Phase 6: Impact (Day 0)
  • Shadow copy deletion (vssadmin, wmic)
  • Backup service termination
  • Mass file encryption + ransom note
```

---

## MITRE ATT&CK Coverage

### Detection Coverage Matrix

| Tactic | Techniques Covered | Coverage |
|---|---|---|
| **Initial Access** (TA0001) | T1566, T1190, T1078, T1133 | High |
| **Execution** (TA0002) | T1059, T1204, T1047 | High |
| **Persistence** (TA0003) | T1053, T1547, T1505 | High |
| **Privilege Escalation** (TA0004) | T1548, T1068, T1134 | Medium |
| **Defense Evasion** (TA0005) | T1027, T1562, T1070 | Medium |
| **Credential Access** (TA0006) | T1003, T1558, T1110 | High |
| **Discovery** (TA0007) | T1087, T1082, T1083 | Medium |
| **Lateral Movement** (TA0008) | T1021, T1550, T1570 | High |
| **Collection** (TA0009) | T1560, T1114 | Medium |
| **Exfiltration** (TA0010) | T1048, T1567 | Medium |
| **Command & Control** (TA0011) | T1071, T1573, T1572 | High |
| **Impact** (TA0040) | T1486, T1490, T1489 | High |

---

## Detection Engineering

### Detection Development Lifecycle

```
1. IDENTIFY     →  Threat intel, gap analysis, ATT&CK mapping
2. RESEARCH     →  Study technique, data sources, patterns
3. DEVELOP      →  Write Sigma/YARA/SPL/KQL rules
4. TEST         →  Validate with Atomic Red Team
5. TUNE         →  Reduce false positives, optimize perf
6. DEPLOY       →  Push to production SIEM/EDR
7. MAINTAIN     →  Monitor effectiveness, update for evasion
```

### Detection Quality Metrics

| Metric | Formula | Target |
|---|---|---|
| True Positive Rate | TP / (TP + FN) | > 95% |
| False Positive Rate | FP / (FP + TN) | < 5% |
| Mean Time to Detect | Avg(detect_time - attack_time) | < 30 min |
| ATT&CK Coverage | Detected / Total techniques | > 60% |
| Rule Freshness | Updated in 90d / Total rules | > 80% |

---

## Contributing

Contributions welcome! All rules must include author, date, MITRE tags, and false positive documentation.

## License

MIT License

---

> **Maintained by [Shakil Md. Rezwanul Bari](https://github.com/mrezwanulbari)** — Cybersecurity & Threat Intelligence Engineer focused on proactive cyber defense and critical infrastructure protection.
