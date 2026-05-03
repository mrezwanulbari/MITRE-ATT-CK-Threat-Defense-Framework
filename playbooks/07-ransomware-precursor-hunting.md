# Hunting Playbook 07: Ransomware Precursor Detection

## Objective
Identify ransomware operator activity BEFORE encryption begins.

## Hypothesis
Ransomware operators follow a multi-week playbook: access > recon > persistence > lateral movement > exfil > impact. We can detect during earlier phases.

## MITRE ATT&CK Techniques
- T1486 - Data Encrypted for Impact
- T1490 - Inhibit System Recovery
- T1021 - Remote Services
- T1003 - OS Credential Dumping
- T1048 - Exfiltration Over Alternative Protocol

## Precursor Timeline

### Phase 1: Initial Compromise (Days -30 to -14)
- Cobalt Strike / Brute Ratel beaconing
- IcedID / QakBot initial payload
- Unusual RDP/VPN from new geolocations

### Phase 2: Reconnaissance (Days -14 to -7)
- AdFind.exe or BloodHound AD enumeration
- Network scanning (Advanced IP Scanner, nmap)
- `nltest /dclist:` (DC discovery)
- `net group "Domain Admins" /domain`

### Phase 3: Credential Theft (Days -7 to -3)
- LSASS access (Mimikatz, ProcDump)
- DCSync attacks (replication requests)
- Kerberoasting / AS-REP Roasting

### Phase 4: Lateral Movement (Days -3 to -1)
- PsExec / WMIC remote execution
- RDP to multiple servers in sequence
- SMB file shares accessed in bulk

### Phase 5: Data Exfiltration (Days -2 to 0)
- Rclone or MegaSync upload activity
- Large archive creation (7z, rar)
- Unusual outbound to cloud storage

### Phase 6: Impact (Day 0)
- Shadow copy deletion (vssadmin, wmic)
- Backup service termination
- Mass file encryption + ransom note

## Key SPL Queries

### Shadow Copy Deletion
```spl
index=win EventCode=1
| where match(CommandLine, "(?i)(vssadmin.*delete|wmic.*shadowcopy.*delete|bcdedit.*recoveryenabled)")
| table _time, Computer, User, CommandLine
```

### Reconnaissance Tools
```spl
index=win EventCode=1
| where match(Image, "(?i)(adfind|bloodhound|sharphound|rubeus|seatbelt)")
| table _time, Computer, User, Image, CommandLine
```

## Expected Outputs
- Timeline of precursor indicators
- List of affected hosts and accounts
- Recommendations for containment
- Updated detection rules
