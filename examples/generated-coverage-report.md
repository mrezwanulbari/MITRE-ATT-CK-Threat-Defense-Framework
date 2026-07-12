# ATT&CK Technique Coverage Report

**This report is generated from the actual Sigma/YARA rule files in this repository — it is not hand-maintained and cannot silently drift out of date.** Regenerate with `tooling/attack-coverage-generator/attack_coverage_generator.py` after adding or removing detection rules.

**Total techniques with detection coverage: 10**

| Technique ID | Description | Sigma Rules | YARA Rules |
|---|---|---|---|
| [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | OS Credential Dumping | `win-credential-dumping-lsass.yml` | `mimikatz-indicators.yar` |
| [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information | `win-susp-powershell-encoded-cmd.yml` | — |
| [T1053.003](https://attack.mitre.org/techniques/T1053/003/) | Scheduled Task/Job | `linux-cron-persistence.yml` | — |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Command and Scripting Interpreter | `windows-suspicious-powershell.yml`, `win-susp-powershell-encoded-cmd.yml` | — |
| [T1059.004](https://attack.mitre.org/techniques/T1059/004/) | Command and Scripting Interpreter | `linux-reverse-shell.yml` | — |
| [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | Server Software Component (Web Shell) | — | `webshell-generic.yar` |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Boot or Logon Autostart Execution | `win-persistence-run-key.yml` | — |
| [T1548.001](https://attack.mitre.org/techniques/T1548/001/) | Abuse Elevation Control Mechanism | `linux-privilege-escalation-suid.yml` | — |
| [T1550.002](https://attack.mitre.org/techniques/T1550/002/) | Use Alternate Authentication Material | `win-pass-the-hash.yml` | — |
| [T1558.003](https://attack.mitre.org/techniques/T1558/003/) | Steal or Forge Kerberos Tickets | `win-kerberoasting.yml` | — |
