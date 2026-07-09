# Threat Hunt: Lateral Movement via PsExec/WMI

Hunting query and methodology for identifying lateral movement using PsExec-style remote execution and WMI, mapped to ATT&CK T1021 and T1047.

## Hypothesis

An attacker with valid credentials (or a compromised account) is using PsExec, WMI, or similar remote execution tooling to move between hosts, rather than relying on interactive RDP sessions that are more heavily monitored.

## Hunting Query (Splunk SPL — Sysmon-sourced)

```spl
index=sysmon EventCode=1
(Image="*PsExec*" OR Image="*psexesvc*" OR ParentImage="*wmiprvse.exe*")
| stats count, values(CommandLine) as commands, values(User) as users, dc(host) as distinct_hosts by ParentImage, Image
| where distinct_hosts > 1
| sort -distinct_hosts
```

## What to Look For in Results

- **A single account touching many hosts in a short window** — normal admin activity tends to be scoped to a specific host group; broad, fast fan-out across unrelated host groups is the strongest signal
- **PsExec service name variance** — PsExec creates a service named `PSEXESVC` by default; attackers using renamed/customized PsExec binaries to evade signature detection will show a service creation event (Sysmon Event ID 7045 / Windows Event ID 7045) with an unusual service name but the same underlying execution pattern
- **WMI process creation without a corresponding logon event** — WMI-based lateral movement (`wmic process call create`) can execute without generating the interactive logon telemetry analysts expect, so cross-reference process creation against Event ID 4624/4625 rather than assuming absence of a logon event means no lateral movement occurred

## False Positive Sources

- Legitimate software deployment tools (SCCM, Ansible with WinRM) that use similar remote execution mechanics — baseline your known-good deployment tooling accounts/hosts and exclude them explicitly rather than broadly excluding WMI/PsExec activity
- IT helpdesk remote troubleshooting tools with overlapping execution signatures

---
*Part of the [MITRE-ATT-CK-Threat-Defense-Framework](../README.md) repository.*
