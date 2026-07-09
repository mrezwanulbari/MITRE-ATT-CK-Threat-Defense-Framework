# ATT&CK Technique Coverage Matrix

Tracks detection coverage against MITRE ATT&CK techniques — the practical tool for answering "what can we actually detect" rather than "what tools have we bought."

## Coverage Levels

| Level | Meaning |
|---|---|
| **None** | No detection logic exists for this technique |
| **Partial** | Detection exists but has known gaps (e.g., covers one sub-technique variant, not all known implementations) |
| **Full** | Detection logic covers the technique's common implementation paths, tuned for false-positive rate |
| **Validated** | Full coverage that has been tested against a real or simulated execution (atomic red team, purple team exercise) |

## Example Coverage Tracking (Initial Access & Execution)

| Technique ID | Technique | Coverage | Detection Source |
|---|---|---|---|
| T1566.001 | Phishing: Spearphishing Attachment | Full | Email security gateway + [SOAR phishing playbook](https://github.com/mrezwanulbari/siem-soar-detection-engineering) |
| T1078 | Valid Accounts | Partial | Authentication anomaly detection (see [brute-force detection](https://github.com/mrezwanulbari/siem-soar-detection-engineering)) — covers brute-force approach, not credential-stuffing from breached-password lists |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Full | Sysmon Event ID 1 + PowerShell script block logging |
| T1204.002 | User Execution: Malicious File | Partial | EDR behavioral detection — covers common loader patterns, gap on heavily obfuscated/novel loaders |

## Why This Matters More Than a Tool Inventory

"We have an EDR and a SIEM" tells you nothing about actual detection coverage. A technique-by-technique matrix tells you exactly where the gaps are, which is what a real threat model requires — and it's the artifact that turns a purple team exercise from "did we get alerted" into "which specific techniques still need work."

---
*Part of the [MITRE-ATT-CK-Threat-Defense-Framework](../README.md) repository.*
