# MITRE ATT&CK Detection Coverage Matrix

**This file previously claimed "85+ techniques with detection, ~42% coverage" — that figure did not reflect reality and has been corrected.** The actual number of techniques with a real Sigma or YARA rule file in this repository, verified by scanning the rule files directly, is documented below. See [`tooling/attack-coverage-generator/`](../tooling/attack-coverage-generator/) for the tool that generates this — it can't overstate coverage because it only reports what it finds an actual rule for.

## Coverage Summary (Accurate, Tool-Verified)

| Metric | Value |
|---|---|
| Total ATT&CK Techniques (v15, Enterprise) | 200+ |
| Techniques with an actual rule file in this repo | **10** |
| Coverage percentage | ~5% of the full Enterprise matrix |

A small, honest number reflecting real, working detections is worth more than a large estimated one — every technique listed below has a specific rule file backing it, checkable by anyone who clones the repo.

## Techniques With Real Coverage

See the full generated table (technique ID, description, and exact rule filename) in [`examples/generated-coverage-report.md`](../examples/generated-coverage-report.md), or upload [`examples/generated-navigator-layer.json`](../examples/generated-navigator-layer.json) to the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) to see it visually.

## Priority Gaps for Development

Given the current coverage is concentrated in credential access, execution, and persistence, the highest-value next additions (common, high-impact techniques not yet covered) are:

1. T1055 — Process Injection
2. T1087 — Account Discovery
3. T1566 — Phishing (initial access — currently zero coverage on the initial access tactic entirely)
4. T1071 — Application Layer Protocol (C2)
5. T1486 — Data Encrypted for Impact (ransomware — see the dedicated [ransomware-defense-framework](https://github.com/mrezwanulbari/ransomware-defense-framework) repo for deeper coverage here)

Adding a rule for any of these and re-running the coverage generator will update the numbers above automatically.
