# Related Open-Source ATT&CK Tooling

This repository focuses on the rules, hunting queries, and coverage tooling built from direct practitioner experience. For the broader ecosystem:

## Official MITRE Tooling
- **[ATT&CK Navigator](https://github.com/mitre-attack/attack-navigator)** — the standard visualization tool for ATT&CK coverage; this repo's [`attack-coverage-generator`](tooling/attack-coverage-generator/) produces layer files ready to upload directly there
- **[CALDERA](https://github.com/mitre/caldera)** — MITRE's own adversary emulation platform, automating execution of ATT&CK techniques for purple-team validation

## Coverage & Detection Scoring
- **[DeTT&CT](https://github.com/rabobank-cdc/DeTTECT)** — a more comprehensive open-source framework for scoring detection, visibility, and threat-actor-specific coverage against ATT&CK than this repo's lightweight generator attempts to be; worth adopting directly if you need multi-dimensional scoring (data source visibility, detection quality, threat actor prioritization) rather than the simpler rule-presence coverage this repo's tool computes

## Adversary Emulation / Validation
- **[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)** — small, testable technique-level tests, the natural way to validate that a rule in `sigma-rules/` or `yara-rules/` actually fires before trusting the coverage report

## Threat Intelligence
- **[Ransomware Tool Matrix](https://github.com/BushidoUK/Ransomware-Tool-Matrix)** — technique-to-tool mapping specific to ransomware groups, complementing this repo's ransomware-related rules and playbooks (see also [ransomware-defense-framework](https://github.com/mrezwanulbari/ransomware-defense-framework))

---

For comprehensive category coverage across the full incident response tooling landscape, see [awesome-incident-response](https://github.com/meirwah/awesome-incident-response).

*Part of the [MITRE-ATT-CK-Threat-Defense-Framework](README.md) repository.*
