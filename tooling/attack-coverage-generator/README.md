# ATT&CK Coverage Generator

Scans this repository's actual Sigma and YARA rules for MITRE ATT&CK technique tags, cross-references against `mappings/*.json`, and generates a data-driven coverage report plus a valid MITRE ATT&CK Navigator layer.

## Why This Exists

`mitre-attack/coverage-matrix.md` is hand-maintained — which means the moment a rule is added or removed without someone remembering to update it, the coverage picture is wrong. This tool computes coverage from the actual rule files every time it's run, so it can't silently drift.

**Running it against this repository's real rules immediately surfaced a genuine finding:** 8 of the 10 techniques with actual Sigma/YARA rule coverage aren't yet reflected in `mappings/enterprise.json` — the hand-maintained mapping had fallen behind the rules. That gap is exactly the class of problem this tool is meant to catch on an ongoing basis.

## Requirements

Python 3.8+, PyYAML (`pip install pyyaml`)

## Usage

```bash
python3 attack_coverage_generator.py \
    --repo-root .. \
    --output-report coverage_report.md \
    --output-layer navigator_layer.json
```

Run from `tooling/attack-coverage-generator/` with `--repo-root ..` pointing at the repository root (where `sigma-rules/`, `yara-rules/`, and `mappings/` live).

## Outputs

1. **`coverage_report.md`** — a markdown table of every technique with actual rule coverage, which specific rule file(s) cover it, and its description (pulled from `mappings/*.json` where available, flagged explicitly where the mapping hasn't caught up to the rule yet)
2. **`navigator_layer.json`** — a valid [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) layer file (schema v4.5). Upload it directly to the Navigator to see your actual detection coverage plotted on the real ATT&CK matrix, colored by coverage, with rule filenames in the comment field for each technique.

## How It Works

- **Sigma rules:** parsed via PyYAML, extracts `attack.tXXXX` / `attack.tXXXX.YYY` tags from the `tags:` field
- **YARA rules:** regex-matched for the `mitre_attack = "TXXXX"` metadata convention used in this repo's rules
- **Mappings:** loads all `mappings/*.json` files and indexes technique descriptions by ID (falls back to the parent technique's description for sub-techniques not individually listed)

## Tested

Verified end-to-end against this repository's actual rule set — correctly extracted 9 techniques from Sigma tags and 2 from YARA metadata (10 unique after merging), generated a valid coverage report, and produced a Navigator layer JSON confirmed to be well-formed (verified programmatically, matches the expected schema structure).

---
*Part of the [MITRE-ATT-CK-Threat-Defense-Framework](../../README.md) repository.*
