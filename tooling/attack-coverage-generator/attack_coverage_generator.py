#!/usr/bin/env python3
"""
attack_coverage_generator.py — Scans this repository's actual Sigma and YARA
rules for MITRE ATT&CK technique tags, cross-references against the
mappings/*.json files, and generates:

  1. A markdown coverage report (data-driven, not hand-maintained)
  2. A valid MITRE ATT&CK Navigator layer JSON — upload it directly to
     https://mitre-attack.github.io/attack-navigator/ to visualize actual
     rule coverage on the real ATT&CK matrix

Why this exists: mitre-attack/coverage-matrix.md (hand-maintained) drifts
from reality the moment a rule is added or removed without someone
remembering to update the table by hand. This tool computes the matrix from
the actual rule files every time it's run, so the coverage report can never
silently go stale.

Requires: Python 3.8+, PyYAML (pip install pyyaml)

Usage:
    python3 attack_coverage_generator.py --repo-root .. \\
        --output-report coverage_report.md \\
        --output-layer navigator_layer.json
"""

import argparse
import json
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("Error: PyYAML is required. Install with: pip install pyyaml --break-system-packages", file=sys.stderr)
    sys.exit(1)

ATTACK_TAG_RE = re.compile(r"attack\.t(\d{4})(?:\.(\d{3}))?", re.IGNORECASE)
YARA_MITRE_RE = re.compile(r'mitre_attack\s*=\s*"T(\d{4})(?:\.(\d{3}))?"', re.IGNORECASE)


def normalize_technique_id(major, minor=None):
    tid = f"T{major}"
    if minor:
        tid += f".{minor}"
    return tid


def scan_sigma_rules(repo_root):
    """Returns {technique_id: [rule_file_paths]}"""
    coverage = {}
    sigma_dir = repo_root / "sigma-rules"
    if not sigma_dir.exists():
        return coverage

    for rule_file in sigma_dir.rglob("*.yml"):
        try:
            with open(rule_file) as f:
                rule = yaml.safe_load(f)
        except yaml.YAMLError:
            print(f"Warning: could not parse {rule_file}, skipping", file=sys.stderr)
            continue

        tags = rule.get("tags", []) if rule else []
        rel_path = str(rule_file.relative_to(repo_root))
        for tag in tags:
            match = ATTACK_TAG_RE.match(str(tag))
            if match:
                tid = normalize_technique_id(match.group(1), match.group(2))
                coverage.setdefault(tid, []).append(rel_path)

    return coverage


def scan_yara_rules(repo_root):
    """Returns {technique_id: [rule_file_paths]}"""
    coverage = {}
    yara_dir = repo_root / "yara-rules"
    if not yara_dir.exists():
        return coverage

    for rule_file in yara_dir.rglob("*.yar"):
        content = rule_file.read_text(errors="replace")
        rel_path = str(rule_file.relative_to(repo_root))
        for match in YARA_MITRE_RE.finditer(content):
            tid = normalize_technique_id(match.group(1), match.group(2))
            coverage.setdefault(tid, []).append(rel_path)

    return coverage


def load_mappings(repo_root):
    """Load mappings/*.json, return {technique_id: description}"""
    descriptions = {}
    mappings_dir = repo_root / "mappings"
    if not mappings_dir.exists():
        return descriptions

    for mapping_file in mappings_dir.glob("*.json"):
        with open(mapping_file) as f:
            data = json.load(f)
        for tactic_id, techniques in data.items():
            for tid, info in techniques.items():
                descriptions[tid] = info.get("description", "")

    return descriptions


def merge_coverage(sigma_cov, yara_cov):
    all_techniques = set(sigma_cov.keys()) | set(yara_cov.keys())
    merged = {}
    for tid in all_techniques:
        merged[tid] = {
            "sigma": sigma_cov.get(tid, []),
            "yara": yara_cov.get(tid, []),
        }
    return merged


def generate_report(merged_coverage, descriptions, output_path):
    lines = [
        "# ATT&CK Technique Coverage Report",
        "",
        "**This report is generated from the actual Sigma/YARA rule files in this repository — it is not hand-maintained and cannot silently drift out of date.** Regenerate with `tooling/attack-coverage-generator/attack_coverage_generator.py` after adding or removing detection rules.",
        "",
        f"**Total techniques with detection coverage: {len(merged_coverage)}**",
        "",
        "| Technique ID | Description | Sigma Rules | YARA Rules |",
        "|---|---|---|---|",
    ]

    for tid in sorted(merged_coverage.keys()):
        cov = merged_coverage[tid]
        # Look up description via parent technique if subtechnique has none
        parent_tid = tid.split(".")[0]
        desc = descriptions.get(tid) or descriptions.get(parent_tid) or "(not in mappings/*.json — rule exists but mapping not yet updated)"
        sigma_list = ", ".join(f"`{Path(p).name}`" for p in cov["sigma"]) or "—"
        yara_list = ", ".join(f"`{Path(p).name}`" for p in cov["yara"]) or "—"
        lines.append(f"| [{tid}](https://attack.mitre.org/techniques/{tid.replace('.', '/')}/) | {desc} | {sigma_list} | {yara_list} |")

    with open(output_path, "w") as f:
        f.write("\n".join(lines) + "\n")


def generate_navigator_layer(merged_coverage, output_path):
    """Generates a valid MITRE ATT&CK Navigator layer (schema v4.5)."""
    techniques = []
    for tid, cov in merged_coverage.items():
        all_rules = cov["sigma"] + cov["yara"]
        comment = f"Covered by: {', '.join(Path(p).name for p in all_rules)}"
        techniques.append({
            "techniqueID": tid,
            "score": 100,
            "color": "",
            "comment": comment,
            "enabled": True,
            "metadata": [],
            "showSubtechniques": False,
        })

    layer = {
        "name": "mrezwanulbari MITRE ATT&CK Threat Defense Framework — Detection Coverage",
        "versions": {"attack": "15", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Auto-generated from actual Sigma/YARA rule ATT&CK tags in this repository. Green = detection coverage exists.",
        "filters": {"platforms": ["Windows", "Linux", "macOS"]},
        "sorting": 0,
        "layout": {"layout": "side", "showID": True, "showName": True},
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {"colors": ["#ff6666", "#ffe766", "#8ec843"], "minValue": 0, "maxValue": 100},
        "legendItems": [],
        "metadata": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }

    with open(output_path, "w") as f:
        json.dump(layer, f, indent=2)


def main():
    parser = argparse.ArgumentParser(description="Generate ATT&CK coverage report and Navigator layer from actual rule files")
    parser.add_argument("--repo-root", default=".", help="Path to repository root (containing sigma-rules/, yara-rules/, mappings/)")
    parser.add_argument("--output-report", default="coverage_report.md")
    parser.add_argument("--output-layer", default="navigator_layer.json")
    args = parser.parse_args()

    repo_root = Path(args.repo_root)

    print("Scanning Sigma rules...")
    sigma_cov = scan_sigma_rules(repo_root)
    print(f"  Found ATT&CK tags in Sigma rules covering {len(sigma_cov)} technique(s)")

    print("Scanning YARA rules...")
    yara_cov = scan_yara_rules(repo_root)
    print(f"  Found mitre_attack metadata in YARA rules covering {len(yara_cov)} technique(s)")

    print("Loading mappings/*.json...")
    descriptions = load_mappings(repo_root)
    print(f"  Loaded {len(descriptions)} technique description(s)")

    merged = merge_coverage(sigma_cov, yara_cov)
    print(f"\nTotal unique techniques with rule-level coverage: {len(merged)}")

    generate_report(merged, descriptions, args.output_report)
    print(f"Coverage report written to {args.output_report}")

    generate_navigator_layer(merged, args.output_layer)
    print(f"Navigator layer written to {args.output_layer}")
    print("Upload the layer file at https://mitre-attack.github.io/attack-navigator/ to visualize.")


if __name__ == "__main__":
    main()
