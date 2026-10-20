#!/usr/bin/env python3
"""Turn a Semgrep JSON report into draft finding files (status: new).

Usage:
  semgrep scan --json -o semgrep.json <folder>
  python scripts/ingest_semgrep.py semgrep.json --repo juice-shop --prefix JS

Then open the new files in findings/, triage them (true-positive or false-positive),
and write the description / recommendation. Existing files are never overwritten.
"""
import argparse
import json
from datetime import date
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
SEV_MAP = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


def first(value, default=""):
    if isinstance(value, list):
        return value[0] if value else default
    return value or default


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("report")
    ap.add_argument("--repo", required=True)
    ap.add_argument("--prefix", required=True, help="ID prefix, e.g. JS gives JS-008")
    args = ap.parse_args()

    out_dir = ROOT / "findings"
    out_dir.mkdir(exist_ok=True)
    existing = [p.stem for p in out_dir.glob(f"{args.prefix}-*.yml")]
    n = max([int(s.split("-")[1]) for s in existing], default=0)

    results = json.loads(Path(args.report).read_text(encoding="utf-8")).get("results", [])
    for r in results:
        n += 1
        fid = f"{args.prefix}-{n:03d}"
        meta = r.get("extra", {}).get("metadata", {})
        finding = {
            "id": fid,
            "title": r["check_id"].split(".")[-1].replace("-", " ").title(),
            "cwe": str(first(meta.get("cwe"), "CWE-unknown")).split(":")[0],
            "owasp": first(meta.get("owasp")),
            "severity": SEV_MAP.get(r["extra"].get("severity", "INFO"), "low"),
            "status": "new",
            "repo": args.repo,
            "files": [f"{r['path']}:{r['start']['line']}"],
            "tool": "semgrep",
            "rule": r["check_id"],
            "first_seen": date.today().isoformat(),
            "description": r["extra"].get("message", "").strip(),
            "recommendation": "",
            "notes": "Draft from scan. Triage me.",
        }
        (out_dir / f"{fid}.yml").write_text(
            yaml.safe_dump(finding, sort_keys=False, allow_unicode=True), encoding="utf-8")
    print(f"Wrote {len(results)} draft findings. Triage them in findings/.")


if __name__ == "__main__":
    main()
