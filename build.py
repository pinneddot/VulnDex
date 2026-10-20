#!/usr/bin/env python3
"""Build the static dashboard from findings/*.yml.

Usage:  python scripts/build.py
Output: docs/index.html and docs/findings.csv

Only dependency: PyYAML  (pip install pyyaml)
"""
import csv
import html
import sys
from datetime import date, datetime
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
FINDINGS_DIR = ROOT / "findings"
OUT_DIR = ROOT / "docs"

SEVERITIES = ["critical", "high", "medium", "low", "info"]
# The lifecycle of a finding, in order. false-positive is a side exit.
STAGES = ["new", "true-positive", "remediated", "retest-passed"]
STATUSES = STAGES + ["false-positive"]
STAGE_LABEL = {
    "new": "New",
    "true-positive": "Confirmed",
    "remediated": "Fixed, awaiting retest",
    "retest-passed": "Retest passed",
    "false-positive": "False positive",
}
REQUIRED = ["id", "title", "cwe", "severity", "status", "repo", "first_seen"]
SEV_COLOR = {
    "critical": "#a61e2d",
    "high": "#d2561f",
    "medium": "#c99a1a",
    "low": "#3f7d6b",
    "info": "#5f7d97",
}


def to_date(value, field, fid):
    if isinstance(value, date):
        return value
    try:
        return datetime.strptime(str(value), "%Y-%m-%d").date()
    except ValueError:
        raise ValueError(f"{fid}: '{field}' must look like 2026-10-20, got {value!r}")


def load_findings():
    findings, errors = [], []
    for path in sorted(FINDINGS_DIR.glob("*.yml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        fid = data.get("id", path.name)
        try:
            missing = [k for k in REQUIRED if k not in data]
            if missing:
                raise ValueError(f"{fid}: missing fields {missing}")
            if data["severity"] not in SEVERITIES:
                raise ValueError(f"{fid}: severity must be one of {SEVERITIES}")
            if data["status"] not in STATUSES:
                raise ValueError(f"{fid}: status must be one of {STATUSES}")
            data["first_seen"] = to_date(data["first_seen"], "first_seen", fid)
            if data.get("closed_at"):
                data["closed_at"] = to_date(data["closed_at"], "closed_at", fid)
            data.setdefault("files", [])
            findings.append(data)
        except ValueError as e:
            errors.append(str(e))
    if errors:
        print("Fix these before building:", file=sys.stderr)
        for e in errors:
            print("  - " + e, file=sys.stderr)
        sys.exit(1)
    return findings


def compute_metrics(findings):
    total = len(findings)
    by_status = {s: sum(f["status"] == s for f in findings) for s in STATUSES}
    by_sev = {s: sum(f["severity"] == s for f in findings) for s in SEVERITIES}
    fixed = [f for f in findings if f["status"] in ("remediated", "retest-passed") and f.get("closed_at")]
    days = [(f["closed_at"] - f["first_seen"]).days for f in fixed]
    avg_days = round(sum(days) / len(days), 1) if days else None
    retested = by_status["remediated"] + by_status["retest-passed"]
    pass_rate = round(100 * by_status["retest-passed"] / retested) if retested else None
    fp_rate = round(100 * by_status["false-positive"] / total) if total else 0
    open_count = by_status["new"] + by_status["true-positive"]
    return dict(total=total, by_status=by_status, by_sev=by_sev, avg_days=avg_days,
                pass_rate=pass_rate, fp_rate=fp_rate, open_count=open_count)


def e(x):
    return html.escape(str(x))


def render(findings, m):
    config = yaml.safe_load((ROOT / "tracker.yml").read_text(encoding="utf-8"))
    title = config.get("title", "VAPT Tracker")
    subtitle = config.get("subtitle", "")
    demo = config.get("demo_data", True)

    total = max(m["total"], 1)
    pipeline = "".join(
        f'<div class="seg s-{s}" style="flex:{max(m["by_status"][s], 0.0001)}" title="{STAGE_LABEL[s]}">'
        f'<b>{m["by_status"][s]}</b><span>{STAGE_LABEL[s]}</span></div>'
        for s in STAGES
    )

    sev_rows = "".join(
        f'<div class="sevrow"><span class="sevname">{s.capitalize()}</span>'
        f'<span class="bar"><i style="width:{100 * m["by_sev"][s] / total}%;background:{SEV_COLOR[s]}"></i></span>'
        f'<span class="sevn">{m["by_sev"][s]}</span></div>'
        for s in SEVERITIES
    )

    def stat(value, label):
        return f'<div class="stat"><div class="v">{value}</div><div class="l">{label}</div></div>'

    stats = "".join([
        stat(m["open_count"], "Open findings"),
        stat(f'{m["avg_days"]} days' if m["avg_days"] is not None else "n/a", "Average time to fix"),
        stat(f'{m["pass_rate"]}%' if m["pass_rate"] is not None else "n/a", "Retests passed"),
        stat(f'{m["fp_rate"]}%', "Scanner noise (false positives)"),
    ])

    sev_order = {s: i for i, s in enumerate(SEVERITIES)}
    rows = []
    for f in sorted(findings, key=lambda f: (sev_order[f["severity"]], f["id"])):
        files = "".join(f"<li><code>{e(p)}</code></li>" for p in f["files"])
        closed = f'<div><dt>Closed</dt><dd>{f["closed_at"]}</dd></div>' if f.get("closed_at") else ""
        rows.append(f"""
<details class="row" data-sev="{f['severity']}" data-status="{f['status']}">
  <summary>
    <span class="dot" style="background:{SEV_COLOR[f['severity']]}"></span>
    <span class="fid">{e(f['id'])}</span>
    <span class="ftitle">{e(f['title'])}</span>
    <span class="chip st-{f['status']}">{STAGE_LABEL[f['status']]}</span>
  </summary>
  <div class="detail">
    <p>{e(f.get('description', ''))}</p>
    <dl>
      <div><dt>Severity</dt><dd>{f['severity'].capitalize()}</dd></div>
      <div><dt>Weakness</dt><dd>{e(f['cwe'])}</dd></div>
      <div><dt>OWASP</dt><dd>{e(f.get('owasp', 'n/a'))}</dd></div>
      <div><dt>Found by</dt><dd>{e(f.get('tool', 'n/a'))}{(' / ' + e(f['rule'])) if f.get('rule') else ''}</dd></div>
      <div><dt>First seen</dt><dd>{f['first_seen']}</dd></div>
      {closed}
    </dl>
    <h4>Affected files</h4><ul>{files}</ul>
    <h4>Recommendation</h4><p>{e(f.get('recommendation', ''))}</p>
    <h4>Reviewer notes</h4><p>{e(f.get('notes', ''))}</p>
  </div>
</details>""")

    filters = "".join(
        f'<button data-f="{s}">{STAGE_LABEL[s]}</button>' for s in STATUSES
    )
    banner = (
        '<p class="demo">Demo data: findings from an intentionally vulnerable practice app '
        "(OWASP Juice Shop). No employer or client information appears here.</p>"
        if demo else ""
    )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(title)}</title>
<style>
:root{{--ink:#12202e;--paper:#eef1f4;--panel:#fff;--line:#cfd7de;--mute:#5a6b7a;--accent:#1f4e79;
--critical:{SEV_COLOR['critical']};}}
@media (prefers-color-scheme:dark){{:root{{--ink:#e6edf3;--paper:#0f1720;--panel:#17222e;--line:#2a3a4a;--mute:#93a4b4;--accent:#7db3e6}}}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--paper);color:var(--ink);font:16px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}}
main{{max-width:960px;margin:0 auto;padding:2.5rem 1.25rem 4rem}}
h1{{font:600 2.1rem/1.15 Georgia,"Times New Roman",serif;margin:0 0 .4rem}}
.sub{{color:var(--mute);max-width:60ch;margin:0 0 1rem}}
.demo{{background:var(--panel);border-left:4px solid var(--accent);padding:.6rem .9rem;font-size:.9rem;margin:0 0 2rem}}
h2{{font:600 1.15rem Georgia,serif;margin:2.2rem 0 .8rem}}
.pipeline{{display:flex;gap:4px;min-height:92px}}
.seg{{display:flex;flex-direction:column;justify-content:space-between;padding:.7rem .8rem;color:#fff;min-width:96px}}
.seg b{{font:600 2rem/1 Georgia,serif}}
.seg span{{font-size:.82rem;line-height:1.25}}
.s-new{{background:#7a8896}}.s-true-positive{{background:#b4541f}}
.s-remediated{{background:#2f6f8f}}.s-retest-passed{{background:#2d7a5a}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem;margin-top:1.4rem}}
.stat{{background:var(--panel);border:1px solid var(--line);padding:1rem}}
.stat .v{{font:600 1.7rem Georgia,serif}}.stat .l{{color:var(--mute);font-size:.88rem}}
.sevrow{{display:grid;grid-template-columns:80px 1fr 30px;gap:.7rem;align-items:center;margin:.35rem 0}}
.bar{{background:var(--line);height:12px;display:block}}.bar i{{display:block;height:100%}}
.sevn{{text-align:right;font-variant-numeric:tabular-nums}}
.filters{{display:flex;flex-wrap:wrap;gap:.5rem;margin-bottom:1rem}}
.filters button{{border:1px solid var(--line);background:var(--panel);color:var(--ink);padding:.35rem .8rem;font:inherit;font-size:.88rem;cursor:pointer}}
.filters button[aria-pressed=true]{{background:var(--accent);color:#fff;border-color:var(--accent)}}
.filters button:focus-visible,summary:focus-visible{{outline:3px solid var(--accent);outline-offset:2px}}
.row{{background:var(--panel);border:1px solid var(--line);margin-bottom:6px}}
summary{{display:grid;grid-template-columns:14px 64px 1fr auto;gap:.7rem;align-items:center;padding:.75rem .9rem;cursor:pointer;list-style:none}}
summary::-webkit-details-marker{{display:none}}
.dot{{width:12px;height:12px;border-radius:50%}}
.fid{{color:var(--mute);font-variant-numeric:tabular-nums}}
.chip{{font-size:.78rem;padding:.15rem .55rem;border:1px solid var(--line);white-space:nowrap}}
.detail{{padding:0 1rem 1rem 3.1rem;border-top:1px solid var(--line)}}
.detail h4{{margin:1rem 0 .2rem;font-size:.95rem}}
.detail ul{{margin:.2rem 0;padding-left:1.1rem}}
dl{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:.6rem 1.2rem;margin:.8rem 0}}
dt{{color:var(--mute);font-size:.8rem}}dd{{margin:0}}
code{{font:.85rem ui-monospace,Menlo,Consolas,monospace;word-break:break-all}}
footer{{color:var(--mute);font-size:.85rem;margin-top:3rem}}
footer a{{color:var(--accent)}}
@media (max-width:560px){{summary{{grid-template-columns:14px 1fr;}}.fid,.chip{{grid-column:2}}.pipeline{{flex-wrap:wrap}}.seg{{flex:1 1 45% !important}}.detail{{padding-left:1rem}}}}
</style></head>
<body><main>
<h1>{e(title)}</h1>
<p class="sub">{e(subtitle)}</p>
{banner}
<h2>Where every finding stands</h2>
<div class="pipeline">{pipeline}</div>
<p class="sub" style="margin-top:.6rem">Plus {m['by_status']['false-positive']} closed as false positive.</p>
<div class="stats">{stats}</div>
<h2>Findings by severity</h2>
{sev_rows}
<h2>All findings</h2>
<div class="filters" id="filters">{filters}</div>
<div id="list">{''.join(rows)}</div>
<footer>Built {date.today()} from <code>findings/*.yml</code>. Raw data: <a href="findings.csv">findings.csv</a>.</footer>
</main>
<script>
(function(){{
  var active=null,btns=document.querySelectorAll('#filters button'),rows=document.querySelectorAll('.row');
  btns.forEach(function(b){{b.setAttribute('aria-pressed','false');b.addEventListener('click',function(){{
    active=(active===b.dataset.f)?null:b.dataset.f;
    btns.forEach(function(x){{x.setAttribute('aria-pressed',String(x.dataset.f===active))}});
    rows.forEach(function(r){{r.hidden=!!active&&r.dataset.status!==active}});
  }})}});
}})();
</script>
</body></html>"""


def write_csv(findings):
    cols = ["id", "title", "cwe", "owasp", "severity", "status", "repo", "files",
            "tool", "rule", "first_seen", "closed_at"]
    with open(OUT_DIR / "findings.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(cols)
        for f in findings:
            row = [f.get(c, "") for c in cols]
            row[cols.index("files")] = "; ".join(f["files"])
            w.writerow(row)


def main():
    OUT_DIR.mkdir(exist_ok=True)
    findings = load_findings()
    m = compute_metrics(findings)
    (OUT_DIR / "index.html").write_text(render(findings, m), encoding="utf-8")
    write_csv(findings)
    print(f"Built {len(findings)} findings -> docs/index.html, docs/findings.csv")


if __name__ == "__main__":
    main()
