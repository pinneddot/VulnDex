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
TYPES = ["code-review", "web-app", "api", "infrastructure", "lab"]
REQUIRED_ALL = ["id", "title", "cwe", "first_seen"]
REQUIRED_ASSESSMENT = ["severity", "status", "target"]  # not needed for learning labs
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
            # accept the older field names too
            if "repo" in data and "target" not in data:
                data["target"] = data.pop("repo")
            if "rule" in data and "reference" not in data:
                data["reference"] = data.pop("rule")
            data.setdefault("type", "code-review")
            if data["type"] not in TYPES:
                raise ValueError(f"{fid}: type must be one of {TYPES}")
            need = REQUIRED_ALL + ([] if data["type"] == "lab" else REQUIRED_ASSESSMENT)
            missing = [k for k in need if k not in data]
            if missing:
                raise ValueError(f"{fid}: missing fields {missing}")
            if data["type"] != "lab":
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


CSS = """
:root{color-scheme:dark light;
--bg:#120f24;--panel:#1a1633;--line:#2d2852;--ink:#f3f1f8;--mute:#9b95ba;
--amber:#f2a65a;--blue:#5b86ff;--cyan:#45c7f0;
--glow1:rgba(242,166,90,.20);--glow2:rgba(91,134,255,.22);
--sev-critical:#ff6b61;--sev-high:#f2a65a;--sev-medium:#e6cf6e;--sev-low:#45c7f0;--sev-info:#8b86b8;
--st-new:#8b86b8;--st-true-positive:#f2a65a;--st-remediated:#5b86ff;--st-retest-passed:#45c7f0;--st-false-positive:#6d688f;}
@media (prefers-color-scheme:light){:root{
--bg:#f5f3f8;--panel:#fff;--line:#dedae8;--ink:#17142a;--mute:#6a6585;
--amber:#b8610f;--blue:#2c52d0;--cyan:#0e87ad;
--glow1:rgba(242,166,90,.16);--glow2:rgba(91,134,255,.14);
--sev-critical:#d03a30;--sev-high:#c26a14;--sev-medium:#a88a0c;--sev-low:#0e87ad;--sev-info:#6f6a98;
--st-new:#6f6a98;--st-true-positive:#b8610f;--st-remediated:#2c52d0;--st-retest-passed:#0e87ad;--st-false-positive:#8a86a6;}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--ink);position:relative;
font:400 15px/1.5 "Helvetica Neue","Inter",Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased}
body::before{content:"";position:absolute;inset:0 0 auto 0;height:460px;pointer-events:none;
background:radial-gradient(620px 320px at 88% -10%,var(--glow1),transparent 70%),
radial-gradient(560px 320px at 6% -10%,var(--glow2),transparent 70%)}
main{position:relative;max-width:920px;margin:0 auto;padding:1.4rem 1.5rem 2.5rem}
a{color:inherit}
a:focus-visible,button:focus-visible,summary:focus-visible{outline:2px solid var(--blue);outline-offset:3px}
.top{display:flex;justify-content:space-between;align-items:center}
.who{font-weight:400;text-decoration:none;color:var(--mute)}
.who:hover{color:var(--ink)}
.pill{font-size:.8rem;padding:.2rem .75rem;border-radius:999px;background:var(--panel);border:1px solid var(--line);color:var(--mute)}
.hero{padding:3rem 0 1.6rem}
h1{font-weight:300;font-size:clamp(2.6rem,7vw,3.8rem);line-height:1;letter-spacing:-.03em;margin:0 0 .9rem}
.lead{font-size:1.1rem;margin:0 0 .5rem}
.note{color:var(--mute);font-size:.85rem;margin:0}
h2{font-weight:400;font-size:1.05rem;margin:0 0 .8rem}
section{border-top:1px solid var(--line);padding:1.3rem 0}
.bar{display:flex;gap:3px;height:6px;margin-bottom:1rem}
.bar i{display:block;background:var(--c);min-width:6px;border-radius:1px}
.stages{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem}
.stage b{display:block;font-weight:300;font-size:2.3rem;line-height:1.1;letter-spacing:-.02em;font-variant-numeric:tabular-nums}
.stage span{display:flex;align-items:center;gap:.45rem;color:var(--mute);font-size:.85rem}
.stage span::before{content:"";width:7px;height:7px;border-radius:50%;background:var(--c);flex:none}
.fp{color:var(--mute);font-size:.85rem;margin:.9rem 0 0}
.two{display:grid;grid-template-columns:1fr 1fr;gap:2.5rem}
.sevrow{display:grid;grid-template-columns:68px 1fr 22px;gap:.7rem;align-items:center;margin:.4rem 0;font-size:.9rem}
.track{height:4px;background:var(--line);display:block}
.track i{display:block;height:100%;background:var(--c)}
.sevn{text-align:right;color:var(--mute);font-variant-numeric:tabular-nums}
.stats{display:grid;grid-template-columns:1fr 1fr;gap:1.1rem 1.5rem;align-content:start}
.stat .v{font-weight:300;font-size:1.7rem;line-height:1.15;letter-spacing:-.02em}
.stat .l{color:var(--mute);font-size:.82rem;line-height:1.35}
.filters{display:flex;flex-wrap:wrap;gap:.2rem 1.1rem;margin:-.2rem 0 .6rem}
.filters button{background:none;border:0;border-bottom:1px solid transparent;color:var(--mute);font:inherit;font-size:.88rem;padding:.2rem 0;cursor:pointer}
.filters button:hover{color:var(--ink)}
.filters button[aria-pressed=true]{color:var(--ink);border-bottom-color:var(--amber)}
.row{border-top:1px solid var(--line)}
.row:last-child{border-bottom:1px solid var(--line)}
summary{display:grid;grid-template-columns:8px 4.4rem 1fr auto;gap:.9rem;align-items:center;padding:.65rem 0;cursor:pointer;list-style:none}
summary::-webkit-details-marker{display:none}
summary:hover .ftitle{color:var(--amber)}
.dot{width:8px;height:8px;border-radius:50%;background:var(--c)}
.fid{color:var(--mute);font-variant-numeric:tabular-nums;font-size:.85rem;white-space:nowrap}
.st{font-size:.82rem;color:var(--c);white-space:nowrap}
.detail{padding:.2rem 0 1.1rem calc(8px + 4.4rem + 1.8rem)}
.detail p{margin:.2rem 0 .7rem;max-width:68ch}
.detail h4{font-weight:400;color:var(--mute);font-size:.82rem;margin:.9rem 0 .15rem}
.detail ul{margin:.1rem 0;padding-left:1.1rem}
dl{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:.6rem 1.5rem;margin:.9rem 0 .2rem}
dt{color:var(--mute);font-size:.8rem}dd{margin:0;font-size:.9rem}
code{font:.82rem ui-monospace,Menlo,Consolas,monospace;word-break:break-all}
footer{border-top:1px solid var(--line);padding-top:1rem;color:var(--mute);font-size:.82rem;display:flex;flex-wrap:wrap;gap:.3rem 1.4rem}
footer a{text-underline-offset:3px}
@media (max-width:640px){
 main{padding:1.1rem 1.1rem 2rem}.hero{padding-top:2rem}
 .stages{grid-template-columns:1fr 1fr}.two{grid-template-columns:1fr;gap:1.4rem}
 summary{grid-template-columns:8px 1fr auto}.fid{grid-column:2}.ftitle{grid-column:2;grid-row:2}
 .st{grid-column:3;grid-row:1 / span 2}.detail{padding-left:0}}
"""

TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="%%DESC%%">
<title>%%TITLE%%</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400&display=swap" rel="stylesheet">
<style>%%CSS%%</style></head>
<body><main>
<header class="top"><a class="who" href="%%GITHUB%%">%%AUTHOR%%</a><span class="pill">%%STATUS%%</span></header>
<div class="hero">
<h1>%%TITLE%%</h1>
<p class="lead">%%SUBTITLE%%</p>
%%BANNER%%
</div>
<section>
<h2>Where every finding stands</h2>
<div class="bar">%%BAR%%</div>
<div class="stages">%%STAGES%%</div>
<p class="fp">Plus %%FP%% closed as false positive.</p>
</section>
<section class="two">
<div><h2>By severity</h2>%%SEV%%</div>
<div><h2>At a glance</h2><div class="stats">%%STATS%%</div></div>
</section>
<section>
<h2>All findings</h2>
<div class="filters" id="filters">%%FILTERS%%</div>
<div id="list">%%ROWS%%</div>
</section>
%%LEARNING%%
<footer><span>Maintained by <a href="%%GITHUB%%">%%AUTHOR%%</a></span><a href="%%REPO%%">Source</a><a href="findings.csv">Data (CSV)</a><span>Updated %%TODAY%%</span></footer>
</main>
<script>
(function(){
  var active=null,btns=document.querySelectorAll('#filters button'),rows=document.querySelectorAll('#list .row');
  btns.forEach(function(b){b.setAttribute('aria-pressed','false');b.addEventListener('click',function(){
    active=(active===b.dataset.f)?null:b.dataset.f;
    btns.forEach(function(x){x.setAttribute('aria-pressed',String(x.dataset.f===active))});
    rows.forEach(function(r){r.hidden=!!active&&r.dataset.status!==active});
  })});
})();
</script>
</body></html>"""


def render(findings, m, labs=()):
    config = yaml.safe_load((ROOT / "tracker.yml").read_text(encoding="utf-8"))
    title = config.get("title", "VAPT Tracker")
    subtitle = config.get("subtitle", "")
    demo = config.get("demo_data", True)
    author = config.get("author", "")
    github = config.get("github", "#")
    repo = config.get("repo", "#")
    status = config.get("status_label", "Work in progress")

    total = max(m["total"], 1)
    bar = "".join(
        f'<i style="flex:{m["by_status"][s]};--c:var(--st-{s})" title="{STAGE_LABEL[s]}"></i>'
        for s in STAGES if m["by_status"][s]
    )
    stages = "".join(
        f'<div class="stage" style="--c:var(--st-{s})"><b>{m["by_status"][s]}</b>'
        f'<span>{STAGE_LABEL[s]}</span></div>' for s in STAGES
    )
    sev = "".join(
        f'<div class="sevrow" style="--c:var(--sev-{s})"><span>{s.capitalize()}</span>'
        f'<span class="track"><i style="width:{100 * m["by_sev"][s] / total}%"></i></span>'
        f'<span class="sevn">{m["by_sev"][s]}</span></div>' for s in SEVERITIES
    )

    def stat(value, label):
        return f'<div class="stat"><div class="v">{value}</div><div class="l">{label}</div></div>'

    stats = "".join([
        stat(m["open_count"], "Open findings"),
        stat(f'{m["avg_days"]} days' if m["avg_days"] is not None else "n/a", "Average time to fix"),
        stat(f'{m["pass_rate"]}%' if m["pass_rate"] is not None else "n/a", "Retests passed"),
        stat(f'{m["fp_rate"]}%', "Scanner false positives"),
    ])

    sev_order = {s: i for i, s in enumerate(SEVERITIES)}
    rows = []
    for f in sorted(findings, key=lambda f: (sev_order[f["severity"]], f["id"])):
        files = "".join(f"<li><code>{e(p)}</code></li>" for p in f["files"])
        closed = f'<div><dt>Closed</dt><dd>{f["closed_at"]}</dd></div>' if f.get("closed_at") else ""
        ref = f"{e(f.get('tool', 'n/a'))}" + (f" / {e(f['reference'])}" if f.get("reference") else "")
        weak = e(f["cwe"]) + (f" / {e(f['cve'])}" if f.get("cve") else "")
        rows.append(f"""<details class="row" data-status="{f['status']}">
<summary><span class="dot" style="--c:var(--sev-{f['severity']})"></span><span class="fid">{e(f['id'])}</span>
<span class="ftitle">{e(f['title'])}</span><span class="st" style="--c:var(--st-{f['status']})">{STAGE_LABEL[f['status']]}</span></summary>
<div class="detail"><p>{e(f.get('description', ''))}</p>
<dl><div><dt>Severity</dt><dd>{f['severity'].capitalize()}</dd></div>
<div><dt>Type</dt><dd>{e(f['type'])}</dd></div><div><dt>Target</dt><dd>{e(f['target'])}</dd></div>
<div><dt>Weakness</dt><dd>{weak}</dd></div><div><dt>OWASP</dt><dd>{e(f.get('owasp', 'n/a'))}</dd></div>
<div><dt>Found by</dt><dd>{ref}</dd></div><div><dt>First seen</dt><dd>{f['first_seen']}</dd></div>{closed}</dl>
<h4>Affected files</h4><ul>{files}</ul>
<h4>Recommendation</h4><p>{e(f.get('recommendation', ''))}</p>
<h4>Reviewer notes</h4><p>{e(f.get('notes', ''))}</p></div></details>""")

    lab_rows = "".join(f"""<details class="row">
<summary><span class="dot" style="--c:var(--blue)"></span><span class="fid">{e(l['id'])}</span>
<span class="ftitle">{e(l['title'])}</span><span class="st" style="--c:var(--mute)">{e(str(l.get('status', 'solved')).replace('-', ' ').capitalize())}</span></summary>
<div class="detail"><p>{e(l.get('description', ''))}</p>
<dl><div><dt>Weakness</dt><dd>{e(l['cwe'])}</dd></div><div><dt>Where</dt><dd>{e(l.get('target', ''))}</dd></div>
<div><dt>Started</dt><dd>{l['first_seen']}</dd></div></dl>
<h4>What I learned</h4><p>{e(l.get('notes', ''))}</p></div></details>""" for l in sorted(labs, key=lambda x: x["id"]))
    learning = (f'<section><h2>Learning log</h2>{lab_rows}</section>') if labs else ""

    filters = "".join(f'<button data-f="{s}">{STAGE_LABEL[s]}</button>' for s in STATUSES)
    banner = ('<p class="note">Demo data from OWASP Juice Shop, a deliberately vulnerable practice app. '
              'Nothing from any employer or client.</p>') if demo else ""

    out = TEMPLATE
    for k, v in {"DESC": e(subtitle), "TITLE": e(title), "CSS": CSS, "GITHUB": e(github), "AUTHOR": e(author),
                 "STATUS": e(status), "SUBTITLE": e(subtitle), "BANNER": banner, "BAR": bar, "STAGES": stages,
                 "FP": str(m["by_status"]["false-positive"]), "SEV": sev, "STATS": stats, "FILTERS": filters,
                 "ROWS": "".join(rows), "LEARNING": learning, "REPO": e(repo), "TODAY": str(date.today())}.items():
        out = out.replace(f"%%{k}%%", v)
    return out


def write_csv(findings):
    cols = ["id", "title", "type", "cwe", "cve", "owasp", "severity", "status", "target",
            "files", "tool", "reference", "first_seen", "closed_at"]
    with open(OUT_DIR / "findings.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(cols)
        for f in findings:
            row = [f.get(c, "") for c in cols]
            row[cols.index("files")] = "; ".join(f.get("files", []))
            w.writerow(row)


def main():
    OUT_DIR.mkdir(exist_ok=True)
    everything = load_findings()
    findings = [f for f in everything if f["type"] != "lab"]
    labs = [f for f in everything if f["type"] == "lab"]
    m = compute_metrics(findings)
    (OUT_DIR / "index.html").write_text(render(findings, m, labs), encoding="utf-8")
    write_csv(everything)
    print(f"Built {len(findings)} findings and {len(labs)} learning entries -> docs/index.html, docs/findings.csv")


if __name__ == "__main__":
    main()
