# VulnDex by Pinneddot

My running index of security findings and lessons, tracked from first discovery to confirmed fix.

**Live dashboard:** https://pinneddot.github.io/VulnDex/

## Why I built this

I work in identity and access management and growing into application security testing, mainly code reviews and penetration testing. At work, findings live in tickets and spreadsheets that are kept internal. VulnDex is the public version of how I work: the same triage habits and the same lifecycle, applied to practice targets so everything here is mine to show.

It also solves a practical problem. I wanted one place where a finding is more than a line in a report: where it came from, how I confirmed it, what I recommended, and whether the fix held up on retest.

## What's in it

- **Findings:** each one is a small text file in `findings/`, with its weakness type (CWE), severity, affected files, recommendation and my review notes.
- **A live dashboard** that rebuilds itself whenever I push a change: where every finding stands, average time to fix, retest pass rate and how noisy my scanners are.
- **A learning log** for practice labs and study notes (currently PortSwigger Web Security Academy), kept separate from the findings numbers.

## How a finding moves

`new` → `true-positive` → `remediated` → `retest-passed`

A scanner result that turns out to be noise is closed as `false-positive`. I track that too, because knowing which rules cry wolf saves time.

## How it works

```
scan (Semgrep, manual testing) -> findings/*.yml -> scripts/build.py -> dashboard
```

1. I scan a target, or test it by hand, and record what I find.
2. I triage each result: real, or false positive.
3. `scripts/build.py` turns the files into the dashboard. A GitHub Action runs it on every push and publishes the page.

No database, no servers. Everything is plain text in git, so the full history of every finding is preserved.

## Running it

```bash
pip install -r requirements.txt
python scripts/build.py        # then open docs/index.html
```

To start from a Semgrep scan:

```bash
semgrep scan --json -o semgrep.json path/to/code
python scripts/ingest_semgrep.py semgrep.json --repo my-target --prefix MT
```

## Finding fields

| Field | Meaning |
|---|---|
| `id`, `title` | Unique ID and short name |
| `type` | `code-review`, `web-app`, `api`, `infrastructure` or `lab` |
| `cwe` | The kind of weakness (e.g. CWE-89, SQL injection) |
| `cve` | Optional. Only when the issue is a published vulnerability in a specific product or version |
| `severity`, `status` | Critical to info, and where it stands in the lifecycle |
| `target` | What was tested (a repo, an app, a host) |
| `tool`, `reference` | How I found it: the tool, plus the scanner rule ID, an OWASP WSTG test ID, or the technique |
| `files`, `description`, `recommendation`, `notes` | The detail |

## Ground rules

- Only practice targets and intentionally vulnerable apps appear here (such as OWASP Juice Shop). Nothing from an employer or client is ever published.
- The sample findings are labelled as demo data on the dashboard.
- Lab entries are my own notes on what I learned, not walkthroughs of solutions.

## Roadmap

- [ ] Excel and PDF report export
- [ ] Retest view: what changed between two scans
- [ ] More finding types: web app, API and infrastructure testing
- [ ] Anonymized metrics export for private use
