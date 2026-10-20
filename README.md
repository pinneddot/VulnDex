# VAPT Findings Tracker

A small, durable tracker for code-review (VAPT) findings. Every finding is one plain text file.
A script turns those files into a static dashboard that GitHub Pages publishes automatically.

**Demo data:** the sample findings come from OWASP Juice Shop, an intentionally vulnerable practice app.

## How it works

```
semgrep scan --json  ->  ingest_semgrep.py  ->  findings/*.yml  ->  build.py  ->  docs/index.html
                          (draft findings)       (you triage)        (dashboard)
```

Life of a finding: `new` -> `true-positive` -> `remediated` -> `retest-passed`, or `false-positive` as a side exit.

## Run it locally

```bash
pip install -r requirements.txt
python scripts/build.py          # then open docs/index.html
```

## Add findings from a scan

```bash
semgrep scan --json -o semgrep.json path/to/code
python scripts/ingest_semgrep.py semgrep.json --repo my-repo --prefix MR
```

Open the new files in `findings/`, set the status, write the description and recommendation, commit.
The dashboard rebuilds on every push to `main`.

## Go live (GitHub Pages)

1. Create a GitHub repo and push this folder to `main`.
2. Settings -> Pages -> Source: **GitHub Actions**.
3. Push any change. Your dashboard appears at `https://<you>.github.io/<repo>/`.

## Public vs private

- Keep this repo **public** with demo data only (`demo_data: true` in `tracker.yml`).
- For real work, use a **private** copy of the same code. Never publish employer or client findings.

## Finding fields

Required: `id, title, cwe, severity, status, repo, first_seen`.
Optional: `owasp, files, tool, rule, closed_at, description, recommendation, notes`.
Severity: critical, high, medium, low, info. A bad file stops the build with a clear message.

## Roadmap

- [ ] Excel report export (Listing / Summary / Details)
- [ ] Retest view: what changed between two scans
- [ ] Jira sync for ticket links
- [ ] Anonymized metrics export from the private tracker
