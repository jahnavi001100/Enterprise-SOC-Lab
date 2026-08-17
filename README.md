# Enterprise SOC Lab

A hands-on simulation of daily SOC analyst work: generating realistic Windows
logon telemetry, detecting brute-force and credential-attack patterns,
investigating suspicious IPs, building Microsoft Sentinel alert rules and
investigation workbooks, and writing formal incident reports.

Built as a portfolio project to demonstrate practical SIEM/SOC skills:
**Microsoft Sentinel · KQL · Log Analytics · Microsoft Defender · PowerShell · Python**

> This repo is designed to be evaluated **without needing an Azure
> subscription** — the Python pipeline reproduces the same detection logic
> as the Sentinel analytic rules against realistic synthetic data, end to
> end, in under a minute. The Sentinel/KQL/PowerShell artifacts are the
> real, production-shaped deployment assets for anyone who *does* want to
> deploy this against a live workspace.

---

## What this project simulates

| SOC Analyst Task | Where it lives |
|---|---|
| Simulate Windows logins & failed logins | `scripts/generate_windows_logs.py` |
| Detect brute-force attempts | `kql/02-05_*.kql`, `scripts/brute_force_detector.py` |
| Investigate suspicious IP addresses | `scripts/ip_investigator.py` |
| Create Sentinel alert rules | `sentinel/analytic_rules/*.json` |
| Build investigation workbooks | `sentinel/workbooks/*.json` |
| Write incident reports | `incident_reports/*.md` |

## Repository structure

```
enterprise-soc-lab/
├── README.md
├── LICENSE
├── requirements.txt
├── docs/
│   ├── architecture.md          # system design, diagram, both run paths
│   └── data-onboarding.md       # how SecurityEvent actually gets populated
├── scripts/                     # Python detection engine (offline path)
│   ├── generate_windows_logs.py
│   ├── brute_force_detector.py
│   └── ip_investigator.py
├── kql/                         # 8 production-style KQL queries for Sentinel
├── sentinel/
│   ├── analytic_rules/          # 5 scheduled analytic rule templates (JSON)
│   └── workbooks/               # investigation workbook (JSON)
├── powershell/                  # real Windows/Azure onboarding scripts
│   ├── Export-LogonEvents.ps1
│   └── Setup-AMADataCollection.ps1
├── incident_reports/            # blank template + one fully worked example
└── sample_data/                 # generated on first run (gitignored outputs optional)
```

## Quick start (offline path, no Azure needed)

```bash
git clone <this-repo>
cd enterprise-soc-lab
pip install -r requirements.txt

# 1. Generate 24h of realistic Windows logon telemetry with 5 embedded attacks
python scripts/generate_windows_logs.py --hours 24 --out sample_data

# 2. Run detection logic (mirrors the KQL/Sentinel rules) against it
python scripts/brute_force_detector.py --input sample_data/windows_logon_events.csv \
                                        --out sample_data/detections.json

# 3. Build per-IP investigation dossiers from the detections
python scripts/ip_investigator.py --events sample_data/windows_logon_events.csv \
                                   --detections sample_data/detections.json \
                                   --out sample_data/ip_investigation_report.json
```

Sample output from step 2:

```
Analyzed 318 events -> 7 findings
  [High    ] Single-Source Brute Force
  [High    ] Single-Source Brute Force
  [High    ] Single-Source Brute Force
  [High    ] Password Spray
  [Critical] Distributed Brute Force (Botnet-style)
  [Critical] Brute Force Followed by Successful Logon (Likely Compromise)
  [Medium  ] Impossible Travel
```

Every finding above maps 1:1 to a real Sentinel analytic rule in
`sentinel/analytic_rules/` and a worked incident report example in
`incident_reports/`.

## Attack scenarios simulated

| Scenario | Pattern | Detection |
|---|---|---|
| Single-source brute force | One IP → one account, 35 rapid failures | `02_single_source_bruteforce.kql` |
| Password spray | One IP → 35 different accounts, low-and-slow | `03_password_spray_detection.kql` |
| Distributed brute force | 15 botnet IPs → one account | `04_distributed_bruteforce.kql` |
| Brute force → compromise | Failures immediately followed by a success | `05_bruteforce_then_success.kql` |
| Impossible travel | Same account, 2 IPs, implausible elapsed time | `06_impossible_travel.kql` |

See `docs/architecture.md` for the full data flow diagram and design
rationale (why multiple detections exist per threat class, why
correlation rules outrank raw-volume rules for severity, etc.).

## Deploying against a real Microsoft Sentinel workspace

1. Read `docs/data-onboarding.md` — covers enabling audit policy, the
   Azure Monitor Agent + Data Collection Rule setup (`powershell/Setup-AMADataCollection.ps1`),
   and enabling the Sentinel Windows Security Events connector.
2. Import the queries in `kql/` into the Sentinel **Logs** blade.
3. Deploy the rules in `sentinel/analytic_rules/` as Scheduled Query Rules.
4. Import `sentinel/workbooks/soc_lab_investigation_workbook.json` as a
   new workbook (Sentinel → Workbooks → Add → Advanced Editor).
5. Use `powershell/Export-LogonEvents.ps1` for local ad-hoc host triage.

## Incident reports

- `incident_reports/TEMPLATE_incident_report.md` — blank template
  (summary, timeline, scope/impact, root cause, containment, recommendations)
- `incident_reports/SOC-LAB-2026-001_administrator_bruteforce_compromise.md` —
  fully worked example written against the simulated administrator
  brute-force-to-compromise scenario, following NIST SP 800-61-style
  incident handling phases (detection → containment → eradication →
  recovery → lessons learned).

## Detection design notes

- All time-based detections use **rolling windows** via a two-pointer
  sliding-window scan, not fixed daily buckets, so bursts are caught
  regardless of when in the day they occur.
- Three independent detections exist for brute-force-class activity
  (single-IP volume, IP fan-in, account fan-out) because real attackers
  pick whichever pattern evades the *simplest* single threshold — a
  realistic SOC never relies on one rule per threat class.
- The correlation rule (failures → success) is scored **Critical**
  even though the raw failure-count rule would have already fired,
  because correlating two weaker signals into "likely compromise" is
  the core value SIEM engineering adds over raw log storage.
- Every Sentinel analytic rule includes MITRE ATT&CK technique mapping
  and entity mappings (Account/IP) so incidents are pivotable in
  Sentinel's investigation graph and compatible with UEBA.

## Tech stack

Microsoft Sentinel (Azure) · Microsoft Defender · Log Analytics · KQL ·
PowerShell (Az module, AMA/DCR) · Python (pandas)

## Recruiter keywords

SIEM, Microsoft Sentinel, KQL, SOC, Incident Response, Threat Detection,
Brute Force Detection, MITRE ATT&CK, Log Analytics, Azure Monitor Agent,
Security Event Monitoring, Detection Engineering

## License

MIT — see [LICENSE](LICENSE).
