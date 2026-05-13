# Shai-Hulud / Carnage APT — Incident Worm Disclosure (IWD) 2026

**Date:** 2026-05-13  
**Researcher:** breakingcircuit ([breakingcircuits.com](https://breakingcircuits.com))  
**Repo:** `breakingcircuitsllc/Shai-Hulud-Carnage-APT-Report`  
**Status:** Public Disclosure — CVE-pending / GHSA-pending

---

> **GitHub Trust & Safety Response:** Marked as **"Informative"** — acknowledging the worm's deadman switch design (token revocation triggers `rm -rf ~/`) but declining to treat the mechanism as a GitHub Platform vulnerability. The attacker-controlled repos (`PedroTortoriello/Shai-Hulud-Open-Source`, `g00dfe11ow/Shai-Hulud-Open-Source`) remain active at time of disclosure.

---

## Executive Summary

**What is Shai-Hulud?**  
A supply chain worm targeting developer workstations and CI/CD runners. It steals NPM publish tokens and cloud credentials (AWS Secrets Manager across 17 regions), exfiltrates data via dynamically created GitHub repos, and backdoors the NPM supply chain with poisoned packages bearing forged Sigstore provenance.

**The Deadman Switch**  
The malware installs a background daemon (`gh-token-monitor`) that polls `api.github.com/user` every 60 seconds. If the stolen GitHub PAT is revoked (returning HTTP 4xx), the daemon executes `rm -rf ~/` — wiping the victim's home directory. This is not a bug. It is a deliberate counter-IR measure designed to punish standard incident response (immediate token rotation).

**The Fork Network**  
At disclosure, `g00dfe11ow/Shai-Hulud-Open-Source` had 80 stars and 68 forks. Only 2 forks were visible in the active fork list — the remainder were deleted or set to private post-fork. The account `agwagwagwa` forked 17 hours before disclosure with a commit claiming FreeBSD/OpenBSD support (false flag). All forks share the same commit: "Shai-Hulud: A Gift From TeamPCP" authored by `TeamPCP_OSS` with timestamp `2099-01-01T01:01:01Z`.

---

## Evidence / OSINT

### agwagwagwa Fork — Pre-Disclosure Activity

The account `agwagwagwa` forked the repo 17 hours before public disclosure with a commit titled "fix: add support for freebsd/openbsd." This appears to be a false-flag commit designed to give the fork superficial legitimacy.

| Evidence | Screenshot |
|----------|-----------|
| agwagwagwa fork commit | `screenshots/Screenshot_20260513_061300.png` |
| agwagwagwa profile | `screenshots/Screenshot_20260513_061354.png` |
| Deadman switch handler payload | `screenshots/Screenshot_20260513_065545.png` |
| NPM token exfiltration regex | `screenshots/Screenshot_20260513_065639.png` |
| AWS credential harvesting (17 regions) | `screenshots/Screenshot_20260513_065705.png` |
| Malicious workflow.yml (GitHub Actions secrets exfil) | `screenshots/Screenshot_20260513_065729.png` |
| VSCode tasks.json persistence | `screenshots/Screenshot_20260513_065808.png` |
| Claude Code hook (SessionStart) | `screenshots/Screenshot_20260513_070316.png` |
| Bun runtime dropper (bash variant) | `screenshots/Screenshot_20260513_070340.png` |
| Obfuscated build output | `screenshots/Screenshot_20260513_070400.png` |

Additional evidence (commit graphs, fork network, C2 domain registration, GitHub search beacon hits):

| Evidence | Screenshot |
|----------|-----------|
| C2 domain `git-tanstack.com` WHOIS | `screenshots/Screenshot_20260513_070414.png` |
| Malicious npm publish with Sigstore forgery | `screenshots/Screenshot_20260513_070429.png` |
| Beacon string search on GitHub | `screenshots/Screenshot_20260513_070447.png` |
| PR / fork network graph | `screenshots/Screenshot_20260513_075445.png` |
| Fork commit analysis | `screenshots/Screenshot_20260513_075510.png` |
| Repo star count | `screenshots/Screenshot_20260513_075522.png` |
| Deadman switch code | `screenshots/Screenshot_20260513_075718.png` |
| NPM package targeting OpenSearch | `screenshots/Screenshot_20260513_094104.png` |
| Python memory dump utility (Runner.Worker) | `screenshots/Screenshot_20260513_095631.png` |
| Node-based Bun dropper (config.mjs) | `screenshots/Screenshot_20260513_101131.png` |
| Python-based Bun dropper | `screenshots/Screenshot_20260513_101231.png` |

### git-identity-manager Tool

The threat actor uses a tool called `git-identity-manager` to rotate git commit identities across forks, making attribution across the fork network difficult. This tool is referenced in the malware's operational security tooling.

### Pull Requests / Merge Activity

See `screenshots/` for full PR evidence including:
- PRs merging poisoned code into the public `Shai-Hulud-Open-Source` repos
- The `g00dfe11ow` account's merge activity prior to disclosure
- Cross-account collaboration between `PedroTortoriello` and `g00dfe11ow`

---

## Indicators of Compromise (IoCs)

<!-- IoCs are maintained in iocs.md — included verbatim below -->

> **Full IoC file:** [`iocs.md`](./iocs.md)
> **YARA rules:** [`teampcp_shai_hulud.yar`](./teampcp_shai_hulud.yar)
> **Observed infected repos:** [`infected-repos.txt`](./infected-repos.txt)
> **Fork analysis (63+ accounts):** [`forks.txt`](./forks.txt)

### Quick-Reference IoC Table

| Category | Indicator |
|----------|-----------|
| **File** | `~/.local/bin/gh-token-monitor.sh` |
| **File** | `~/.config/gh-token-monitor/token` |
| **File** | `~/.config/gh-token-monitor/handler` |
| **Persistence (macOS)** | `~/Library/LaunchAgents/com.user.gh-token-monitor.plist` |
| **Persistence (Linux)** | `~/.config/systemd/user/gh-token-monitor.service` |
| **Process** | `gh-token-monitor.sh` |
| **Beacon string** | `IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner` |
| **C2 domain** | `git-tanstack.com` |
| **NPM UA** | `npm/11.13.1 node/v24.10.0` |
| **Lock file** | `tmp.ts018051808.lock` |
| **Exfil pattern** | `results-<timestamp>-<counter>.json[.pN]` |
| **Fake author** | `TeamPCP_OSS` / `TeamPCP` |
| **Commit message** | `Shai-Hulud: A Gift From TeamPCP` |
| **Fake timestamp** | `2099-01-01T01:01:01Z` |
| **Trigger** | HTTP 4xx from `api.github.com/user` |

### Beacon String Search

Platform defenders and SOC teams can search GitHub for the worm's unique beacon string to identify additional compromised tokens:

```
https://api.github.com/search/code?q=IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner
```

---

## Vaccine / Remediation

**CRITICAL WARNING:** Do NOT revoke compromised GitHub tokens before running the remediation script. Premature revocation WILL trigger the deadman switch (`rm -rf ~/`).

### Quick Remediation

```bash
# 1. Clone this repo
git clone https://github.com/breakingcircuitsllc/Shai-Hulud-Carnage-APT-Report.git
cd Shai-Hulud-Carnage-APT-Report

# 2. Run the vaccine (no network calls unless you pass --revoke-endpoint)
chmod +x shaihuld-remediate.sh
./shaihuld-remediate.sh

# 3. After the script confirms "THREAT NEUTRALIZED" or "No active threat found",
#    manually revoke tokens at: https://github.com/settings/tokens
```

### What the Vaccine Does

| Phase | Action |
|-------|--------|
| Phase 1: Detect | Scans for LaunchAgent, systemd service, running processes, and payload files |
| Phase 2: Defuse | Kills processes, removes persistence, purges payload files |
| Phase 3: Immunize | Locks the config directory (chflags/chattr +i), disables npm lifecycle scripts |
| Phase 4: Signal | Optionally sends "clean" status to a coordinated safe-revocation endpoint |
| Phase 5: Report | Writes a detailed IR report to `~/.local/share/ir-reports/` |

### Remediation Script

Full source: [`shaihuld-remediate.sh`](./shaihuld-remediate.sh) (247 lines)

**Usage:**
```bash
chmod +x shaihuld-remediate.sh
./shaihuld-remediate.sh              # Detect + defuse + immunize
./shaihuld-remediate.sh --silent     # CI mode, no stdout
./shaihuld-remediate.sh --revoke-endpoint https://ir.example.com/host-clean
```

---

## Full Intelligence Report

- **Threat Intelligence Report:** [`Threat Intelligence.md`](./Threat Intelligence.md)
- **Original Security Disclosure (docx):** [`docs/github-security-disclosure-shai-hulud.docx`](./docs/github-security-disclosure-shai-hulud.docx)
- **Follow-up Report v1:** [`docs/shai-hulud-followup-report.docx`](./docs/shai-hulud-followup-report.docx)
- **Follow-up Report v2:** [`docs/shai-hulud-followup-report-v2.docx`](./docs/shai-hulud-followup-report-v2.docx)
- **General Disclosure:** [`docs/shai-hulud-general-disclosure.docx`](./docs/shai-hulud-general-disclosure.docx)

---

## Repository Contents

```
Shai-Hulud-Carnage-APT-Report/
├── README.md                    ← This file — the Anchor Post
├── iocs.md                      ← Full Indicators of Compromise
├── teampcp_shai_hulud.yar       ← YARA detection rules (12 rules)
├── shaihuld-remediate.sh        ← Vaccine / remediation script
├── Threat Intelligence.md       ← Full threat intel & defense report
├── infected-repos.txt           ← 40+ repos referencing Shai-Hulud IOCs
├── forks.txt                    ← 63 forked accounts with commit forensics
├── screenshots/                 ← 26 evidence screenshots
│   ├── Screenshot_20260513_060837.png
│   ├── ...
│   └── Screenshot_20260513_190310.png
└── docs/                        ← Original disclosure documents
    ├── github-security-disclosure-shai-hulud.docx
    ├── report.docx
    ├── shai-hulud-followup-report.docx
    ├── shai-hulud-followup-report-v2.docx
    └── shai-hulud-general-disclosure.docx
```

---

## Disclosure Timeline

| Date | Event |
|------|-------|
| 2026-05-12 | Initial identification of `gh-token-monitor` persistence mechanism |
| 2026-05-12 | Discovery of the deadman switch (wiper triggered by token revocation) |
| 2026-05-12 | agwagwagwa fork observed (17h before disclosure) |
| 2026-05-12 | GLP23 fork observed (10h before disclosure) |
| 2026-05-13 | GitHub Security Disclosure submitted |
| 2026-05-13 | GitHub T&S response: **Informative** — not a platform vulnerability |
| 2026-05-13 | Public disclosure |

---

## References

- [NPM Registry Security](https://www.npmjs.com/support)
- [GitHub Personal Access Tokens](https://github.com/settings/tokens)
- [Sigstore Supply Chain Integrity](https://www.sigstore.dev)

---

**License:** This report is provided for defensive purposes. Use at your own risk.  
**Contact:** security@breakingcircuits.com
