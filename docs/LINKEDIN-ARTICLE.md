# Shai-Hulud: The Worm That Wipes Your Home Directory When You Revoke the Token — And Why HackerOne Called It "Informative"

**A perfect use case for AI-assisted Incident Response. A cautionary tale for DevOpSec. A wake-up call for the platform.**

---

## The TL;DR

A supply chain worm named **Shai-Hulud** (attribution: TeamPCP / Carnage APT) targets developer workstations, steals NPM + AWS credentials, backdoors the NPM registry with forged Sigstore provenance, and exfiltrates data to dynamically created GitHub repos. It has a **deadman switch**: a background daemon that polls `api.github.com/user` every 60 seconds. If you revoke the stolen token — standard IR 101 — it `rm -rf ~/` your home directory.

I took it to HackerOne because they have the reach — better avenues to get the word out than I do alone. I handed them everything: the vaccine script, surgery plans, threat reports, full IoCs, and a complete YARA rule set. Everything a platform needs to protect its users.

The response was just kinda rude.

They marked it **"Informative"**.

The attacker repos are **still live** on GitHub as of this post.

---

## The Timeline (The Speedrun Part)

| Time | What Happened |
|------|---------------|
| **04:20 UTC** | Worm sample received |
| **05:15** | Deadman switch identified |
| **06:00** | NPM token pipeline reversed |
| **06:30** | AWS 17-region harvester found |
| **07:00** | YARA rules + remediation script generated |
| **10:35** | Full reversal complete |
| **~6 hours total** | Worm to disclosure |

**Traditional timeline for a multi-stage supply chain worm of this complexity: 14–21 days.**

The acceleration was entirely AI-assisted — decompilation, logic extraction, IoC generation, YARA rule authoring, and remediation script writing. What would take a human analyst a full sprint cycle was compressed into a single morning.

**This is the future of IR.** Not replacing analysts — giving them superpowers.

---

## The Threat (For the DevOpSec Crowd)

Here's what this worm does, end to end:

1. **Bun runtime dropper** — Downloads and installs Bun via a fake `ai_init.js` entry point. Three variants: bash, Python, Node (config.mjs).

2. **Credential harvesting** — Regex-scrapes NPM tokens (`npm_[A-Za-z0-9]{36,}`), iterates AWS Secrets Manager across **17 regions** dumping every secret, memory-dumps `Runner.Worker` process for CI/CD credentials.

3. **Supply chain poisoning** — Publishes malicious tarballs to `registry.npmjs.org` using stolen tokens. **Forges Sigstore provenance bundles** to bypass integrity checks.

4. **GitHub exfiltration** — Creates attacker-controlled repos, commits stolen data in `results-<timestamp>.json` envelopes. Beacon string embedded so attacker can search-index their haul: `IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner`.

5. **Deadman switch** — `gh-token-monitor` polls GitHub API. HTTP 4xx = `rm -rf ~/`. Cross-platform: LaunchAgent on macOS, systemd user service on Linux.

6. **Fork network** — The source repo (`g00dfe11ow/Shai-Hulud-Open-Source`) had 80 stars and **68 forks**. Only 2 visible. All commits authored as `TeamPCP_OSS` with timestamp `2099-01-01T01:01:01Z`. The remaining 66 forks were deleted or set to private.

7. **OpSec tooling** — A `git-identity-manager` tool to rotate commit identities across forks. VSCode `tasks.json` persistence on folder open. Claude Code `SessionStart` hooks.

---

## The Part That Should Upset You

I submitted this to HackerOne as a coordinated disclosure — specifically because HackerOne has the distribution to actually protect people. I didn't hold anything back:

- **Vaccine script** — `shaihuld-remediate.sh`, production-ready
- **Surgery plans** — Phase-by-phase IR playbook
- **Threat reports** — Full intelligence package
- **IoCs** — File, process, network, registry, the works
- **YARA rule set** — 12 rules covering every stage of the kill chain

Everything a platform needs to shield its userbase. Handed over on a silver platter.

The response: **"Informative"** — not a valid vulnerability. And the tone of it was dismissive. Rude, even.

A worm that:
- Installs a daemon that watches your GitHub token
- Has an explicitly coded wiper triggered by standard IR token rotation
- Targets the developer supply chain end-to-end
- Uses GitHub as its C2 channel, exfiltration target, AND distribution vector
- Is still actively forked from live repos on the platform

...is "Informative."

Meanwhile, the repos `PedroTortoriello/Shai-Hulud-Open-Source` and `g00dfe11ow/Shai-Hulud-Open-Source` are **still on GitHub** as of this post. Any developer who stumbles on them, runs the install script, and has their machine wiped when their org rotates the token — that's not a vulnerability. That's a feature.

**To HackerOne:** I came to you because you have the megaphone. I brought the full toolkit. The response was dismissive, and that's disappointing. You had a chance to lead on developer supply chain safety, and you passed.

**To GitHub Trust & Safety:** Your platform is the C2 channel, the exfiltration target, and the distribution vector — the attacker's entire OPSEC relies on your API continuing to serve their payloads. A deadman switch that punishes standard IR deserves coordinated action, not a procedural shrug. Take the repos down.

---

## The AI-Use Case: Why This Matters for IR

This is a concrete, measurable demonstration of AI-assisted incident response:

| Phase | Traditional | AI-Assisted | Speedup |
|-------|------------|-------------|---------|
| Binary decomp & capability mapping | 3-5 days | ~2 hours | 20x |
| Deadman switch logic identification | 1-2 days | ~15 min | 50x |
| NPM pipeline reverse | 2-3 days | ~45 min | 40x |
| AWS harvester discovery | 1-2 days | ~30 min | 30x |
| Fork network forensics | 2-4 days | ~1 hour | 30x |
| C2 correlation | 1 day | ~10 min | 60x |
| YARA rules | 1 day | ~5 min | 100x+ |
| Remediation script | 1-2 days | ~30 min | 30x |

**6 hours vs. 14-21 days.** That's not a marginal improvement. That's a category shift.

AI doesn't replace the analyst. It removes the friction between "I see something suspicious" and "I understand the entire kill chain and have published defenses."

---

## What Defenders Should Do

1. **Run the vaccine** — `shaihuld-remediate.sh` before revoking any tokens. It detects, defuses, and immunizes.

2. **Search your org** — `IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner` on GitHub code search. If it hits, you have an active token on the attacker's radar.

3. **Set `npm config set ignore-scripts true`** globally on dev machines until the malicious packages are identified.

4. **Shift to ephemeral secrets** — OIDC for CI/CD, short-lived NPM tokens. Static tokens are what this worm eats.

5. **Read the full report** — All IoCs, YARA rules, screenshots, and fork forensics are in the public disclosure repo.

---

**Full disclosure:** [github.com/breakingcircuits1337/Shai-Hulud-Carnage-APT-Report](https://github.com/breakingcircuits1337/Shai-Hulud-Carnage-APT-Report)

**Remediation script:** `shaihuld-remediate.sh` — run this before touching any tokens.

**#InfoSec #SupplyChainSecurity #AI #IncidentResponse #DevSecOps #ThreatIntelligence #WormDisclosure**
