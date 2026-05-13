# Indicators of Compromise — Shai-Hulud / Carnage APT

Last updated: 2026-05-13  
Reported by: breakingcircuit

---

## File System Artifacts

| Path | Platform | Description |
|------|----------|-------------|
| `~/.local/bin/gh-token-monitor.sh` | Both | Malware binary |
| `~/.config/gh-token-monitor/` | Both | Config / data directory |
| `~/.config/gh-token-monitor/token` | Both | Stolen GitHub token |
| `~/.config/gh-token-monitor/handler` | Both | Destructive handler payload |
| `~/Library/LaunchAgents/com.user.gh-token-monitor.plist` | macOS | Persistence mechanism |
| `~/.config/systemd/user/gh-token-monitor.service` | Linux | Persistence mechanism |

---

## Process Indicators

| Indicator | Type | Notes |
|-----------|------|-------|
| `gh-token-monitor.sh` | Process name | Appears in `pgrep`, `ps aux` |
| `com.user.gh-token-monitor` | LaunchAgent label | Visible in `launchctl list` |
| `gh-token-monitor.service` | Systemd unit | Visible in `systemctl --user list-units` |

**Detection commands:**

```bash
# Check for running process
pgrep -a -f gh-token-monitor

# macOS — check LaunchAgent
launchctl list | grep gh-token-monitor

# Linux — check systemd
systemctl --user status gh-token-monitor.service
```

---

## Network Indicators

| Indicator | Type | Notes |
|-----------|------|-------|
| `api.github.com/user` | C2 heartbeat | Polled continuously with stolen token; 4xx triggers destructive payload |
| `api.github.com/user/repos` | Exfiltration | Used to create attacker-controlled repos for data staging |
| `api.github.com/repos/*/contents/*` | Exfiltration | Used to commit stolen data via PUT requests |

---

## Search Beacon String

The malware commits stolen data to GitHub repositories and uses the GitHub Search API to locate them. Every commit contains this unique string embedded in the repository content:

```
IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner
```

**GitHub Search API query used by attacker:**
```
https://api.github.com/search/code?q=IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner
```

Platform defenders can sinkhole the attacker's C2 by filtering this string from search index results.

---

## Attacker Infrastructure

| Repo | Owner | Commit | Stars | Forks | Status |
|------|-------|--------|-------|-------|--------|
| `PedroTortoriello/Shai-Hulud-Open-Source` | PedroTortoriello / TeamPCP_OSS | `a656ef1` | 4 | 5 | Reported |
| `g00dfe11ow/Shai-Hulud-Open-Source` | g00dfe11ow / TeamPCP_OSS | `da10861` | 80 | 68 | Reported |

**Known active fork accounts (observed at time of disclosure):**
- `agwagwagwa` — forked 17 hours before disclosure
- `GLP23` — forked 10 hours before disclosure

Note: 68 total forks recorded on the g00dfe11ow repo, with only 2 visible in the active forks view — the remainder are likely deleted or set to private, consistent with operational security practices.

**Threat actor group:** TeamPCP / TeamPCP_OSS  
**Language:** TypeScript (compiled) + Shell  
**Build targets:** `bun run build` (standard), `bun run build:obf` (obfuscated)

---

## Deadman Switch Logic

```bash
# Simplified representation of the polling/trigger loop
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: token $STOLEN_TOKEN" \
  https://api.github.com/user)

if [[ "$HTTP_CODE" =~ ^40[0-9]$ ]]; then
  bash "${CONFIG_DIR}/handler"
fi
```

Trigger condition: any HTTP 4xx response to `api.github.com/user`  
This includes: `401 Unauthorized` (standard revocation), `403 Forbidden`, `404 Not Found`

---

## SIEM / Detection Rules

**Bash history / auditd — file creation:**
```
~/.local/bin/gh-token-monitor.sh
~/.config/gh-token-monitor/token
~/Library/LaunchAgents/com.user.gh-token-monitor.plist
```

**Network — repeated polling pattern:**
```
dst: api.github.com
path: /user
interval: ~60s
user-agent: curl/*
```

**GitHub audit log — anomalous token activity:**
- Token creating repositories with randomized names at high frequency
- Token committing files containing the beacon string
- Token activity from multiple IPs in short timeframes

---

## Yara Rule

```yara
rule ShaiHulud_Worm {
    meta:
        description = "Detects Shai-Hulud / Carnage APT supply chain worm artifacts"
        author = "breakingcircuit"
        date = "2026-05-13"
        severity = "critical"

    strings:
        $beacon    = "IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner" ascii
        $service   = "gh-token-monitor" ascii
        $launchd   = "com.user.gh-token-monitor" ascii
        $deadman   = "^40[0-9]$" ascii
        $handler   = "gh-token-monitor/handler" ascii

    condition:
        any of them
}
```

---

## Recommended Immediate Actions for Defenders

1. Search your GitHub organization audit log for the beacon string
2. Check endpoints for the file and process IOCs above
3. If found — run `remediate.sh` before revoking any tokens
4. After remediation — rotate all GitHub tokens, SSH keys, and any secrets that may have been in environment variables
5. Set `npm config set ignore-scripts true` globally on developer machines until the malicious package is identified and removed from the registry
6. Report affected npm packages to [npmjs.com/support](https://www.npmjs.com/support)
