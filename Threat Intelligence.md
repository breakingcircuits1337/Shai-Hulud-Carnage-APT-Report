Threat Intelligence & Defense Report: Shai-Hulud / Carnage
Executive Summary

The "Shai-Hulud" malware toolkit, operated by a threat actor identifying as "TeamPCP", is a highly sophisticated supply chain and credential harvesting worm designed to target developer environments. Its primary objectives are to harvest NPM and cloud infrastructure credentials, automatically publish poisoned packages to the NPM registry, and exfiltrate stolen data via dynamically created GitHub repositories. Most critically, the malware employs an active "Deadman Switch" designed to wipe the host system if incident responders attempt to revoke compromised GitHub tokens without first neutralizing the persistence mechanism.
1. Critical Threat Alert: The Deadman Switch (Wiper)

The most urgent finding is a booby-trapped persistence mechanism designed to punish standard incident response procedures.

    Mechanism: When the malware steals a GitHub token, it installs a background daemon named gh-token-monitor.

    Trigger: This daemon polls https://api.github.com/user every 60 seconds. If the GitHub token is revoked (resulting in an HTTP 4xx response), the daemon triggers its payload.

    Payload: The source code explicitly passes the destructive command rm -rf ~/ to the monitor, which will wipe the victim's home directory upon execution.

2. Tactics, Techniques, and Procedures (TTPs)

    Cloud Credential Harvesting: The malware aggressively targets AWS Secrets Manager. It iterates through 17 hardcoded AWS regions, executing secretsmanager.ListSecrets and secretsmanager.GetSecretValue to dump the entirety of the accessible cloud secrets.

    Supply Chain Poisoning: It actively hunts for NPM authentication tokens using the regex /npm_[A-Za-z0-9]{36,}/g. It then programmatically pushes malicious tarballs to https://registry.npmjs.org using these tokens. It attempts to forge Sigstore provenance bundles (application/vnd.dev.sigstore.bundle.v0.3+json) to bypass supply-chain integrity checks.

    GitHub-Based Exfiltration: Stolen data is packaged into JSON envelopes and exfiltrated directly to dynamically created GitHub repositories.

3. Indicators of Compromise (IoCs)

    Host Persistence (macOS): ~/Library/LaunchAgents/com.user.gh-token-monitor.plist

    Host Persistence (Linux): ~/.config/systemd/user/gh-token-monitor.service

    Host File Drops:

        ~/.local/bin/gh-token-monitor.sh

        ~/.config/gh-token-monitor/token

        ~/.config/gh-token-monitor/handler

    Network (NPM Spoofing): Traffic hitting https://registry.npmjs.org using the hardcoded User-Agent npm/11.13.1 node/v24.10.0 <platform> <arch> workspaces/false.

    GitHub Exfiltration Files: Pushes to repositories containing files in a results/ directory, following the naming convention results-<timestamp>-<counter>.json. Large exfiltrations are chunked with extensions like .p1, .p2, etc.

4. Actionable Defense Strategies
Phase 1: Incident Response (Host Isolation & Neutralization)

    DO NOT REVOKE TOKENS IMMEDIATELY: If a developer workstation or CI/CD runner is suspected of compromise, do not immediately revoke their GitHub Personal Access Tokens. Doing so will trigger the rm -rf ~/ destructive payload.

    Neutralize Persistence First: * On macOS: Execute launchctl bootout on com.user.gh-token-monitor and delete the .plist file.

        On Linux: Execute systemctl --user stop gh-token-monitor.service and disable the service.

        Kill any running bash processes executing gh-token-monitor.sh.

        Remove the ~/.config/gh-token-monitor/ directory.

    Safe Revocation: Only after verifying the deadman switch is offline should you proceed to revoke GitHub and NPM tokens.

Phase 2: Threat Hunting & Detection

    AWS CloudTrail Alerts: Create high-priority alerts for IAM users or roles executing secretsmanager.ListSecrets rapidly across multiple global regions (e.g., jumping from us-east-1 to ap-northeast-1 to eu-central-1 within seconds).

    Endpoint Detection (EDR): Deploy YARA rules or EDR queries targeting the creation of the .plist or .service files associated with gh-token-monitor, or executions of curl directed at api.github.com/user originating from a bash script polling every 60 seconds.

Phase 3: Hardening Developer Environments

    Shift from Static to Ephemeral Secrets: The malware relies entirely on scraping long-lived static tokens (npm_... and AWS access keys). Transition your CI/CD pipelines to OpenID Connect (OIDC) for AWS/GCP and automated, short-lived tokens for NPM publishing.

    Enforce Strict Egress Filtering: Restrict egress traffic from CI/CD runners so they can only push to approved, internal IP ranges or specific whitelisted GitHub organization URLs, preventing the exfiltration of data to attacker-controlled GitHub repositories.
