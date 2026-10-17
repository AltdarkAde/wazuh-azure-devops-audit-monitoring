# Azure DevOps → Wazuh: CI/CD Audit Monitoring

A Python collector pulls Azure DevOps audit logs through a Microsoft Entra ID service principal, writes them as JSON lines, and Wazuh ingests them with custom rules for permission changes, destructive Git operations, pipeline edits, service-connection tampering, and repository deletion.

📝 Original article: [Integrating Azure DevOps with Wazuh](https://medium.com/@aabiodunadeleke/integrating-azure-devops-with-wazuh-a-complete-security-monitoring-guide-d909aa7cda82)

## Architecture

```
Entra ID service principal --OAuth2 client credentials--> Azure DevOps Audit API
        ^                                                          |
        |                                              (cron, every 5 min)
        +---------- azure_devops_audit.py (on Wazuh manager) <-----+
                               |
                     /var/log/AzureDevops/*.json
                               |
                   Wazuh logcollector (json) --> rules 1007xx --> alerts / dashboard
```

## Files

| File | Purpose |
|---|---|
| [`scripts/azure_devops_audit.py`](scripts/azure_devops_audit.py) | Collector (`/var/ossec/integrations/`) |
| [`config/azure_devops.env.example`](config/azure_devops.env.example) | Credentials template (real file is gitignored) |
| [`config/ossec-localfile.xml`](config/ossec-localfile.xml) | Tells Wazuh to read the JSON file |
| [`config/crontab.example`](config/crontab.example) | 5-minute schedule |
| [`rules/azure-devops-rules.xml`](rules/azure-devops-rules.xml) | Detection rules |

## Prerequisites

- Azure DevOps organisation with admin access and auditing enabled
- Entra ID permission to create app registrations
- Wazuh Manager 4.x, Python 3 with `requests`

## Part 1 — Azure setup

1. **App registration** — Entra ID → App registrations → New registration (`Wazuh-DevOps-Integration`, single tenant). Record the **Application (client) ID** and **Directory (tenant) ID**.
2. **Client secret** — Certificates & secrets → New client secret (6–12 months). Copy the value immediately.
3. **API permissions** — Add a permission → *APIs my organization uses* → **Azure DevOps** (resource ID `499b84ac-1321-427f-aa17-267ca6975798`) → delegated `user_impersonation` → grant admin consent.
4. **Add the service principal to Azure DevOps** — Organization settings → Users → Add users → paste the client ID → access level *Basic*.
5. **Grant audit access** — Organization settings → Permissions → *Project Collection Administrators* → Members → add the client ID.
6. **Enable auditing** — `https://dev.azure.com/<org>/_settings/audit` → Enable auditing (not available on all plans).

## Part 2 — Wazuh server

```bash
# Log directory
sudo mkdir -p /var/log/AzureDevops
sudo chown wazuh:wazuh /var/log/AzureDevops
sudo chmod 750 /var/log/AzureDevops

# Collector
sudo cp scripts/azure_devops_audit.py /var/ossec/integrations/
sudo chmod +x /var/ossec/integrations/azure_devops_audit.py
sudo chown root:wazuh /var/ossec/integrations/azure_devops_audit.py

# Credentials
sudo cp config/azure_devops.env.example /var/ossec/integrations/azure_devops.env
sudo nano /var/ossec/integrations/azure_devops.env      # fill in real values
sudo chmod 600 /var/ossec/integrations/azure_devops.env
sudo chown root:root /var/ossec/integrations/azure_devops.env

# Manual test
sudo bash -c 'source /var/ossec/integrations/azure_devops.env && python3 /var/ossec/integrations/azure_devops_audit.py'
```

Expected output ends with `✓ Successfully wrote N log entries to file` and `SUCCESS: Audit log collection completed`.

Schedule it (see [`config/crontab.example`](config/crontab.example)):

```bash
sudo crontab -e -u root
```

## Part 3 — Wazuh monitoring and rules

1. Add [`config/ossec-localfile.xml`](config/ossec-localfile.xml) to `/var/ossec/etc/ossec.conf`.
2. Add [`rules/azure-devops-rules.xml`](rules/azure-devops-rules.xml) to `/var/ossec/etc/rules/local_rules.xml`.
3. Restart and confirm:

```bash
sudo systemctl restart wazuh-manager
sudo grep -i AzureDevops /var/ossec/logs/ossec.log
# wazuh-logcollector: INFO: Analyzing file: '/var/log/AzureDevops/AzureDevops_Audit_logs.json'
```

| Rule | Level | Detects |
|---|---|---|
| 100701 | 3 | Any Azure DevOps audit event |
| 100702 | 10 | Security permission modified |
| 100703 | 9 | Ref deletion / force push |
| 100704 | 8 | Release or build pipeline modified |
| 100705 | 7 | Group membership / licence changes |
| 100706 | 6 | Project settings changed |
| 100707 | 11 | Service connection modified |
| 100708 | 12 | Repository deleted |
| 100709 | 8 | After-hours activity (optional) |
| 100710 | 9 | Access from non-private IP (optional) |

## Part 4 — Testing

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Paste:

```json
{"Logtype": "AzureDevops", "AzureDevops.Id": "test-123", "AzureDevops.ActionId": "Git.CreateRef", "AzureDevops.ActorDisplayName": "Test User", "AzureDevops.Timestamp": "2026-03-12T10:00:00Z", "AzureDevops.ScopeDisplayName": "YourOrg", "AzureDevops.IpAddress": "192.0.2.10", "AzureDevops.Details": "Created a new branch", "AzureDevops.Area": "Git", "AzureDevops.Category": "Modify"}
```

Expect rule `100701`, level 3. Then generate real activity (create a branch, edit a pipeline, change a group member), run the collector, and check:

```bash
wc -l /var/log/AzureDevops/AzureDevops_Audit_logs.json
sudo grep "100701" /var/ossec/logs/alerts/alerts.json | tail
```

In the dashboard: **Threat Hunting**, filter `rule.groups is azure_devops`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `401` when getting a token | Check client ID / tenant ID / secret, secret expiry, and admin consent |
| `403` fetching logs | Service principal not added to the org, not in Project Collection Administrators, or auditing disabled; permissions can take minutes to propagate |
| Script works, 0 logs | No activity in the window, auditing off, or plan doesn't support auditing |
| Logs collected, no alerts | Confirm Wazuh is analysing the file; Wazuh only alerts on lines appended after it starts monitoring; check `wazuh-indexer` |
| Works manually, not from cron | Use `.` instead of `source` (cron runs `sh`); use absolute paths |

## Security notes

- Rotate the client secret every 3–6 months; prefer Azure Key Vault over an env file in production
- `chmod 600` the env file; never commit it
- Restrict egress to `login.microsoftonline.com` and `auditservice.dev.azure.com`
- The service principal is a Project Collection Administrator, which is powerful. Review whether a narrower audit-reader permission is available for your plan

## Limitations and improvements

- **Overlap/gaps:** each run asks for the last 5 minutes, but audit events can lag by up to ~15 minutes, so late events can be missed. A more robust collector stores a high-water-mark timestamp and requests `[last_run, now]`, and de-duplicates by event `Id`.
- Rule 100705 includes `Security.ModifyPermission`, which rule 100702 already catches first
- Add MITRE ATT&CK mapping (e.g. T1098 Account Manipulation, T1195 Supply Chain Compromise)
- Forward level 10+ alerts to a SOAR platform (Shuffle, TheHive)

## Compliance mapping

PCI-DSS 10.2.5 / 10.3 · GDPR Art. 32, 35.7(d) · HIPAA §164.312(b) · ISO 27001 A.12.4.1–3 · NIST 800-53 AU-2, AU-6, AU-14
