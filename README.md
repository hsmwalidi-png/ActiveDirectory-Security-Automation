# Active Directory Brute-Force Detection and Automated Response

Automated monitoring and response for failed logons in an Active Directory lab (`hsw.local`), built with PowerShell, n8n, and Windows Task Scheduler.

> **Verify, then trust.**

## How it works

```text
Windows 11 client (failed logons)
        |
        v
Domain Controller - Security log (events 4625 / 4771 / 4776)
        |
        +-- Task 1: AD-4625-to-n8n (every 1 min)
        |     Send-4625.ps1 -> HTTP POST -> n8n webhook -> filter -> email alert
        |
        +-- Task 2: AD-BruteForce-Block (every 1 min)
              Block-BruteForce.ps1 -> count failures per user
              -> 5+ in 10 min -> Disable-ADAccount -> block-log.txt
```

Alerting (n8n) and blocking (PowerShell on the DC) are independent paths, so a stopped n8n does not stop the response.

## Components

| File | Purpose |
|---|---|
| `scripts/Send-4625.ps1` | Reads failed-logon events, sends them to the n8n webhook, keeps a state file so no event is lost or repeated |
| `scripts/Block-BruteForce.ps1` | Counts failures per user and disables the account at the threshold |
| `tasks/*.xml` | Scheduled tasks (run as SYSTEM, every minute) |
| `workflows/workflows.json` | n8n workflow: webhook, filter, email alert |

## Lab environment

| Component | Purpose |
|---|---|
| Windows Server 2022 | Domain Controller |
| Windows 11 | Client and testing |
| Kali Linux + Docker | Hosts n8n |
| n8n | Webhook and email alerts |
| PowerShell | Event collection and response |

## Detection logic

- Threshold: 5 failed attempts within 10 minutes
- Excluded accounts: `administrator`, `krbtgt`, `guest`, `unknown`
- Only existing, enabled accounts are touched
- Every action is written to `C:\Scripts\block-log.txt`
- `-DryRun` shows what would be disabled without changing anything

## Setup

1. Copy both scripts to `C:\Scripts\` on the Domain Controller.
2. Set `$WebhookUrl` in `Send-4625.ps1` to your n8n host.
3. Import the scheduled tasks from an elevated PowerShell:
   ```powershell
   schtasks /Create /TN "AD-4625-to-n8n" /XML ".\tasks\AD-4625-to-n8n.xml"
   schtasks /Create /TN "AD-BruteForce-Block" /XML ".\tasks\AD-BruteForce-Block.xml"
   ```
4. Import `workflows/workflows.json` into n8n, attach your own SMTP credential, and activate it.

## Testing

1. Create a test user (never a real account).
2. Dry run first:
   ```powershell
   powershell -ExecutionPolicy Bypass -File C:\Scripts\Block-BruteForce.ps1 -DryRun
   ```
3. From the Windows 11 client, enter a wrong password 5 times for the test user.
4. Check the alert email, `block-log.txt`, and `Get-ADUser <name> | Select Enabled`.

## Security notes

- Usernames in logon events are attacker-controlled. The block script validates them against a strict pattern before querying AD.
- The webhook uses plain HTTP inside an isolated lab. Use HTTPS and a secret header outside a lab.
- Auto-disable can be abused to lock out a victim account. Privileged accounts are excluded, and a production setup should prefer temporary lockout or alert-only for sensitive accounts.
- No credentials are stored in this repository.
