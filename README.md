# Active Directory Brute-Force Detection and Automated Response

## Project Overview

This project demonstrates an automated security monitoring and response system for an Active Directory environment.

It detects repeated failed login attempts, collects Windows Security Events, sends security events to an n8n workflow, and automatically disables accounts when the configured brute-force threshold is reached.

The project combines Windows Server, PowerShell, Active Directory, Kali Linux, Docker, and n8n to demonstrate a practical security automation scenario.

## Lab Environment

| Component | Purpose |
|---|---|
| Windows Server 2022 | Active Directory Domain Controller |
| Windows 11 | Client workstation and testing |
| Kali Linux | Hosts the automation environment |
| Docker | Runs n8n |
| n8n | Workflow automation and email notifications |
| PowerShell | Event collection and automated response |

## Architecture

```text
Windows 11 Client
       |
       | Failed Login Attempts
       v
Windows Server 2022
       |
       | Windows Security Events
       v
PowerShell Monitoring Script
       |
       | HTTP POST / Webhook
       v
n8n Webhook
       |
       v
Event Filtering and Processing
       |
       +----------------------+
       |                      |
       v                      v
Email Notification     Brute-Force Detection
                              |
                              v
                       PowerShell Response
                              |
                              v
                    Disable AD User Account
```

## Main Features

- Monitors Windows Security Events.
- Detects repeated failed authentication attempts.
- Collects relevant event information, including usernames and timestamps.
- Sends security events to n8n through a Webhook.
- Sends email notifications when security events are detected.
- Automatically disables an Active Directory account when the configured threshold is reached.
- Uses scheduled tasks to automate monitoring and response.
- Includes persistent n8n data storage
