# powershell-security-toolkit

PowerShell scripts for cloud security operations, incident response, and Microsoft 365 automation.

## Focus areas

- Cloud security operations in Microsoft 365 and Azure.
- Incident response triage and evidence collection.
- Automation around Microsoft Sentinel and Defender XDR.
- Microsoft Graph–based enrichment and investigation.

## Structure

- `IR` – Host triage, artifact collection, quick "grab & go" IR helpers.
- `Sentinel` – Managing analytic rules, exporting/importing content, bulk updates.
- `Defender` – Device isolation, AV scans, IOC submission.
- `Graph` – Microsoft Graph helpers for Entra ID and M365 investigations.

## Example script ideas

- `IR/Get-EndpointTriagePackage.ps1` – Collect key OS artifacts from a host.
- `Sentinel/Export-AnalyticRules.ps1` – Export analytic rules as JSON.
- `Defender/Invoke-IsolateDevice.ps1` – Isolate a device via Defender for Endpoint.
- `Graph/Get-SuspiciousSignins.ps1` – List risky sign-ins for investigation.

Each script should include:

- Synopsis and description.
- Parameters and examples.
- Safe defaults (e.g., `-WhatIf` where appropriate).
