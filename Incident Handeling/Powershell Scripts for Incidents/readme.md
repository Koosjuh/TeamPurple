# Get-ScamSpurTriage

PowerShell function for SOC analysts to quickly enrich IP addresses using the **Scamalytics IP Fraud Risk API v3** and optionally check **SPUR** accessibility.  
The function outputs triage-ready text that can be pasted directly into investigations.

## Features

- Scamalytics API v3 integration
- Multi-source geo lookup (MaxMind → DBIP → IP2Proxy)
- VPN / Datacenter / TOR classification
- ISP / ASN identification
- Risk score and risk level
- Optional SPUR accessibility check
- Supports single or multiple IP input
- SOC-friendly Markdown output

## Requirements

- PowerShell 5.1 or PowerShell 7+
- Scamalytics API credentials [Scamalytics API Enquiry](https://scamalytics.com/ip/api/enquiry?monthly_api_calls=5000)

## Notes

Currently Spur does not support this. I tried to get the URLCAL and return the Title of the page as even though the requests have been exceeded the vpn provider is still visible in the title of the page.