# Get-ScamSpurTriage

PowerShell function for SOC triage enrichment using:

- Scamalytics API (risk scoring, ISP, location, datacenter/VPN indicators)
- ProxyCheck API (VPN provider attribution, proxy/VPN detection, first seen)

The function outputs triage-ready Markdown blocks per IP.

---

# Features

- Scamalytics risk score and classification
- ISP and geolocation enrichment
- Datacenter / VPN / TOR detection
- VPN provider attribution (NordVPN, Mullvad, etc.)
- Additional overlapping providers
- ProxyCheck VPN/Proxy confirmation
- First seen timestamp
- Multi-IP support
- Interactive input fallback
- Triage-ready Markdown output

---

# Requirements

You need API keys for:

## Scamalytics

https://scamalytics.com/ip/api/enquiry?monthly_api_calls=5000

You will receive:

- API User
- API Key

---

## ProxyCheck

https://proxycheck.io

You will receive:

- ProxyCheck API key

Free tier is sufficient for SOC triage.

---

# Usage

Single IP

```powershell
Get-ScamSpurTriage `
    -ApiUser "SCAMALYTICS_USER" `
    -ApiKey "SCAMALYTICS_KEY" `
    -ProxyCheckApiKey "PROXYCHECK_KEY" `
    -IPs "1.1.1.1"
```

## Multiple IPs

Get-ScamSpurTriage `
    -ApiUser "SCAMALYTICS_USER" `
    -ApiKey "SCAMALYTICS_KEY" `
    -ProxyCheckApiKey "PROXYCHECK_KEY" `
    -IPs "1.1.1.1","8.8.8.8"

## Interactive mode

Get-ScamSpurTriage `
    -ApiUser "SCAMALYTICS_USER" `
    -ApiKey "SCAMALYTICS_KEY" `
    -ProxyCheckApiKey "PROXYCHECK_KEY"

You will then be prompted:

Enter IP(s) (comma separated)
Example Output
##### 1.1.1.1
- Location: Santa Clara, United States
- ISP: PacketHub S.A.
- Risk score: 100 (very high)
- Proxy/TOR/Datacenter: True / False / True
- Provider: NordVPN, with additional overlap noted for LunaProxy
- ProxyCheck VPN/Proxy: True / False
- First seen: 2026-02-05
Field Explanation

Location
Derived from Scamalytics geolocation sources.

ISP
Primary ISP/ASN owner of the IP.

Risk score
Scamalytics fraud risk score and classification.

Proxy/TOR/Datacenter
Format:

VPN / TOR / Datacenter

Example:

True / False / True

Provider
VPN provider attribution from ProxyCheck operator detection.

Example:

NordVPN
Mullvad
ProtonVPN
NordVPN, with additional overlap noted for LunaProxy

ProxyCheck VPN/Proxy

Format:

VPN / Proxy

Example:

True / False

First seen
First time ProxyCheck detected this IP as VPN/proxy infrastructure.

Useful for:

New infrastructure detection
Recently deployed VPN nodes
Suspicious short-lived providers
Notes
Scamalytics handles location and risk scoring
ProxyCheck handles VPN provider attribution
Provider detection is not always available
Some residential proxies may not resolve to provider names
First seen timestamp depends on ProxyCheck dataset
Output Format

The function outputs SOC triage-ready Markdown:

One block per IP
Copy/paste friendly
Suitable for incident notes
No post-processing required
Example SOC Use
Investigate suspicious sign-in IP
Identify VPN provider used
Determine datacenter vs residential
Validate impossible travel alerts
Identify anonymization infrastructure
Determine new vs known VPN nodes
Function Name

Current name:

Get-ScamSpurTriage

The name is legacy. SPUR is no longer used.

Suggested future rename:

Get-IpTriageEnrichment
Rate Limits

Scamalytics
Depends on plan (typically 5,000/month)

ProxyCheck
Free tier sufficient for SOC triage

Security

Do not hardcode API keys in scripts.
Use variables or secure storage.

Example:

$ScamUser = "..."
$ScamKey  = "..."
$ProxyKey = "..."

Get-ScamSpurTriage `
    -ApiUser $ScamUser `
    -ApiKey $ScamKey `
    -ProxyCheckApiKey $ProxyKey `
    -IPs "1.1.1.1"
