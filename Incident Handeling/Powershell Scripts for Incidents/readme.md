# Get-ScamSpurTriage

**Note**
This is a legacy name. Spur does not support this, I now use Proxycheck.io.

PowerShell function for SOC IP enrichment using:

- **Scamalytics API v3** for location, ISP, risk score, and datacenter/TOR context
- **ProxyCheck v3** for VPN provider attribution, VPN/proxy confirmation, and first-seen timestamp
- **Microsoft PowerShell SecretManagement / SecretStore** for secure local secret retrieval

## Current vault model

This setup assumes:

- Vault name is **`SecretVault`**
- The vault uses **Password** authentication
- The vault is unlocked **automatically inside the triage script**
- The unlock password is stored locally in a **DPAPI-protected CLIXML file**
- Timeout is **9 hours** per shift

This means the vault is:

- locked by default
- unlocked when the script runs
- available for the duration of the shift
- automatically locked again when the timeout expires

## Required secret names

Store these secrets in `SecretVault`:

- `ScamalyticsUser`
- `ScamalyticsKey`
- `ProxyCheckKey`

## Prerequisites

Install the required modules:

```powershell
Install-Module Microsoft.PowerShell.SecretManagement -Scope CurrentUser
Install-Module Microsoft.PowerShell.SecretStore -Scope CurrentUser
```

## Vault registration

If not already done:

```powershell
Register-SecretVault -Name SecretVault -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault
```

## SecretStore configuration

Configure the store for:

- password authentication
- no interactive prompts during script execution
- 9 hour unlock timeout

```powershell
$password = Import-CliXml -Path $securePasswordPath

$storeConfiguration = @{
    Authentication = 'Password'
    PasswordTimeout = 32400 ## Given how long a shift is. This can be cut down. Time is in seconds.
    Interaction = 'None'
    Password = $password
    Confirm = $false
}

Set-SecretStoreConfiguration @storeConfiguration
```

## One-time setup for the DPAPI-protected password file

Create the local encrypted password file once:

```powershell
$securePasswordPath = "$env:APPDATA\PowerShell\SecretStore\secretstore-password.xml"

New-Item -ItemType Directory -Force -Path (Split-Path $securePasswordPath) | Out-Null

$vaultPassword = Read-Host "Enter SecretStore vault password" -AsSecureString
$vaultPassword | Export-Clixml -Path $securePasswordPath
```

This file is protected by **Windows DPAPI** and can only be decrypted by the same user on the same device.

## Store the API secrets in the vault

```powershell
Set-Secret -Vault SecretVault -Name ScamalyticsUser -Secret "YOUR_SCAMALYTICS_USER"
Set-Secret -Vault SecretVault -Name ScamalyticsKey -Secret "YOUR_SCAMALYTICS_KEY"
Set-Secret -Vault SecretVault -Name ProxyCheckKey -Secret "YOUR_PROXYCHECK_KEY"
```

## Script

```powershell
function Get-ScamSpurTriage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string[]]$IPs,

        [Parameter(Mandatory = $false)]
        [string]$BaseUrl = "https://api12.scamalytics.com/v3",

        [Parameter(Mandatory = $false)]
        [string]$VaultName = "SecretVault",

        [Parameter(Mandatory = $false)]
        [string]$ScamalyticsUserSecretName = "ScamalyticsUser",

        [Parameter(Mandatory = $false)]
        [string]$ScamalyticsKeySecretName = "ScamalyticsKey",

        [Parameter(Mandatory = $false)]
        [string]$ProxyCheckKeySecretName = "ProxyCheckKey",

        [Parameter(Mandatory = $false)]
        [string]$SecretStorePasswordPath = "$env:APPDATA\PowerShell\SecretStore\secretstore-password.xml",

        [Parameter(Mandatory = $false)]
        [int]$VaultUnlockTimeoutSeconds = 32400
    )

    try {
        $null = Get-SecretVault -Name $VaultName -ErrorAction Stop

        $storeStatus = Get-SecretStoreConfiguration -ErrorAction Stop
        if ($storeStatus.Authentication -eq 'Password') {
            if (-not (Test-Path -Path $SecretStorePasswordPath)) {
                throw "SecretStore password file not found at: $SecretStorePasswordPath"
            }

            $vaultPassword = Import-Clixml -Path $SecretStorePasswordPath
            Unlock-SecretStore -Password $vaultPassword -PasswordTimeout $VaultUnlockTimeoutSeconds -ErrorAction Stop
        }

        $ApiUser = Get-Secret -Vault $VaultName -Name $ScamalyticsUserSecretName -AsPlainText -ErrorAction Stop
        $ApiKey = Get-Secret -Vault $VaultName -Name $ScamalyticsKeySecretName -AsPlainText -ErrorAction Stop
        $ProxyCheckApiKey = Get-Secret -Vault $VaultName -Name $ProxyCheckKeySecretName -AsPlainText -ErrorAction Stop
    }
    catch {
        throw "Failed to unlock vault or retrieve secrets. $($_.Exception.Message)"
    }

    if (-not $IPs -or $IPs.Count -eq 0) {
        $inputIPs = Read-Host "Enter IP(s) (comma separated)"
        $IPs = $inputIPs -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    }

    foreach ($ip in $IPs) {
        $location = "Unknown"
        $isp = "Unknown"
        $score = "Unknown"
        $risk = "Unknown"
        $proxyTorDc = "Unknown / Unknown / Unknown"
        $provider = "Unknown"
        $proxyCheckVpnProxy = "Unknown / Unknown"
        $firstSeen = "Unknown"

        try {
            $scamUrl = "${BaseUrl}/${ApiUser}/?key=${ApiKey}&ip=${ip}"
            Write-Verbose "Requesting Scamalytics for $ip"
            $resp = Invoke-RestMethod -Uri $scamUrl -Method Get -ErrorAction Stop

            $scam = $resp.scamalytics
            $ext  = $resp.external_datasources

            if ($scam.status -eq "ok") {
                $score = if ($null -ne $scam.scamalytics_score) { $scam.scamalytics_score } else { "Unknown" }
                $risk  = if (-not [string]::IsNullOrWhiteSpace($scam.scamalytics_risk)) { $scam.scamalytics_risk } else { "Unknown" }

                $vpn = if ($null -ne $scam.scamalytics_proxy.is_vpn) { $scam.scamalytics_proxy.is_vpn } else { "Unknown" }
                $dc  = if ($null -ne $scam.scamalytics_proxy.is_datacenter) { $scam.scamalytics_proxy.is_datacenter } else { "Unknown" }
                $tor = if ($null -ne $ext.x4bnet.is_tor) { $ext.x4bnet.is_tor } else { "Unknown" }
                $proxyTorDc = "$vpn / $tor / $dc"

                $mm   = $ext.maxmind_geolite2
                $dbip = $ext.dbip

                $city = $null
                $country = $null

                if ($mm) {
                    if (-not [string]::IsNullOrWhiteSpace($mm.ip_city)) {
                        $city = $mm.ip_city
                    }
                    if (-not [string]::IsNullOrWhiteSpace($mm.ip_country_name)) {
                        $country = $mm.ip_country_name
                    }
                }

                if ([string]::IsNullOrWhiteSpace($city) -and $dbip -and -not [string]::IsNullOrWhiteSpace($dbip.ip_city)) {
                    $city = $dbip.ip_city
                }

                if ([string]::IsNullOrWhiteSpace($country) -and $dbip -and -not [string]::IsNullOrWhiteSpace($dbip.ip_country_name)) {
                    $country = $dbip.ip_country_name
                }

                if (-not [string]::IsNullOrWhiteSpace($city) -and -not [string]::IsNullOrWhiteSpace($country)) {
                    $location = "$city, $country"
                }
                elseif (-not [string]::IsNullOrWhiteSpace($country)) {
                    $location = $country
                }

                if ($dbip -and -not [string]::IsNullOrWhiteSpace($dbip.isp_name)) {
                    $isp = $dbip.isp_name
                }
                elseif (-not [string]::IsNullOrWhiteSpace($scam.scamalytics_isp)) {
                    $isp = $scam.scamalytics_isp
                }
                elseif ($mm -and -not [string]::IsNullOrWhiteSpace($mm.as_name)) {
                    $isp = $mm.as_name
                }
            }
            else {
                $risk = "API status: $($scam.status)"
            }
        }
        catch {
            $risk = "Lookup failed"
            Write-Verbose "Scamalytics failed for $ip. $($_.Exception.Message)"
        }

        try {
            $pcUrl = "https://proxycheck.io/v3/${ip}?key=${ProxyCheckApiKey}&vpn=1&asn=1"
            Write-Verbose "Requesting ProxyCheck for $ip"

            $pcRaw = Invoke-WebRequest -Uri $pcUrl -UseBasicParsing -ErrorAction Stop
            $pcResp = $pcRaw.Content | ConvertFrom-Json

            if ($pcResp.status -in @("ok", "warning")) {
                $pcProperty = $pcResp.PSObject.Properties | Where-Object { $_.Name -eq $ip }

                if ($null -ne $pcProperty) {
                    $pcData = $pcProperty.Value

                    if ($null -ne $pcData.detections) {
                        $pcVpn   = if ($null -ne $pcData.detections.vpn) { $pcData.detections.vpn } else { "Unknown" }
                        $pcProxy = if ($null -ne $pcData.detections.proxy) { $pcData.detections.proxy } else { "Unknown" }
                        $proxyCheckVpnProxy = "$pcVpn / $pcProxy"

                        if (-not [string]::IsNullOrWhiteSpace([string]$pcData.detections.first_seen)) {
                            $firstSeen = [string]$pcData.detections.first_seen
                        }
                    }

                    $mainOperator = $null
                    $additionalOperators = @()

                    if ($null -ne $pcData.operator) {
                        if (-not [string]::IsNullOrWhiteSpace([string]$pcData.operator.name)) {
                            $mainOperator = [string]$pcData.operator.name
                        }

                        if ($null -ne $pcData.operator.additional_operators) {
                            if ($pcData.operator.additional_operators -is [System.Array]) {
                                $additionalOperators = $pcData.operator.additional_operators | Where-Object {
                                    -not [string]::IsNullOrWhiteSpace([string]$_)
                                }
                            }
                            elseif (-not [string]::IsNullOrWhiteSpace([string]$pcData.operator.additional_operators)) {
                                $additionalOperators = @([string]$pcData.operator.additional_operators)
                            }
                        }
                    }

                    if (-not [string]::IsNullOrWhiteSpace($mainOperator) -and $additionalOperators.Count -gt 0) {
                        $provider = "$mainOperator, with additional overlap noted for $($additionalOperators -join ', ')"
                    }
                    elseif (-not [string]::IsNullOrWhiteSpace($mainOperator)) {
                        $provider = $mainOperator
                    }
                }
                else {
                    Write-Verbose "ProxyCheck returned status ok, but no IP result block was found for $ip"
                }
            }
            else {
                Write-Verbose "ProxyCheck status was $($pcResp.status)"
            }
        }
        catch {
            Write-Verbose "ProxyCheck failed for $ip. $($_.Exception.Message)"
        }

        Write-Output "##### $ip"
        Write-Output "- Location: $location"
        Write-Output "- ISP: $isp"
        Write-Output "- Risk score: $score ($risk)"
        Write-Output "- Proxy/TOR/Datacenter: $proxyTorDc"
        Write-Output "- Provider: $provider"
        Write-Output "- ProxyCheck VPN/Proxy: $proxyCheckVpnProxy"
        Write-Output "- First seen: $firstSeen"
        Write-Output ""
    }
}

```

## Usage

### Interactive input

```powershell
Get-ScamSpurTriage
```

### Single IP

```powershell
Get-ScamSpurTriage -IPs "1.1.1.1"
```

### Multiple IPs

```powershell
Get-ScamSpurTriage -IPs "1.1.1.1","8.8.8.8"
```

### Verbose logging

```powershell
Get-ScamSpurTriage -IPs "1.1.1.1" -Verbose
```

## Example output

```markdown
##### 1.1.1.1
- Location: Santa Clara, United States
- ISP: PacketHub S.A.
- Risk score: 100 (very high)
- Proxy/TOR/Datacenter: True / False / True
- Provider: NordVPN, with additional overlap noted for LunaProxy
- ProxyCheck VPN/Proxy: True / False
- First seen: 2026-02-05
```

## Field explanation

**Location**  
Derived from Scamalytics geolocation sources.

**ISP**  
Primary ISP or ASN owner of the IP.

**Risk score**  
Scamalytics fraud score and risk label.

**Proxy/TOR/Datacenter**  
Format is:

```text
VPN / TOR / Datacenter
```

**Provider**  
Named provider attribution from ProxyCheck.

**ProxyCheck VPN/Proxy**  
Format is:

```text
VPN / Proxy
```

**First seen**  
First observed VPN/proxy detection timestamp from ProxyCheck.

## Operational flow

1. Run the script
2. Script imports the DPAPI-protected SecretStore password file
3. Script unlocks `SecretVault`
4. Script retrieves the three API secrets
5. Script performs IP enrichment
6. Vault stays unlocked for **9 hours**
7. Vault locks again automatically after timeout

# Requirements

You need API keys for:

## Scamalytics

https://scamalytics.com/ip/api/enquiry?monthly_api_calls=5000

You will receive:

- API User
- API Key

## ProxyCheck

https://proxycheck.io

You will receive:

- ProxyCheck API key

Free tier is sufficient for SOC triage.

## Notes

- No API keys are stored in the script
- No manual unlock is required during the shift
- No plaintext password is stored on disk
- The password file is local-user and local-device bound
- If the CLIXML password file is deleted, recreate it with the one-time setup step above
