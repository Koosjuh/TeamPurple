# IP validation tool

## Updates

| Date       | Update                                                                                                                                                      |
| ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 2026-06-17 | Added AzureSpeed integration to enrich Microsoft Infrastructure IP addresses with Azure Service Tag, Region, Address Prefix and System Service information. |

## Session validation

---

During my investigations when I have duty one of the most frequent things I do is validating sessions. Most of the time I investigate 2 types of entities: The user activity and the location it's from. The location investigation can become tedious as in the past I used Scamalytics and spur.us. Spur.us however changed their GUI and adjusted their limit rates, thus when I am on my corporate VPN I can never use spur.us because the night shift probably already used up all the API calls. One thing that verifies behaviour though is the VPN operator. Seeing "Nord VPN" for instance on sign in sessions 10x in the past and now for the 10th time this user generates an "Anonymous sign in", it helps to see that this is anonymous IP belongs to "Nord VPN". I also integrated abuseipdb to give more context and see any reporting categories.

So not being able to do this, or it takes 5 minutes longer per investigation is tedious to say the least. Something trivial but necesary should be simple and fast. To streamline this workflow, I created a PowerShell based IP session tool that generates a triage based on the properties of the IP address through scamalytics and proxycheck (my new spur). The function queries Scamalytics for infrastructure properties and location, and ProxyCheck for VPN attribution Abuseipdb for reports and morecontext. The results are merged into a structured format that can be pasted directly into investigation notes or incident timelines.

The tool also integrates with Microsoft PowerShell SecretManagement and SecretStore to securely store API keys. Secrets remain locked by default, are unlocked only during analyst usage, and automatically lock again after the configured timeout. This is why I like blogging because this also forces me to think about handling secrets correctly. I am in no way shape or form a developer so if there is feedback if this can be better or safer or other ways please do comment and let me know!

The sections below describes the setup, secretvault configuration, script, and usage examples. 

**Disclaimer:** All api keys can (for the time being) be atained for `free`. The limits are of course low but in my case and I hope for your work/life balance as well, enough for 1 SOC analyst. 

## Get-ScamSpurTriage (Powershell Function)

**Note**

This is a legacy name. Spur does not support this, I now use Proxycheck.io. I like the name, for now it stays. :) Feel free to change the name and/or adjust the triage output to fit your style.

**Requirements:** You need API keys for

- **Scamalytics API v3** for location, ISP, risk score, and datacenter/TOR context
   - [Scamalytics](https://scamalytics.com/ip/api/enquiry?monthly_api_calls=5000 "Scamalytics IP Location & Infrastructure API")
   - Here you will receive an `API User` and `API Key`.
- **ProxyCheck v3** for VPN provider attribution, VPN/proxy confirmation, and first-seen timestamp
   - [ProxyCheck](https://proxycheck.io "Proxy/VPN detection API")
   - Here you will receive an `API Key`
- **AbuseIPDB API** for more context and potential reports
   - [AbuseIPDB](https://www.abuseipdb.com/register "AbuseIPDB reports can be quite handy!")   
- **Microsoft PowerShell SecretManagement / SecretStore** for secure local secret retrieval

Free tier is sufficient for 1 soc analyst. Do not use per department or team. This is for a single user. If you want this for a whole SOC the free tier will not suffice.

### Prerequisites

Install the required modules:

```powershell
Install-Module Microsoft.PowerShell.SecretManagement -Scope CurrentUser
Install-Module Microsoft.PowerShell.SecretStore -Scope CurrentUser
```
### Current vault model

This setup assumes:

- Vault name is **`SecretVault`** 
- The vault uses **Password** authentication
- The vault needs to be unlocked by the SecretVault password once every `4 hours`
- Timeout is **4 hours**
- First time running this script will ask for password for SecretVault to unlock it. Then it will either timeout after 4 hours or if you stop the terminal session you will need to unlock it again.

#### Required secret names

Store these secrets in `SecretVault`:

- `ScamalyticsUser`
- `ScamalyticsKey`
- `ProxyCheckKey`
- `AbuseIPDBKey`

You will end up with:

- Vault that is locked by default
- Can only be unlocked by password in current user session
- Unlock required once per session (session assumes a SOC shift of 4 hours, please do adjust to your needs)
- Auto-lock after 4 hours or if the session is terminated
- Store the secretvault password in your password manager of choice.

#### Vault registration

If not already done:

```powershell
Register-SecretVault -Name SecretVault -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault
```

#### SecretStore configuration

```powershell
Set-SecretStoreConfiguration `
    -Authentication Password `
    -PasswordTimeout 14400 `
    -Interaction Prompt
```

#### Store the API secrets in the vault

```powershell
Set-Secret -Vault SecretVault -Name ScamalyticsUser -Secret "YOUR_SCAMALYTICS_USER"
```

```powershell
Set-Secret -Vault SecretVault -Name ScamalyticsKey -Secret "YOUR_SCAMALYTICS_KEY"
```

```powershell
Set-Secret -Vault SecretVault -Name ProxyCheckKey -Secret "YOUR_PROXYCHECK_KEY"
```

```powershell
Set-Secret -Vault SecretVault -Name AbuseIPDBKey -Secret "YOUR_ABUSEIPDB_KEY"
```

### Script

```powershell
function Get-ScamSpurTriage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string[]]$IPs,

        [Parameter(Mandatory = $false)]
        [string]$BaseUrl = "https://api12.scamalytics.com/v3",

        [Parameter(Mandatory = $false)]
        [string]$AzureIpLookupUrl = "https://www.azurespeed.com/api/ipAddress",

        [Parameter(Mandatory = $false)]
        [string]$VaultName = "SecretVault",

        [Parameter(Mandatory = $false)]
        [string]$ScamalyticsUserSecretName = "ScamalyticsUser",

        [Parameter(Mandatory = $false)]
        [string]$ScamalyticsKeySecretName = "ScamalyticsKey",

        [Parameter(Mandatory = $false)]
        [string]$ProxyCheckKeySecretName = "ProxyCheckKey",

        [Parameter(Mandatory = $false)]
        [string]$AbuseIPDBKeySecretName = "AbuseIPDBKey",

        [Parameter(Mandatory = $false)]
        [int]$AbuseIPDBMaxAgeDays = 90,

        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 3,

        [Parameter(Mandatory = $false)]
        [int]$InitialRetryDelaySeconds = 2
    )

    function Invoke-WithRetry {
        param(
            [Parameter(Mandatory = $true)]
            [scriptblock]$ScriptBlock,
            [Parameter(Mandatory = $true)]
            [string]$OperationName,
            [Parameter(Mandatory = $false)]
            [int]$Retries = 3,
            [Parameter(Mandatory = $false)]
            [int]$InitialDelaySeconds = 2
        )

        $attempt = 0
        $delay = $InitialDelaySeconds

        while ($attempt -lt $Retries) {
            try {
                return & $ScriptBlock
            }
            catch {
                $attempt++
                if ($attempt -ge $Retries) { throw }

                Write-Verbose "$OperationName failed on attempt $attempt. Retrying in $delay second(s)."
                Start-Sleep -Seconds $delay
                $delay = [Math]::Min($delay * 2, 30)
            }
        }
    }

    function Test-ValidIpAddress {
        param([Parameter(Mandatory = $true)][string]$InputIp)

        $nullIp = $null
        return [System.Net.IPAddress]::TryParse($InputIp, [ref]$nullIp)
    }

    function Add-UniqueItem {
        param(
            [Parameter(Mandatory = $true)]$List,
            [Parameter(Mandatory = $true)][string]$Value
        )

        if ($null -ne $List -and -not [string]::IsNullOrWhiteSpace($Value) -and -not $List.Contains($Value)) {
            [void]$List.Add($Value)
        }
    }

    function Remove-ListItem {
        param(
            [Parameter(Mandatory = $true)]$List,
            [Parameter(Mandatory = $true)][string]$Value
        )

        while ($List.Contains($Value)) {
            [void]$List.Remove($Value)
        }
    }

    function Get-FirstNonEmptyValue {
        param([Parameter(Mandatory = $false)][object[]]$Values)

        foreach ($value in $Values) {
            if ($null -eq $value) { continue }

            $text = ([string]$value).Trim()
            if ([string]::IsNullOrWhiteSpace($text)) { continue }

            $normalized = $text.ToLowerInvariant()

            if (
                $normalized -match 'premium field' -or
                $normalized -match 'upgrade to view' -or
                $normalized -eq 'n/a' -or
                $normalized -eq 'na' -or
                $normalized -eq 'unknown' -or
                $normalized -eq 'null' -or
                $normalized -eq 'none' -or
                $normalized -eq 'not available' -or
                $normalized -eq 'unavailable'
            ) {
                continue
            }

            return $text
        }

        return $null
    }

    function Join-LocationParts {
        param(
            [Parameter(Mandatory = $false)][string]$City,
            [Parameter(Mandatory = $false)][string]$Region,
            [Parameter(Mandatory = $false)][string]$Country
        )

        $parts = New-Object 'System.Collections.Generic.List[string]'

        if (-not [string]::IsNullOrWhiteSpace($City)) {
            [void]$parts.Add($City.Trim())
        }

        if (-not [string]::IsNullOrWhiteSpace($Region) -and $Region.Trim() -notin $parts) {
            [void]$parts.Add($Region.Trim())
        }

        if (-not [string]::IsNullOrWhiteSpace($Country) -and $Country.Trim() -notin $parts) {
            [void]$parts.Add($Country.Trim())
        }

        if ($parts.Count -gt 0) {
            return ($parts -join ", ")
        }

        return $null
    }

    function Convert-AbuseIPDBCategory {
        param([Parameter(Mandatory = $true)][int]$CategoryId)

        $map = @{
            3  = "Fraud Orders"
            4  = "DDoS Attack"
            5  = "FTP Brute-Force"
            6  = "Ping of Death"
            7  = "Phishing"
            8  = "Fraud VoIP"
            9  = "Open Proxy"
            10 = "Web Spam"
            11 = "Email Spam"
            12 = "Blog Spam"
            13 = "VPN IP"
            14 = "Port Scan"
            15 = "Hacking"
            16 = "SQL Injection"
            17 = "Spoofing"
            18 = "Brute-Force"
            19 = "Bad Web Bot"
            20 = "Exploited Host"
            21 = "Web App Attack"
            22 = "SSH"
            23 = "IoT Targeted"
        }

        if ($map.ContainsKey($CategoryId)) {
            return $map[$CategoryId]
        }

        return "Category $CategoryId"
    }

    function Get-AzureIpLookup {
        param(
            [Parameter(Mandatory = $true)][string]$Ip,
            [Parameter(Mandatory = $true)][string]$LookupUrl
        )

        $encodedIp = [System.Uri]::EscapeDataString($Ip)
        $url = "${LookupUrl}?ipOrDomain=${encodedIp}"

        return Invoke-WithRetry -OperationName "Azure IP lookup for ${Ip}" -Retries $MaxRetries -InitialDelaySeconds $InitialRetryDelaySeconds -ScriptBlock {
            Invoke-RestMethod -Uri $url -Method Get -ErrorAction Stop
        }
    }

    try {
        $null = Get-SecretVault -Name $VaultName -ErrorAction Stop

        $storeStatus = Get-SecretStoreConfiguration -ErrorAction Stop
        if ($storeStatus.Authentication -eq 'Password') {
            Write-Verbose "SecretStore uses password authentication. Unlock it first with Unlock-SecretStore."
        }

        $ApiUser          = Get-Secret -Vault $VaultName -Name $ScamalyticsUserSecretName -AsPlainText -ErrorAction Stop
        $ApiKey           = Get-Secret -Vault $VaultName -Name $ScamalyticsKeySecretName -AsPlainText -ErrorAction Stop
        $ProxyCheckApiKey = Get-Secret -Vault $VaultName -Name $ProxyCheckKeySecretName -AsPlainText -ErrorAction Stop
        $AbuseIPDBApiKey  = Get-Secret -Vault $VaultName -Name $AbuseIPDBKeySecretName -AsPlainText -ErrorAction Stop
    }
    catch {
        throw "Failed to retrieve secrets from vault '$VaultName'. If the vault is password protected, run Unlock-SecretStore first. $($_.Exception.Message)"
    }

    if (-not $IPs -or $IPs.Count -eq 0) {
        $inputIPs = Read-Host "Enter IP(s) (comma separated)"
        $IPs = $inputIPs -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    }

    foreach ($rawIp in $IPs) {
        $ip = $rawIp.Trim()

        if (-not (Test-ValidIpAddress -InputIp $ip)) {
            Write-Warning "Skipping invalid IP: ${ip}"
            continue
        }

        $location = $null
        $isp = $null
        $score = $null
        $risk = $null
        $provider = $null
        $proxyCheckVpnProxy = $null
        $firstSeen = $null
        $lastSeen = $null

        $abuseConfidence = $null
        $abuseReports = $null
        $abuseLastReported = $null
        $abuseUsageType = $null
        $abuseDomain = $null
        $abuseWhitelisted = $null

        $azureLookup = $null
        $azureResults = @()

        $labels = New-Object 'System.Collections.Generic.List[string]'
        $subTypes = New-Object 'System.Collections.Generic.List[string]'
        $abuseLatestCategories = New-Object 'System.Collections.Generic.List[string]'

        $scam = $null
        $ext = $null
        $pcResp = $null
        $pcData = $null
        $abuse = $null

        try {
            $scamUrl = "${BaseUrl}/${ApiUser}/?key=${ApiKey}&ip=${ip}"
            Write-Verbose "Requesting Scamalytics for ${ip}"

            $resp = Invoke-WithRetry -OperationName "Scamalytics request for ${ip}" -Retries $MaxRetries -InitialDelaySeconds $InitialRetryDelaySeconds -ScriptBlock {
                Invoke-RestMethod -Uri $scamUrl -Method Get -ErrorAction Stop
            }

            $scam = $resp.scamalytics
            $ext  = $resp.external_datasources

            if ($scam.status -eq "ok") {
                if ($null -ne $scam.scamalytics_score) {
                    $score = $scam.scamalytics_score
                }

                if (-not [string]::IsNullOrWhiteSpace([string]$scam.scamalytics_risk)) {
                    $risk = [string]$scam.scamalytics_risk
                }

                $dbip   = $ext.dbip
                $mm     = $ext.maxmind_geolite2
                $ipinfo = $ext.ipinfo

                $city = Get-FirstNonEmptyValue @(
                    $dbip.ip_city
                    $mm.ip_city
                    $ipinfo.ip_city
                )

                $region = Get-FirstNonEmptyValue @(
                    $dbip.ip_region_name
                    $mm.ip_subdivision_name
                    $ipinfo.ip_region
                )

                $country = Get-FirstNonEmptyValue @(
                    $dbip.ip_country_name
                    $mm.ip_country_name
                    $ipinfo.ip_country_name
                    $ipinfo.ip_country
                )

                $location = Join-LocationParts -City $city -Region $region -Country $country

                $isp = Get-FirstNonEmptyValue @(
                    $dbip.isp_name
                    $scam.scamalytics_isp
                    $mm.as_name
                    $ipinfo.as_name
                    $ipinfo.isp
                )

                if ($scam.scamalytics_proxy.is_datacenter -eq $true) { Add-UniqueItem $labels "Datacenter" }
                if ($scam.scamalytics_proxy.is_vpn -eq $true) { Add-UniqueItem $labels "VPN" }
                if ($scam.scamalytics_proxy.is_google -eq $true) { Add-UniqueItem $labels "Google Infrastructure" }
                if ($scam.scamalytics_proxy.is_amazon_aws -eq $true) { Add-UniqueItem $labels "AWS" }

                if (
                    ([string]$scam.scamalytics_isp -match "Microsoft") -or
                    ([string]$ext.maxmind_geolite2.as_name -match "Microsoft") -or
                    ([string]$ext.ipinfo.as_name -match "Microsoft")
                ) {
                    Add-UniqueItem $labels "Microsoft Infrastructure"
                }

                if ($scam.scamalytics_proxy.is_apple_icloud_private_relay -eq $true) { Add-UniqueItem $labels "Apple iCloud Relay" }
                if ($ext.x4bnet.is_tor -eq $true) { Add-UniqueItem $labels "TOR" }
                if ($ext.x4bnet.is_vpn -eq $true) { Add-UniqueItem $labels "VPN" }
                if ($ext.x4bnet.is_datacenter -eq $true) { Add-UniqueItem $labels "Datacenter" }
                if ($ext.firehol.is_proxy -eq $true) { Add-UniqueItem $labels "Proxy" }

                if ($ext.firehol.ip_blacklisted_30 -eq $true -or $ext.firehol.ip_blacklisted_1day -eq $true) {
                    Add-UniqueItem $labels "Blacklist: Firehol"
                }

                if ($ext.ipsum.ip_blacklisted -eq $true -or ($null -ne $ext.ipsum.num_blacklists -and [int]$ext.ipsum.num_blacklists -gt 0)) {
                    Add-UniqueItem $labels "Blacklist: IPsum"
                }

                if ($ext.spamhaus_drop.ip_blacklisted -eq $true) {
                    Add-UniqueItem $labels "Blacklist: Spamhaus"
                }

                if ($ext.x4bnet.is_blacklisted_spambot -eq $true) {
                    Add-UniqueItem $labels "Blacklist: X4Bnet Spambot"
                }

                if ($ext.google.is_googlebot -eq $true -or $ext.google.is_special_crawler -eq $true) {
                    Add-UniqueItem $labels "Search Engine Robot"
                }

                if ($ext.ip2proxy) {
                    switch ([string]$ext.ip2proxy.proxy_type) {
                        "VPN" { Add-UniqueItem $labels "VPN" }
                        "TOR" { Add-UniqueItem $labels "TOR" }
                        "DCH" { Add-UniqueItem $labels "Datacenter" }
                        "PUB" { Add-UniqueItem $labels "Proxy"; Add-UniqueItem $subTypes "Public Proxy" }
                        "WEB" { Add-UniqueItem $labels "Proxy"; Add-UniqueItem $subTypes "Web Proxy" }
                        "SES" { Add-UniqueItem $labels "Search Engine Robot" }
                        "RES" { Add-UniqueItem $subTypes "Residential" }
                        "MOB" { Add-UniqueItem $subTypes "Mobile" }
                    }
                }

                if ($ext.ip2proxy_lite) {
                    if ($ext.ip2proxy_lite.ip_blacklisted -eq $true) {
                        Add-UniqueItem $labels "Blacklist: IP2ProxyLite"
                    }

                    switch ([string]$ext.ip2proxy_lite.proxy_type) {
                        "VPN" { Add-UniqueItem $labels "VPN" }
                        "TOR" { Add-UniqueItem $labels "TOR" }
                        "DCH" { Add-UniqueItem $labels "Datacenter" }
                        "PUB" { Add-UniqueItem $labels "Proxy"; Add-UniqueItem $subTypes "Public Proxy" }
                        "WEB" { Add-UniqueItem $labels "Proxy"; Add-UniqueItem $subTypes "Web Proxy" }
                        "SES" { Add-UniqueItem $labels "Search Engine Robot" }
                    }
                }
            }
            else {
                $risk = "API status: $($scam.status)"
            }
        }
        catch {
            Write-Verbose "Scamalytics failed for ${ip}. $($_.Exception.Message)"
        }

        try {
            $pcUrl = "https://proxycheck.io/v3/${ip}?key=${ProxyCheckApiKey}&vpn=1&asn=1"
            Write-Verbose "Requesting ProxyCheck for ${ip}"

            $pcResp = Invoke-WithRetry -OperationName "ProxyCheck request for ${ip}" -Retries $MaxRetries -InitialDelaySeconds $InitialRetryDelaySeconds -ScriptBlock {
                Invoke-RestMethod -Uri $pcUrl -Method Get -ErrorAction Stop
            }

            if ($pcResp.status -in @("ok", "warning")) {
                $pcProperty = $pcResp.PSObject.Properties | Where-Object { $_.Name -eq $ip } | Select-Object -First 1

                if ($null -ne $pcProperty) {
                    $pcData = $pcProperty.Value

                    if ($null -ne $pcData.detections) {
                        $pcVpn = $pcData.detections.vpn
                        $pcProxy = $pcData.detections.proxy
                        $pcTor = $pcData.detections.tor
                        $pcHosting = $pcData.detections.hosting
                        $pcAnonymous = $pcData.detections.anonymous

                        if ($null -ne $pcVpn -or $null -ne $pcProxy) {
                            $proxyCheckVpnProxy = "$pcVpn / $pcProxy"
                        }

                        if (-not [string]::IsNullOrWhiteSpace([string]$pcData.detections.first_seen)) {
                            $firstSeen = [string]$pcData.detections.first_seen
                        }

                        if (-not [string]::IsNullOrWhiteSpace([string]$pcData.detections.last_seen)) {
                            $lastSeen = [string]$pcData.detections.last_seen
                        }

                        if ($pcVpn -eq $true) { Add-UniqueItem $labels "VPN" }
                        if ($pcProxy -eq $true) { Add-UniqueItem $labels "Proxy" }
                        if ($pcTor -eq $true) { Add-UniqueItem $labels "TOR" }
                        if ($pcHosting -eq $true) { Add-UniqueItem $labels "Datacenter" }
                        if ($pcAnonymous -eq $true) { Add-UniqueItem $subTypes "Anonymous" }
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

                    if (-not [string]::IsNullOrWhiteSpace($provider) -and $pcData.detections.vpn -eq $true) {
                        Remove-ListItem $labels "VPN"
                        Add-UniqueItem $labels "VPN: $provider"
                    }
                }
            }
        }
        catch {
            Write-Verbose "ProxyCheck failed for ${ip}. $($_.Exception.Message)"
        }

        try {
            $encodedIp = [System.Uri]::EscapeDataString($ip)
            $abuseUrl = "https://api.abuseipdb.com/api/v2/check?ipAddress=$encodedIp&maxAgeInDays=$AbuseIPDBMaxAgeDays&verbose"
            Write-Verbose "Requesting AbuseIPDB for ${ip}"

            $abuseResp = Invoke-WithRetry -OperationName "AbuseIPDB request for ${ip}" -Retries $MaxRetries -InitialDelaySeconds $InitialRetryDelaySeconds -ScriptBlock {
                Invoke-RestMethod -Uri $abuseUrl -Method Get -Headers @{
                    Key    = $AbuseIPDBApiKey
                    Accept = "application/json"
                } -ErrorAction Stop
            }

            if ($null -ne $abuseResp.data) {
                $abuse = $abuseResp.data

                $abuseConfidence = $abuse.abuseConfidenceScore
                $abuseReports = $abuse.totalReports
                $abuseLastReported = $abuse.lastReportedAt
                $abuseUsageType = $abuse.usageType
                $abuseDomain = $abuse.domain
                $abuseWhitelisted = $abuse.isWhitelisted

                if ($abuse.isTor -eq $true) {
                    Add-UniqueItem $labels "TOR"
                }

                if (-not [string]::IsNullOrWhiteSpace([string]$abuse.usageType)) {
                    switch -Regex ([string]$abuse.usageType) {
                        "Data Center|Web Hosting|Transit" { Add-UniqueItem $labels "Datacenter" }
                        "Search Engine Spider" { Add-UniqueItem $labels "Search Engine Robot" }
                        "Content Delivery Network" { Add-UniqueItem $subTypes "CDN" }
                    }
                }

                if ($null -ne $abuse.reports -and $abuse.reports.Count -gt 0) {
                    $latestReports = $abuse.reports |
                        Sort-Object { [datetime]$_.reportedAt } -Descending |
                        Select-Object -First 50

                    foreach ($report in $latestReports) {
                        foreach ($categoryId in $report.categories) {
                            Add-UniqueItem $abuseLatestCategories (Convert-AbuseIPDBCategory -CategoryId ([int]$categoryId))
                        }
                    }
                }
            }
        }
        catch {
            Write-Verbose "AbuseIPDB failed for ${ip}. $($_.Exception.Message)"
        }

        if ($labels.Contains("Microsoft Infrastructure")) {
            try {
                Write-Verbose "Requesting Azure IP Lookup for Microsoft infrastructure IP ${ip}"

                $azureLookup = Get-AzureIpLookup -Ip $ip -LookupUrl $AzureIpLookupUrl

                if ($azureLookup -is [string]) {
                    $azureLookup = $azureLookup | ConvertFrom-Json -ErrorAction Stop
                }

                if ($null -ne $azureLookup) {
                    if ($azureLookup -is [System.Array]) {
                        $azureResults = @($azureLookup)
                    }
                    else {
                        $azureResults = @($azureLookup)
                    }

                    if ($azureResults.Count -gt 0) {
                        Add-UniqueItem $labels "Azure Service Tag"
                    }
                }
            }
            catch {
                Write-Verbose "Azure IP Lookup failed for ${ip}. $($_.Exception.Message)"
            }
        }

        if ([string]::IsNullOrWhiteSpace($location)) {
            $pcCity = $null
            $pcRegion = $null
            $pcCountry = $null

            if ($pcData -and $pcData.location) {
                $pcCity = Get-FirstNonEmptyValue @(
                    $pcData.location.city_name
                    $pcData.location.city
                )

                $pcRegion = Get-FirstNonEmptyValue @(
                    $pcData.location.region
                    $pcData.location.region_name
                    $pcData.location.state
                )

                $pcCountry = Get-FirstNonEmptyValue @(
                    $pcData.location.country_name
                    $pcData.location.country
                )
            }

            $location = Join-LocationParts -City $pcCity -Region $pcRegion -Country $pcCountry
        }

        if ([string]::IsNullOrWhiteSpace($location) -and $abuse) {
            $location = Join-LocationParts -Country (Get-FirstNonEmptyValue @(
                $abuse.countryName
                $abuse.countryCode
            ))
        }

        if ([string]::IsNullOrWhiteSpace($isp)) {
            $isp = Get-FirstNonEmptyValue @(
                $pcData.network.provider
                $pcData.network.organization
                $pcData.provider
                $abuse.isp
                $abuse.domain
            )
        }

        $headerLabels = ($labels | ForEach-Object { "[$_]" }) -join " "

        if ([string]::IsNullOrWhiteSpace($headerLabels)) {
            Write-Output "##### $ip"
        }
        else {
            Write-Output "##### $headerLabels $ip"
        }

        if (-not [string]::IsNullOrWhiteSpace($location)) {
            Write-Output "- Location: $location"
        }

        if (-not [string]::IsNullOrWhiteSpace($isp)) {
            Write-Output "- ISP: $isp"
        }

        if ($azureResults.Count -gt 0) {
            foreach ($azureResult in $azureResults) {
                $azureServiceTagId = Get-FirstNonEmptyValue @($azureResult.serviceTagId)
                $azurePrefix = Get-FirstNonEmptyValue @($azureResult.ipAddressPrefix)
                $azureRegion = Get-FirstNonEmptyValue @($azureResult.region)
                $azureRegionId = Get-FirstNonEmptyValue @($azureResult.regionId)
                $azureSystemService = Get-FirstNonEmptyValue @($azureResult.systemService)
                $azureNetworkFeatures = Get-FirstNonEmptyValue @($azureResult.networkFeatures)

                if (-not [string]::IsNullOrWhiteSpace($azureServiceTagId)) {
                    Write-Output "- [AzureSpeed] Service tag: $azureServiceTagId"
                }

                if (-not [string]::IsNullOrWhiteSpace($azurePrefix)) {
                    Write-Output "- [AzureSpeed] Address prefix: $azurePrefix"
                }

                if (-not [string]::IsNullOrWhiteSpace($azureRegion)) {
                    Write-Output "- [AzureSpeed] Region: $azureRegion"
                }

                if (-not [string]::IsNullOrWhiteSpace($azureRegionId)) {
                    Write-Output "- [AzureSpeed] Region ID: $azureRegionId"
                }

                if (-not [string]::IsNullOrWhiteSpace($azureSystemService)) {
                    Write-Output "- [AzureSpeed] System service: $azureSystemService"
                }

                if (-not [string]::IsNullOrWhiteSpace($azureNetworkFeatures)) {
                    Write-Output "- [AzureSpeed] Network features: $azureNetworkFeatures"
                }
            }
        }

        $scamalyticsConnectionType = Get-FirstNonEmptyValue @(
            $ext.dbip.connection_type
        )

        if (-not [string]::IsNullOrWhiteSpace($scamalyticsConnectionType)) {
            Write-Output "- [Scamalytics: Connection]: $scamalyticsConnectionType"
        }

        if ($pcData -and $pcData.network) {
            $proxyCheckConnectionType = Get-FirstNonEmptyValue @(
                $pcData.network.type
            )

            if (-not [string]::IsNullOrWhiteSpace($proxyCheckConnectionType)) {
                Write-Output "- [ProxyCheck: Connection]: $proxyCheckConnectionType"
            }
        }

        if (-not [string]::IsNullOrWhiteSpace([string]$abuseUsageType)) {
            Write-Output "- [AbuseIPDB: Usage]: $abuseUsageType"
        }

        if ($subTypes.Count -gt 0) {
            Write-Output "- [ProxyCheck] Subtype(s): $(($subTypes -join ', '))"
        }

        if ($null -ne $score -or -not [string]::IsNullOrWhiteSpace($risk)) {
            $scoreText = if ($null -ne $score) { $score } else { "Unknown" }
            $riskText  = if (-not [string]::IsNullOrWhiteSpace($risk)) { $risk } else { "Unknown" }
            Write-Output "- [Scamalytics] risk: $scoreText ($riskText)"
        }

        if (-not [string]::IsNullOrWhiteSpace($provider)) {
            Write-Output "- [ProxyCheck] Provider: $provider"
        }

        if (-not [string]::IsNullOrWhiteSpace($proxyCheckVpnProxy)) {
            Write-Output "- [ProxyCheck] VPN/Proxy: $proxyCheckVpnProxy"
        }

        if (-not [string]::IsNullOrWhiteSpace($firstSeen)) {
            Write-Output "- [ProxyCheck] first seen: $firstSeen"
        }

        if (-not [string]::IsNullOrWhiteSpace($lastSeen)) {
            Write-Output "- [ProxyCheck] last seen: $lastSeen"
        }

        if ($null -ne $abuseConfidence) {
            Write-Output "- [AbuseIPDB] confidence: $abuseConfidence"
        }

        if ($null -ne $abuseReports) {
            Write-Output "- [AbuseIPDB] reports: $abuseReports in last $AbuseIPDBMaxAgeDays days"
        }

        if ($abuseReports -gt 0 -and $abuseLastReported) {
            Write-Output "- [AbuseIPDB] last reported: $abuseLastReported"
        }

        if (-not [string]::IsNullOrWhiteSpace([string]$abuseDomain)) {
            Write-Output "- [AbuseIPDB] domain: $abuseDomain"
        }

        if ($null -ne $abuseWhitelisted) {
            Write-Output "- [AbuseIPDB] whitelisted: $abuseWhitelisted"
        }

        if ($abuseWhitelisted -eq $true) {
            Write-Output "- [AbuseIPDB] IMPORTANT NOTE: IP is whitelisted. Whitelisted netblocks often belong to trusted providers but may still host abused cloud infrastructure. Validate context before trusting."
        }

        if ($abuseLatestCategories.Count -gt 0) {
            Write-Output "- [AbuseIPDB] latest categories: $(($abuseLatestCategories -join ', '))"
        }

        Write-Output ""
    }
}
```

## How to use

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
##### [Datacenter] [Blacklist: IPsum] 198.235.24.79
- [Scamalytics] Location: Santa Clara, United States
- [Scamalytics] ISP: Google LLC
- [Scamalytics] risk: 0 (low)
- [ProxyCheck] VPN/Proxy: False / False
- [AbuseIPDB] confidence: 0
- [AbuseIPDB] reports: 4587 in last 90 days
- [AbuseIPDB] last reported: 2026-03-29T11:34:41+00:00
- [AbuseIPDB] usage type: Data Center/Web Hosting/Transit
- [AbuseIPDB] domain: paloaltonetworks.com
- [AbuseIPDB] whitelisted: True
- [AbuseIPDB] IMPORTANT NOTE: IP is whitelisted. Whitelisted netblocks often belong to trusted providers but may still host abused cloud infrastructure. Validate context before trusting.
- [AbuseIPDB] latest categories: Port Scan, Brute-Force, SSH, Hacking, Bad Web Bot, Web App Attack, IoT Targeted, Spoofing
```

### Operational flow

1. Start script/function
2. Unlock vault with password pasted from password manager
3. Secrets retrieved from SecretVault
4. Execute function
5. Triage generated
6. Vault auto-locks after 4 hours or when session is terminated

## Field explanation

**Header Labels**

The labels shown in the header provide a quick classification of the IP address. These are derived from Scamalytics, ProxyCheck, and AbuseIPDB combined. Multiple labels may be present.

Examples:

Datacenter
VPN
VPN: NordVPN
TOR
Proxy
Google Infrastructure
Microsoft Infrastructure
AWS
Search Engine Robot
Blacklist: Firehol
Blacklist: Spamhaus

These labels are meant to give an immediate triage verdict.

**Location**

Geolocation of the IP address. Primarily derived from Scamalytics external data sources (DB-IP / MaxMind), with fallback to ProxyCheck if unavailable.

Format:

City, Country

**ISP**

Primary ISP or ASN owner of the IP address. This is typically the infrastructure owner and not necessarily the actual end user.

Examples:

Microsoft Corporation
Google LLC
Amazon Technologies Inc.
Datacamp Limited

**Subtype(s)**

Additional contextual classification that does not change the primary label but provides extra detail.

Examples:

CDN
Anonymous
Residential
Mobile
Public Proxy
Web Proxy

These are derived from Scamalytics, ProxyCheck, and AbuseIPDB usage type hints.

**Risk**

Scamalytics fraud risk score and classification.

Format:

[score] (risk level)

Example:

100 (very high)

**Provider**

VPN or proxy operator attribution from ProxyCheck. When a provider is identified, the generic VPN label is replaced with a provider-specific label.

Examples:

NordVPN
Mullvad
ProtonVPN
TOR

Header example:

[VPN: NordVPN]

**ProxyCheck VPN/Proxy**

Boolean detection from ProxyCheck indicating whether the IP is detected as a VPN or proxy.

Format:

VPN / Proxy

Example:

True / False

**First seen**

First observed timestamp for VPN/proxy detection from ProxyCheck. Indicates when the IP was first identified as belonging to the detected provider.

**Last seen**

Most recent timestamp ProxyCheck observed the IP as VPN/proxy infrastructure. Useful to determine whether the detection is recent or stale. However I am debating if I should keep this because we are investigating an active incident thus the last seen for the analyst would of course be "now" however it can give additional context if the last seen is not recent. 

## Azure Service Tag Enrichment

When an IP address is identified as Microsoft-owned infrastructure, the tool automatically performs an Azure Service Tag lookup using AzureSpeed.

This enrichment provides additional Azure-specific context that is normally unavailable from traditional reputation services.

### Additional Fields

| Field            | Description                                             |
| ---------------- | ------------------------------------------------------- |
| Service Tag      | Azure service identifier associated with the IP range   |
| Address Prefix   | Azure subnet containing the IP                          |
| Region           | Azure region where the range is registered              |
| Region ID        | Internal Azure region identifier                        |
| System Service   | Azure service associated with the range                 |
| Network Features | Azure networking capabilities associated with the range |

### Why This Matters

Many Microsoft sign-ins originate from Azure infrastructure.

Without Azure Service Tag validation, analysts may only see:

* Microsoft Corporation
* Microsoft Azure
* Datacenter

This provides limited context.

With Azure Service Tag enrichment, analysts can determine whether an IP belongs to:

* AzureActiveDirectory
* AzureFrontDoor
* AzureMonitor
* AzureTrafficManager
* AzureCloud
* Storage
* Sql
* Microsoft Defender related services
* Other Azure platform services

This can significantly reduce false positives during sign-in investigations and help validate whether an IP is likely part of legitimate Microsoft infrastructure.

### Example

##### [Microsoft Infrastructure] 20.x.x.x

* ISP: Microsoft Corporation
* Location: Dublin, Ireland
* [AzureSpeed] Service Tag: AzureActiveDirectory
* [AzureSpeed] Region: northeurope
* [AzureSpeed] Address Prefix: 20.x.x.x/28

Interpretation:

This IP belongs to Microsoft Entra ID infrastructure operating from the North Europe Azure region. Authentication activity originating from this address is generally expected Microsoft service traffic rather than a customer-hosted Azure virtual machine.

### Analyst Guidance

The presence of a Microsoft Infrastructure label alone should not be considered sufficient validation.

Always review:

* Azure Service Tag
* Authentication result
* MFA status
* Device state
* User behavior
* Historical sign-in patterns

Examples:

| Service Tag          | Typical Interpretation                    |
| -------------------- | ----------------------------------------- |
| AzureActiveDirectory | Microsoft Entra ID service infrastructure |
| AzureFrontDoor       | Microsoft reverse proxy / CDN             |
| AzureMonitor         | Monitoring and telemetry infrastructure   |
| AzureCloud           | Generic Azure workload space              |
| Storage              | Azure Storage services                    |
| Sql                  | Azure SQL services                        |

A result of AzureCloud generally indicates generic Azure-hosted infrastructure and should be treated similarly to other cloud-hosted workloads until additional context is available.


**AbuseIPDB confidence**

Abuse confidence score from AbuseIPDB. Higher values indicate stronger consensus of malicious activity.

Range:

0–100

**AbuseIPDB reports**

Number of reports submitted to AbuseIPDB within the configured time window (default 90 days).

Format:

X in last 90 days

**AbuseIPDB last reported**

Timestamp of the most recent report. Only shown when reports exist within the configured window.

**AbuseIPDB usage type**

Infrastructure classification provided by AbuseIPDB.

Examples:

Data Center/Web Hosting/Transit
Content Delivery Network
Fixed Line ISP
Search Engine Spider

This may also influence subtype classification.

**AbuseIPDB domain**

Domain associated with the IP address according to AbuseIPDB. Often useful for identifying infrastructure ownership.

Examples:

google.com
microsoft.com
amazon.com

**AbuseIPDB whitelisted**

Indicates whether the IP belongs to a trusted infrastructure block maintained by AbuseIPDB.

Whitelisted IPs may still be abused because they often belong to large cloud or CDN providers.

When true, an additional warning is shown.

**AbuseIPDB latest categories**

Unique abuse categories extracted from the most recent AbuseIPDB reports (latest 50 entries). These provide context about observed malicious behavior.

Examples:

Port Scan
Brute-Force
Bad Web Bot
Exploited Host
Web App Attack
