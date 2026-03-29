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

                if ($attempt -ge $Retries) {
                    throw
                }

                Write-Verbose "$OperationName failed on attempt $attempt. Retrying in $delay second(s)."
                Start-Sleep -Seconds $delay
                $delay = [Math]::Min($delay * 2, 30)
            }
        }
    }

    function Test-ValidIpAddress {
        param(
            [Parameter(Mandatory = $true)]
            [string]$InputIp
        )

        $nullIp = $null
        return [System.Net.IPAddress]::TryParse($InputIp, [ref]$nullIp)
    }

    function Add-UniqueItem {
        param(
            [Parameter(Mandatory = $true)]
            $List,

            [Parameter(Mandatory = $true)]
            [string]$Value
        )

        if ($null -ne $List -and -not [string]::IsNullOrWhiteSpace($Value) -and -not $List.Contains($Value)) {
            [void]$List.Add($Value)
        }
    }

    function Convert-AbuseIPDBCategory {
        param(
            [Parameter(Mandatory = $true)]
            [int]$CategoryId
        )

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

        $labels = New-Object 'System.Collections.Generic.List[string]'
        $subTypes = New-Object 'System.Collections.Generic.List[string]'
        $abuseLatestCategories = New-Object 'System.Collections.Generic.List[string]'

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

                $dbip = $ext.dbip
                $mm   = $ext.maxmind_geolite2

                $city = $null
                $country = $null

                if ($dbip) {
                    if (-not [string]::IsNullOrWhiteSpace([string]$dbip.ip_city)) {
                        $city = [string]$dbip.ip_city
                    }
                    if (-not [string]::IsNullOrWhiteSpace([string]$dbip.ip_country_name)) {
                        $country = [string]$dbip.ip_country_name
                    }
                }

                if ([string]::IsNullOrWhiteSpace($city) -and $mm -and -not [string]::IsNullOrWhiteSpace([string]$mm.ip_city)) {
                    $city = [string]$mm.ip_city
                }

                if ([string]::IsNullOrWhiteSpace($country) -and $mm -and -not [string]::IsNullOrWhiteSpace([string]$mm.ip_country_name)) {
                    $country = [string]$mm.ip_country_name
                }

                if (-not [string]::IsNullOrWhiteSpace($city) -and -not [string]::IsNullOrWhiteSpace($country)) {
                    $location = "$city, $country"
                }
                elseif (-not [string]::IsNullOrWhiteSpace($country)) {
                    $location = $country
                }

                if ($dbip -and -not [string]::IsNullOrWhiteSpace([string]$dbip.isp_name)) {
                    $isp = [string]$dbip.isp_name
                }
                elseif (-not [string]::IsNullOrWhiteSpace([string]$scam.scamalytics_isp)) {
                    $isp = [string]$scam.scamalytics_isp
                }
                elseif ($mm -and -not [string]::IsNullOrWhiteSpace([string]$mm.as_name)) {
                    $isp = [string]$mm.as_name
                }

                if ($scam.scamalytics_proxy.is_datacenter -eq $true) {
                    Add-UniqueItem $labels "Datacenter"
                }

                if ($scam.scamalytics_proxy.is_vpn -eq $true) {
                    Add-UniqueItem $labels "VPN"
                }

                if ($scam.scamalytics_proxy.is_google -eq $true) {
                    Add-UniqueItem $labels "Google Infrastructure"
                }

                if ($scam.scamalytics_proxy.is_amazon_aws -eq $true) {
                    Add-UniqueItem $labels "AWS"
                }

                if ($scam.scamalytics_isp -match "Microsoft" -or
                    $ext.maxmind_geolite2.as_name -match "Microsoft" -or
                    $ext.ipinfo.as_name -match "Microsoft") {

                    Add-UniqueItem $labels "Microsoft Infrastructure"
                }

                if ($scam.scamalytics_proxy.is_apple_icloud_private_relay -eq $true) {
                    Add-UniqueItem $labels "Apple iCloud Relay"
                }

                if ($ext.x4bnet.is_tor -eq $true) {
                    Add-UniqueItem $labels "TOR"
                }

                if ($ext.x4bnet.is_vpn -eq $true) {
                    Add-UniqueItem $labels "VPN"
                }

                if ($ext.x4bnet.is_datacenter -eq $true) {
                    Add-UniqueItem $labels "Datacenter"
                }

                if ($ext.firehol.is_proxy -eq $true) {
                    Add-UniqueItem $labels "Proxy"
                }

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
                        "PUB" {
                            Add-UniqueItem $labels "Proxy"
                            Add-UniqueItem $subTypes "Public Proxy"
                        }
                        "WEB" {
                            Add-UniqueItem $labels "Proxy"
                            Add-UniqueItem $subTypes "Web Proxy"
                        }
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
                        "PUB" {
                            Add-UniqueItem $labels "Proxy"
                            Add-UniqueItem $subTypes "Public Proxy"
                        }
                        "WEB" {
                            Add-UniqueItem $labels "Proxy"
                            Add-UniqueItem $subTypes "Web Proxy"
                        }
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

                        if ($pcVpn -eq $true) {
                            Add-UniqueItem $labels "VPN"
                        }

                        if ($pcProxy -eq $true) {
                            Add-UniqueItem $labels "Proxy"
                        }

                        if ($pcTor -eq $true) {
                            Add-UniqueItem $labels "TOR"
                        }

                        if ($pcHosting -eq $true) {
                            Add-UniqueItem $labels "Datacenter"
                        }

                        if ($pcAnonymous -eq $true) {
                            Add-UniqueItem $subTypes "Anonymous"
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

                    if (-not [string]::IsNullOrWhiteSpace($provider) -and $pcData.detections.vpn -eq $true) {
                        while ($labels.Contains("VPN")) {
                            [void]$labels.Remove("VPN")
                        }
                        Add-UniqueItem $labels "VPN: $provider"
                    }

                    if ([string]::IsNullOrWhiteSpace($location) -and $null -ne $pcData.location) {
                        $pcCity = [string]$pcData.location.city_name
                        $pcCountry = [string]$pcData.location.country_name

                        if (-not [string]::IsNullOrWhiteSpace($pcCity) -and -not [string]::IsNullOrWhiteSpace($pcCountry)) {
                            $location = "$pcCity, $pcCountry"
                        }
                        elseif (-not [string]::IsNullOrWhiteSpace($pcCountry)) {
                            $location = $pcCountry
                        }
                    }

                    if ([string]::IsNullOrWhiteSpace($isp) -and $null -ne $pcData.network -and -not [string]::IsNullOrWhiteSpace([string]$pcData.network.provider)) {
                        $isp = [string]$pcData.network.provider
                    }
                }
                else {
                    Write-Verbose "ProxyCheck returned status ok, but no IP result block was found for ${ip}"
                }
            }
            else {
                Write-Verbose "ProxyCheck status was $($pcResp.status)"
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

                if ([string]::IsNullOrWhiteSpace($isp) -and -not [string]::IsNullOrWhiteSpace([string]$abuse.isp)) {
                    $isp = [string]$abuse.isp
                }

                if ([string]::IsNullOrWhiteSpace($location) -and -not [string]::IsNullOrWhiteSpace([string]$abuse.countryName)) {
                    $location = [string]$abuse.countryName
                }

                if ($abuse.isTor -eq $true) {
                    Add-UniqueItem $labels "TOR"
                }

                if (-not [string]::IsNullOrWhiteSpace([string]$abuse.usageType)) {
                    switch -Regex ([string]$abuse.usageType) {
                        "Data Center|Web Hosting|Transit" {
                            Add-UniqueItem $labels "Datacenter"
                        }
                        "Search Engine Spider" {
                            Add-UniqueItem $labels "Search Engine Robot"
                        }
                        "Content Delivery Network" {
                            Add-UniqueItem $subTypes "CDN"
                        }
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

        if ($labels.Count -eq 0) {
            Add-UniqueItem $labels "Normal"
        }

        $headerLabels = ($labels | ForEach-Object { "[$_]" }) -join " "
        Write-Output "##### $headerLabels $ip"

        if (-not [string]::IsNullOrWhiteSpace($location)) {
            Write-Output "- [Scamalytics] Location: $location"
        }

        if (-not [string]::IsNullOrWhiteSpace($isp)) {
            Write-Output "- [Scamalytics] ISP: $isp"
        }

        ## Write-Output "- Labels: $(($labels -join ', '))"

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

        if (-not [string]::IsNullOrWhiteSpace([string]$abuseUsageType)) {
            Write-Output "- [AbuseIPDB] usage type: $abuseUsageType"
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
