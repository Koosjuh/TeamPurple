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

    try {
        $null = Get-SecretVault -Name $VaultName -ErrorAction Stop

        $storeStatus = Get-SecretStoreConfiguration -ErrorAction Stop
        if ($storeStatus.Authentication -eq 'Password') {
            Write-Verbose "SecretStore uses password authentication. Unlock it first with Unlock-SecretStore."
        }

        $ApiUser = Get-Secret -Vault $VaultName -Name $ScamalyticsUserSecretName -AsPlainText -ErrorAction Stop
        $ApiKey = Get-Secret -Vault $VaultName -Name $ScamalyticsKeySecretName -AsPlainText -ErrorAction Stop
        $ProxyCheckApiKey = Get-Secret -Vault $VaultName -Name $ProxyCheckKeySecretName -AsPlainText -ErrorAction Stop
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
            Write-Warning "Skipping invalid IP: $ip"
            continue
        }

        $location = $null
        $isp = $null
        $score = $null
        $risk = $null
        $proxyTorDc = $null
        $provider = $null
        $proxyCheckVpnProxy = $null
        $firstSeen = $null

        $isVpn = $false
        $isTor = $false
        $isDatacenter = $false
        $isProxy = $false
        $label = $null

        try {
            $scamUrl = "${BaseUrl}/${ApiUser}/?key=${ApiKey}&ip=${ip}"
            Write-Verbose "Requesting Scamalytics for $ip"

            $resp = Invoke-WithRetry -OperationName "Scamalytics request for $ip" -Retries $MaxRetries -InitialDelaySeconds $InitialRetryDelaySeconds -ScriptBlock {
                Invoke-RestMethod -Uri $scamUrl -Method Get -ErrorAction Stop
            }

            $scam = $resp.scamalytics
            $ext  = $resp.external_datasources

            if ($scam.status -eq "ok") {
                if ($null -ne $scam.scamalytics_score) {
                    $score = $scam.scamalytics_score
                }

                if (-not [string]::IsNullOrWhiteSpace($scam.scamalytics_risk)) {
                    $risk = $scam.scamalytics_risk
                }

                if ($null -ne $scam.scamalytics_proxy.is_vpn) {
                    $isVpn = [bool]$scam.scamalytics_proxy.is_vpn
                }

                if ($null -ne $scam.scamalytics_proxy.is_datacenter) {
                    $isDatacenter = [bool]$scam.scamalytics_proxy.is_datacenter
                }

                if ($null -ne $ext.x4bnet.is_tor) {
                    $isTor = [bool]$ext.x4bnet.is_tor
                }

                if ($null -ne $ext.firehol.is_proxy) {
                    $isProxy = [bool]$ext.firehol.is_proxy
                }

                $proxyTorDc = "$isVpn / $isTor / $isDatacenter"

                if ($isVpn -or $isTor -or $isDatacenter -or $isProxy) {
                    $label = "VPN"
                }

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
            Write-Verbose "Scamalytics failed for $ip. $($_.Exception.Message)"
        }

        try {
            $pcUrl = "https://proxycheck.io/v3/${ip}?key=${ProxyCheckApiKey}&vpn=1&asn=1"
            Write-Verbose "Requesting ProxyCheck for $ip"

            $pcRaw = Invoke-WithRetry -OperationName "ProxyCheck request for $ip" -Retries $MaxRetries -InitialDelaySeconds $InitialRetryDelaySeconds -ScriptBlock {
                Invoke-WebRequest -Uri $pcUrl -UseBasicParsing -ErrorAction Stop
            }

            $pcResp = $pcRaw.Content | ConvertFrom-Json

            if ($pcResp.status -in @("ok", "warning")) {
                $pcProperty = $pcResp.PSObject.Properties | Where-Object { $_.Name -eq $ip }

                if ($null -ne $pcProperty) {
                    $pcData = $pcProperty.Value

                    if ($null -ne $pcData.detections) {
                        $pcVpn   = if ($null -ne $pcData.detections.vpn) { $pcData.detections.vpn } else { $null }
                        $pcProxy = if ($null -ne $pcData.detections.proxy) { $pcData.detections.proxy } else { $null }

                        if ($null -ne $pcVpn -or $null -ne $pcProxy) {
                            $proxyCheckVpnProxy = "$pcVpn / $pcProxy"
                        }

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

        if (-not [string]::IsNullOrWhiteSpace($label)) {
            Write-Output "##### ($label) $ip"
        }
        else {
            Write-Output "##### $ip"
        }

        if (-not [string]::IsNullOrWhiteSpace($location)) {
            Write-Output "- Location: $location"
        }

        if (-not [string]::IsNullOrWhiteSpace($isp)) {
            Write-Output "- ISP: $isp"
        }

        if ($null -ne $score -or -not [string]::IsNullOrWhiteSpace($risk)) {
            $scoreText = if ($null -ne $score) { $score } else { "Unknown" }
            $riskText  = if (-not [string]::IsNullOrWhiteSpace($risk)) { $risk } else { "Unknown" }
            Write-Output "- Risk score: $scoreText ($riskText)"
        }

        if (-not [string]::IsNullOrWhiteSpace($proxyTorDc)) {
            Write-Output "- Proxy/TOR/Datacenter: $proxyTorDc"
        }

        if (-not [string]::IsNullOrWhiteSpace($provider)) {
            Write-Output "- Provider: $provider"
        }

        if (-not [string]::IsNullOrWhiteSpace($proxyCheckVpnProxy)) {
            Write-Output "- ProxyCheck VPN/Proxy: $proxyCheckVpnProxy"
        }

        if (-not [string]::IsNullOrWhiteSpace($firstSeen)) {
            Write-Output "- First seen: $firstSeen"
        }

        Write-Output ""
    }
}
