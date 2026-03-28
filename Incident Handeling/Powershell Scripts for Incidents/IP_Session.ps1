function Get-ScamSpurTriage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiUser,

        [Parameter(Mandatory = $true)]
        [string]$ApiKey,

        [Parameter(Mandatory = $false)]
        [string[]]$IPs,

        [Parameter(Mandatory = $false)]
        [string]$BaseUrl = "https://api12.scamalytics.com/v3"
    )

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
        $spur = "Not checked"

        try {
            $scamUrl = "$BaseUrl/$ApiUser/?key=$ApiKey&ip=$ip"
            Write-Verbose "Requesting Scamalytics for $ip"
            $resp = Invoke-RestMethod -Uri $scamUrl -Method Get -ErrorAction Stop

            $scam = $resp.scamalytics
            $ext  = $resp.external_datasources

            if ($scam.status -eq "ok") {
                $score = if ($null -ne $scam.scamalytics_score) { $scam.scamalytics_score } else { "Unknown" }
                $risk  = if ($scam.scamalytics_risk) { $scam.scamalytics_risk } else { "Unknown" }

                $vpn = if ($null -ne $scam.scamalytics_proxy.is_vpn) { $scam.scamalytics_proxy.is_vpn } else { "Unknown" }
                $dc  = if ($null -ne $scam.scamalytics_proxy.is_datacenter) { $scam.scamalytics_proxy.is_datacenter } else { "Unknown" }
                $tor = if ($null -ne $ext.x4bnet.is_tor) { $ext.x4bnet.is_tor } else { "Unknown" }
                $proxyTorDc = "$vpn / $tor / $dc"

                $mm   = $ext.maxmind_geolite2
                $dbip = $ext.dbip
                $ip2l = $ext.ip2proxy_lite
                $ip2  = $ext.ip2proxy

                $city = $null
                $country = $null

                if ($mm) {
                    if (-not [string]::IsNullOrWhiteSpace($mm.ip_city)) { $city = $mm.ip_city }
                    if (-not [string]::IsNullOrWhiteSpace($mm.ip_country_name)) { $country = $mm.ip_country_name }
                }

                if ([string]::IsNullOrWhiteSpace($city) -and $dbip -and -not [string]::IsNullOrWhiteSpace($dbip.ip_city)) {
                    $city = $dbip.ip_city
                }
                if ([string]::IsNullOrWhiteSpace($country) -and $dbip -and -not [string]::IsNullOrWhiteSpace($dbip.ip_country_name)) {
                    $country = $dbip.ip_country_name
                }

                if ([string]::IsNullOrWhiteSpace($city) -and $ip2l -and -not [string]::IsNullOrWhiteSpace($ip2l.ip_city)) {
                    $city = $ip2l.ip_city
                }
                if ([string]::IsNullOrWhiteSpace($country) -and $ip2l -and -not [string]::IsNullOrWhiteSpace($ip2l.ip_country_name)) {
                    $country = $ip2l.ip_country_name
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
                elseif ($scam -and -not [string]::IsNullOrWhiteSpace($scam.scamalytics_isp)) {
                    $isp = $scam.scamalytics_isp
                }
                elseif ($mm -and -not [string]::IsNullOrWhiteSpace($mm.as_name)) {
                    $isp = $mm.as_name
                }

                if ($ip2l -and -not [string]::IsNullOrWhiteSpace($ip2l.ip_provider)) {
                    $provider = $ip2l.ip_provider
                }
                elseif ($ip2 -and -not [string]::IsNullOrWhiteSpace($ip2.proxy_type)) {
                    $provider = $ip2.proxy_type
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
            $spurResp = Invoke-WebRequest -Uri "https://spur.us/context/$ip" -UseBasicParsing -ErrorAction Stop
            $html = [string]$spurResp.Content

            if ($html -match 'captcha\?redirect=' -or $html -match 'Testing your connection') {
                $spur = "Blocked by captcha/interstitial"
            }
            else {
                $spur = "Real page returned"
            }
        }
        catch {
            $spur = "Lookup failed"
        }

        Write-Output "##### $ip"
        Write-Output "- Location: $location"
        Write-Output "- ISP: $isp"
        Write-Output "- Risk score: $score ($risk)"
        Write-Output "- Proxy/TOR/Datacenter: $proxyTorDc"
        Write-Output "- Provider: $provider"
        Write-Output "- SPUR: $spur"
        Write-Output ""
    }
}

Get-ScamSpurTriage -ApiUser "" -ApiKey "" -IPs ""