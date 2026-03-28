function Get-ScamSpurTriage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiUser,

        [Parameter(Mandatory = $true)]
        [string]$ApiKey,

        [Parameter(Mandatory = $true)]
        [string]$ProxyCheckApiKey,

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
        Write-Output "LOCATION"
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
