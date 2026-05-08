Workflow:

1. Run the KQL.
2. Copy the unique BaseFolder values.
3. Paste them into:
```text
$FoldersToCheck = @(
    '',
    ''
)
```
4. Run the script on the affected server.
5. Review ServiceBaseFolderAclReport.csv.

Check the Services and folder that are tagged outside of a common protected location

```kql
let RecommendationName = "Change service executable path to a common protected location";
DeviceTvmSecureConfigurationAssessment
| join kind=inner (
    DeviceTvmSecureConfigurationAssessmentKB
    | where ConfigurationName =~ RecommendationName
    | project ConfigurationId, ConfigurationName
) on ConfigurationId
| where IsApplicable == 1
| where IsCompliant == 0
| extend ContextJson = parse_json(Context)
| extend
    ServiceName = tostring(ContextJson[0]),
    RawServicePath = tostring(ContextJson[1])
| extend ServicePath = replace_string(RawServicePath, @"\""", @"""")
| extend ServicePath = trim(@'"', ServicePath)
| extend ServicePath = replace_regex(ServicePath, @"^\\\?\?\\", "")
| extend ServicePath = replace_regex(ServicePath, @"^\\\\\?\\", "")
| extend ExecutablePath = extract(@"([A-Za-z]:\\[^""]+?\.exe)", 1, ServicePath)
| extend BaseFolder = extract(@"^([A-Za-z]:\\[^\\]+)", 1, ExecutablePath)
| summarize arg_max(Timestamp, *) by DeviceId, ServiceName, ExecutablePath
| project
    DeviceName,
    Recommendation = ConfigurationName,
    ServiceName
```

```powershell
//Insert folders that are returned from above KQL
$FoldersToCheck = @(
    '',
    ''
)

$OutputFolder = Join-Path $env:USERPROFILE 'Desktop\ServiceAclAudit'

if (-not (Test-Path -LiteralPath $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder | Out-Null
}

$BroadPrincipals = @(
    'Everyone',
    'Authenticated Users',
    'BUILTIN\Users',
    'Users',
    'Domain Users'
)

$WriteRightsPattern = 'Write|Modify|FullControl|CreateFiles|CreateDirectories|AppendData|WriteData|ChangePermissions|TakeOwnership'

$AclReport = foreach ($folder in $FoldersToCheck) {

    if (Test-Path -LiteralPath $folder) {

        $acl = Get-Acl -LiteralPath $folder

        foreach ($ace in $acl.Access) {

            $identity = $ace.IdentityReference.Value
            $rightsText = $ace.FileSystemRights.ToString()

            $isBroadPrincipal = $false
            foreach ($principal in $BroadPrincipals) {
                if ($identity -match [regex]::Escape($principal)) {
                    $isBroadPrincipal = $true
                    break
                }
            }

            $hasWriteRights = $rightsText -match $WriteRightsPattern

            $riskLevel = if (
                $ace.AccessControlType -eq 'Allow' -and
                $isBroadPrincipal -and
                $hasWriteRights -and
                -not $ace.IsInherited
            ) {
                'High'
            }
            elseif (
                $ace.AccessControlType -eq 'Allow' -and
                $isBroadPrincipal -and
                $hasWriteRights -and
                $ace.IsInherited
            ) {
                'Medium'
            }
            else {
                'None'
            }

            $riskIndicator = if (
                $ace.AccessControlType -eq 'Allow' -and
                $isBroadPrincipal -and
                $hasWriteRights
            ) {
                'Broad principal has write-capable permissions on service base folder'
            }
            else {
                ''
            }

            [PSCustomObject]@{
                ComputerName        = $env:COMPUTERNAME
                BaseFolder          = $folder
                Owner               = $acl.Owner
                IdentityReference   = $identity
                FileSystemRights    = $rightsText
                AccessControlType   = $ace.AccessControlType
                IsInherited         = $ace.IsInherited
                InheritanceFlags    = $ace.InheritanceFlags
                PropagationFlags    = $ace.PropagationFlags
                RiskLevel           = $riskLevel
                RiskIndicator       = $riskIndicator
            }
        }
    }
    else {
        [PSCustomObject]@{
            ComputerName        = $env:COMPUTERNAME
            BaseFolder          = $folder
            Owner               = ''
            IdentityReference   = ''
            FileSystemRights    = ''
            AccessControlType   = ''
            IsInherited         = ''
            InheritanceFlags    = ''
            PropagationFlags    = ''
            RiskLevel           = 'Unknown'
            RiskIndicator       = 'Folder not found'
        }
    }
}

$CsvPath = Join-Path $OutputFolder 'ServiceBaseFolderAclReport_Full.csv'

$AclReport |
    Sort-Object BaseFolder, IdentityReference |
    Export-Csv -Path $CsvPath -NoTypeInformation -Delimiter ';' -Encoding UTF8

Write-Host ''
Write-Host 'Complete ACL report exported to:'
Write-Host $CsvPath
Write-Host ''

$AclReport | Format-Table -AutoSize
```
