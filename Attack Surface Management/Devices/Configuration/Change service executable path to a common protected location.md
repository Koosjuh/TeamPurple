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

$AclReport = foreach ($folder in $FoldersToCheck) {
    if (Test-Path -LiteralPath $folder) {
        $acl = Get-Acl -LiteralPath $folder

        foreach ($ace in $acl.Access) {
            [PSCustomObject]@{
                ComputerName        = $env:COMPUTERNAME
                BaseFolder          = $folder
                Owner               = $acl.Owner
                IdentityReference   = $ace.IdentityReference.Value
                FileSystemRights    = $ace.FileSystemRights
                AccessControlType   = $ace.AccessControlType
                IsInherited         = $ace.IsInherited
                InheritanceFlags    = $ace.InheritanceFlags
                PropagationFlags    = $ace.PropagationFlags
                RiskIndicator       = if (
                    $ace.AccessControlType -eq 'Allow' -and
                    $ace.IdentityReference.Value -match 'Everyone|Authenticated Users|Users|Domain Users|BUILTIN\\Users' -and
                    $ace.FileSystemRights -match 'Write|Modify|FullControl|CreateFiles|CreateDirectories|AppendData|WriteData'
                ) {
                    'Potentially risky write permission'
                }
                else {
                    ''
                }
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
            RiskIndicator       = 'Folder not found'
        }
    }
}

$AclReport |
    Sort-Object BaseFolder, IdentityReference |
    Export-Csv -Path ".\ServiceBaseFolderAclReport.csv" -NoTypeInformation -Delimiter ';' -Encoding UTF8

$AclReport | Format-Table -AutoSize
```
