---
title: "Finding Weak Service Executable Paths with Defender TVM and PowerShell"
date: 2026-05-08
hero: "/images/posts/defender/service-executable-path-acl.jpg"
description: "How to validate Microsoft Defender's service executable path recommendation by checking real folder ACLs."
summary: "Microsoft Defender can flag services that run outside common protected locations. This post shows how to use KQL to identify the affected service paths and PowerShell to validate whether the base folders are writable by broad user groups."
categories:
  - "Microsoft Defender"
  - "Security Hardening"
tags:
  - "Defender for Endpoint"
  - "KQL"
  - "PowerShell"
  - "Service Hardening"
draft: true
toc: true
menu:
  sidebar:
    name: "Service Executable Path ACL Review"
    identifier: "defender-service-executable-path-acl-review"
    parent: "defender"
    weight: 10
---

# Finding Weak Service Executable Paths with Defender TVM and PowerShell

Most organizations focus on vulnerabilities, missing patches, exposed services and risky configurations.

That is good.

However, one of the the more practical privilege escalation risks is often much simpler:

A Windows service runs from a folder where normal users have write permissions.

That creates a real-world risk.

If a service executable or related service files are located in a folder that can be modified by broad principals such as `Authenticated Users`, `Users`, or `Domain Users`, a local user or attacker may be able to tamper with that service path.

If that service runs with elevated privileges, such as `LocalSystem` or a privileged service account, this can become a local privilege escalation or persistence path.

This is where the Microsoft Defender recommendation becomes useful:

> Change service executable path to a common protected location

The idea is simple. Service binaries should preferably live in common protected locations such as `C:\Program Files` or `C:\Windows`, where normal users should not have write access.

But as always: do not just accept the recommendation blindly.

First check what is actually exposed.

# Why this matters

A weak service executable path can matter in several scenarios:

- Local privilege escalation
- Service binary hijacking
- DLL search order or side-loading abuse
- Persistence through service tampering
- Ransomware staging or defense evasion
- Abuse of build agents or vendor services running from writable folders

This is especially relevant for devices where services run from custom folders such as:

- `C:\temp`
- `D:\apps`
- `D:\azuredevops`
- `C:\tools`
- vendor-specific application folders
- old migration or installer directories

The folder location itself is not always the problem.

The real question is:

> Who can write to that folder?

If a service runs from `D:\SomeApp`, and only Administrators and SYSTEM can modify that folder, the practical risk is much lower.

If `Authenticated Users` or `Domain Users` have `Modify`, `Write`, or `FullControl`, the risk becomes much more interesting.

# Workflow

The workflow is straightforward:

1. Run the KQL in Microsoft Defender Advanced Hunting.
2. Review the affected services and extracted base folders.
3. Copy the unique `BaseFolder` values.
4. Paste them into the PowerShell array.
5. Run the PowerShell script on the affected device.
6. Review `ServiceBaseFolderAclReport_Full.csv`.

The KQL tells you which folders Defender is concerned about.

The PowerShell tells you whether the ACLs on those folders are actually risky.

# Step 1: Find services outside common protected locations

Use the following KQL in Microsoft Defender Advanced Hunting.

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
    ServiceName,
    RawServicePath,
    ServicePath,
    ExecutablePath,
    BaseFolder,
    Timestamp
| order by DeviceName asc, BaseFolder asc, ServiceName asc
```

This query:

- Finds devices exposed to the Defender recommendation.
- Extracts the service executable path.
- Extracts the service base folder.
- Provides the exact folders that should be reviewed.

Example:

```text
D:\azuredevops\a01\bin\agentservice.exe
```

becomes:

```text
D:\azuredevops
```

This is the folder we want to validate.

# Step 2: Copy the unique BaseFolder values

From the KQL output, copy the unique `BaseFolder` values for the affected device.

Example:

```powershell
$FoldersToCheck = @(
    'D:\azuredevops',
    'C:\oracle'
)
```

# Step 3: Run the ACL check on the affected device

Run the following PowerShell script on the affected device.

```powershell
# Insert the BaseFolder values returned by the KQL query.
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

# What to look for

The most important thing to review is whether broad principals have write-capable permissions.

Examples:

```text
Authenticated Users    Modify
BUILTIN\Users          Modify
Domain Users           Write
Everyone               FullControl
```

These are the entries that usually matter.

Read-only entries such as:

```text
BUILTIN\Users    ReadAndExecute
```

are generally less concerning.

# Deployment options

There are several operational ways to deploy this at scale.

## Option 1: Manual assessment

Best for:
- one-off reviews
- small environments
- focused investigations

Workflow:

- Run the KQL.
- Copy the folders.
- Run the PowerShell manually.
- Review the CSV locally.

This is the simplest approach.

## Option 2: Intune deployment with local CSV output

Best for:
- medium environments
- phased assessments
- operational validation

Workflow:

1. Use the KQL to identify affected devices.
2. Deploy the PowerShell using:
   - Intune Platform Scripts
   - Intune Proactive Remediations
3. The script generates the CSV locally.
4. Retrieve results using:
   - Intune Collect Diagnostics
   - Defender Live Response
   - RMM tooling
   - remote collection methods

This is often the safest operational approach because ACL changes are not performed automatically.

## Option 3: Centralized ingestion into Sentinel or Log Analytics

Best for:
- large environments
- security engineering
- posture management
- ongoing monitoring

Workflow:

1. Run the script through Intune.
2. Convert findings to JSON.
3. Send results to:
   - Log Analytics
   - Sentinel custom tables
   - Data Collection Endpoints

This allows:

- dashboards
- trending
- alerting
- attack-path correlation
- service hardening visibility

This becomes significantly more powerful because you can correlate:

- risky service path
- writable ACL
- privileged service account
- internet-exposed systems
- EDR alerts
- ransomware activity

# Important operational nuance

Do not blindly remediate this recommendation.

Some environments intentionally run services from:

- build agents
- deployment frameworks
- middleware stacks
- legacy applications
- vendor software

The important thing is not only the folder path itself.

The real issue is usually:

> Can broad principals modify the folder contents?

A custom folder with only:

- SYSTEM
- Administrators

may be acceptable.

A writable service folder is the actual concern.

# Why ransomware operators care

Ransomware is not only about encryption.

Before encryption, attackers often try to:

- escalate privileges
- maintain persistence
- disable security tooling
- tamper with services
- abuse trusted execution paths

A writable service executable folder can help with that.

If an attacker already has a foothold as a normal user and can modify files inside a privileged service path, that may become a local privilege escalation or persistence mechanism.

That does not mean every finding is immediately exploitable.

But it absolutely means the finding deserves review.

# Final thought

This Defender recommendation is useful, but the real value is not the recommendation itself.

The real value is validating the actual ACLs.

A service running outside `C:\Program Files` is not automatically dangerous.

A service running from a folder where `Authenticated Users` or `Domain Users` can modify files is a different story.

So the practical workflow becomes:

```text
Find the exposed service path with KQL.
Extract the base folder.
Validate the ACLs locally or centrally.
Determine whether broad principals can write.
Then decide whether remediation is needed.
```
