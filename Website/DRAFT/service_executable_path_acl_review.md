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

Most organizations focus on vulnerabilities, missing patches, exposed services and risky configurations. That is good, it can in all cases always be even better.

However, one of the the more practical privilege escalation risks is often overlooked because they are hard to spot:

A (Windows) service runs from a folder where normal users have write permissions.

That creates a real risk.

If a service executable or related service files are located in a folder that can be modified by broad principals such as `Authenticated Users`, `Users`, or `Domain Users`, a local user or attacker may be able to tamper with that service path.

If that service runs with elevated privileges, such as `LocalSystem` or a privileged service account, this can become a local privilege escalation or persistence path.

This is where the Microsoft Defender recommendation becomes useful:

> Change service executable path to a common protected location

The idea is simple. Service binaries should preferably live in common protected locations such as `C:\Program Files` or `C:\Windows`, where normal users should not have write access.

But as always: do not just accept the recommendation blindly. Because just because this recommendation is there doesn't mean something is inherently wrong, however during my frequent customer meetings, I always ask, if they regularly check the ACL permissions these folders have, the answer so far has always been 'no'. 

So where do we start? First check what is actually exposed.

# Why

A weak service executable path can matter in several scenarios:

- Local privilege escalation
- Service binary hijacking
- Persistence through service tampering
- Ransomware staging or defense evasion

This is especially relevant for devices where services run from custom folders such as:

- `C:\temp`
- `D:\apps`
- `D:\azuredevops`
- `C:\tools`
- vendor-specific application folders (I am looking at you Oracle!)
- old migration or installer directories

The folder location itself is not always the problem.

The real question is:

> Who can write to that folder? Because Program Files or Windows have set ACL permission lists whilest anything outside of these standard OS Folders does not. 

If a service runs from `D:\SomeApp`, and only Administrators and SYSTEM can modify that folder, the practical risk is much lower.

If `Authenticated Users` or `Domain Users` have `Modify`, `Write`, or `FullControl`, the risk becomes much more great or interesting depending on who looks at it.

Most of these folders go unnoticed because in general they slowly grow as most organisations don't keep this in check and some applications even say in their manual; create a folder in C:\ and work from there. They do not want to bother you with ACL permissions, because than the barrier to entry might become to great and you might not use their software. Or maybe they also are not aware of the potential risk, either way, as an IT organisation you are responsible for what happens in your organisation. 

This can be quite a daunting task however I wrote a KQL and a powershell script that, depending on how you want to put this in operation might need adjusting, can help with the tedious check of checking ACL permissions.

# Workflow

The workflow is straightforward:

1. Run the KQL in Microsoft Defender Advanced Hunting.
2. Review the affected services and extracted base folders.
3. Copy the `ServiceName`, `ExecutableDirectory` & `BaseFolder` values.
4. Paste them into the PowerShell array.
5. Run the PowerShell script on the affected device.
6. Review `ServiceExecutableFolderAclEvidence.csv`.

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
| extend ExecutableDirectory = extract(@"^(.+)\\[^\\]+\.exe$", 1, ExecutablePath)
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
    ExecutableDirectory,
    Timestamp
| order by DeviceName asc, BaseFolder asc, ServiceName asc
```

This query:

- Finds devices exposed to the Defender recommendation.
- ServiceName
- RawServicePath
- ServicePath
- ExecutablePath
- BaseFolder
- ExecutableDirectory
- Provides the exact folders that should be reviewed.

Example:

| DeviceName | ServiceName | ExecutablePath | BaseFolder | ExecutableDirectory |
|---|---|---|---|---|
| ENG-LT-024 | DockerDesktopService | C:\Tools\Docker\com.docker.service.exe | C:\Tools | C:\Tools\Docker |
| DEV-LT-118 | JenkinsAgent | D:\BuildAgents\Jenkins\agent.exe | D:\BuildAgents | D:\BuildAgents\Jenkins |
| IT-LT-009 | PDQDeployRunner | C:\Applications\PDQ\Runner\runner.exe | C:\Applications | C:\Applications\PDQ\Runner |
| DEV-LT-203 | CustomUpdater | C:\DevTools\Updater\updater.exe | C:\DevTools | C:\DevTools\Updater |
| ENG-LT-077 | AzureDevOpsAgent | D:\azuredevops\a01\bin\AgentService.exe | D:\azuredevops | D:\azuredevops\a01\bin |
| APP-LT-041 | OracleServiceXE | C:\Oracle\product\21c\dbhomeXE\bin\oracle.exe | C:\Oracle | C:\Oracle\product\21c\dbhomeXE\bin |

# Step 2: Copy the unique BaseFolder values

From the KQL output, copy the `ServiceName`, `ExecutableDirectory` & `BaseFolder` values for the affected device. into the array below in the powershell.

Also note that below `$ServicePathsToCheck` is `$EnableRecursiveCheck = $false`.

This can be set to `$true`, which will scan all folders recursively.

Because of obvious resource considerations, recursive scanning is disabled by default. However, if needed, the script can also be used recursively.

Example:

```powershell
$ServicePathsToCheck = @(
    [PSCustomObject]@{
        ServiceName         = ''
        BaseFolder          = ''
        ExecutableDirectory = ''
    }
)

$EnableRecursiveCheck = $false

$OutputFolder = Join-Path $env:USERPROFILE 'Desktop\ServiceAclAudit'

if (-not (Test-Path -LiteralPath $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder | Out-Null
}

function Get-IdentitySid {
    param(
        [Parameter(Mandatory)]
        [System.Security.Principal.IdentityReference]$IdentityReference
    )

    try {
        return $IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
    }
    catch {
        return $null
    }
}

function Get-ServicePathAclEvidence {
    param(
        [Parameter(Mandatory)]
        [string]$ServiceName,

        [Parameter(Mandatory)]
        [string]$BaseFolder,

        [Parameter(Mandatory)]
        [string]$ExecutableDirectory,

        [bool]$Recursive = $false
    )

    $pathsToInspect = @(
        [PSCustomObject]@{
            Path     = $BaseFolder
            PathType = 'BaseFolder'
        },
        [PSCustomObject]@{
            Path     = $ExecutableDirectory
            PathType = 'ExecutableDirectory'
        }
    ) | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_.Path)
    }

    if ($Recursive -and (Test-Path -LiteralPath $BaseFolder)) {
        $childFolders = Get-ChildItem -LiteralPath $BaseFolder -Directory -Recurse -Force -ErrorAction SilentlyContinue

        foreach ($childFolder in $childFolders) {
            $pathsToInspect += [PSCustomObject]@{
                Path     = $childFolder.FullName
                PathType = 'SubFolder'
            }
        }
    }

    $pathsToInspect = $pathsToInspect | Sort-Object Path -Unique

    foreach ($pathItem in $pathsToInspect) {

        if (-not (Test-Path -LiteralPath $pathItem.Path)) {
            [PSCustomObject]@{
                ComputerName        = $env:COMPUTERNAME
                ServiceName         = $ServiceName
                BaseFolder          = $BaseFolder
                ExecutableDirectory = $ExecutableDirectory
                CheckedPath         = $pathItem.Path
                PathType            = $pathItem.PathType
                Owner               = ''
                InheritanceEnabled  = ''
                IdentityReference   = ''
                IdentitySid         = ''
                FileSystemRights    = ''
                AccessControlType   = ''
                IsInherited         = ''
                InheritanceFlags    = ''
                PropagationFlags    = ''
            }

            continue
        }

        try {
            $acl = Get-Acl -LiteralPath $pathItem.Path -ErrorAction Stop
        }
        catch {
            [PSCustomObject]@{
                ComputerName        = $env:COMPUTERNAME
                ServiceName         = $ServiceName
                BaseFolder          = $BaseFolder
                ExecutableDirectory = $ExecutableDirectory
                CheckedPath         = $pathItem.Path
                PathType            = $pathItem.PathType
                Owner               = ''
                InheritanceEnabled  = ''
                IdentityReference   = "Could not read ACL: $($_.Exception.Message)"
                IdentitySid         = ''
                FileSystemRights    = ''
                AccessControlType   = ''
                IsInherited         = ''
                InheritanceFlags    = ''
                PropagationFlags    = ''
            }

            continue
        }

        $inheritanceEnabled = -not $acl.AreAccessRulesProtected

        foreach ($ace in $acl.Access) {
            $identitySid = Get-IdentitySid -IdentityReference $ace.IdentityReference

            [PSCustomObject]@{
                ComputerName        = $env:COMPUTERNAME
                ServiceName         = $ServiceName
                BaseFolder          = $BaseFolder
                ExecutableDirectory = $ExecutableDirectory
                CheckedPath         = $pathItem.Path
                PathType            = $pathItem.PathType
                Owner               = $acl.Owner
                InheritanceEnabled  = $inheritanceEnabled
                IdentityReference   = $ace.IdentityReference.Value
                IdentitySid         = $identitySid
                FileSystemRights    = $ace.FileSystemRights.ToString()
                AccessControlType   = $ace.AccessControlType.ToString()
                IsInherited         = $ace.IsInherited
                InheritanceFlags    = $ace.InheritanceFlags.ToString()
                PropagationFlags    = $ace.PropagationFlags.ToString()
            }
        }
    }
}

$AclReport = foreach ($servicePath in $ServicePathsToCheck) {
    Get-ServicePathAclEvidence `
        -ServiceName $servicePath.ServiceName `
        -BaseFolder $servicePath.BaseFolder `
        -ExecutableDirectory $servicePath.ExecutableDirectory `
        -Recursive $EnableRecursiveCheck
}

$CsvPath = Join-Path $OutputFolder 'ServiceExecutableFolderAclEvidence.csv'

$AclReport |
    Select-Object `
        ComputerName,
        ServiceName,
        BaseFolder,
        ExecutableDirectory,
        CheckedPath,
        PathType,
        Owner,
        InheritanceEnabled,
        IdentityReference,
        IdentitySid,
        FileSystemRights,
        AccessControlType,
        IsInherited,
        InheritanceFlags,
        PropagationFlags |
    Sort-Object ServiceName, BaseFolder, CheckedPath, IdentityReference |
    Export-Csv -Path $CsvPath -NoTypeInformation -Delimiter ';' -Encoding UTF8

Write-Host ''
Write-Host 'ACL evidence exported to:'
Write-Host $CsvPath
Write-Host ''

$AclReport |
    Select-Object `
        ComputerName,
        ServiceName,
        BaseFolder,
        ExecutableDirectory,
        CheckedPath,
        PathType,
        Owner,
        InheritanceEnabled,
        IdentityReference,
        IdentitySid,
        FileSystemRights,
        AccessControlType,
        IsInherited,
        InheritanceFlags,
        PropagationFlags |
    Format-Table -AutoSize
```

# Example of Output

| ComputerName | ServiceName | BaseFolder | ExecutableDirectory | CheckedPath | PathType | Owner | InheritanceEnabled | IdentityReference | IdentitySid | FileSystemRights | AccessControlType | IsInherited | InheritanceFlags | PropagationFlags |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Host-01 | battlenet_helpersvc | C:\ProgramData | C:\ProgramData\Battle.net_components\battlenet_helpersvc | C:\ProgramData | BaseFolder | NT AUTHORITY\SYSTEM | FALSE | BUILTIN\Administrators | S-1-5-32-544 | FullControl | Allow | FALSE | ContainerInherit, ObjectInherit | None |
| Host-01 | battlenet_helpersvc | C:\ProgramData | C:\ProgramData\Battle.net_components\battlenet_helpersvc | C:\ProgramData | BaseFolder | NT AUTHORITY\SYSTEM | FALSE | BUILTIN\Users | S-1-5-32-545 | ReadAndExecute, Synchronize | Allow | FALSE | ContainerInherit, ObjectInherit | None |
| Host-01 | battlenet_helpersvc | C:\ProgramData | C:\ProgramData\Battle.net_components\battlenet_helpersvc | C:\ProgramData | BaseFolder | NT AUTHORITY\SYSTEM | FALSE | BUILTIN\Users | S-1-5-32-545 | Write | Allow | FALSE | ContainerInherit | None |
| Host-01 | battlenet_helpersvc | C:\ProgramData | C:\ProgramData\Battle.net_components\battlenet_helpersvc | C:\ProgramData | BaseFolder | NT AUTHORITY\SYSTEM | FALSE | CREATOR OWNER | S-1-3-0 | 268435456 | Allow | FALSE | ContainerInherit, ObjectInherit | InheritOnly |
| Host-01 | battlenet_helpersvc | C:\ProgramData | C:\ProgramData\Battle.net_components\battlenet_helpersvc | C:\ProgramData | BaseFolder | NT AUTHORITY\SYSTEM | FALSE | NT AUTHORITY\SYSTEM | S-1-5-18 | FullControl | Allow | FALSE | ContainerInherit, ObjectInherit | None |
| Host-01 | battlenet_helpersvc | C:\ProgramData | C:\ProgramData\Battle.net_components\battlenet_helpersvc | C:\ProgramData\Battle.net_components\battlenet_helpersvc | ExecutableDirectory | BUILTIN\Administrators | TRUE | BUILTIN\Administrators | S-1-5-32-544 | FullControl | Allow | TRUE | ContainerInherit, ObjectInherit | None |
| Host-01 | battlenet_helpersvc | C:\ProgramData | C:\ProgramData\Battle.net_components\battlenet_helpersvc | C:\ProgramData\Battle.net_components\battlenet_helpersvc | ExecutableDirectory | BUILTIN\Administrators | TRUE | BUILTIN\Users | S-1-5-32-545 | ReadAndExecute, Synchronize | Allow | TRUE | ContainerInherit, ObjectInherit | None |
| Host-01 | battlenet_helpersvc | C:\ProgramData | C:\ProgramData\Battle.net_components\battlenet_helpersvc | C:\ProgramData\Battle.net_components\battlenet_helpersvc | ExecutableDirectory | BUILTIN\Administrators | TRUE | NT AUTHORITY\INTERACTIVE | S-1-5-4 | ReadAndExecute, Synchronize | Allow | TRUE | ContainerInherit, ObjectInherit | None |
| Host-01 | TempTestService | C:\Temp | C:\Temp | C:\Temp | BaseFolder | BUILTIN\Administrators | TRUE | BUILTIN\Administrators | S-1-5-32-544 | FullControl | Allow | TRUE | ContainerInherit, ObjectInherit | None |
| Host-01 | TempTestService | C:\Temp | C:\Temp | C:\Temp | BaseFolder | BUILTIN\Administrators | TRUE | BUILTIN\Users | S-1-5-32-545 | ReadAndExecute, Synchronize | Allow | TRUE | ContainerInherit, ObjectInherit | None |
| Host-01 | TempTestService | C:\Temp | C:\Temp | C:\Temp | BaseFolder | BUILTIN\Administrators | TRUE | NT AUTHORITY\Authenticated Users | S-1-5-11 | -536805376 | Allow | TRUE | ContainerInherit, ObjectInherit | InheritOnly |
| Host-01 | TempTestService | C:\Temp | C:\Temp | C:\Temp | BaseFolder | BUILTIN\Administrators | TRUE | NT AUTHORITY\Authenticated Users | S-1-5-11 | Modify, Synchronize | Allow | TRUE | None | None |
| Host-01 | TempTestService | C:\Temp | C:\Temp | C:\Temp | BaseFolder | BUILTIN\Administrators | TRUE | NT AUTHORITY\SYSTEM | S-1-5-18 | FullControl | Allow | TRUE | ContainerInherit, ObjectInherit | None |
| Host-01 | TempTestService | C:\Temp | C:\Temp | C:\Temp | ExecutableDirectory | BUILTIN\Administrators | TRUE | BUILTIN\Administrators | S-1-5-32-544 | FullControl | Allow | TRUE | ContainerInherit, ObjectInherit | None |
| Host-01 | TempTestService | C:\Temp | C:\Temp | C:\Temp | ExecutableDirectory | BUILTIN\Administrators | TRUE | BUILTIN\Users | S-1-5-32-545 | ReadAndExecute, Synchronize | Allow | TRUE | ContainerInherit, ObjectInherit | None |
| Host-01 | TempTestService | C:\Temp | C:\Temp | C:\Temp | ExecutableDirectory | BUILTIN\Administrators | TRUE | NT AUTHORITY\Authenticated Users | S-1-5-11 | -536805376 | Allow | TRUE | ContainerInherit, ObjectInherit | InheritOnly |
| Host-01 | TempTestService | C:\Temp | C:\Temp | C:\Temp | ExecutableDirectory | BUILTIN\Administrators | TRUE | NT AUTHORITY\Authenticated Users | S-1-5-11 | Modify, Synchronize | Allow | TRUE | None | None |
| Host-01 | TempTestService | C:\Temp | C:\Temp | C:\Temp | ExecutableDirectory | BUILTIN\Administrators | TRUE | NT AUTHORITY\SYSTEM | S-1-5-18 | FullControl | Allow | TRUE | ContainerInherit, ObjectInherit | None |
| Host-01 | WinDefend | C:\ProgramData | C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26030.3011-0 | C:\ProgramData | BaseFolder | NT AUTHORITY\SYSTEM | FALSE | BUILTIN\Administrators | S-1-5-32-544 | FullControl | Allow | FALSE | ContainerInherit, ObjectInherit | None |
| Host-01 | WinDefend | C:\ProgramData | C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26030.3011-0 | C:\ProgramData | BaseFolder | NT AUTHORITY\SYSTEM | FALSE | BUILTIN\Users | S-1-5-32-545 | Write | Allow | FALSE | ContainerInherit | None |

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

are generally less concerning. Still use your best judgement and take into context the product we are reviewing, is it least priveledge? If not, can we change it? Or can we accept the risk. Also take into account that 

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

This allows:

- dashboards
- trending
- potential alerting
- Centralized information for decission making

# Important nuance

Do not blindly remediate this recommendation. Just because this recommendation is there, doesn't mean it can be exploited or that it's bad, but it deserves review!

Some environments intentionally run services from:

- build agents
- deployment frameworks
- middleware stacks
- legacy applications (Which can be an accepted risk)
- vendor software

The important thing is not only the folder path itself.

The real issue is usually:

> Can broad principals modify the folder contents?

A custom folder with only:

- SYSTEM
- Administrators

may be acceptable.

A writable service folder is the actual concern. And this needs to be checked and verified that its least priveledge.

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

1. Find the exposed service path with KQL.
2. Extract the data.
3. Validate the ACLs locally or centrally.
4. Determine whether broad principals are adhered to least priveledge.
5. Then decide whether remediation is needed.
