# Entra ID Privileged Role Assignment and PIM Activity Assessment

## Overview

This document contains a collection of KQL queries designed to assess privileged role assignments and Privileged Identity Management (PIM) usage within Microsoft Entra ID.

The queries provide visibility into:

* PIM role activation activity
* Most frequently activated privileged roles
* Global Administrator assignment counts
* Accounts holding multiple privileged roles
* Overall privileged role exposure within the tenant

Together these queries help evaluate privileged access governance, administrative role distribution, and the effectiveness of least privilege principles.

---

# Query 1: PIM Role Activation Distribution

## Description

This query analyzes Microsoft Entra ID PIM activation events over the previous 30 days and visualizes the distribution of activated roles.

The query identifies role activations recorded in AuditLogs and calculates:

* Number of activations per role
* Percentage of all role activations
* Percentage of all audit log activity

The output is displayed as a pie chart.

## Data Sources

* AuditLogs

## Lookback Period

* 30 days

## Included Operations

* Add member to role completed
* Add eligible member to role
* Add member to role requested
* Activate eligible assignment

## Output

| Column                      | Description                         |
| --------------------------- | ----------------------------------- |
| RoleName                    | Activated role                      |
| Activations                 | Number of activations               |
| PercentageOfRoleActivations | Percentage of total activations     |
| PercentageOfAllAuditLogs    | Percentage of all audit log entries |

## Use Cases

* Identify most commonly activated administrative roles.
* Measure administrative activity concentration.
* Detect unusually frequent role activations.
* Support privileged access governance reviews.

## KQL 

```kql
let lookback = 30d;
let PIMEvents =
    AuditLogs
    | where TimeGenerated >= ago(lookback)
    | where OperationName contains "PIM activation"
    | where Result =~ "success"
    | extend EventId = tostring(Id);
let Targets =
    PIMEvents
    | mv-expand Target = TargetResources
    | extend
        TargetType = tostring(Target.type),
        TargetName = tostring(Target.displayName);
let DirectRoles =
    Targets
    | where TargetType =~ "Role"
    | where TargetName !in~ ("Member", "Owner")
    | summarize
        TimeGenerated = max(TimeGenerated),
        ActivatedRole = any(TargetName)
        by EventId;
let GroupResourceRoles =
    Targets
    | where TargetType =~ "Other"
    | where TargetName contains "-Resource-"
    | summarize
        TimeGenerated = max(TimeGenerated),
        ActivatedRole = any(TargetName)
        by EventId;
union DirectRoles, GroupResourceRoles
| summarize arg_max(TimeGenerated, *) by EventId
| summarize Activations = count() by ActivatedRole
| order by Activations desc
| render piechart with (
    title = "PIM role and resource activations during the past 30 days"
)
```

For only direct members aand standard roles

```kql
let lookback = 30d;
let AuditBase =
    AuditLogs
    | where TimeGenerated >= ago(lookback);
let RoleActivations =
    AuditBase
    | where Category =~ "RoleManagement"
    | where LoggedByService has_any ("PIM", "Privileged Identity Management")
        or OperationName has_any ("Activate", "activated", "PIM")
    | where OperationName has_any (
        "Add member to role completed",
        "Add eligible member to role",
        "Add member to role requested",
        "Activate eligible assignment"
    )
    | extend InitiatedByUser =
        tostring(InitiatedBy.user.userPrincipalName)
    | mv-expand TargetResources
    | extend TargetType = tostring(TargetResources.type)
    | extend RoleName = tostring(TargetResources.displayName)
    | mv-expand ModifiedProperties = TargetResources.modifiedProperties
    | extend PropName = tostring(ModifiedProperties.displayName)
    | extend NewValue = trim(@'"', tostring(ModifiedProperties.newValue))
    | extend RoleName = iff(
        PropName has_any ("Role.DisplayName", "RoleName", "Role"),
        NewValue,
        RoleName
    )
    | where isnotempty(RoleName)
    | summarize arg_max(TimeGenerated, *) by Id, RoleName;
let TotalAuditLogs =
    toscalar(AuditBase | count);
let TotalRoleActivations =
    toscalar(RoleActivations | count);
RoleActivations
| summarize Activations = count() by RoleName
| extend
    PercentageOfRoleActivations = round(100.0 * Activations / TotalRoleActivations, 2),
    PercentageOfAllAuditLogs = round(100.0 * Activations / TotalAuditLogs, 4)
| order by Activations desc
| render piechart
```

---

# Query 2: Global Administrator Assignment Count

## Description

This query identifies all accounts assigned the Global Administrator role and returns both the number of assigned users and the associated account list.

## Data Sources

* IdentityInfo

## Output

| Column   | Description                           |
| -------- | ------------------------------------- |
| Users    | Total number of Global Administrators |
| Accounts | List of assigned accounts             |

## Use Cases

* Verify adherence to least privilege.
* Identify excessive Global Administrator assignments.
* Support administrative access reviews.
* Measure alignment with Microsoft security recommendations.

## KQL

```kql
IdentityInfo
| mv-expand AssignedRoles
| extend Role = tostring(AssignedRoles)
| where Role =~ "Global Administrator"
| summarize Users=count(), Accounts=make_set(AccountUPN)
```

---

# Query 3: Accounts Assigned Multiple Administrative Roles

## Description

This query identifies accounts assigned three or more Entra ID roles.

The query expands role assignments and calculates the total number of unique assigned roles per account.

## Data Sources

* IdentityInfo

## Output

| Column     | Description              |
| ---------- | ------------------------ |
| AccountUPN | User account             |
| Roles      | Assigned role list       |
| RoleCount  | Number of assigned roles |

## Use Cases

* Identify role accumulation.
* Detect separation-of-duties concerns.
* Review highly privileged accounts.
* Assess privilege concentration within the tenant.


## KQL

```kql
IdentityInfo
| mv-expand AssignedRoles
| summarize Roles=make_set(tostring(AssignedRoles)), RoleCount=dcount(tostring(AssignedRoles)) by AccountUPN
| where RoleCount >= 3
| order by RoleCount desc
```

---

# Query 4: High-Privilege Role Exposure Assessment

## Description

This query measures the overall exposure of high-privilege Entra ID roles within the tenant.

The following roles are evaluated:

* Global Administrator
* Privileged Role Administrator
* Security Administrator
* Exchange Administrator
* SharePoint Administrator
* Conditional Access Administrator
* Authentication Administrator
* User Administrator

The query calculates:

* Total accounts present in IdentityInfo
* Accounts holding at least one high-privilege role
* Percentage of the tenant population with elevated privileges

## Data Sources

* IdentityInfo

## Output

| Column                                               | Description                   |
| ---------------------------------------------------- | ----------------------------- |
| Total accounts in IdentityInfo                       | Total discovered accounts     |
| Accounts with one or more high-privilege Entra roles | Privileged accounts           |
| Percentage of accounts with high-privilege roles     | Privileged account percentage |

## Use Cases

* Measure privileged access exposure.
* Benchmark administrative footprint.
* Support identity governance assessments.
* Identify opportunities to reduce administrative privileges.

## KQL

```kql
let PrivRoles = dynamic([
    "Global Administrator",
    "Privileged Role Administrator",
    "Security Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "Conditional Access Administrator",
    "Authentication Administrator",
    "User Administrator"
]);
let TotalIdentityAccounts =
    toscalar(
        IdentityInfo
        | summarize dcount(AccountUPN)
    );
let UsersWithHighPrivilegeRoles =
    toscalar(
        IdentityInfo
        | mv-expand AssignedRoles
        | extend Role = tostring(AssignedRoles)
        | where Role in (PrivRoles)
        | summarize dcount(AccountUPN)
    );
print
    ["Total accounts in IdentityInfo"] = TotalIdentityAccounts,
    ["Accounts with one or more high-privilege Entra roles"] = UsersWithHighPrivilegeRoles,
    ["Percentage of accounts with high-privilege roles"] =
        round((todouble(UsersWithHighPrivilegeRoles) / todouble(TotalIdentityAccounts)) * 100, 2)****
```

---

# Assessment Goals

These queries collectively help answer the following governance questions:

* How many privileged accounts exist?
* Which users hold the most administrative access?
* How many Global Administrators are assigned?
* Which privileged roles are actively used?
* Are privileged roles distributed according to least privilege principles?
* Is privileged access concentrated among a small number of accounts?
* What percentage of the tenant population holds elevated permissions?

## Recommended Review Frequency

* Monthly for operational governance reviews.
* Quarterly for formal access reviews.
* Before security audits or compliance assessments.
* Following major administrative or organizational changes.
