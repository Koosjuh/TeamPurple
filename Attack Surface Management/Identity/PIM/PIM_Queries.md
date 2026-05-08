
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

```kql
IdentityInfo
| mv-expand AssignedRoles
| extend Role = tostring(AssignedRoles)
| where Role =~ "Global Administrator"
| summarize Users=count(), Accounts=make_set(AccountUPN)
```

```kql
IdentityInfo
| mv-expand AssignedRoles
| summarize Roles=make_set(tostring(AssignedRoles)), RoleCount=dcount(tostring(AssignedRoles)) by AccountUPN
| where RoleCount >= 3
| order by RoleCount desc

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
