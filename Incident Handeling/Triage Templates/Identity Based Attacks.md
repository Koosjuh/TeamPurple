## Session Validation

### Entra ID
```text
**User**
#####
UPN:
- [AuditLogs] 
- [InteractiveLogs]
- [Non interactive Logs]
- [Valid MFA]
- [Identity Info]
- [Office Activity]
```

- Assumes use of IP validation tool for other context

```text
- [IP interactive]
- [IP MFA]
- [IP Non interactive]
```

### On-Premis

```text
**User**
#####
User:
- [IdentityInfo]
- [On Premis Account Changes]
- [OnPremis Logon]
- [IdentityLogonEvents]
- [DeviceLogonEvents]
```

#### Session Check
```kql
// ws-vit-c-aad-user-audit-log.kql
// This KQL query is used to determine the Azure Active Directory audit history of a specific user or application
// SET PARAMETERS
let comb_entity = "COMB_ENTITY"; // Set the User Principal Name, UserId, AppId or App Display Name. Example: hello@wortell.nl, 123456789-abcd-1234-efgh-123456789012, Azure AD SSO
let days_ago = ago(14d); // Set the time. Example: 8h, 7d
// DO NOT EDIT BELOW THIS LINE
let UserEmailToId_ = (
IdentityInfo
| where TimeGenerated > ago(14d)
| where AccountUPN =~ comb_entity and AccountObjectId != ''
| distinct AccountObjectId
);
let UserIdToEmail_ = (
IdentityInfo
| where TimeGenerated > ago(14d)
| where AccountObjectId =~ comb_entity
| distinct AccountUPN
);
AuditLogs
| where TimeGenerated > days_ago
| extend ParsedTargetResources_ = parse_json(TargetResources)
| mv-expand todynamic(ParsedTargetResources_)
| extend UserPrincipalName_ = iff(isempty(tostring(ParsedTargetResources_.userPrincipalName)) == true, tostring(ParsedTargetResources_.displayName), tostring(ParsedTargetResources_.userPrincipalName))
| extend DisplayName_ = tostring(ParsedTargetResources_.displayName)
| extend id_ = tostring(ParsedTargetResources_.id)
| where UserPrincipalName_ contains comb_entity or DisplayName_ contains comb_entity or id_ contains comb_entity or UserPrincipalName_ in~(UserIdToEmail_) or id_ in~(UserEmailToId_)
| extend ParsedInitiatedBy_ = parse_json(InitiatedBy)
| mv-expand todynamic(ParsedInitiatedBy_)
| extend InitiatedBy_ = iff(isempty(tostring(ParsedInitiatedBy_.app.displayName)) == true, tostring(ParsedInitiatedBy_.user.userPrincipalName), tostring(ParsedInitiatedBy_.app.displayName))
| extend InitiatedByIp_ = iff(isempty(tostring(ParsedInitiatedBy_.app.Dummy)) == true, tostring(ParsedInitiatedBy_.user.ipAddress), tostring(ParsedInitiatedBy_.app.Dummy))
| project TimeGenerated, UserPrincipalName_, id_, InitiatedBy_, InitiatedByIp_, OperationName, Result, ResultDescription
| sort by TimeGenerated desc

// ws-vit-c-aad-user-interactive.kql
// This KQL query is used to determine interactive sign-in history for a specific user
// SET PARAMETERS
let comb_entity = "COMB_ENTITY"; // Set the User Principal Name or UserId. Example: hello@wortell.nl, 123456789-abcd-1234-efgh-123456789012
let days_ago = ago(30d); // Set the time. Example: 8h, 7d
// DO NOT EDIT BELOW THIS LINE
SigninLogs
| lookup _GetWatchlist('WS-Azure-AD-Error-Codes') on $left.ResultType == $right.SearchKey
| where TimeGenerated > days_ago
| where UserPrincipalName =~ comb_entity or UserId =~ comb_entity
// Handle results in "AuthenticationDetails" column that equal "[]" before using mv-expand as mv-expand does not parse them otherwise
| extend AuthenticationDetails = replace_string((AuthenticationDetails), '[]', '[{"authenticationMethod": "Auth method unknown","succeeded": "Auth status unknown"}]')
| mv-expand todynamic(AuthenticationDetails)
| extend AuthenticationMethod_ = tostring(AuthenticationDetails.authenticationMethod)
| extend authenticationStepResultDetail_ = tostring(AuthenticationDetails.authenticationStepResultDetail)
| extend AdditionalDetails_ = tostring(Status.additionalDetails)
| extend AuthStatusSuccess_ = tostring(AuthenticationDetails.succeeded)
| extend DeviceId_ = tostring(DeviceDetail.deviceId)
| extend DeviceTrustType_ = tostring(DeviceDetail.trustType)
| extend OperatingSystem_ = tostring(DeviceDetail.operatingSystem)
| extend Browser_ = tostring(DeviceDetail.browser)
| extend ResultDescription = iff(ResultDescription =~ "Other", iff(isempty(Code), "Other", Message), ResultDescription)
| extend OrigSignInTime_ = CreatedDateTime
| project TimeGenerated, OrigSignInTime_, UserPrincipalName, AuthenticationRequirement, ResultType, ResultDescription, IPAddress, Location, AuthenticationMethod_, AuthStatusSuccess_, authenticationStepResultDetail_, AdditionalDetails_, SessionId, UniqueTokenIdentifier, RiskState, RiskDetail, DeviceId_, DeviceTrustType_, UserAgent, OperatingSystem_, Browser_, ClientAppUsed, AppDisplayName
| sort by TimeGenerated desc

// ws-vit-c-aad-user-noninteractive.kql
// This KQL query is used to determine non-interactive sign-in history for a specific user
// SET PARAMETERS
let comb_entity = "COMB_ENTITY"; // Set the User Principal Name or UserId. Example: hello@wortell.nl, 123456789-abcd-1234-efgh-123456789012
let days_ago = ago(30d); // Set the time. Example: 8h, 7d
// DO NOT EDIT BELOW THIS LINE
AADNonInteractiveUserSignInLogs
| lookup _GetWatchlist('WS-Azure-AD-Error-Codes') on $left.ResultType == $right.SearchKey
| where TimeGenerated > days_ago
| where UserPrincipalName =~ comb_entity or UserId =~ comb_entity
| extend AdditionalDetails_ = tostring(parse_json(Status).additionalDetails)
| extend DeviceId_ = tostring(parse_json(DeviceDetail).deviceId)
| extend DeviceTrustType_ = tostring(parse_json(DeviceDetail).trustType)
| extend OperatingSystem_ = tostring(parse_json(DeviceDetail).operatingSystem)
| extend Browser_ = tostring(parse_json(DeviceDetail).browser)
| extend ResultDescription = iff(ResultDescription =~ "Other", iff(isempty(Code), "Other", Message), ResultDescription)
| extend OrigSignInTime_ = CreatedDateTime
| project TimeGenerated, OrigSignInTime_, UserPrincipalName, AuthenticationRequirement, ResultType, ResultDescription, IPAddress, Location, AdditionalDetails_, SessionId, UniqueTokenIdentifier, RiskState, RiskDetail, DeviceId_, DeviceTrustType_, UserAgent, OperatingSystem_, Browser_, ClientAppUsed, AppDisplayName
| sort by TimeGenerated desc

// ws-vit-c-aad-user-mfa.kql
// This KQL query is used to determine valid interactive MFA sign-in history for a specific user
// SET PARAMETERS
let comb_entity = "COMB_ENTITY"; // Set the User Principal Name or UserId. Example: hello@wortell.nl, 123456789-abcd-1234-efgh-123456789012
let days_ago = ago(30d); // Set the time. Example: 8h, 7d
let trustedMFAType = _GetWatchlist("WS-Trusted-MFA-types") | project trustedMFAType;
// DO NOT EDIT BELOW THIS LINE
SigninLogs
| where TimeGenerated > days_ago
| where IncomingTokenType in ('none', 'refreshToken')
| where UserPrincipalName =~ comb_entity or UserId =~ comb_entity
| where AuthenticationRequirement == "multiFactorAuthentication"
// Handle results in "AuthenticationDetails" column that equal "[]" before using mv-expand as mv-expand does not parse them otherwise
| extend AuthenticationDetails = replace_string((AuthenticationDetails), '[]', '[{"authenticationMethod": "Auth method unknown","succeeded": "Auth status unknown"}]')
| mv-expand todynamic(AuthenticationDetails)
| where ResultType in (0, 50140)
| extend AuthenticationMethod_ = tostring(AuthenticationDetails.authenticationMethod)
| where isnotempty(AuthenticationMethod_)
| extend AuthStatusSuccess_ = tostring(AuthenticationDetails.succeeded)
| where isnotempty(AuthStatusSuccess_)
| where AuthenticationMethod_ in~(trustedMFAType) and AuthStatusSuccess_ == "true"
| extend authenticationMethodDetail_ = tostring(AuthenticationDetails.authenticationMethodDetail)
| extend AdditionalDetails_ = tostring(Status.additionalDetails)
| where AdditionalDetails_ <> "MFA requirement satisfied by claim in the token"
| extend DeviceId_ = tostring(DeviceDetail.deviceId)
| extend DeviceTrustType_ = tostring(DeviceDetail.trustType)
| extend OrigSignInTime_ = CreatedDateTime
// Tier 1 project
| project TimeGenerated, OrigSignInTime_, UserPrincipalName, IPAddress, Location, ResultType, AuthenticationMethod_, AuthStatusSuccess_, AdditionalDetails_, SessionId, UniqueTokenIdentifier, DeviceId_, DeviceTrustType_, ClientAppUsed, AppDisplayName, IncomingTokenType
// Tier 2 project - Adds authenticationMethodDetail_ (PhoneNumber)
//| project TimeGenerated, OrigSignInTime_, UserPrincipalName, IPAddress, Location, ResultType, AuthenticationMethod_, AuthStatusSuccess_, authenticationMethodDetail_, AdditionalDetails_, SessionId, UniqueTokenIdentifier, DeviceId_, DeviceTrustType_, ClientAppUsed, AppDisplayName
| sort by TimeGenerated desc

// ws-vit-c-office-user-activity-all.kql
// This KQL query is used to determine all office activity for a specific user
// SET PARAMETERS
let user_entity = "USERPRINCIPALNAME"; // Set the User Principal Name or UserId. Example: hello@wortell.nl, 123456789-abcd-1234-efgh-123456789012
let days_ago = ago(14d); // Set the time. Example: 8h, 7d
// DO NOT EDIT BELOW THIS LINE
OfficeActivity
| where TimeGenerated > days_ago
| where UserId =~ user_entity
| extend ClientIP_ = iff(isempty(ClientIP) == true, Client_IPAddress, ClientIP)
| project TimeGenerated, UserId, SessionId = AppAccessContext.AADSessionId, UniqueTokenIdentifier = AppAccessContext.UniqueTokenId, ClientIP_, OfficeWorkload, Operation, ItemType, SourceFileName, UserAgent, OfficeObjectId
| sort by TimeGenerated desc

// ws-vit-t-identityinfo-user.kql
// This KQL query is used to lookup information of a specific user
// SET PARAMETERS
let comb_entity = "COMB_ENTITY"; // Set the User Principal Name, AccountObjectId or SamAccountName. Example: hello@wortell.nl, 123456789-abcd-1234-efgh-123456789012, John.Doe
let days_ago = ago(14d); // Set the time. Example: 8h, 7d
// DO NOT EDIT BELOW THIS LINE
IdentityInfo
| where TimeGenerated > days_ago
| where AccountUPN =~ comb_entity or AccountObjectId =~ comb_entity or AccountName =~ comb_entity
| summarize arg_max(TimeGenerated, *) by comb_entity
| project TimeGenerated, AccountUPN, AccountObjectId, AccountName, UserType, AccountCreationTime, AccountDisplayName, Department, JobTitle, AssignedRoles, GroupMembership, OnPremisesDistinguishedName
| sort by TimeGenerated desc
```
