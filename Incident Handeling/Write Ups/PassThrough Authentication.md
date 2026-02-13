# Verifying Pass-through Authentication (PTA) Sign-ins in Entra ID

This note shows how to verify **PTA sign-ins** in `SigninLogs` by inspecting the `AuthenticationDetails` array.

**Goal:**

1. Find sign-ins where **any authentication step** is marked as `Pass-through Authentication`.
2. For a specific sign-in, inspect **all steps** (password + MFA) using its `CorrelationId`.

---

## 1. Find candidate PTA sign-ins

Use this query to list sign-ins that contain a PTA step.  
This expands `AuthenticationDetails` and filters on `"Pass-through Authentication"`.

```KQL
SigninLogs
| where TimeGenerated >= ago(120d)
| where isnotempty(AuthenticationDetails)
| extend authDetails = todynamic(AuthenticationDetails)
| mv-expand auth = authDetails
| extend
    authMethod        = tostring(auth.authenticationMethod),
    authMethodDetail  = tostring(auth.authenticationMethodDetail),
    authSucceeded     = tostring(auth.succeeded),
    authRequirement   = tostring(auth.authenticationStepRequirement),
    authResultDetail  = tostring(auth.authenticationStepResultDetail),
    authDateTime      = todatetime(auth.authenticationStepDateTime)
| where authMethodDetail has "Pass-through Authentication"
       or authResultDetail has "Pass-through Authentication"
| project
    TimeGenerated,
    UserPrincipalName,
    CorrelationId,
    AppDisplayName,
    IPAddress,
    ResultType,
    ResultDescription,
    authMethod,
    authMethodDetail,
    authRequirement,
    authResultDetail,
    authSucceeded,
    authDateTime
| order by TimeGenerated desc
```

From this output, pick a single CorrelationId you want to inspect further.

## 2. Inspect the full authentication flow for a single sign-in

Use the selected CorrelationId to see all authentication steps (password + MFA) in order.

```KQL
SigninLogs
| where CorrelationId == "<PASTE_CORRELATION_ID_HERE>"
| extend authDetails = todynamic(AuthenticationDetails)
| mv-expand auth = authDetails
| extend
    authMethod        = tostring(auth.authenticationMethod),
    authMethodDetail  = tostring(auth.authenticationMethodDetail),
    authSucceeded     = tostring(auth.succeeded),
    authRequirement   = tostring(auth.authenticationStepRequirement),
    authResultDetail  = tostring(auth.authenticationStepResultDetail),
    authDateTime      = todatetime(auth.authenticationStepDateTime)
| project
    TimeGenerated,
    CorrelationId,
    UserPrincipalName,
    AppDisplayName,
    IPAddress,
    authMethod,
    authMethodDetail,
    authRequirement,
    authResultDetail,
    authSucceeded,
    authDateTime
| order by authDateTime asc
```

## 3. How to interpret the results

In the AuthenticationDetails output, look for:
PTA (primary password step)

A PTA step typically looks like:

    authMethod = "Password"

    authMethodDetail = "Pass-through Authentication" or "Pass-through Authentication; PTA AgentId: <GUID>"

    authRequirement = "Primary authentication"

    authSucceeded = "true"

This confirms that the password was validated on-prem via a PTA agent.
MFA (cloud second factor)

### Subsequent steps usually show Azure AD MFA:

    authMethod = "Mobile app notification" (or similar)

    authResultDetail examples:

        "Authentication in progress"

        "MFA denied; user declined the authentication"

        "MFA successfully completed"

These steps confirm that MFA is handled in Azure AD, after the PTA password validation.

### Conclusion

If you see:

    At least one step with authMethodDetail containing "Pass-through Authentication", and

    MFA steps afterwards,

then the sign-in is a genuine Pass-through Authentication sign-in, followed by Azure AD MFA.
