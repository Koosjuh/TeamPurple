---
title: "Preparing for Microsoft Entra Token Protection Enforcement with Sentinel"
date: 2026-05-08
hero: "/images/posts/entraid/token-protection-readiness.webp"
description: "How to assess Microsoft Entra Token Protection readiness using Microsoft Sentinel and Conditional Access telemetry."
summary: "A practical guide for engineers and security consultants on how to assess Token Protection readiness, identify unsupported sign-in flows, and prepare organizations for future enforcement."
categories:
  - "Entra ID"
  - "Security"
tags:
  - "Conditional Access"
  - "Microsoft Sentinel"
  - "Token Protection"
draft: true
toc: true
menu:
  sidebar:
    name: "Token Protection Readiness"
    identifier: "token-protection-readiness"
    parent: "entraid"
    weight: 10
---

# Preparing for Microsoft Entra Token Protection Enforcement with Sentinel

## Making Token Replay Risk Visible

---

One of the more interesting developments in Microsoft Entra ID over the last period is Token Protection. Most organizations already focus heavily on MFA, compliant devices and Conditional Access, but token replay remains one of those areas that is often not operationalized or even measured properly.

That creates a visibility gap.

A user can successfully complete MFA, use a compliant device and still have a token replayed under certain circumstances. This is exactly where Token Protection comes in. Microsoft Entra attempts to cryptographically bind sign-in session tokens to a device so stolen tokens cannot simply be replayed elsewhere.

The important part here is not just enforcement. The real challenge is understanding whether your environment is even ready for it.

This is where Sentinel and sign-in telemetry become extremely valuable.

Microsoft already exposes Token Protection telemetry in `SigninLogs`, which means organizations can start assessing readiness long before they enforce anything through Conditional Access.

Microsoft documentation:
https://learn.microsoft.com/en-us/entra/identity/devices/protecting-tokens-microsoft-entra-id

## Why This Matters

A lot of organizations assume:

- MFA solves token theft
- compliant devices solve replay attacks
- Conditional Access is enough

That is not entirely true.

If an attacker steals a valid session token, especially from unmanaged or compromised systems, they may be able to replay that token from another location or system without needing the original MFA challenge again.

Token Protection attempts to reduce this risk by binding the sign-in session to the original device state.

The important nuance is that not every authentication flow currently supports this.

This means organizations need to understand:

- Which sign-ins are already token-bound
- Which sign-ins are unbound
- Which applications or authentication paths do not support Token Protection
- Whether Conditional Access policies are already evaluating Token Protection controls
- Whether enforcement would break parts of the environment

That last point is critical.

## Important Requirements and Limitations

One of the biggest mistakes I see is assuming Token Protection can simply be globally enabled.

That is not how Microsoft positions it either.

At the time of writing, there are several important requirements and limitations:

### Supported Platforms

Currently supported or partially supported:

- Windows 10 and newer
- Windows Server 2019+
- macOS (Preview)
- iOS/iPadOS (Preview)

### Supported Device States

Windows devices generally need to be:

- Microsoft Entra Joined
- Hybrid Microsoft Entra Joined
- Microsoft Entra Registered

Apple devices additionally require:

- MDM management
- Microsoft Enterprise SSO plug-in or Platform SSO

### Supported Resources

Currently focused on workloads like:

- Exchange Online
- SharePoint Online
- Teams

### Important Limitation: Browser-Based Applications

This is the part many engineers miss.

Microsoft explicitly states that browser-based applications are currently not supported for Token Protection enforcement.

That means environments with large browser-heavy workflows may see a large amount of unbound sessions. This does not automatically mean something is insecure. It often simply means the authentication flow does not currently support token binding.

This is exactly why readiness assessment matters before enforcement.

## Making Token Protection Visible

The first thing I usually want to know is very simple:

> Are sign-ins already token-bound in this environment?

This KQL query provides a very strong high-level overview:

```kusto
let lookback = 30d;
SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType == 0
| extend tp = todynamic(TokenProtectionStatusDetails)
| extend code = tostring(tp.signInSessionStatusCode)
| extend status = tostring(tp.signInSessionStatus)
| extend Category = case(
    status =~ "bound", "Token binding: Bound",
    code == "1002", "Token binding: Unbound (1002 - no Entra device state)",
    isempty(status) and isempty(code), "Token binding: Not present",
    "Token binding: Unbound/Other"
)
| summarize SignIns=count() by Category
| render piechart with (title="Token Protection binding state (last 30 days)")
```

This query gives immediate operational visibility into:

- Bound sign-ins
- Unbound sign-ins
- Missing Token Protection telemetry
- Sign-ins without valid Entra device state

This becomes extremely useful during customer assessments or security posture reviews.

A healthy environment will usually show a large percentage of bound sessions, especially in modern managed Windows environments using native Microsoft clients.

Large amounts of `1002` typically indicate:

- Browser-based authentication
- Missing Entra device state
- Unmanaged devices
- Unsupported clients
- Missing PRT/device claims

Again, this does not automatically mean malicious activity. It usually means compatibility or unsupported authentication paths.

## Checking Whether Token Protection Is Already Evaluated

The next step is checking whether Token Protection is already present inside Conditional Access policies.

Many organizations assume they are using it because they see telemetry in the logs. Those are two different things.

This query checks whether Token Protection session controls appear in Conditional Access evaluation results:

```kusto
let lookback = 30d;
SigninLogs
| where TimeGenerated > ago(lookback)
| extend CAPolicies = todynamic(ConditionalAccessPolicies)
| mv-expand CAPolicies
| extend
    PolicyName = tostring(CAPolicies.displayName),
    PolicyResult = tostring(CAPolicies.result),
    EnforcedControls = tostring(CAPolicies.enforcedGrantControls),
    EnforcedSessionControls = tostring(CAPolicies.enforcedSessionControls),
    SessionControlsNotSatisfied = tostring(CAPolicies.sessionControlsNotSatisfied)
| where EnforcedSessionControls has_any ("SignInTokenProtection", "Binding", "tokenProtection")
   or SessionControlsNotSatisfied has_any ("SignInTokenProtection", "Binding", "tokenProtection")
   or PolicyName has_any ("token protection", "token", "binding")
| summarize
    SignIns=count(),
    Results=make_set(PolicyResult, 10),
    EnforcedSessionControls=make_set(EnforcedSessionControls, 10),
    SessionControlsNotSatisfied=make_set(SessionControlsNotSatisfied, 10)
by PolicyName
| order by SignIns desc
```

This is important because it tells you whether:

- Token Protection policies already exist
- Policies are in report-only mode
- Session controls are being evaluated
- Users are failing Token Protection requirements

In many environments, this query returns no results at all. That usually means Token Protection telemetry exists, but enforcement has not yet been configured.

## Combining Both Perspectives

The strongest readiness assessment comes from combining both perspectives:

- Are sessions already token-bound?
- Is Conditional Access already evaluating Token Protection?

This gives you a much more realistic picture of whether the organization is technically mature enough to start piloting enforcement.

The most important thing here is avoiding a binary mindset.

This is not:

> “Enable Token Protection everywhere immediately.”

This is:

> “Understand authentication flows first, measure compatibility, then gradually move toward enforcement.”

## Recommended Approach

Microsoft’s own guidance aligns quite well with what I would operationally recommend:

1. Start with telemetry and visibility
2. Measure bound versus unbound sign-ins
3. Identify unsupported applications and browser-heavy flows
4. Review unmanaged or unregistered device populations
5. Create a Conditional Access policy in report-only mode
6. Pilot with a small controlled user group
7. Expand gradually

The biggest value is not only security improvement. It is reducing uncertainty before enforcement.

A lot of Conditional Access problems happen because organizations skip the visibility phase entirely.

Token Protection should absolutely be viewed as another layer in a broader defense-in-depth strategy against token theft and replay attacks, especially as attackers continue shifting toward session abuse instead of traditional password attacks.

For organizations already heavily invested in:

- modern authentication
- compliant devices
- Entra Join
- Conditional Access
- native Microsoft clients

this is definitely something worth evaluating now rather than later.
