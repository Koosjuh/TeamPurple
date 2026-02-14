# ASR Validation via Advanced Hunting (TVM) and Registry Policy Evidence

This document describes two KQL queries that help validate Attack Surface Reduction (ASR) rule posture on endpoints, and explains why results can differ from what you see in the Microsoft Defender portal ASR configuration UI.

## Overview

There are two different questions you may want to answer:

1. What is the effective ASR security state on the device (what is actually enforced)?
2. What ASR settings were deployed via policy (what was written/configured on the device)?

These are related, but not always represented consistently in the GUI.

This repo contains two queries:
- Query 1: TVM-based ASR posture (effective security state)
- Query 2: Registry-based ASR policy evidence (policy writes to device)

---

## Query 1: TVM ASR Posture (Effective Device Security State)

### Purpose
This query uses `DeviceTvmSecureConfigurationAssessment` to report ASR-related security control status per device. It maps `ConfigurationId` values (SCIDs) to readable rule names and returns a per-device view of results.

### What it answers
- Is the rule applicable on this device?
- Is the device compliant?
- What context is reported (Block, Audit, Off, etc.)?

### Why this matters
`DeviceTvmSecureConfigurationAssessment` represents Defender’s assessment of the device security configuration. It is a strong indicator of effective posture, especially when you see:
- `IsApplicable = 1`
- `IsCompliant = 1`
- `Context = ["Block"]` (or equivalent)

### Notes
- This is a “security posture” view, not a “policy object” view.
- It helps answer what is effectively enforced, regardless of how it was deployed.

---

## Query 2: Registry ASR Policy Evidence (Policy Manager ASRRules)

### Purpose
This query parses registry writes to:

`HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager`

Value name:
`ASRRules`

This value contains a pipe-separated string with ASR GUIDs and states, for example:

`<GUID>=1|<GUID>=2|<GUID>=0`

### What it answers
- Did a policy write ASR rules to the device via Policy Manager?
- Which ASR rule GUIDs are present?
- What state is each rule configured to (Block, Audit, Disabled, Warn)?
- Which process performed the write (for example `omadmclient.exe` typically indicates MDM/Intune/OMA-DM)?

### State mapping used
- `0` = Disabled  
- `1` = Block  
- `2` = Audit  
- `6` = Warn (supported on some rules/platforms)

### Why this matters
Registry evidence is strong proof of configuration deployment on the endpoint. If the GUID exists in `ASRRules`, it was explicitly written as policy state.

This is particularly useful when portal views appear inconsistent.

---

## Why the GUI Can Differ (security.microsoft.com/asr → Configuration)

The ASR Configuration view in the portal is not always a reliable reflection of effective device enforcement state. In practice, it often behaves more like a management-plane and policy-scope view.

Common reasons for differences:
- The GUI may show policy visibility within a specific configuration context, rather than runtime state.
- Policy can be applied via different channels (MDM/Intune, Security Baselines, GPO, CSP, legacy profiles), and the GUI may not surface all sources consistently.
- TVM and registry evidence can show a rule as active/enforced even when the GUI says “Not applicable”.

Recommended interpretation:
- Use TVM + registry to establish effective state and deployment evidence.
- Treat GUI “Not applicable” as “not visible/managed in this specific policy view”, not as “not enforced on device”.

---

## How to Keep These Queries Updated

ASR evolves over time (new SCIDs, new rules). To update the TVM query list of SCIDs, run:

```kql
DeviceTvmSecureConfigurationAssessmentKB
| where ConfigurationDescription contains "ASR"
| distinct ConfigurationId
```

And for the GUID's please see: https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference#asr-rule-to-guid-matrix
