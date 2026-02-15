# ASR Validation via Advanced Hunting (TVM), Registry Policy Evidence, and Local Effective State (PowerShell)

This document describes three validation methods for Attack Surface Reduction (ASR) posture on endpoints and explains why results can differ from what you see in the Microsoft Defender portal ASR configuration UI.

# Index

1. [Overview](#overview)  
2. [Query 1: TVM ASR Posture (Secure Configuration Assessment)](#query-1-tvm-asr-posture-secure-configuration-assessment)  
3. [Query 2: Registry ASR Policy Evidence (Policy Manager ASRRules)](#query-2-registry-asr-policy-evidence-policy-manager-asrrules)  
4. [Script 1: PowerShell ASR Effective State (Local Defender Engine)](#script-1-powershell-asr-effective-state-local-defender-engine)  
5. [When to Trust Which Signal (Decision Guide)](#when-to-trust-which-signal-decision-guide)  
6. [References (Microsoft)](#references-microsoft)

---

## Overview

There are three different questions you may want to answer:

1. What is the effective ASR state on the device (what Defender will enforce)?
2. What ASR settings were deployed via policy (what was written/configured on the device)?
3. What does the portal ASR configuration UI show (management-plane / applicability / policy-view)?

These are related, but not always represented consistently in the GUI.

This repo contains:
- Query 1: TVM-based ASR posture (cloud-reported secure configuration assessment)
- Query 2: Registry-based ASR policy evidence (policy writes to device)
- Script 1: PowerShell effective ASR state (local Defender engine resolved configuration)

---

## Query 1: TVM ASR Posture (Secure Configuration Assessment)

### Purpose
Uses `DeviceTvmSecureConfigurationAssessment` (optionally joined with `DeviceTvmSecureConfigurationAssessmentKB`) to report ASR-related secure configuration posture per device.

### What it answers
- Is the control applicable on this device?
- Is the device compliant?
- What assessment context is reported (Block, Audit, Off, etc.)?

### Why this matters
This represents Defender Vulnerability Management (TVM) secure configuration assessment as reported through Defender XDR advanced hunting. It is a strong indicator of cloud-assessed posture when you see:
- `IsApplicable = true`
- `IsCompliant = true`
- `Context` or equivalent indicates Block/Audit/Off

### Notes
- This is a “secure configuration assessment” view, not a “policy object” view.
- It helps answer what posture Defender reports regardless of how it was deployed.
- Strong indicator of cloud‑assessed posture at **last assessment**, not a guaranteed real‑time enforcement view.

---

## Query 2: Registry ASR Policy Evidence (Policy Manager ASRRules)

### Purpose
Uses advanced hunting registry telemetry to find policy writes that set ASR rules. In many environments this is observed as changes under:

`HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager`

Value name example:
`ASRRules`

The data can contain pipe-separated entries similar to:
`<GUID>=1|<GUID>=2|<GUID>=0`

### What it answers
- Did a policy write ASR rules to the device via policy channels?
- Which ASR rule GUIDs are present?
- What state is each rule configured to (Block, Audit, Disabled, Warn)?
- Which process performed the write (example: `omadmclient.exe` often indicates MDM/Intune/OMA-DM activity)

### State mapping used
- `0` = Disabled  
- `1` = Block  
- `2` = Audit  
- `6` = Warn (platform and rule dependent)

### Why this matters
Registry evidence is strong proof of configuration deployment on the endpoint. If a GUID exists in the policy value, it was explicitly written as policy state.

This is particularly useful when portal views appear inconsistent.

---

## Script 1: PowerShell ASR Effective State (Local Defender Engine)

### Purpose
Reads the Defender engine resolved ASR configuration from `Get-MpPreference` and maps:
- GUID -> friendly rule name (local hashtable)
- Action code -> mode (Block/Audit/Disabled/Warn)

### What it answers
- What action does the Defender engine believe is configured for each ASR rule right now?

---

## When to Trust Which Signal (Decision Guide)
Because ASR state is represented in multiple planes, no single signal should be treated as absolute truth. Use the guidance below to decide which source to trust based on your question.

**If you want to know what Defender is actually enforcing on the device**

- Trust: PowerShell (Get-MpPreference)
- Why: This reflects the Defender engine–resolved configuration after all policies, merges, conflicts, and defaults are applied. It is the closest available view to the real enforcement state without triggering an ASR event.

Caveats:
- Does not show why a rule is set that way
- Does not account for runtime exclusions (certificate, hash, path)

**If you want to know whether ASR was deployed via policy**

- Trust: Registry policy evidence (Policy Manager\\ASRRules)
- Why: Presence of ASR rule GUIDs in policy-backed registry locations is strong proof of configuration intent. It confirms that a management channel (MDM, GPO, etc.) explicitly wrote the setting to the device.

Caveats:
- Policy presence ≠ effective enforcement
- A rule can exist in policy but be overridden or merged differently by the engine

**If you want to know what Defender reports as security posture**

- Trust: TVM Secure Configuration Assessment
- Why: TVM reflects Defender’s cloud-assessed security posture, including applicability and compliance, independent of how the rule was deployed. This is the authoritative source for exposure scoring and Secure Score impact.

Caveats:
- Not real-time (assessment latency applies)
- Represents assessment outcome, not raw policy or engine state

### Summary Rule of Thumb

**Enforcement truth**: PowerShell (Get-MpPreference)
**Deployment proof:** Registry policy telemetry
**Posture & reporting:** TVM Secure Configuration Assessment

Use all three together when troubleshooting discrepancies between policy, device behavior, and portal UI.
- Which rules exist on the device that are not in your local mapping (shown as `Unknown / New Rule`)?

### Why this matters
This is the closest “effective state” view you can get locally without needing a block event to occur. It reflects the engine-resolved configuration (after policy merge/conflict resolution).

---

## References (Microsoft)

The following Microsoft documentation is directly relevant to the validation approaches described in this document and serves as authoritative reference material.

### Attack Surface Reduction (ASR)

- **Attack surface reduction rules reference**  
  Official reference for all ASR rules, including rule names, GUIDs, supported platforms, and available modes (Block, Audit, Warn, Disabled).  
  https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference

- **Enable attack surface reduction rules**  
  Describes supported configuration methods (Intune, Group Policy, PowerShell) and prerequisite requirements for ASR enforcement.  
  https://learn.microsoft.com/defender-endpoint/enable-attack-surface-reduction

---

### Defender Vulnerability Management / TVM

- **DeviceTvmSecureConfigurationAssessment table (Advanced Hunting)**  
  Schema reference for TVM secure configuration assessment data, including `IsApplicable`, `IsCompliant`, and `Context`.  
  https://learn.microsoft.com/defender-xdr/advanced-hunting-devicetvmsecureconfigurationassessment-table

- **DeviceTvmSecureConfigurationAssessment (Azure Monitor reference)**  
  Detailed column definitions and assessment semantics for TVM configuration posture reporting.  
  https://learn.microsoft.com/azure/azure-monitor/reference/tables/devicetvmsecureconfigurationassessment

---

### Local Defender Engine (PowerShell)

- **Get-MpPreference cmdlet reference**  
  Documents how Microsoft Defender Antivirus exposes its effective configuration, including ASR rule IDs and actions.  
  https://learn.microsoft.com/powershell/module/defender/get-mppreference

---

### Advanced Hunting & Schema

- **Advanced hunting schema reference**  
  Overview of Defender XDR advanced hunting tables and their intended use for security posture and investigation.  
  https://learn.microsoft.com/defender-xdr/advanced-hunting-schema-tables

---

### Notes on scope

These references intentionally focus on:

- Authoritative Microsoft documentation  
- Schema- and engine-level behavior, not portal UI presentation  
- What is assessed, reported, or enforced, rather than how it is visualized  

They are intended to support validation, troubleshooting, and auditability of ASR posture across cloud, policy, and endpoint layers.
