### DKIM Rollover and Configuration Change Audit (Microsoft Sentinel)

This KQL query analyzes the Microsoft 365 Unified Audit Log (via the `OfficeActivity` table) to identify when DKIM signing settings were changed or DKIM keys were rotated for Exchange Online domains.

**What it does:**
- Reviews the past **365 days** of Exchange-related audit events.
- Filters specifically for DKIM operations:
  - `Set-DkimSigningConfig` (configuration changes such as enable/disable)
  - `Rotate-DkimSigningConfig` (DKIM key rotation)
- Parses the `Parameters` field to extract:
  - The affected **domain** (`Identity`)
  - The **DKIM enabled state** (`Enabled`, `IsEnabled`, or `Enable`)
  - The **selector** used during rotation events
- Groups results to provide a structured audit trail of DKIM-related changes.

**Output fields:**
- `TimeGenerated` — Timestamp of the DKIM change  
- `Operation` — Type of DKIM action performed  
- `Domain` — Domain affected by the change  
- `Enabled` — DKIM state after the change (enabled/disabled)  

**Use cases:**
- Auditing DKIM key rotations for compliance and governance
- Detecting unauthorized or unexpected DKIM configuration changes
- Supporting change management validation for email authentication controls

```kql
let lookback = 365d;
OfficeActivity
| where TimeGenerated >= ago(lookback)
| where RecordType in ("ExchangeAdmin", "Exchange")
| where Operation has_any ("Set-DkimSigningConfig", "Rotate-DkimSigningConfig")
| extend ParametersJson = todynamic(Parameters)
| mv-expand Param = ParametersJson
| extend
    ParamName = tostring(Param.Name),
    ParamValue = tostring(Param.Value)
| summarize
    Domain = maxif(ParamValue, ParamName == "Identity"),
    Enabled = maxif(ParamValue, ParamName in ("Enabled", "IsEnabled", "Enable")),
    Selector = maxif(ParamValue, ParamName in ("Selector", "SelectorAfterRotateOnDate", "SelectorBeforeRotateOnDate"))
  by
    TimeGenerated,
    Operation,
    UserId,
    ClientIP
| project
    TimeGenerated,
    Operation,
    Domain,
    Enabled
| order by TimeGenerated desc
```
