### DKIM Rollover and Configuration Change Audit (Microsoft Sentinel)

This KQL query searches the Microsoft 365 Unified Audit Log (ingested into the `OfficeActivity` table) to identify when DKIM signing settings were changed or DKIM keys were rotated for Exchange Online domains.

**What it does:**
- Looks back **365 days** for Exchange administrative events related to DKIM.
- Filters for DKIM operations:
  - `Set-DkimSigningConfig` (enable/disable or configuration changes)
  - `Rotate-DkimSigningConfig` (explicit DKIM key rollover)
- Parses the `Parameters` array to reliably extract:
  - The **domain** affected (`Identity`)
  - The **DKIM enabled state** (`Enabled`, `IsEnabled`, or `Enable`)
- Groups results by time, operation, and actor to produce a clean audit trail.

**Output fields:**
- `TimeGenerated` — when the DKIM change occurred  
- `Operation` — type of DKIM action performed  
- `Domain` — domain whose DKIM configuration was modified  
- `Enabled` — whether DKIM was enabled or disabled after the change  
- `UserId` — account that performed the action  
- `ClientIP` — source IP of the change  

**Use cases:**
- Audit DKIM key rollovers for compliance and security reviews
- Investigate unauthorized or unexpected DKIM configuration changes
- Validate operational change management for email authentication controls

```KQL
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
