### DKIM Configuration and Key Change Audit (Microsoft Sentinel)

This KQL query analyzes the Microsoft 365 Unified Audit Log (via the `OfficeActivity` table) to determine the most recent DKIM-related change per domain, including configuration updates, key rotations, creation, and removal events.

**What it does:**
- Reviews the past **365 days** of Exchange-related audit events.
- Filters for DKIM operations:
  - `New-DkimSigningConfig` (initial DKIM configuration)
  - `Set-DkimSigningConfig` (configuration changes such as enable/disable)
  - `Rotate-DkimSigningConfig` (DKIM key rotation)
  - `Remove-DkimSigningConfig` (DKIM configuration removal)
- Parses the `Parameters` field to extract:
  - The affected **domain** (`Identity`)
  - The **DKIM key size** (`KeySize`)
- Determines the **most recent DKIM-related event per domain**.

**Output fields:**
- `Domain` — Domain affected by the DKIM change  
- `Last change` — Timestamp of the most recent DKIM-related action  
- `Operation` — Type of DKIM action performed  
- `Key size` — DKIM key size associated with the change (if available)  

**Use cases:**
- Identifying when DKIM was last modified per domain
- Verifying whether DKIM key rotations have occurred

**NOTE:** This table shows DKIM-related configuration changes over the past 365 days. Domains without any DKIM activity (creation, modification, rotation, or removal) during this period will not appear. Absence from this table does not indicate whether DKIM is currently enabled or disabled.

```kql
let lookback = 365d;
OfficeActivity
| where TimeGenerated >= ago(lookback)
| where RecordType in ("ExchangeAdmin", "Exchange")
| where Operation in~ (
    "New-DkimSigningConfig",
    "Set-DkimSigningConfig",
    "Rotate-DkimSigningConfig",
    "Remove-DkimSigningConfig"
)
| extend ParametersJson = todynamic(Parameters)
| mv-expand Param = ParametersJson
| extend
    ParamName = tostring(Param.Name),
    ParamValue = tostring(Param.Value)
| summarize
    Domain = maxif(ParamValue, ParamName == "Identity"),
    KeySize = maxif(ParamValue, ParamName == "KeySize")
  by TimeGenerated, Operation
| summarize arg_max(TimeGenerated, *) by Domain
| project
    Domain,
    ["Last change"] = TimeGenerated,
    Operation,
    ["Key size"] = KeySize
| order by ["Last change"] desc
```
