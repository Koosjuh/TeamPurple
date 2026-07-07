```kql
EasmRisk_CL
| where TimeGenerated > ago(180d)
| where CategoryName_s in ("High Severity", "Medium Severity")
| summarize arg_max(SnapshotDateTime_t, *) by AssetId_s, CategoryName_s
| project Severity = CategoryName_s, AssetName = AssetName_s, AssetType = AssetType_s
          Description = AssetDescription_s, FirstSeen = AssetFirstSeen_t, LastSeen = AssetLastSeen_t
| sort by Severity asc, AssetName asc
```
