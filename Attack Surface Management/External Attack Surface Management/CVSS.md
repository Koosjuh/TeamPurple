```kql
union EasmHostAsset_CL, EasmPageAsset_CL
| summarize arg_max(SnapshotDateTime_t, *) by AssetId_s
| where isnotempty(WebComponents_s)
| mv-expand Component = parse_json(WebComponents_s)
| mv-expand Cve = Component.cves
| extend
    Asset      = AssetName_s,
    CveId      = tostring(Cve.name),
    CvssV2     = todouble(Cve.cvssScore),
    CvssV3     = todouble(Cve.cvss3Summary.baseScore),
    SeverityV3 = tostring(Cve.cvss3Summary.baseSeverity),
    ComponentName = strcat(tostring(Component.name), " ", tostring(Component.version))
| where isnotempty(CveId)
| project Asset, ComponentName, CveId, CvssV2, CvssV3, SeverityV3
| sort by CvssV3 desc
```

```kql
union EasmHostAsset_CL, EasmPageAsset_CL
| summarize arg_max(SnapshotDateTime_t, *) by AssetId_s
| mv-expand Component = parse_json(WebComponents_s)
| mv-expand Cve = Component.cves
| extend CvssV3 = todouble(Cve.cvss3Summary.baseScore)
| where isnotnull(CvssV3)
| extend Bucket = case(
    CvssV3 >= 9.0, "Critical (9.0-10.0)",
    CvssV3 >= 7.0, "High (7.0-8.9)",
    CvssV3 >= 4.0, "Medium (4.0-6.9)",
    "Low (0.1-3.9)")
| summarize CVEs = dcount(tostring(Cve.name)), AffectedAssets = dcount(AssetId_s) by Bucket
| render piechart
```

Components detected, but which of them carry version info and CVEs?
```kql
kustounion EasmHostAsset_CL, EasmPageAsset_CL
| summarize arg_max(SnapshotDateTime_t, *) by AssetId_s
| mv-expand Component = parse_json(WebComponents_s)
| extend
    ComponentName = tostring(Component.name),
    HasVersion    = isnotempty(tostring(Component.version)),
    CveCount      = array_length(Component.cves)
| summarize
    Instances       = count(),
    WithVersion     = countif(HasVersion),
    WithCves        = countif(CveCount > 0),
    AffectedAssets  = dcount(AssetId_s)
    by ComponentName
| sort by Instances desc
```

Where that unconfirmed risk actually lives — Potential insights:
```kql
kustoEasmRisk_CL
| summarize arg_max(SnapshotDateTime_t, *) by AssetId_s, CategoryName_s
| where AssetDescription_s has "Potential" or CategoryName_s has "Potential"
| project Severity = CategoryName_s, AssetName = AssetName_s, AssetType = AssetType_s,
          Description = AssetDescription_s, LastSeen = AssetLastSeen_t
| sort by Severity asc, AssetName asc
```
