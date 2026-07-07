
For a list of pages with protocol

```kql
EasmPageAsset_CL
| summarize arg_max(SnapshotDateTime_t, *) by AssetId_s
| extend Protocol = toupper(tostring(parse_url(AssetName_s).Scheme))   // AssetName_s = page URL for page assets
| project Protocol, LoginPage = AssetName_s, FirstSeen = AssetFirstSeen_t, LastSeen = AssetLastSeen_t
| sort by Protocol asc, LoginPage asc
```
