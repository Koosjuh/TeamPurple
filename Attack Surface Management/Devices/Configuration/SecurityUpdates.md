# Security Updates Exposure

These queries identify devices that are missing monthly Microsoft Security Updates and groups them by update release.
It provides a quick overview of patch posture and highlights which security update cycle has the highest exposure.

The results are sorted from most recent → older to prioritize current patch gaps.

## Overview Query Exposure by Security Update

**Shows how many devices are missing each monthly security update.**

```kql
DeviceTvmSoftwareVulnerabilities
| where isnotempty(RecommendedSecurityUpdate)
| extend Month = extract(@"(January|February|March|April|May|June|July|August|September|October|November|December)", 1, RecommendedSecurityUpdate)
| extend Year = extract(@"(20\d{2})", 1, RecommendedSecurityUpdate)
| extend SortDate = todatetime(strcat("1 ", Month, " ", Year))
| summarize
    ["Exposed Devices"] = dcount(DeviceId)
by ["Missing KB"] = RecommendedSecurityUpdate, SortDate
| sort by SortDate desc
| project-away SortDate
```

**Example Output**

| Exposed Devices   |  Missing KB |
| 100                | Security Updates March 2026 |
| 20                 | Security Updates February 2026 |
| 1                 | Security Updates October 2025 |

## Device Drill-down Query

Use this query to see which **devices** are missing a specific security update.

```kql
DeviceTvmSoftwareVulnerabilities
| where isnotempty(RecommendedSecurityUpdate)
| extend Month = extract(@"(January|February|March|April|May|June|July|August|September|October|November|December)", 1, RecommendedSecurityUpdate)
| extend Year = extract(@"(20\d{2})", 1, RecommendedSecurityUpdate)
| extend SortDate = todatetime(strcat("1 ", Month, " ", Year))
| summarize
    ["Exposed Devices"] = dcount(DeviceId)
    , Devices = make_set(DeviceName, 500)
    , DeviceIds = make_set(DeviceId, 500)
by ["Missing KB"] = RecommendedSecurityUpdate, SortDate
| sort by SortDate desc
| project-away SortDate
```

Data Source

Table used:

- DeviceTvmSoftwareVulnerabilities

Field used:

- RecommendedSecurityUpdate

This field maps vulnerabilities to the monthly Microsoft Security Update release required to remediate them.

### Notes
- Devices may appear in multiple update groups if multiple updates are missing
- Results depend on Defender TVM data freshness
- Preview / optional updates may also appear depending on environment configuration
