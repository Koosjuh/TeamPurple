# Security Updates Exposure

These queries identify devices that are missing monthly Microsoft Security Updates and groups them by update release.
It provides a quick overview of patch posture and highlights which security update cycle has the highest exposure.

The results are sorted from most recent → older to prioritize current patch gaps.

## Overview Exposure by Security Update

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

### Example Output

| Exposed Devices | Missing KB                     |
|-----------------|--------------------------------|
| 100             | Security Updates March 2026    |
| 20              | Security Updates February 2026 |
| 1               | Security Updates October 2025  |

## Overview Exposure by Security Update - Per RecommendedSecurityUpdateId

**Shows how many devices are missing each monthly security update. Per RecommendedSecurityUpdateId**

For example March 2026 Updates have Regular patches for Windows 11, Windows Server 2022 and Hotfixes. The query below shows the ratio per unique update id.

```kql
DeviceTvmSoftwareVulnerabilities
| where isnotempty(RecommendedSecurityUpdate)
| summarize
    ["Exposed Devices"] = dcount(DeviceId)
by ["Missing KB"] = RecommendedSecurityUpdate, RecommendedSecurityUpdateId
| sort by RecommendedSecurityUpdateId desc
```

### Example Output

| Exposed Devices | RecommendedSecurityUpdateId    | Missing KB                     |
|-----------------|--------------------------------|--------------------------------|
| 100             | 5079473                        | Security Updates March 2026    |
| 20              | 5079766                        | Security Updates February 2026 |
| 1               | 5077472                        | Security Updates October 2025  |

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

### Example Output — Device Drill-down

| Exposed Devices | Missing KB                  | Devices                         | DeviceIds                    |
|-----------------|-----------------------------|----------------------------------|------------------------------|
| 100 | Security Updates March 2026 | ["PC-01","PC-02","PC-03"] | ["id1","id2","id3"] |
| 20  | Security Updates February 2026 | ["SRV-01","SRV-02"] | ["id4","id5"] |
| 1   | Security Updates October 2025 | ["LEGACY-01"] | ["id6"] |

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
