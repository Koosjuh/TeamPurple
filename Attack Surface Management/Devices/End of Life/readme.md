# OS End-of-Life & MDE Unsupported Devices Reporting

## Overview

This solution provides a centralized, GitHub-driven OS End-of-Life (EOL)
reporting framework for Microsoft Defender for Endpoint (MDE)
environments.

It supports: - Multi-customer environments - Centralized OS lifecycle
management via GitHub - Exposure breakdown (High / Medium / Low /
None) - Internet-facing visibility - MDE Unsupported endpoint
detection - Future-proof EOL tracking (10+ years)

------------------------------------------------------------------------

# Architecture

## 1. GitHub CSV (Source of Truth)

The OS lifecycle definitions are stored in GitHub:

    https://raw.githubusercontent.com/Koosjuh/TeamPurple/refs/heads/main/Attack%20Surface%20Management/Devices/End%20of%20Life/os-eol-map.csv

This ensures: - Single source of truth - No watchlist sync required -
Immediate updates across all tenants - Version control via Git

------------------------------------------------------------------------

## 2. KQL Query

The KQL: - Pulls OS definitions from GitHub - Maps devices using
DeviceInfo - Calculates exposure breakdown - Determines support status
dynamically - Adds a calculated "MDE unsupported devices" row

### KQL Logic Summary

### OS/EOL Section

-   Uses externaldata() to pull CSV
-   Aggregates Windows families (e.g. 7/8/8.1)
-   Calculates:
    -   Active device count
    -   Exposure levels
    -   Internet-facing devices
    -   Not onboarded devices
    -   Support status (Out of support / EOL soon / Supported)

### MDE Unsupported Section

Calculated directly from DeviceInfo:

    DeviceInfo
    | where OnboardingStatus == "Unsupported"
    | where DeviceCategory == "Endpoint"
    | distinct DeviceId

This is intentionally NOT managed via GitHub because: - It is static
logic - It does not change over time - It represents product state, not
lifecycle policy

------------------------------------------------------------------------

# CSV Structure

    Sort,OsRow,OSPlatform,OSVersion,EOS,Notes,RowType

### Column Definitions

| Column \| Description \|

\|--------\|-------------\| Sort \| Controls report ordering \| \| OsRow
\| Display name in report \| \| OSPlatform \| DeviceInfo OSPlatform
match \| \| OSVersion \| Specific OS version (or \*) \| \| EOS \|
End-of-support date \| \| Notes \| Lifecycle notes \| \| RowType \|
OS_EOF or MDE_UNSUPPORTED \|

------------------------------------------------------------------------

# CSV Example

``` csv
Sort,OsRow,OSPlatform,OSVersion,EOS,Notes,RowType
10,"Windows 7, 8 and 8.1","Windows7","*",2020-01-14,,"OS_EOF"
20,"Windows 10","Windows10","*",2025-10-14,"GA channel; final Win10 feature update = 22H2","OS_EOF"
90,"MDE unsupported devices","*","*",,"healthStatuses!=Active,onBoardingStatuses=Unsupported","MDE_UNSUPPORTED"
```

------------------------------------------------------------------------

# Output Columns

| Column \| Meaning \|

\|--------\|---------\| OSVersion \| OS group label \| \| SupportStatus
\| Supported / EOL soon / Out of support \| \| EOS \| End-of-support
date \| \| ActiveTotal \| Active MDE devices \| \| ExposureBreakdown \|
High/Medium/Low/None \| \| InternetFacing \| Internet-exposed device
count \| \| NotOnboarded \| Devices that can be onboarded \| \| Notes \|
Lifecycle notes \|

------------------------------------------------------------------------

# Design Principles

-   Zero watchlist dependencies
-   GitHub as authoritative lifecycle source
-   Portable across all tenants
-   Clean union-based unsupported calculation
-   Future-proof EOL model
-   Minimal tenant customization required

------------------------------------------------------------------------

# Maintenance

To update lifecycle dates:

1.  Modify os-eol-map.csv in GitHub
2.  Commit changes
3.  All tenants automatically reflect update

No KQL changes required.

------------------------------------------------------------------------

# Security & Governance

-   Uses raw GitHub content (public repo recommended)
-   Version-controlled lifecycle definitions
-   No tenant-stored static lifecycle data
-   Deterministic logic
-   Fully reproducible reporting

------------------------------------------------------------------------

# Recommended Repo Structure

    Attack Surface Management/
      Devices/
        End of Life/
          os-eol-map.csv
          README.md

------------------------------------------------------------------------

# Author

TeamPurple -- OS Lifecycle & Attack Surface Governance Framework
