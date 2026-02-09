# Windows End-of-Life Detection (CSV-Driven)

This folder contains a **data-driven Windows End-of-Life (EOL) detection solution** for Microsoft Defender and Microsoft Sentinel.

The solution identifies **out-of-support** and **near-EOL** Windows operating systems using Microsoft lifecycle data, enriched with Defender device context such as:

- Active sensor state
- Internet exposure
- Onboarding status
- Unsupported Defender sensors

The design intentionally separates **data** and **logic**:

- **CSV** = lifecycle truth (single point of management)
- **KQL** = stable detection and aggregation logic

This allows lifecycle updates **without modifying the KQL query**.

---

## Files in this folder

- **Lifecycle catalog (CSV)**  
  `endoflife.csv`  
  https://github.com/Koosjuh/TeamPurple/blob/main/Attack%20Surface%20Management/Devices/End%20of%20Life/endoflife.csv

- **Detection query (KQL)**  
  `endoflife.kql`  
  https://github.com/Koosjuh/TeamPurple/blob/main/Attack%20Surface%20Management/Devices/End%20of%20Life/endoflife.kql

---

## Why this exists

Besides lack of Microsoft support, using older OS versions puts organizations at a higher risk of being attacked.

This solution provides:
- Visibility into **(near) out-of-support Windows versions**
- Risk-based prioritization using Defender context
- A future-proof model that scales with new Windows releases

---

## What the KQL query does

### 1. Loads lifecycle data from CSV
The query uses `externaldata()` to load `endoflife.csv` directly from GitHub.

All lifecycle intelligence comes from the CSV:
- OS versions
- Major build numbers
- End-of-support dates
- Grouping logic

No lifecycle dates are hardcoded in KQL.

---

### 2. Builds an active device inventory
From `DeviceInfo`, the query:
- Selects the **latest record per device**
- Filters to **SensorHealthState == Active**
- Extracts OS platform, version and build
- Detects:
  - LTSC vs GA editions
  - Unsupported Defender sensors
  - Not-onboarded devices
  - Internet-facing devices

This aligns with Defender portal filters such as:
- `healthStatuses = Active`
- `category = Endpoint`

---

### 3. Maps devices to lifecycle entries
Devices are matched to CSV rows using:
- `OSPlatform`
- `MajorBuild`

Special handling exists for:
- Windows 10 21H2 LTSC (same build as GA but different lifecycle)

Each device maps to **exactly one lifecycle row**.

---

### 4. Calculates lifecycle and risk state
For each lifecycle entry, the query calculates:
- **Support state**
  - Supported
  - EOL within 365 days
  - Out of support
- Counts of:
  - Total devices
  - Internet-facing devices
  - Not-onboarded devices
  - Unsupported Defender sensors
- A readable **RiskNote** used directly in reporting

---

### 5. Collapses versions into summary rows
If a lifecycle entry has a `CollapseGroup`, the query:
- Hides individual rows
- Produces **one aggregated summary row per group**

All grouping behavior is controlled **only via the CSV**.

---

## Understanding the CSV (`endoflife.csv`)

### CSV schema
CatalogKey,SpecificBucket,OSPlatform,MajorBuild,EosDate,Notes,CollapseGroup

### Column explanation

| Column | Purpose |
|------|--------|
| CatalogKey | Stable unique identifier |
| SpecificBucket | Display name in output |
| OSPlatform | Must match `DeviceInfo.OSPlatform` |
| MajorBuild | Windows major build (nullable for legacy OS) |
| EosDate | Microsoft end-of-support date |
| Notes | Lifecycle clarification |
| CollapseGroup | Optional grouping key |

---

## How to add or update Windows versions

### Adding a new Windows version
When Microsoft releases a new Windows version:

1. Add a new row to `endoflife.csv`
2. Populate:
   - `OSPlatform`
   - `MajorBuild`
   - `EosDate`
3. Decide whether it should be grouped using `CollapseGroup`

**No KQL changes are required.**

---

## How grouping / collapsing works

### What is a CollapseGroup
A `CollapseGroup` tells the query to **aggregate multiple lifecycle rows into one summary row**.

Examples used here:
- Windows 7 / 8 / 8.1
- Windows 10 (all versions)
- Windows Server 2008 (R2)

### Example: collapsing all Windows 10 versions
win10_22h2,"Windows 10 22H2",Windows10,19045,2025-10-14,"22H2","Windows 10 (all versions)"


Result:
- Individual Windows 10 rows are hidden
- One summary row appears:
  **Windows 10 (all versions) (summary)**

### Future scenario (Windows 12)
When Windows 12 exists:
- Add a CollapseGroup to all Windows 11 rows
- Leave Windows 12 rows uncollapsed

This allows reporting to evolve without touching KQL.

---

## Special lifecycle row: MDE unsupported devices

The CSV includes a dedicated row:
mde_unsupported,"MDE unsupported devices",MDEUnsupported,,,,


This row is populated dynamically by the KQL using:
- `OnboardingStatus == "Unsupported"`
- `DeviceCategory == "Endpoint"`
- `SensorHealthState == "Active"`

This mirrors Defender’s **Unsupported Endpoints** view.

---

## Rebuilding the CSV from scratch (AI prompt)

Use the prompt below if the CSV ever falls behind or needs a full rebuild.

```text
You are a data extraction and normalization assistant.

Goal:
Rebuild a complete CSV for Windows OS lifecycle tracking, compatible with a Microsoft Defender / Sentinel KQL query using externaldata().

Authoritative sources:

https://en.wikipedia.org/wiki/List_of_Microsoft_Windows_versions

https://en.wikipedia.org/wiki/Windows_10_version_history

https://en.wikipedia.org/wiki/Windows_11_version_history

Microsoft Learn lifecycle documentation (authoritative when dates differ)

Scope:

Include all supported Windows client and server versions

Include LTSC/LTSB variants where lifecycle differs

Exclude Insider / Preview builds

Output format:
Produce a CSV with exactly these columns:

CatalogKey,SpecificBucket,OSPlatform,MajorBuild,EosDate,Notes,CollapseGroup

Rules:

CatalogKey must be unique and stable

OSPlatform must match Defender DeviceInfo.OSPlatform values

Use Enterprise/Education lifecycle dates for client OS

Quote fields containing commas

Every row must have exactly 7 columns

No explanations, output CSV only

Special row:
Add:
mde_unsupported,"MDE unsupported devices",MDEUnsupported,,,,
```

---

## Intended use

This solution is intended for:
- SOC reporting
- Attack Surface Management
- Security posture reviews
- Lifecycle risk prioritization

The model is **data-driven, Defender-aligned, and future-proof by design**.
