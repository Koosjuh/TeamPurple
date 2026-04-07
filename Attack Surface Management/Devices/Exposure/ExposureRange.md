# Device Exposure Overview Query

## Purpose

This KQL query provides a simple overview of active endpoint devices by exposure level in Microsoft Defender XDR Advanced Hunting.

It returns the number of active endpoint devices in the following categories:

- High
- Medium
- Low
- No Data Available
- All levels, internet facing

The query is intended for reporting and dashboarding where a stable output is required, including rows with value `0` when no devices exist in a category.

---

## Query

```kql
let LatestDevice =
    DeviceInfo
    | where Timestamp > ago(30d)
    | where DeviceCategory == "Endpoint"
    | summarize arg_max(Timestamp, *) by DeviceId;
let ActiveDevices =
    LatestDevice
    | where SensorHealthState has "Active";
let ExposureCounts =
    ActiveDevices
    | where ExposureLevel in~ ("High", "Medium", "Low")
    | summarize NrOfActiveDevices = count() by ExposureLevel
    | extend Sort = case(
        ExposureLevel =~ "High", 1,
        ExposureLevel =~ "Medium", 2,
        ExposureLevel =~ "Low", 3,
        99
    );
let InternetFacingCount =
    ActiveDevices
    | where IsInternetFacing == true
    | summarize NrOfActiveDevices = count()
    | extend ExposureLevel = "All levels, internet facing", Sort = 5;
let NoDataCount =
    DeviceInfo
    | where DeviceCategory == "Endpoint" and ExposureLevel == "None" and SensorHealthState has "Active"
    | distinct DeviceId
    | summarize NrOfActiveDevices = count()
    | extend ExposureLevel = "No Data Available", Sort = 4;
let Rows =
    datatable(ExposureLevel:string, Sort:int, NrOfActiveDevices:long)
    [
        "High", 1, 0,
        "Medium", 2, 0,
        "Low", 3, 0,
        "No Data Available", 4, 0,
        "All levels, internet facing", 5, 0
    ];
Rows
| union ExposureCounts, NoDataCount, InternetFacingCount
| summarize NrOfActiveDevices = max(NrOfActiveDevices) by ExposureLevel
| project ExposureLevel, NrOfActiveDevices
```

---

## What the query does

### 1. Selects the latest record per device
The query starts by looking at `DeviceInfo` over the last 30 days and keeps only the most recent record for each `DeviceId`.

This ensures that each device is counted once based on its latest known state.

### 2. Filters to active endpoints
Only devices with:

- `DeviceCategory == "Endpoint"`
- `SensorHealthState` containing `"Active"`

are included in the main exposure counts.

### 3. Counts devices by exposure level
The query counts active devices where `ExposureLevel` is:

- High
- Medium
- Low

### 4. Separately counts internet-facing devices
A separate count is created for active devices where:

- `IsInternetFacing == true`

This produces a single summary row named:

- `All levels, internet facing`

This row is independent from the High/Medium/Low grouping.

### 5. Separately counts devices with no exposure data
Devices that have:

- `ExposureLevel == "None"`
- `SensorHealthState` containing `"Active"`
- `DeviceCategory == "Endpoint"`

are counted separately and labeled as:

- `No Data Available`

This makes the output easier to understand for reporting purposes, because `None` is presented as missing exposure data rather than as a normal exposure level.

### 6. Ensures all rows always exist
A static `datatable` is used to pre-create all expected output rows with value `0`.

This guarantees that the query always returns all five categories, even when there are no matching devices in one or more categories.

### 7. Merges and returns the final result
The query combines:

- Static default rows
- Exposure counts
- No data count
- Internet-facing count

Then it keeps the highest value per category and returns:

- `ExposureLevel`
- `NrOfActiveDevices`

---

## Output

The final output contains two columns:

| Column | Description |
|---|---|
| ExposureLevel | The reporting category |
| NrOfActiveDevices | Number of active devices in that category |

Expected output rows:

- High
- Medium
- Low
- No Data Available
- All levels, internet facing
