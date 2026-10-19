# MDE Coverage

## Purpose

Use these two queries during an Attack Surface Management (ASM) assessment to report device visibility, Microsoft Defender for Endpoint (MDE) onboarding, EDR sensor status and the role of Microsoft Defender Antivirus.

1. **Device visibility, onboarding and sensor status:** summarize the observed inventory by operating system or device category.
2. **Defender Antivirus role:** identify onboarded Windows devices where Defender Antivirus is primary, passive or providing EDR in block mode.

These are separate measurements. An active MDE sensor does not establish that Defender Antivirus is the primary antivirus, that all security controls are healthy, or that the device is covered by the contracted MxDR service.

## Scope and use

- Run both queries in **Microsoft Defender XDR Advanced Hunting** with access to the relevant devices. Query 2 requires Defender Vulnerability Management assessment data.
- Use a hunting time range that includes the full 30-day lookback. Available retention, permissions and data collection can limit the results.
- Both queries use the latest available record per device ID and exclude identities that Defender has marked as merged. This removes known merged identities, but is not a guarantee of perfect physical-device deduplication.
- The seven-day freshness thresholds are reporting choices, not Microsoft telemetry service-level guarantees. Adjust them to the agreed device population and record the values in the ASM report.
- These are latest-known-state summaries within the lookback, not uptime measurements or proof of continuous coverage throughout the month.
- The queries have been reviewed against documented schemas and examples. Validate their results in the customer tenant before using them as report evidence.

## Supporting evidence: monitored networks

Use **Settings > Device discovery > Monitored networks** in the Defender portal as supporting evidence for the corporate network discovery baseline. Microsoft documents that this view shows up to 50 networks, ordered by device observations during the previous seven days.

A monitored network means device discovery is enabled for that network. It does not establish that every device or all traffic receives security monitoring. The queries below are not filtered to the networks in that page.

Validate expected sites and network segments against the customer's network inventory. Include remote endpoints and cloud servers in the asset scope, even if they have not connected to the main corporate networks. Treat devices that cannot be attributed to an owned network or agreed scope as requiring validation.

## Query 1: Device visibility, onboarding and sensor status

### Query

```kusto
let Lookback = 30d;
let RecordFreshness = 7d;
let Devices = materialize(
    DeviceInfo
    | where Timestamp >= ago(Lookback)
    | where isnotempty(DeviceId)
    | project
        Timestamp,
        DeviceId,
        DeviceName,
        OSPlatform,
        DeviceCategory,
        OnboardingStatus,
        SensorHealthState,
        MergedToDeviceId
    | summarize arg_max(Timestamp, *) by DeviceId
    // Exclude invalidated/merged device identities.
    | where isempty(MergedToDeviceId)
    | extend DeviceGroup = case(
        DeviceCategory =~ "Network device", "Network Devices",
        DeviceCategory in~ ("IoT", "OT", "IoT/OT", "BMS", "Medical"),
            "IoT / OT / Embedded",
        OSPlatform startswith "WindowsServer", "Windows Server",
        OSPlatform =~ "Windows11", "Windows 11",
        OSPlatform =~ "Windows10", "Windows 10",
        OSPlatform =~ "Linux", "Linux",
        OSPlatform in~ ("macOS", "Mac", "OSX"), "macOS",
        OSPlatform =~ "Android", "Android",
        OSPlatform =~ "iOS", "iOS",
        OSPlatform startswith "Windows", "Other Windows",
        "Other / Unidentified"
    )
    | extend
        Status = replace_string(tolower(OnboardingStatus), " ", ""),
        Sensor = replace_regex(tolower(SensorHealthState), @"[^a-z0-9]", "")
    | extend OnboardingGroup = case(
        Status == "onboarded", "Onboarded",
        Status == "canbeonboarded", "Can be onboarded",
        Status == "unsupported", "Unsupported",
        Status in ("insufficientinfo", "insufficientinformation"),
            "Insufficient info",
        "Unknown / other"
    )
    | extend SensorGroup = case(
        Sensor == "active", "Active",
        Sensor == "inactive", "Inactive",
        Sensor in (
            "misconfigured",
            "impairedcommunication",
            "impairedcommunications",
            "nosensordata",
            "nosensordataimpairedcommunication",
            "nosensordataimpairedcommunications"
        ), "Misconfigured",
        "Unknown / other"
    )
    | project
        DeviceId,
        DeviceName,
        DeviceGroup,
        OSPlatform,
        OnboardingStatus,
        SensorHealthState,
        OnboardingGroup,
        SensorGroup,
        LastInventoryRecord = Timestamp
);
union
    (Devices | extend SortOrder = 0),
    (Devices | extend DeviceGroup = "TOTAL", SortOrder = 1)
| summarize
    InventoryDevices = count(),
    Onboarded = countif(OnboardingGroup == "Onboarded"),
    CanBeOnboarded = countif(OnboardingGroup == "Can be onboarded"),
    Unsupported = countif(OnboardingGroup == "Unsupported"),
    InsufficientInfo = countif(OnboardingGroup == "Insufficient info"),
    UnknownOnboarding = countif(OnboardingGroup == "Unknown / other"),
    ActiveSensorRecentRecord = countif(
        OnboardingGroup == "Onboarded"
        and SensorGroup == "Active"
        and LastInventoryRecord >= ago(RecordFreshness)
    ),
    ActiveSensorOlderRecord = countif(
        OnboardingGroup == "Onboarded"
        and SensorGroup == "Active"
        and LastInventoryRecord < ago(RecordFreshness)
    ),
    InactiveSensor = countif(
        OnboardingGroup == "Onboarded"
        and SensorGroup == "Inactive"
    ),
    MisconfiguredSensor = countif(
        OnboardingGroup == "Onboarded"
        and SensorGroup == "Misconfigured"
    ),
    UnknownSensor = countif(
        OnboardingGroup == "Onboarded"
        and SensorGroup == "Unknown / other"
    )
  by DeviceGroup, SortOrder
| order by SortOrder asc, DeviceGroup asc
| project
    ["Device Group"] = DeviceGroup,
    ["Total Devices"] = InventoryDevices,
    ["MDE Onboarded"] = Onboarded,
    ["Can Be Onboarded"] = CanBeOnboarded,
    ["MDE Unsupported"] = Unsupported,
    ["Insufficient Information"] = InsufficientInfo,
    ["Unknown Onboarding Status"] = UnknownOnboarding,
    ["Active Sensor - Recent Record"] = ActiveSensorRecentRecord,
    ["Active Sensor - Older Record"] = ActiveSensorOlderRecord,
    ["Inactive Sensor"] = InactiveSensor,
    ["Misconfigured Sensor"] = MisconfiguredSensor,
    ["Unknown Sensor Status"] = UnknownSensor
```

### How it works

The query retains the latest DeviceInfo record per DeviceId within 30 days, removes known merged identities, assigns a reporting group, and counts onboarding and sensor states. Device categories take precedence over operating systems for network and IoT/OT devices. Unrecognized platforms remain visible under Other / Unidentified.

Sensor values are normalized by removing spaces and punctuation. This ensures that **No sensor data, impaired communications** is counted under **Misconfigured Sensor**, including both issues on the same device.

The TOTAL row counts the retained device IDs across all reporting groups. Groups with no matching devices are omitted. An empty result should trigger a scope/data-availability check rather than a conclusion that the customer has no devices.

### Output

| Column | Meaning |
| --- | --- |
| Device Group | Reported operating system or device category used for grouping. |
| Total Devices | Device IDs retained in the 30-day inventory baseline after merge filtering. |
| MDE Onboarded | Devices whose latest onboarding status is Onboarded. |
| Can Be Onboarded | Discovered devices reported as eligible for onboarding but not onboarded. Ownership and service scope still require confirmation. |
| MDE Unsupported | Devices Defender reports as unsupported for MDE onboarding. This does not establish whether alternative monitoring exists. |
| Insufficient Information | Devices for which Defender cannot determine onboarding supportability. |
| Unknown Onboarding Status | Empty or unrecognized onboarding values. |
| Active Sensor - Recent Record | Onboarded devices with an Active sensor state and an inventory record within seven days. |
| Active Sensor - Older Record | Onboarded devices whose latest record says Active but is older than seven days, within the 30-day lookback. |
| Inactive Sensor | Onboarded devices whose latest reported sensor state is Inactive. |
| Misconfigured Sensor | Onboarded devices with missing sensor data, impaired communications, a combined fault, or a Misconfigured state. |
| Unknown Sensor Status | Onboarded devices with empty or unrecognized sensor-health values. |

**Interpretation:** A recent inventory record is not an independent check of recent EDR events. Sensor health describes the EDR sensor; it does not establish antivirus, ASR or other configuration health. Devices with no record in the lookback are absent from this query.

Reconciliation checks:

- Total Devices equals MDE Onboarded + Can Be Onboarded + MDE Unsupported + Insufficient Information + Unknown Onboarding Status.
- MDE Onboarded equals the sum of the five sensor-status columns.

### ACTION: Misconfigured Sensor

These devices are onboarded, but their latest sensor state indicates missing sensor data or impaired communication. Detection visibility can be reduced and response actions such as isolation or file collection may fail.

1. Open **Microsoft Defender > Assets > Devices**. Filter onboarding status to **Onboarded** and sensor health to **Misconfigured**.
2. Open each affected device and review sensor-health details, the last device update and the timeline. Match the reporting period and account scope when comparing portal and query results; refresh timing can produce differences.
3. For **No sensor data**, confirm the device is online and investigate the endpoint sensor/service state and local errors.
4. For **Impaired communications**, investigate access to required Defender service endpoints, including firewall, proxy and TLS inspection settings.
5. For **No sensor data, impaired communications**, investigate both conditions; this is a combined fault on the same device.
6. Run the **MDE Client Analyzer** on the endpoint to collect connectivity and diagnostic information.
7. After remediation, confirm an Active sensor state and new endpoint telemetry. Record the device, owner, action and remediation status.

### ACTION: Other onboarding and sensor gaps

| Finding | Action and where to look |
| --- | --- |
| Can Be Onboarded | Review Assets > Devices with the matching onboarding filter. Confirm ownership, intended MDE coverage and any approved exception before arranging onboarding. |
| MDE Unsupported | Confirm the reported platform/version and document alternative monitoring, its owner and any remaining visibility gap. |
| Insufficient Information | Review the device's discovery source, category and identification evidence. Check device discovery configuration and whether sufficient information is available to classify it. |
| Inactive Sensor / Older Record | Check whether the device is offline, retired, replaced or still expected to report. Reconcile with the asset owner and management inventory before closing the gap or retiring the record. |
| Unknown Status | Inspect the raw OnboardingStatus and SensorHealthState values. Do not silently classify unknown values as healthy, unsupported or protected. |

## Query 2: Defender Antivirus role

### Query

```kusto
let Lookback = 30d;
let AssessmentFreshness = 7d;
let WindowsDevices =
    DeviceInfo
    | where Timestamp >= ago(Lookback)
    | where isnotempty(DeviceId)
    | summarize arg_max(
        Timestamp,
        DeviceName,
        OSPlatform,
        OnboardingStatus,
        MergedToDeviceId
      ) by DeviceId
    | where isempty(MergedToDeviceId)
    | where OnboardingStatus =~ "Onboarded"
    | where OSPlatform startswith "Windows"
    | project DeviceId, DeviceName, OSPlatform;
let AntivirusMode =
    DeviceTvmSecureConfigurationAssessment
    | where Timestamp >= ago(Lookback)
    | where ConfigurationId == "scid-2010"
    | summarize arg_max(Timestamp, Context) by DeviceId
    | extend ModeCode = tostring(Context[0][0])
    | project
        DeviceId,
        ModeCode,
        LastAVAssessment = Timestamp;
WindowsDevices
| join kind=leftouter AntivirusMode on DeviceId
| extend AVMode = case(
    ModeCode == "0", "Active",
    ModeCode == "1", "Passive",
    ModeCode == "4", "EDR in Block Mode",
    "Unknown / No Recognized Assessment"
)
| extend PrimaryAVStatus = case(
    ModeCode == "0", "Defender Is Primary AV",
    ModeCode in ("1", "4"), "Defender Is Not Primary AV",
    "Requires Investigation"
)
| extend DeviceLabel = iff(
    isempty(DeviceName), DeviceId, DeviceName
)
| summarize
    DeviceCount = count(),
    RecentAssessments = countif(
        LastAVAssessment >= ago(AssessmentFreshness)
    ),
    OlderAssessments = countif(
        LastAVAssessment < ago(AssessmentFreshness)
    ),
    MissingAssessments = countif(isnull(LastAVAssessment)),
    DeviceNames = make_set(DeviceLabel, 1000)
  by AVMode, PrimaryAVStatus
| order by DeviceCount desc
| project
    ["Defender Antivirus Mode"] = AVMode,
    ["Primary Antivirus Status"] = PrimaryAVStatus,
    ["Device Count"] = DeviceCount,
    ["Recent Assessments"] = RecentAssessments,
    ["Older Assessments"] = OlderAssessments,
    ["Missing Assessments"] = MissingAssessments,
    ["Device Names"] = DeviceNames
```

### How it works

This query starts with the latest inventory record for MDE-onboarded Windows devices, including Windows Server. It joins the latest scid-2010 assessment per device and interprets Context[0][0] using the mapping in Microsoft's published hunting example:

| Mode Code | Reported Mode | Interpretation |
| --- | --- | --- |
| 0 | Active | Defender reports that it is the primary antivirus. This does not exclude another installed product or establish the health of every protection setting. |
| 1 | Passive | Defender is not the primary antivirus. Confirm the intended alternative product and its operational health. |
| 4 | EDR in Block Mode | Defender provides additional EDR remediation alongside the primary antivirus. |
| Empty or other | Unknown / No Recognized Assessment | Investigate missing or unrecognized data. Do not infer a healthy alternative antivirus or assume Defender is disabled. |

The mapping is based on a published Microsoft example in an archived repository, not a guarantee that every future Context value is covered. Unrecognized values remain visible for review. The query deliberately does not infer Disabled from missing assessment data.

The left outer join keeps onboarded Windows devices with no matching assessment in the result. It does not filter out devices with inactive or misconfigured MDE sensors, since those may be relevant assessment gaps.

### Output

| Column | Meaning |
| --- | --- |
| Defender Antivirus Mode | Latest recognized mode, or Unknown. |
| Primary Antivirus Status | Whether the latest recognized assessment reports Defender as primary, not primary, or unresolved. |
| Device Count | Unique device IDs in the mode group. |
| Recent Assessments | Devices with an AV assessment within seven days. |
| Older Assessments | Devices with an assessment older than seven days but within the 30-day lookback. |
| Missing Assessments | Devices without a matching assessment within the lookback. |
| Device Names | Device names, falling back to DeviceId where the name is empty. The list is capped at 1,000 entries per group; Device Count is not capped by this list. |

Recent Assessments + Older Assessments + Missing Assessments equals Device Count for each row. A recent assessment may still have an unrecognized mode value. Older assessments represent historical evidence and should not be treated as confirmed current protection.

**Scope:** This query covers onboarded Windows devices visible in the selected data. It does not assess macOS, Linux, mobile devices, or Windows devices that are absent from MDE. Its population therefore differs from Query 1.

### ACTION: Defender Is Not Primary AV

Review devices reported as Passive or EDR in Block Mode and confirm whether this configuration is intentional. In the Defender portal, use **Reports > Device health and compliance** and the antivirus health report to review AV mode and related health information. Confirm the primary antivirus product, its last check-in and protection state in the relevant management console or endpoint management inventory.

Record the alternative product and the team responsible for monitoring and response. Passive mode alone does not prove that another antivirus is installed, active or healthy. Do not change the mode solely because it is passive; it may be part of an approved coexistence configuration.

Where no working primary antivirus can be confirmed, record a protection gap and agree remediation with the responsible owner. For unknown or older assessments, validate the endpoint and current AV health before drawing a conclusion.

## Reporting coverage in ASM

Use the outputs as evidence for **Device Visibility, MDE Onboarding and Sensor Status** and **Defender Antivirus Role**.

Before calculating customer-wide coverage, reconcile the observed devices with an independent asset population, such as Intune/RMM, server inventories and cloud inventories. Record ownership, expected monitoring, approved exceptions and devices missing from Defender. Keep unsupported devices visible with their alternative controls rather than treating them as covered by MDE.

Recommended measures for this ASM methodology:

| Measure | Definition |
| --- | --- |
| MDE onboarding coverage | Onboarded devices within the agreed population divided by all devices in that population expected to run MDE. |
| Operational EDR coverage | Devices in the same population with validated sensor health and sufficiently recent endpoint telemetry, using agreed device-class thresholds. Query 1 supplies part of the evidence, not the full validation. |
| Defender Antivirus role | The distribution of recognized AV modes from Query 2, with missing and older assessments kept visible. |
| Alternative antivirus coverage | Confirmed alternative antivirus deployment and operational health from additional product or management evidence. Query 2 alone cannot establish this count. |
| MxDR service coverage | The agreed asset and data-source scope, validated alert delivery to the SOC, and available investigation/response capabilities. Endpoint counts alone are insufficient. |

These are proposed reporting definitions, not a universal Microsoft MxDR coverage formula. Validate critical assets and service scope separately; a high aggregate percentage can hide an important unmonitored server.

## References

- [Microsoft: DeviceInfo schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table)
- [Microsoft: Review and assess discovered devices](https://learn.microsoft.com/en-us/defender-endpoint/assess-devices)
- [Microsoft: Configure device discovery and monitored networks](https://learn.microsoft.com/en-us/defender-endpoint/configure-device-discovery)
- [Microsoft: Check sensor health](https://learn.microsoft.com/en-us/defender-endpoint/check-sensor-status)
- [Microsoft: Sensor health and OS report](https://learn.microsoft.com/en-us/defender-endpoint/device-health-sensor-health-os)
- [Microsoft: MDE Client Analyzer](https://learn.microsoft.com/en-us/defender-endpoint/overview-client-analyzer)
- [Microsoft: Secure configuration assessment schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicetvmsecureconfigurationassessment-table)
- [Microsoft: Published AV mode hunting example](https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/master/General%20queries/MD%20AV%20Signature%20and%20Platform%20Version.md)
- [Microsoft: Antivirus health report](https://learn.microsoft.com/en-us/defender-endpoint/device-health-microsoft-defender-antivirus-health)
- [Microsoft: Antivirus compatibility](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-compatibility)
- [Microsoft: EDR in block mode](https://learn.microsoft.com/en-us/defender-endpoint/edr-in-block-mode)
- [Microsoft: Validate onboarding with a detection test](https://learn.microsoft.com/en-us/defender-endpoint/run-detection-test)
- [Jeffrey Appel, Microsoft MVP: Checking a healthy Defender environment](https://jeffreyappel.nl/how-to-check-for-a-healthy-defender-for-endpoint-environment/)
- [Ru Campbell, Microsoft MVP: MDE feature comparison by OS](https://campbell.scot/mde-comparison/)
