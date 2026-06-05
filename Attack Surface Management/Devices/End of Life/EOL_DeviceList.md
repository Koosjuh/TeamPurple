```KQL
let RawCsvUrl = "https://raw.githubusercontent.com/Koosjuh/TeamPurple/refs/heads/main/Attack%20Surface%20Management/Devices/End%20of%20Life/os-eol-map.csv";
let Ref =
    externaldata(Release:string, Released:string, ActiveSupport:string, SecuritySupport:string, ExtendedSecurityUpdates:string, Latest:string)
    [RawCsvUrl]
    with (format="csv", ignoreFirstRecord=true)
    | extend EndOfLifeDate = todatetime(SecuritySupport)
    | extend RefType = iff(Release startswith "Windows Server", "Server", "Client")
    | project OSName = Release, BaseBuild = tostring(Latest), EndOfLifeDate, RefType;
let LatestDeviceInfo =
    DeviceInfo
    | where OSPlatform startswith "Windows"
    | where isnotempty(DeviceId)
    | summarize arg_max(Timestamp, OSPlatform, OSVersion, OSBuild, ClientVersion, OnboardingStatus) by DeviceId
    | extend DeviceInfoOSPlatform = tostring(OSPlatform)
    | extend OSVersion = tostring(OSVersion)
    | extend OSBuild = tostring(OSBuild)
    | extend ClientVersion = tostring(ClientVersion)
    | extend OnboardingStatus = tostring(OnboardingStatus)
    | where isnotempty(OSBuild) and isnotempty(OSVersion)
    | extend BaseBuild = strcat(OSVersion, ".", OSBuild)
    | extend Revision = tostring(split(ClientVersion, ".")[3])
    | extend FullBuild = iff(isempty(Revision), BaseBuild, strcat(BaseBuild, ".", Revision))
    | extend DeviceType = iff(DeviceInfoOSPlatform startswith "WindowsServer", "Server", "Client")
    | extend OnboardingBucket =
        case(
            OnboardingStatus =~ "Onboarded", "Onboarded",
            OnboardingStatus in~ ("Can be onboarded", "Unsupported", "Insufficient info", "Misconfigured", "Not onboarded"), "NotOnboarded",
            isempty(OnboardingStatus), "OtherOrUnknown",
            "OtherOrUnknown"
        )
    | project DeviceId, DeviceInfoOSPlatform, DeviceType, BaseBuild, FullBuild, OnboardingStatus, OnboardingBucket;
LatestDeviceInfo
| join kind=leftouter Ref on BaseBuild
| where RefType == DeviceType
| extend SupportState =
    case(
        isnull(EndOfLifeDate), "Unknown (no CSV match)",
        EndOfLifeDate < now(), "OutOfSupport",
        EndOfLifeDate <= datetime_add("year", 1, now()), "EndingWithin1Year",
        "Supported"
    )
```

### What the query does

The query retrieves Windows devices from `DeviceInfo`, determines their operating system build, joins that data with an external Windows end-of-life reference CSV, and classifies each device as supported, nearing end of support, out of support, or unknown.

### Main steps

1. Loads an external CSV reference table from GitHub.

   The CSV contains Windows release information, including:
   - Release name
   - Release date
   - Active support date
   - Security support end date
   - Extended Security Updates date
   - Latest build number

2. Converts the `SecuritySupport` column into a datetime value called `EndOfLifeDate`.

3. Determines whether each CSV entry is for a Windows Server or Windows Client release.

   This is done by checking whether the release name starts with `Windows Server`.

4. Retrieves the latest known `DeviceInfo` record per device.

   It uses:

   `summarize arg_max(Timestamp, ...) by DeviceId`

   This ensures only the most recent inventory record for each device is used.

5. Filters to Windows devices only.

   Only devices where `OSPlatform` starts with `Windows` are included.

6. Builds the device OS version fields.

   The query creates:
   - `BaseBuild` from `OSVersion.OSBuild`
   - `FullBuild` from `OSVersion.OSBuild.ClientVersionRevision`

7. Classifies the device type.

   Devices where `OSPlatform` starts with `WindowsServer` are treated as `Server`; all others are treated as `Client`.

8. Groups onboarding status into buckets.

   Devices are classified as:
   - `Onboarded`
   - `NotOnboarded`
   - `OtherOrUnknown`

9. Joins device data with the external CSV reference.

   The join is performed on `BaseBuild`.

10. Keeps only valid client/server matches.

   This prevents a Windows Client build from being matched against a Windows Server entry, or the other way around.

11. Calculates support state.

   Each device is classified as:
   - `OutOfSupport` when the end-of-life date is in the past.
   - `EndingWithin1Year` when the end-of-life date is within the next year.
   - `Supported` when the end-of-life date is more than one year away.
   - `Unknown (no CSV match)` when no matching CSV entry exists.

### Practical outcome

The result shows which Windows devices are running operating system builds that are:
- already out of support,
- approaching end of support within one year,
- still supported,
- or could not be matched to the reference CSV.

This can be used for attack surface management, lifecycle reporting, and prioritizing endpoint upgrade or migration actions.
