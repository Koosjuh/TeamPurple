End of Life KQL for Advanced hunting

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
        isnull(EndOfLifeDate), "Unknown",
        EndOfLifeDate < now(), "EOS",
        EndOfLifeDate <= datetime_add("year", 1, now()), "Near EOS",
        "Supported"
    )
| where SupportState in ("EOS", "Near EOS") // Remove this line to include supported operating systems in the report.
| summarize
    TotalDevices = dcount(DeviceId),
    NotOnboarded = dcountif(DeviceId, OnboardingBucket == "NotOnboarded"),
    Onboarded = dcountif(DeviceId, OnboardingBucket == "Onboarded"),
    OtherOrUnknown = dcountif(DeviceId, OnboardingBucket == "OtherOrUnknown"),
    RawOnboardingStates = strcat_array(make_set(OnboardingStatus), ", "),
    DeviceInfoOSPlatforms = strcat_array(make_set(DeviceInfoOSPlatform), ", "),
    VersionDistribution =
        strcat_array(
            make_set(
                strcat(
                    FullBuild,
                    " (EoS: ",
                    format_datetime(EndOfLifeDate, "yyyy-MM-dd"),
                    ")"
                )
            ),
            "; "
        )
by OSName, Version=BaseBuild, SupportState, EndOfLifeDate
| extend CountCheck = TotalDevices - (NotOnboarded + Onboarded + OtherOrUnknown)
| project
    ["Operating System"] = OSName,
    ["Version"] = Version,
    ["Support State"] = SupportState,
    ["End of Support Date"] = format_datetime(EndOfLifeDate, "yyyy-MM-dd"),
    ["Total Devices"] = TotalDevices,
    ["Not Onboarded Devices"] = NotOnboarded,
    ["Onboarded Devices"] = Onboarded,
    ["Other / Unknown Onboarding"] = OtherOrUnknown,
    ["Count Check"] = CountCheck,
    ["Reported OS Platforms"] = DeviceInfoOSPlatforms,
    ["Raw Onboarding States"] = RawOnboardingStates,
    ["Version Distribution"] = VersionDistribution
| order by ["Support State"] asc, ["End of Support Date"] asc, ["Total Devices"] desc
```
