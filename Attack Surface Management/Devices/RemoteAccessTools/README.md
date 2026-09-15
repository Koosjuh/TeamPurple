# Remote Access / RMM catalogue

Files:

- `RemoteAccessProducts.csv`: one canonical row per product.
- `RemoteAccessIndicators.csv`: normalized software/process indicators with evidence, activity role and optional qualifiers.
- `RemoteAccessTools.kql`: Defender XDR Advanced Hunting query that loads both CSV files through `externaldata()`.

## Evidence policy

- `VendorVerified`: exact executable/component documented by the vendor.
- `VendorCommunity`: vendor-operated support/community evidence.
- `VendorProduct`: the product/software name is vendor-confirmed; executable detail may not be explicitly enumerated.
- `Supplemental`: useful cross-check from a reputable external catalogue, disabled by default in KQL.

`Enabled=false` indicators remain in the catalogue for research/coverage but are excluded from the production query unless `IncludeSupplementalIndicators` is changed to `true`.

## Reporting semantics

- `InstalledDevices`: distinct devices from `DeviceTvmSoftwareInventory`.
- `ActiveDevices30d`: distinct devices with any matched product process in the last 30 days. Persistent agent/service activity is included.
- `InteractiveOrSessionDevices30d`: distinct devices where a user-facing or session-specific component was observed. This is stronger evidence of interactive use, but is still not equivalent to a confirmed successful remote-control session for every product.
- `LastObserved`: latest matching process event.

The catalogue is Windows-focused because the current report logic uses Windows executable/process telemetry.

## Query performance

`RemoteAccessTools.kql` uses equality joins for exact process filenames. Only the small set of `contains`/`startswith` process indicators uses pattern matching. This avoids a Cartesian join between the full 30-day `DeviceProcessEvents` dataset and the complete indicator catalogue.

## Intune Deployed RMM Tooling

This section identifies remote access, remote assistance, and RMM tooling that is configured, deployed, or integrated through Microsoft Intune. It covers native Intune capabilities such as Remote Help, TeamViewer integrations, and third-party remote access applications deployed through Intune. Microsoft Graph is needed for these Tenant settings.

### Integrated Teamviewer

For Integrated Teamviewer settings please see: https://graph.microsoft.com/beta/deviceManagement/remoteAssistancePartners

Permissions: DeviceManagementServiceConfig.Read.All, DeviceManagementServiceConfig.ReadWrite.All

```json
{
  "@odata.type": "#microsoft.graph.remoteAssistancePartner",
  "id": "",
  "displayName": "Display Name",
  "onboardingUrl": "https://example.com/onboardingUrl/",
  "onboardingStatus": "onboarding",
  "lastConnectionDateTime": "YYYY-MM-DDThh:mm"
}

### Remote Help Settings

For default Intune Remote Help settings please see: https://graph.microsoft.com/beta/deviceManagement/remoteAssistanceSettings

Permissions: DeviceManagementServiceConfig.Read.All, DeviceManagementServiceConfig.ReadWrite.All, DeviceManagementConfiguration.Read.All, DeviceManagementConfiguration.ReadWrite.All

```json
{
  "value": {
    "@odata.type": "#microsoft.graph.remoteAssistanceSettings",
    "id": "cfef360e-360e-cfef-0e36-efcf0e36efcf",
    "remoteAssistanceState": "enabled",
    "allowSessionsToUnenrolledDevices": true,
    "blockChat": true
  }
}
```


### Remote Help Session Report

For sessions from Intune Remote Help see: https://graph.microsoft.com/beta/deviceManagement/reports/getRemoteAssistanceSessionsReport

Permissions: DeviceManagementServiceConfig.ReadWrite.All

POST the values to return a session.

```json
POST https://graph.microsoft.com/beta/deviceManagement/reports/getRemoteAssistanceSessionsReport

Content-type: application/json
Content-length: 278

{
  "name": "Name value",
  "select": [
    "Select value"
  ],
  "search": "Search value",
  "groupBy": [
    "Group By value"
  ],
  "orderBy": [
    "Order By value"
  ],
  "skip": 4,
  "top": 3,
  "sessionId": "Session Id value",
  "filter": "Filter value"
}
```

Example Result report

```json
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 103

{
  "value": "Z2V0UmVtb3RlQXNzaXN0YW5jZVNlc3Npb25zUmVwb3J0IEludHVuZSBEb2MgU2FtcGxlIC0xNzcyMDEwMDQ1" 
}
```

### Remote Help Session Report

For sessions from Intune Remote Help see: https://graph.microsoft.com/beta/deviceManagement/reports/getRemoteAssistanceSessionsReport

Permissions: DeviceManagementServiceConfig.ReadWrite.All

POST report parameters to return the Remote Help session report.

```json
POST https://graph.microsoft.com/beta/deviceManagement/reports/getRemoteAssistanceSessionsReport

Content-type: application/json
Content-length: 278

{
  "name": "Name value",
  "select": [
    "Select value"
  ],
  "search": "Search value",
  "groupBy": [
    "Group By value"
  ],
  "orderBy": [
    "Order By value"
  ],
  "skip": 4,
  "top": 3,
  "sessionId": "Session Id value",
  "filter": "Filter value"
}
```

Example Result report

```json
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 103

{
  "value": "Z2V0UmVtb3RlQXNzaXN0YW5jZVNlc3Npb25zUmVwb3J0IEludHVuZSBEb2MgU2FtcGxlIC0xNzcyMDEwMDQ1"
}
```

### Remote Help Active Sessions Report

For active Intune Remote Help sessions see: https://graph.microsoft.com/beta/deviceManagement/reports/getRemoteAssistanceMonitorActiveSessionsReport

Permissions: DeviceManagementServiceConfig.Read.All, DeviceManagementServiceConfig.ReadWrite.All, DeviceManagementConfiguration.Read.All, DeviceManagementConfiguration.ReadWrite.All

POST report parameters to return the active Remote Help sessions report.

```json
POST https://graph.microsoft.com/beta/deviceManagement/reports/getRemoteAssistanceMonitorActiveSessionsReport

Content-type: application/json
Content-length: 278

{
  "name": "Name value",
  "select": [
    "Select value"
  ],
  "search": "Search value",
  "groupBy": [
    "Group By value"
  ],
  "orderBy": [
    "Order By value"
  ],
  "skip": 4,
  "top": 3,
  "sessionId": "Session Id value",
  "filter": "Filter value"
}
```

Example Result report

```json
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 119

{
  "value": "Z2V0UmVtb3RlQXNzaXN0YW5jZU1vbml0b3JBY3RpdmVTZXNzaW9uc1JlcG9ydCBJbnR1bmUgRG9jIFNhbXBsZSA3Mjc0MTA5OTE="
}
```

### Remote Help Total Sessions Report

For the total number of Intune Remote Help sessions see: https://graph.microsoft.com/beta/deviceManagement/reports/getRemoteAssistanceMonitorTotalSessionsReport

Permissions: DeviceManagementServiceConfig.Read.All, DeviceManagementServiceConfig.ReadWrite.All, DeviceManagementConfiguration.Read.All, DeviceManagementConfiguration.ReadWrite.All

POST report parameters to return the total Remote Help sessions report.

```json
POST https://graph.microsoft.com/beta/deviceManagement/reports/getRemoteAssistanceMonitorTotalSessionsReport

Content-type: application/json
Content-length: 278

{
  "name": "Name value",
  "select": [
    "Select value"
  ],
  "search": "Search value",
  "groupBy": [
    "Group By value"
  ],
  "orderBy": [
    "Order By value"
  ],
  "skip": 4,
  "top": 3,
  "sessionId": "Session Id value",
  "filter": "Filter value"
}
```

Example Result report

```json
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 119

{
  "value": "Z2V0UmVtb3RlQXNzaXN0YW5jZU1vbml0b3JUb3RhbFNlc3Npb25zUmVwb3J0IEludHVuZSBEb2MgU2FtcGxlIDIwNDgyNjQ4ODE="
}
```

### Remote Help Average Session Time Report

For the average Intune Remote Help session duration see: https://graph.microsoft.com/beta/deviceManagement/reports/getRemoteAssistanceMonitorAvgSessionTimeReport

Permissions: DeviceManagementServiceConfig.Read.All, DeviceManagementServiceConfig.ReadWrite.All, DeviceManagementConfiguration.Read.All, DeviceManagementConfiguration.ReadWrite.All

POST report parameters to return the average Remote Help session time report.

```json
POST https://graph.microsoft.com/beta/deviceManagement/reports/getRemoteAssistanceMonitorAvgSessionTimeReport

Content-type: application/json
Content-length: 278

{
  "name": "Name value",
  "select": [
    "Select value"
  ],
  "search": "Search value",
  "groupBy": [
    "Group By value"
  ],
  "orderBy": [
    "Order By value"
  ],
  "skip": 4,
  "top": 3,
  "sessionId": "Session Id value",
  "filter": "Filter value"
}
```

Example Result report

```json
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 123

{
  "value": "Z2V0UmVtb3RlQXNzaXN0YW5jZU1vbml0b3JBdmdTZXNzaW9uVGltZVJlcG9ydCBJbnR1bmUgRG9jIFNhbXBsZSAtMTUzNDAwMDU5OQ=="
}
```
