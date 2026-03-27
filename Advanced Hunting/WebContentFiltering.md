```kql
DeviceEvents
| where ActionType in ("SmartScreenUrlWarning", "ExploitGuardNetworkProtectionBlocked", "ExploitGuardNetworkProtectionAudited")
| extend AF = parse_json(AdditionalFields)
| project Timestamp, DeviceName, ActionType, RemoteUrl, RemoteIP,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          Experience=tostring(AF.Experience),
          ResponseCategory=tostring(AF.ResponseCategory),
          DisplayName=tostring(AF.DisplayName)
| order by Timestamp desc
```
