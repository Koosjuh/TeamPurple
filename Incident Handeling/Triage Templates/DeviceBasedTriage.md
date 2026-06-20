## Malware Incidents

```text
#####
**- [File]  **
  - [Location] 
  - [DeviceFileEvents]
      - []
  - [DeviceProcessEvents]
      - []
  - [DeviceEvents]
      - []
  **- [SHA256] **
    - [DeviceFileEvents]
      - []
    - [DeviceProcessEvents]
      - []
    - [DeviceEvents]
      - []
  - [VirusTotal]
```

```KQL
union isfuzzy=true DeviceProcessEvents, DeviceEvents, DeviceFileEvents
| where FileName has "FILE" and DeviceName has "HOST"
| sort by Timestamp asc 

union isfuzzy=true DeviceProcessEvents, DeviceEvents, DeviceFileEvents
| where SHA256 == "SHA256"
| sort by Timestamp asc 
```
