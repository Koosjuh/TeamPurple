```kql
EasmAssetBanner_CL
| where isnotempty(Port_d)
| summarize OpenPorts=make_set(toint(Port_d)) by IPAddress=AssetName_s
| order by IPAddress asc
```

### Internet-exposed open ports per IP address

This query retrieves all discovered internet-facing open ports from the Microsoft Defender EASM banner data and groups them by IP address.

For each IP address, it creates a unique list of observed open ports, providing a concise overview of the externally exposed services identified during EASM scans.

This query is useful for quickly identifying an organization's external attack surface and determining which services are exposed to the Internet.
