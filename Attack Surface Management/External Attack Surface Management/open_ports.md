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

```kql
let HighRiskPorts = dynamic([21,22,23,25,53,135,139,445,1433,1521,2049,3306,3389,5432,5900,6379,9200,11211,27017]);
EasmAssetBanner_CL
| where isnotempty(Port_d)
| extend Port = toint(Port_d)
| summarize
    OpenPorts = make_set(Port),
    HighRiskOpenPorts = make_set_if(strcat("!!! ", tostring(Port)), Port in (HighRiskPorts))
by IPAddress = AssetName_s
| extend HasHighRiskPorts = array_length(HighRiskOpenPorts) > 0
| order by HasHighRiskPorts desc, IPAddress asc
```
### Internet-exposed open ports with high-risk identification

This query retrieves all internet-facing open ports identified by Microsoft Defender EASM and groups them by IP address.

In addition to listing all observed open ports, the query compares each port against a predefined list of commonly targeted or high-risk services, such as SSH, SMB, RDP, SQL Server, and Elasticsearch. Any matching ports are highlighted in a separate column and prefixed with `!!!` to make them easy to identify during review.

This provides a quick overview of an organization's external attack surface while helping prioritize systems that expose services commonly associated with remote administration, file sharing, databases, or other high-value attack vectors.
