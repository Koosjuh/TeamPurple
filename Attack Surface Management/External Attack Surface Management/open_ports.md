```kql
let RiskyPorts = externaldata(
    RiskPort:int,
    Service:string,
    RiskCategory:string,
    Comment:string
)
[
    "https://raw.githubusercontent.com/Koosjuh/TeamPurple/refs/heads/main/Attack%20Surface%20Management/External%20Attack%20Surface%20Management/risky_ports.csv"
]
with (
    format = "csv",
    ignoreFirstRecord = true
);
let EasmOpenPorts =
    EasmAssetBanner_CL
    | where isnotempty(Port_d)
    | extend Port = toint(Port_d)
    | project
        IPAddress = AssetName_s,
        Port,
        Banner = Banner_s,
        BannerLastSeen = BannerLastSeen_t;
let AllOpenPorts =
    EasmOpenPorts
    | summarize OpenPorts = make_set(Port) by IPAddress;
let RiskyOpenPorts =
    EasmOpenPorts
    | join kind=inner RiskyPorts on $left.Port == $right.RiskPort
    | extend RiskyPort = strcat(
        "[",
        Service,
        "(",
        tostring(Port),
        ") - ",
        RiskCategory,
        iff(isempty(Comment), "", strcat(" - ", Comment)),
        "]"
    )
    | summarize
        RiskyPorts = make_set(RiskyPort),
        RiskyPortDetails = make_set(
            strcat(
                "Port=", tostring(Port),
                "; Service=", Service,
                "; RiskCategory=", RiskCategory,
                iff(isempty(Comment), "", strcat("; Comment=", Comment)),
                "; LastSeen=", tostring(BannerLastSeen)
            )
        )
        by IPAddress;
AllOpenPorts
| join kind=leftouter RiskyOpenPorts on IPAddress
| project IPAddress, OpenPorts, RiskyPorts, RiskyPortDetails
| order by IPAddress asc
```

# Microsoft Defender EASM Risky Open Ports Query

This KQL query identifies internet-facing open ports discovered by Microsoft Defender External Attack Surface Management and enriches them with a custom risky-port reference list hosted in GitHub.

## Purpose

The query provides a concise overview of exposed services per IP address and highlights ports that match a predefined risky-port catalog.

It helps answer:

- Which ports are exposed per public IP address?
- Which exposed ports are considered risky?
- What service and risk category is associated with each risky port?
- When was the risky port last observed by EASM?

## Data sources

### Microsoft Defender EASM

The query uses the following Log Analytics table:

EasmAssetBanner_CL

#### Required columns:

AssetName_s
Port_d
Banner_s
BannerLastSeen_t
Risky ports CSV

The query loads a GitHub-hosted CSV using externaldata.

#### CSV format:

Port,Service,RiskCategory,Comment
22,SSH,Remote Administration,
3389,RDP,Remote Administration,
445,SMB,Windows File Sharing,

## Output columns

| Column | Description |
|---------|-------------|
| **IPAddress** | Public IP address identified by Microsoft Defender EASM. |
| **OpenPorts** | A complete list of all internet-facing open ports observed for the IP address. |
| **RiskyPorts** | A filtered list of ports that match entries in the risky port reference file, displayed as `[Service(Port) - RiskCategory - Comment]`. |
| **RiskyPortDetails** | Detailed information for each matched risky port, including the port number, service name, risk category, optional analyst comment, and the last time the service banner was observed by EASM. |

The query does not automatically confirm exploitability. It identifies exposed services that should be reviewed because they match the risky-port reference list.

Risk depends on context, including business purpose, source restrictions, authentication, patch level, and compensating controls.
