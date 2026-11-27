## URL Triage

```text
- [Host]
  - [DeviceNetworkEvents]

- [Email]
  - [NetworkMessageID]
  - [UrlClickEvents]

-[URL]
  - [Virustotal]
  - [VM - SourceOS: <OS>]
```

Check to see if a link was clicked from mail


URL ClickEvents and DeviceNetworkevents

```kql
let Lookback = 30d;
let Indicators = dynamic([
"",
""
]);
let Clicks =
    UrlClickEvents
    | where Timestamp > ago(Lookback)
    | mv-apply Indicator = Indicators to typeof(string) on (
        where Url contains Indicator
    )
    | project Timestamp, Source = "UrlClickEvents", MatchedIndicator = Indicator,
              Url, Account = AccountUpn, ActionType, IPAddress, IsClickedThrough, NetworkMessageId;
let Network =
    DeviceNetworkEvents
    | where Timestamp > ago(Lookback)
    | where isnotempty(RemoteUrl)
    | mv-apply Indicator = Indicators to typeof(string) on (
        where RemoteUrl contains Indicator
    )
    | project Timestamp, Source = "DeviceNetworkEvents", MatchedIndicator = Indicator,
              Url = RemoteUrl, Account = InitiatingProcessAccountUpn, ActionType,
              DeviceName, RemoteIP, InitiatingProcessFileName;
union Clicks, Network
| sort by Timestamp desc
```

```kql
EmailEvents
| where SenderFromAddress contains "SENDER" //put in sender
| join kind=inner (UrlClickEvents) on NetworkMessageId
| project Timestamp, RecipientEmailAddress, AccountUpn, Url, ActionType, IsClickedThrough, UrlChain, IPAddress
```
