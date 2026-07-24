## URL Triage

```text
##### 
- [DeviceNetworkEvents]
- [UrlClickEvents]
- [Virustotal]
- [VM - SourceOS: <OS>]
```

Check to see if a link was clicked from mail

```kql
EmailEvents
| where SenderFromAddress contains "SENDER" //put in sender
| join kind=inner (UrlClickEvents) on NetworkMessageId
| project Timestamp, RecipientEmailAddress, AccountUpn, Url, ActionType, IsClickedThrough, UrlChain, IPAddress
```
