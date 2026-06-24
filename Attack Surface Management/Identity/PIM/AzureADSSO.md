# AZUREADSSOACC Kerberos Activity Query 

This query searches Windows Security Events for Kerberos service ticket requests (Event ID 4769) involving the `AZUREADSSOACC$` account over the last 120 days.

## What the query does

### Filter the timeframe

Searches the `SecurityEvent` table for events from the last 120 days.

### Filter Windows Security Events

Limits the results to events from the Windows Security log.

### Filter Kerberos Service Ticket Requests

Filters on Event ID `4769`, which indicates that a Kerberos service ticket was requested from a Domain Controller.

### Extract relevant fields

Parses the event XML and extracts:

* `ServiceName` - The service/SPN being accessed (for example `HOST/server01`, `CIFS/fileserver01`, or `HTTP/webapp`).
* `TargetUserName` - The account requesting the Kerberos ticket.

### Search for AZUREADSSOACC$

Filters events where the string `AZUREADSSOACC$` appears anywhere within the event data.

This commonly means:

* `TargetUserName` is `AZUREADSSOACC$`
* The account appears elsewhere within the event details

### Rename the username field

Creates a new column named `SubjectUserName_` containing the value of `TargetUserName`.

### Summarize the results

Groups events by:

* Day
* Service Name
* Username

And returns the number of occurrences for each combination.

## Use Case

This query is typically used to:

* Validate Microsoft Entra Seamless SSO usage
* Monitor activity of the `AZUREADSSOACC$` account
* Identify which services are generating Kerberos ticket requests
* Establish a baseline for Kerberos authentication activity
* Investigate unusual authentication patterns involving Seamless SSO

Courtesy of Daan Bentsnijder Wortell

```kql
let user_entity = "AZUREADSSOACC$";
let days_ago = ago(120d); // Set the time. Example: 8h, 7d
SecurityEvent
| where TimeGenerated > days_ago
| where Channel == "Security"
| where EventID == 4769
| parse EventData with * '<Data Name="ServiceName">' ServiceName '</Data>' *
| parse EventData with * '<Data Name="TargetUserName">' TargetUserName '</Data>' *
| where * has user_entity
| extend SubjectUserName_ = TargetUserName
| summarize count() by bin(TimeGenerated, 1d), ServiceName, SubjectUserName_
```
