# Kerberos Abuse Hunting Queries for Microsoft Defender XDR

This document contains KQL hunting queries for common Kerberos abuse tooling, plus complementary NTLM Pass-the-Hash hunting queries.

## Purpose

These queries are intended to help identify:
- Common **Mimikatz** Kerberos ticket abuse activity
- Common **Rubeus** Kerberos abuse activity
- Common **NTLM Pass-the-Hash** activity and related tooling

## Notes

- These queries are **behavior-based** and primarily rely on command-line artifacts.
- They are useful for hunting and triage, but they are **not sufficient on their own** to prove malicious activity.
- Red team activity, labs, detection tests, and admin tooling can create overlaps.
- NTLM Pass-the-Hash often leaves **indirect evidence**, so correlation with logon, network, and lateral movement telemetry is recommended.

---

## 1. Common Mimikatz Kerberos command lines

```kusto
// Common Mimikatz command lines 
DeviceProcessEvents
| where Timestamp > ago(5d)
| where ProcessCommandLine has_any ('sekurlsa::tickets /export', 'kerberos::ptt')
| project Timestamp, AccountName, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
```

### What this may indicate

- Export of Kerberos tickets from memory
- Pass-the-Ticket activity using imported `.kirbi` tickets
- Interactive use of Mimikatz for credential access or ticket manipulation

### Typical follow-up

- Review the full process tree
- Check whether the parent process was PowerShell, cmd.exe, rundll32.exe, or a remote execution mechanism
- Correlate with suspicious authentication or lateral movement shortly after execution

---

## 2. Common Rubeus command lines

```kusto
// Common Rubeus command lines
DeviceProcessEvents
| where Timestamp > ago(5d)
| where ProcessCommandLine has_any ('ptt /ticket', ' monitor /interval', ' asktgt', ' asktgs', ' golden', ' silver', ' kerberoast', ' asreproast', ' renew', ' brute')
| project Timestamp, AccountName, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
```

### What this may indicate

- Pass-the-Ticket with Rubeus
- TGT or TGS requests outside normal workflows
- Kerberoasting or AS-REP roasting
- Ticket renewal, monitoring, or forged ticket abuse

### Typical follow-up

- Confirm whether the file name, signer, and path are expected
- Check for encoded PowerShell or renamed binaries
- Correlate with unusual service ticket volume, lateral movement, or account misuse

---

## 3. NTLM Pass-the-Hash via Mimikatz

```kusto
DeviceProcessEvents
| where Timestamp > ago(5d)
| where ProcessCommandLine has_any ("sekurlsa::pth", "sekurlsa::pth /user:", "sekurlsa::pth /ntlm:", "sekurlsa::pth /domain:")
| project Timestamp, AccountName, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
```

### What this may indicate

- Classic Mimikatz Pass-the-Hash execution
- Creation of a process under a supplied NTLM hash
- Staged lateral movement or privileged access abuse

### Why this complements the Kerberos queries

The Kerberos queries focus on ticket abuse. This query specifically covers **NTLM hash-based authentication abuse**, which is a different credential abuse path and is often used when Kerberos ticket abuse is not the chosen technique.

---

## 4. NTLM Pass-the-Hash and hash-parameter tooling

```kusto
DeviceProcessEvents
| where Timestamp > ago(5d)
| where ProcessCommandLine has_any ("-hashes", "/hashes:", "pth", "pass-the-hash", "ntlm hash", "/ntlm:")
    or ProcessCommandLine matches regex @"(?i)sekurlsa::pth\b"
| project Timestamp, AccountName, DeviceName, FolderPath, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### What this may indicate

- Offensive tooling using NTLM hashes as authentication material
- Mimikatz or other tooling that exposes hash-based parameters
- Potential Impacket-style operator activity where command lines are visible on the endpoint

### Caveat

This query is broader and can produce more noise. It is best used as a hunting query and then narrowed with exclusions for known tools or testing activity.

---

## 5. Suspicious remote execution tools often associated with Pass-the-Hash

```kusto
DeviceProcessEvents
| where Timestamp > ago(5d)
| where FileName in~ ("psexec.exe", "paexec.exe", "wmic.exe", "cmd.exe", "powershell.exe")
| where ProcessCommandLine has_any ("\\", "admin$", "ipc$", "process call create", "wmic /node", "sc \\", "psexec", "paexec")
| project Timestamp, AccountName, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### What this may indicate

- Remote service creation
- Remote command execution over SMB, SCM, or WMI
- Post-authentication lateral movement that may follow successful Pass-the-Hash

### Why this matters

Pass-the-Hash is often only one step in the chain. The actual impact commonly appears as **remote execution**, **service creation**, **WMI process execution**, or **SMB-admin-share access**.

---

## 6. Correlate suspicious NTLM logons with possible lateral movement

```kusto
DeviceLogonEvents
| where Timestamp > ago(5d)
| where LogonType in~ ("Network", "RemoteInteractive")
| where Protocol =~ "NTLM"
| project Timestamp, DeviceName, AccountName, RemoteIP, LogonType, Protocol, ActionType
| order by Timestamp desc
```
## 7. Optional correlation query for likely Pass-the-Hash chains

```kusto
let SuspiciousPthProcess =
    DeviceProcessEvents
    | where Timestamp > ago(5d)
    | where ProcessCommandLine has_any ("sekurlsa::pth", "/ntlm:", "-hashes")
    | project PthTimestamp=Timestamp, DeviceId, DeviceName, AccountName, PthFileName=FileName, PthCommandLine=ProcessCommandLine;
let NtLmLogons =
    DeviceLogonEvents
    | where Timestamp > ago(5d)
    | where Protocol =~ "NTLM"
    | project LogonTimestamp=Timestamp, DeviceId, DeviceName, AccountName, RemoteIP, LogonType, Protocol;
SuspiciousPthProcess
| join kind=inner NtLmLogons on DeviceId
| where LogonTimestamp between (PthTimestamp .. PthTimestamp + 30m)
| project PthTimestamp, LogonTimestamp, DeviceName, AccountName, RemoteIP, LogonType, Protocol, PthFileName, PthCommandLine
| order by PthTimestamp desc
```

### Purpose

This correlation query looks for:
- a suspicious Pass-the-Hash related process artifact
- followed by NTLM authentication on the same device within 30 minutes

This is not proof, but it is a useful hunting starting point.

---

## Analyst guidance

### High-confidence indicators
- `sekurlsa::pth`
- `kerberos::ptt`
- `Rubeus kerberoast`, `asreproast`, `golden`, `silver`
- hash parameters combined with remote execution tooling

### Medium-confidence indicators
- NTLM network logons on sensitive systems
- remote admin-share execution
- WMI remote process creation
- suspicious parent-child process chains

### Recommended enrichment
- DeviceLogonEvents
- DeviceNetworkEvents
- DeviceFileEvents
- IdentityLogonEvents or SigninLogs where relevant
- Service creation telemetry
- Remote IP reputation and asset criticality

## Suggested exclusions

Consider excluding:
- approved red team activity
- known admin jump boxes
- sanctioned IR or detection engineering tests
- lab devices
- known credential audit tooling used by defenders

## Conclusion

Use the Kerberos queries and the NTLM Pass-the-Hash queries together. Kerberos ticket abuse and NTLM hash abuse are closely related from an operator perspective, but they do not leave the same artifacts. Best results come from combining process telemetry with authentication and lateral movement evidence.
