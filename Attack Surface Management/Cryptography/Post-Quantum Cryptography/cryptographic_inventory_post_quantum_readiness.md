# Cryptographic Inventory & Post-Quantum Readiness

## Contents

**Part 1 — External Attack Surface**
- Why this matters now · What this assessment can and cannot see · Recommended customer actions (phased)
- External inventory queries 1–7 (Defender EASM): signature algorithms · weak/deprecated algorithms · quantum-vulnerable keys · legacy TLS insights · self-signed/private-PKI certs · migration prioritization matrix · certificate lifetimes

**Part 2 — Internal Layers**
- Layered coverage model
- **Layer 1 — Entra ID:** 1.1 legacy TLS (enumerate-first) · 1.2 legacy authentication protocols · 1.3 workload identities
- **Layer 2 — On-prem AD:** 2.1 weak Kerberos encryption · 2.2 NTLMv1 · 2.3 Schannel negotiation · 2.4a AD CS templates via logs · 2.4b PKI full inventory (gap-fill) · 2.5 Defender for Identity coverage
- **Layer 3 — Device:** 3.1 crypto library inventory (KPI + attribution + load evidence) · 3.2 TLS config compliance · 3.3 Schannel drift
- **Layer 4 — Application/cloud:** 4.0 resource existence first · 4.1 Azure ingress TLS · 4.2 minimum TLS policy (ARG) · 4.3 Key Vault inventory + usage overlay

**Cross-cutting**
- Symmetric cryptography · Scope boundaries · Continuous monitoring (rules R1–R7 + maintenance model) · External dependencies · Executive maturity score · Migration roadmap · Consolidated reporting view · Follow-up engagements

## How to use this document

This is a **reusable assessment template**, validated end-to-end against a live environment. Per engagement: (1) run the queries section by section, enumeration-first; (2) record every result — including empty ones, with their coverage label — into the companion **findings matrix** (`findings-matrix-template.md`); (3) score maturity per the level criteria, applying the coverage cap; (4) seed the detection watchlists from the findings and deploy the R1–R7 pack; (5) the filled matrix plus this document's narrative sections *is* the customer report. Placeholders throughout use `⟨angle brackets⟩`. Queries may fail per tenant on schema variance — that is expected and diagnostic (see the schema-defensiveness convention below); the fix patterns are embedded in each section.

## How to read this document (legend)

**Coverage vocabulary** — every zero or empty result carries one of three labels, and the distinction is the methodological spine of the assessment:
- **Verified clean** — telemetry present, finding absent (e.g. "0 of N sign-ins over legacy TLS, field emitted on all N"). The strong claim.
- **Not measured** — telemetry absent or prerequisite missing. A coverage gap, itself a finding; never reported as a zero.
- **Not applicable** — the resource/protocol does not exist in the environment.

**Query surfaces** — queries run in different planes that do not share tables; each section states its surface:
- *Sentinel / Log Analytics* — `SigninLogs`, `SecurityEvent`, `Event`, `AzureDiagnostics`, `Easm*_CL`
- *Defender XDR Advanced Hunting* — `Device*`, `Identity*` tables (unified portal merges both surfaces if the Sentinel workspace is onboarded — required for the maturity composite query)
- *Azure Resource Graph* — resource configuration, not telemetry (4.0, 4.2)
- *CLI / PowerShell gap-fill* — where no log-based inventory exists (certutil, PSPKI, az cli, Graph)

**Working conventions**
- **Enumerate first:** before filtering on any value (`getschema`, `distinct`, key/ActionType enumeration) — establishes what is measurable and prevents misreading empty results.
- **Evidence ladder (device findings):** on disk → attributed (path/vendor) → executing (process events) → network-active. Climbing it can downgrade severity as legitimately as escalate it.
- **Schema defensiveness:** `column_ifexists()` + `EventData` extraction where workspaces differ; `todynamic()` where LA exports type JSON as string.
- **Gap-fill:** a labeled boundary where telemetry ends and direct enumeration takes over — named explicitly rather than silently omitted.
- **First-seen detection (R1–R7):** 13-day rolling baseline + accepted-debt watchlist; remediation *removes* watchlist entries so regressions re-alert.

---

## Part 1 — External Attack Surface

## Why this matters now

The cryptography protecting your external attack surface today — RSA and elliptic-curve (ECDSA/ECDH) — is secure against classical computers but will be breakable by a cryptographically relevant quantum computer (CRQC). The practical risk is not the arrival date of such a machine: it is **Harvest Now, Decrypt Later (HNDL)**. Adversaries are recording encrypted traffic today with the intent of decrypting it once quantum capability exists. Any data with a confidentiality lifetime beyond roughly 2030–2035 is already at risk.

This is no longer only a technical concern. It is becoming a compliance obligation:

- **NIST** finalized the first post-quantum standards in August 2024: **FIPS 203 (ML-KEM)** for key exchange, **FIPS 204 (ML-DSA)** and **FIPS 205 (SLH-DSA)** for digital signatures.
- The **EU Coordinated Implementation Roadmap** (NIS Cooperation Group, June 2025) sets three milestones: cryptographic **inventories and national transition planning by end of 2026**, migration of **high-risk/critical use cases by 2030**, and **medium-risk use cases by 2035**.
- The European Commission has proposed (COM(2026) 13, January 2026) writing PQC transition explicitly into the **NIS2 Directive** as a new Article 7(2)(k). For NIS2-regulated entities, PQC migration planning is moving from "best practice" to a named legal requirement.
- NIS2 already requires "state-of-the-art" cryptography policies. Demonstrating a cryptographic inventory and migration plan is the accepted evidence of compliance.

**The first mandated step in every framework is the same: know what cryptography you are running.** This section provides that inventory for your internet-facing estate.

## What this assessment can and cannot see

Our External Attack Surface Management (EASM) platform observes the certificates and TLS configurations presented by your public-facing assets. Two honest scoping notes:

1. **Every certificate we observe today is quantum-vulnerable.** All public TLS certificates currently use RSA or ECDSA — no public CA issues PQC certificates yet. The value of this inventory is therefore not "which assets are PQC-ready" but **which assets carry the highest exposure and migration cost**, so remediation can be sequenced against the 2030/2035 deadlines.
2. **PQC key exchange is not visible in certificate data.** Hybrid key agreement (e.g. X25519MLKEM768, now default in major browsers) is negotiated in the TLS handshake, not encoded in the certificate. Measuring actual PQC handshake support requires active scanning, which we can perform as a follow-up engagement.

What the inventory *does* reliably surface, and what this section reports on:

| Finding | Why it matters for PQC migration |
|---|---|
| Signature algorithm distribution (SHA-1, MD5, weak RSA) | Legacy algorithms indicate systems that cannot follow modern crypto — these will be the hardest to migrate and should be prioritized or decommissioned |
| Key algorithm and key size (RSA-1024/2048, ECC curves) | Maps the quantum-vulnerable footprint; small keys signal aging infrastructure |
| Legacy TLS protocol versions (SSLv3, TLS 1.0/1.1) | Endpoints stuck on old protocols will not support hybrid PQC cipher suites; protocol hygiene is a migration prerequisite |
| Self-signed and internally-issued certificates on public assets | Indicates private PKI dependencies — root/issuing CA migration to PQC has the longest lead time of any component |
| Certificate lifetimes and renewal patterns | Long-lived certificates and manual renewal processes are incompatible with the crypto-agility PQC migration demands |

## Recommended customer actions — phased

**Immediate (this quarter)**
1. **Establish the cryptographic inventory** (this report is that inventory; keep the coverage table current).
2. **Remove classical weaknesses:** SHA-1 signatures, RSA < 2048, TLS 1.0/1.1, EOL crypto libraries, legacy authentication protocols. These are both current risk and migration blockers.
3. **Raise symmetric strength where configurable:** BitLocker to XTS-AES-256, AES-256 in IPsec/backup — the one PQC-readiness action completable today.
4. **Request vendor PQC roadmap statements** for every product in the External Dependencies section below.

**Mid-term (2027–2028)**
5. **Build crypto-agility:** certificate lifecycle automation (ACME/CLM), short-lived certs, crypto parameters out of code and into config.
6. **Modernize the private PKI:** v3/KSP templates, NDES → Cloud PKI decision, and **plan** the root CA transition ceremony (12–18 month lead time).
7. **Complete the NTLM elimination ladder:** v2 to zero via Restrict-NTLM audit → dependency remediation → disable, landing on Kerberos-only with AES-only tickets (v1 elimination and the AES landing-zone prep belong in Immediate).
8. **Classify data by confidentiality lifetime** and assign HNDL risk buckets; contract crypto-agility clauses into renewals (CRA-aligned).

**Long-term (2029–2035)**
9. **Execute PQC migration by bucket:** hybrid key exchange for high-risk transit, KEK rewrap and PKI re-issuance as platforms ship PQC support — high-risk complete by 2030, remainder by 2035 per the EU roadmap.

---

## KQL — External Inventory Queries (Defender EASM → Log Analytics)

> **Schema note:** these queries target the legacy custom-log export (`_CL` tables, `_s`/`_d`/`_t` typed columns). Run `TableName | getschema` and `| distinct <column>` first to confirm exact field names in the target workspace — EASM export schemas vary by connector version. Time filters assume daily snapshot ingestion; the `arg_max` pattern deduplicates to the latest observation per asset.

## 1. Certificate signature algorithm distribution (headline chart)

```kql
// Distribution of signature algorithms across all observed live certificates
EasmSslCertAsset_CL
| where TimeGenerated > ago(7d)
| summarize arg_max(TimeGenerated, *) by Sha1_s
| summarize CertCount = count() by SigAlgName_s
| order by CertCount desc
| render piechart
```

## 2. Weak / deprecated signature algorithms (immediate findings)

```kql
// SHA-1, MD5, or otherwise deprecated signature algorithms still live
EasmSslCertAsset_CL
| where TimeGenerated > ago(7d)
| summarize arg_max(TimeGenerated, *) by Sha1_s
| where SigAlgName_s has_any ("SHA1", "MD5", "MD2")
| project CertName = tostring(SubjectCommonNames_s),
          Issuer = tostring(IssuerCommonNames_s),
          SigAlgName_s,
          KeySize = KeySize_d,
          ValidUntil = InvalidAfter_t,
          SelfSigned_b
| order by ValidUntil asc
```

## 3. Quantum-vulnerable key inventory by algorithm and key size

```kql
// The HNDL exposure map: everything here is quantum-vulnerable by definition.
// Buckets small RSA keys separately — those are also classically weak.
EasmSslCertAsset_CL
| where TimeGenerated > ago(7d)
| summarize arg_max(TimeGenerated, *) by Sha1_s
| extend CryptoClass = case(
    KeyAlgorithm_s has "RSA" and KeySize_d < 2048, "RSA <2048 (weak today + quantum-vulnerable)",
    KeyAlgorithm_s has "RSA", strcat("RSA-", tostring(toint(KeySize_d)), " (quantum-vulnerable)"),
    KeyAlgorithm_s has_any ("EC", "ECDSA"), "ECC (quantum-vulnerable)",
    strcat("Other: ", KeyAlgorithm_s))
| summarize CertCount = count() by CryptoClass
| order by CertCount desc
```

## 4. Legacy TLS protocol exposure via EASM insights

```kql
// SSL/TLS-related risk observations, by severity category.
// Verify insight naming first: EasmRisk_CL | distinct RiskName_s
EasmRisk_CL
| where TimeGenerated > ago(7d)
| where RiskName_s has_any ("SSL", "TLS", "Certificate")
| summarize arg_max(TimeGenerated, *) by RiskName_s
| project RiskName_s, Severity = CategoryName_s, AssetCount = toint(Count_d)
| order by Severity asc, AssetCount desc
```

## 5. Self-signed and private-PKI certificates on public assets

```kql
// Public-facing assets presenting self-signed or internally issued certs.
// These indicate private PKI dependencies — longest PQC migration lead time.
EasmSslCertAsset_CL
| where TimeGenerated > ago(7d)
| summarize arg_max(TimeGenerated, *) by Sha1_s
| where SelfSigned_b == true
   or IssuerCommonNames_s has_any ("internal", "corp", "local", "lan")
| project CertName = tostring(SubjectCommonNames_s),
          Issuer = tostring(IssuerCommonNames_s),
          KeyAlgorithm_s, KeySize_d,
          ValidUntil = InvalidAfter_t
| order by ValidUntil asc
```

## 6. Migration prioritization matrix (report table)

```kql
// Combines weakness signals into a single prioritized remediation table.
// Priority 1 = classically weak now; Priority 2 = expiring soon (natural
// migration moment — renew onto crypto-agile infrastructure); Priority 3 = rest.
EasmSslCertAsset_CL
| where TimeGenerated > ago(7d)
| summarize arg_max(TimeGenerated, *) by Sha1_s
| extend WeakSig = SigAlgName_s has_any ("SHA1", "MD5"),
         WeakKey = KeyAlgorithm_s has "RSA" and KeySize_d < 2048,
         ExpiringSoon = InvalidAfter_t < now() + 90d
| extend Priority = case(
    WeakSig or WeakKey, 1,
    ExpiringSoon, 2,
    3)
| project Priority,
          CertName = tostring(SubjectCommonNames_s),
          SigAlgName_s, KeyAlgorithm_s, KeySize_d,
          ValidUntil = InvalidAfter_t,
          WeakSig, WeakKey, ExpiringSoon
| order by Priority asc, ValidUntil asc
```

## 7. Certificate lifetime / crypto-agility indicator

```kql
// Long-lived certificates suggest manual issuance processes incompatible
// with the frequent rotation PQC migration (and 47-day CA/B rules) will demand.
EasmSslCertAsset_CL
| where TimeGenerated > ago(7d)
| summarize arg_max(TimeGenerated, *) by Sha1_s
| extend LifetimeDays = datetime_diff('day', InvalidAfter_t, InvalidBefore_t)
| summarize CertCount = count() by LifetimeBucket = case(
    LifetimeDays <= 90, "≤90 days (automated, agile)",
    LifetimeDays <= 398, "91–398 days (standard)",
    LifetimeDays <= 825, "399–825 days (legacy issuance)",
    "> 825 days (very long-lived — agility risk)")
| order by CertCount desc
```

---

## Part 2 — Internal Layers

The external attack surface assessment (previous section) covers the outside-in view. The EU Coordinated Implementation Roadmap, however, expects a **complete cryptographic inventory and dependency map** — and the highest-risk, longest-lead-time cryptography lives inside the environment: identity protocols, PKI, endpoint crypto libraries, and application configurations. This section extends the inventory across four internal layers using telemetry already flowing into Microsoft Sentinel and Defender XDR, and explicitly identifies where log-based inventory ends and active discovery must take over.

## Layered coverage model

| Layer | Primary telemetry | Coverage | Gap-fill required |
|---|---|---|---|
| Identity (Entra ID) | SigninLogs, service principal sign-ins | TLS versions per sign-in, legacy auth protocols | Graph API for app credential inventory |
| Identity (on-prem AD) | SecurityEvent (DC events), Event (Schannel), MDI Identity* tables + ISPM assessments | Kerberos encryption types, NTLM versions, negotiated TLS, config drift | AD CS full inventory, `msDS-SupportedEncryptionTypes` enumeration via PowerShell |
| Device | Defender TVM tables, DeviceRegistryEvents | Crypto library versions, TLS configuration compliance, config drift | Code-signing cert algorithms (not in telemetry) |
| Application / cloud | AzureDiagnostics, Azure Resource Graph | Negotiated TLS at load balancers, minimum TLS policies | Key Vault key inventory via CLI, app-embedded crypto |

---

## Layer 1 — Entra ID

### 1.1 Legacy TLS at the identity layer — enumerate first, then measure

Entra ID endpoints have enforced TLS 1.2+ since 2022, but tenants may still emit the "Legacy TLS (TLS 1.0, 1.1, 3DES)" key in `AuthenticationProcessingDetails` on every sign-in (with value `False`). **Always run the enumeration query first** — it establishes whether the field is measurable in this tenant, which determines how an empty filtered result must be interpreted:

- Key present on all sign-ins + zero `True` values → **verified measured zero** ("0 of N sign-ins over legacy TLS") — the strong claim
- Key absent entirely → **mitigated by platform enforcement, not measured** — report it as such, never as a zero

```kql
// Step 1 — enumerate which processing-detail keys this tenant emits
SigninLogs
| where TimeGenerated > ago(7d)
| extend APD = todynamic(AuthenticationProcessingDetails) // field is string-typed in LA export
| mv-expand APD
| summarize SignInCount = count() by DetailKey = tostring(APD.key)
| order by SignInCount desc
```

```kql
// Step 2 — if the Legacy TLS key is emitted, measure it
SigninLogs
| where TimeGenerated > ago(30d)
| where AuthenticationProcessingDetails has "Legacy TLS"
| extend APD = todynamic(AuthenticationProcessingDetails)
| mv-expand APD
| extend DetailKey = tostring(APD.key), DetailValue = tostring(APD.value)
| where DetailKey has "Legacy TLS" and DetailValue =~ "True"
| summarize SignInCount = count(),
            DistinctUsers = dcount(UserPrincipalName),
            SampleApps = make_set(AppDisplayName, 10)
         by ClientAppUsed, UserAgent
| order by SignInCount desc
```

Residual client-crypto risk at the identity layer surfaces through two further paths: **legacy authentication protocols** (1.2 below) and **TLS termination points in front of Entra** — AD FS farms, application proxy connectors, and reverse proxies — which fall under the on-prem Schannel inventory in Layer 2. Ensure the diagnostic setting exports `NonInteractiveUserSignInLogs` (`AADNonInteractiveUserSignInLogs` table) as well; legacy clients concentrate there.

### 1.2 Legacy authentication protocols

Basic/legacy auth protocols correlate strongly with clients pinned to obsolete crypto stacks. These are migration blockers regardless of the PQC discussion and belong in the same remediation wave.

```kql
SigninLogs
| where TimeGenerated > ago(30d)
| where ClientAppUsed in ("Exchange ActiveSync", "IMAP4", "POP3",
                          "Authenticated SMTP", "MAPI Over HTTP", "Other clients")
| summarize SignInCount = count(),
            DistinctUsers = dcount(UserPrincipalName),
            LastSeen = max(TimeGenerated)
         by ClientAppUsed, AppDisplayName
| order by SignInCount desc
```

Interpretation notes: `Exchange ActiveSync` no longer implies basic authentication (disabled by Microsoft in Exchange Online since early 2023) — it typically means native mail apps on EAS with modern auth, still a migration target (Outlook mobile) due to weaker Conditional Access and token-protection coverage. `Authenticated SMTP` **is** live basic auth (the one opt-in exception Microsoft left) — almost always printers, scanners, or applications with hardcoded credentials, and typically old firmware with old TLS stacks. Drill down to attributable identities before writing remediation actions:

```kql
SigninLogs
| where TimeGenerated > ago(30d)
| where ClientAppUsed in ("Exchange ActiveSync", "Authenticated SMTP", "Other clients")
| where ResultType == 0   // successful sign-ins only
| summarize SignInCount = count(),
            LastSeen = max(TimeGenerated),
            SourceIPs = make_set(IPAddress, 5)
         by ClientAppUsed, UserPrincipalName, UserAgent
| order by ClientAppUsed asc, SignInCount desc
// UserAgent usually names the device for SMTP AUTH accounts;
// run the same against AADNonInteractiveUserSignInLogs for service-style usage
```

### 1.3 Service principal / workload identity sign-in surface

Workload identities authenticate with client secrets or certificates. Certificate-based credentials on app registrations are RSA today and part of the quantum-vulnerable inventory; secrets are worse for different reasons.

```kql
AADServicePrincipalSignInLogs
| where TimeGenerated > ago(30d)
| summarize SignInCount = count(), LastSeen = max(TimeGenerated)
         by ServicePrincipalName, AppId, ResourceDisplayName
| order by SignInCount desc
```

> **Gap-fill:** sign-in logs do not expose credential type or key parameters. Enumerate app registration credentials (secret vs. certificate, key size, expiry) via Microsoft Graph:
> `Get-MgApplication -All -Property DisplayName,KeyCredentials,PasswordCredentials` — export `KeyCredentials` for algorithm/lifetime analysis. This list is the Entra half of the PKI dependency map.

---

## Layer 2 — On-premises Active Directory

> **Prerequisite:** queries 2.1–2.2 require domain controller Security events ingested via AMA/legacy agent (`SecurityEvent` table). If the customer runs Defender for Identity only, equivalent hunting is possible in `IdentityLogonEvents` (noted per query).

### 2.1 Weak Kerberos ticket encryption (RC4 / DES)

The highest-signal on-prem crypto finding. RC4 tickets (`0x17`) typically indicate accounts or systems that never received AES keys — legacy service accounts, old trusts, appliances. These are both a Kerberoasting exposure today and the hardest identity crypto to migrate.

```kql
// Coverage check first: zero rows here = DCs not shipping Kerberos events
// (Minimal collection tier / restrictive xPath DCR) — tag as "not measured"
// SecurityEvent | where TimeGenerated > ago(7d) | where EventID in (4768, 4769) | take 5

SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID in (4768, 4769)
// TicketEncryptionType is not parsed into a column in all workspaces —
// column_ifexists falls back to extracting from the EventData XML
| extend EncTypeRaw = tostring(coalesce(
    column_ifexists("TicketEncryptionType", ""),
    extract(@'TicketEncryptionType">([^<]+)<', 1, EventData)))
| where EncTypeRaw in ("0x17", "0x18", "0x1", "0x3")
| extend EncType = case(
    EncTypeRaw == "0x17", "RC4-HMAC",
    EncTypeRaw == "0x18", "RC4-HMAC-EXP",
    "DES")
| extend Service = tostring(coalesce(
    column_ifexists("ServiceName", ""),
    extract(@'ServiceName">([^<]+)<', 1, EventData)))
| summarize TicketCount = count(),
            RequestingAccounts = make_set(TargetUserName, 15),
            SourceIPs = make_set(IpAddress, 10)
         by EncType, Service, EventID
| order by TicketCount desc
```

Interpretation: a baseline of RC4 hits against `krbtgt` is normal in mixed environments. The actionable findings are RC4 tickets for **service SPNs** (the Kerberoastable legacy service account list — remediate by rotating passwords with AES-only `msDS-SupportedEncryptionTypes`) and any DES hit, which indicates genuinely ancient systems or trusts.

Defender for Identity equivalent: `IdentityLogonEvents | where LogonType == "Kerberos" | extend AdditionalFields` — check `EncryptionType` in the parsed fields.

### 2.1b Is AES Kerberos good enough?

Once RC4/DES are gone, the answer is **yes for the symmetric core, conditional on key material, no for the certificate entry points** — four distinct verdicts customers tend to collapse into one:

- **Ticket encryption:** AES256-CTS (0x12) is post-quantum resilient (symmetric, Grover-only); prefer it over AES128 (0x11) via `msDS-SupportedEncryptionTypes`, same margin logic as BitLocker AES-256. The HMAC-**SHA1** in the etype name is *not* a finding — HMAC-SHA1 is unaffected by SHA-1 collision attacks. RFC 8009 (AES-SHA-2 etypes) is **not implemented by Windows**: AES256-SHA1 is the ceiling, a Microsoft dependency, not a customer gap.
- **Key material under the tickets — the real condition:** Kerberoasting attacks the password the key derives from, not the AES. An AES-256 ticket over a human-chosen service account password is offline-crackable regardless of etype. Conditions for "good enough": gMSA/dMSA for service accounts (random 120+ char, auto-rotated), Kerberos pre-auth required everywhere (AS-REP roast surface — also rule R4's territory), and scheduled `krbtgt` double-rotation.
- **Asymmetric entry points:** PKINIT (smartcards, Windows Hello for Business certificate trust) is RSA/ECC — **quantum-vulnerable**, inheriting the PKI chapter's timeline; post-quantum PKINIT is IETF work-in-progress. Precise report sentence: *Kerberos's symmetric core is PQC-resilient at AES-256; its certificate-based front door is not.*

```kql
// AES etype mix — the "prefer 256" KPI, same stream as 2.1
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID in (4768, 4769)
| extend E = tostring(coalesce(column_ifexists("TicketEncryptionType", ""),
             extract(@'TicketEncryptionType">([^<]+)<', 1, EventData)))
| where E in ("0x11", "0x12")
| summarize Tickets = count() by EncType = iff(E == "0x12", "AES256", "AES128"), EventID
| order by Tickets desc
```

Config-side complement (gap-fill): enumerate `msDS-SupportedEncryptionTypes` for AES256 preference and inventory service accounts by type (gMSA/dMSA vs password-based with SPNs — the latter list *is* the Kerberoastable surface, whatever the etype says). Note the KB5021131 `DefaultDomainSupportedEncTypes` hardening interactions before changing domain-wide defaults.

### 2.2 NTLM authentication — v1 elimination, NTLM-wide reduction

Two tiers, two severities. **NTLMv1** uses DES-based challenge-response: any hit is an immediate finding, and Microsoft removed v1 entirely from Windows 11 24H2 / Server 2025. **NTLMv2** is stronger (HMAC-MD5) but still legacy-generation crypto: offline-crackable challenge-responses, no server identity verification (the enabler for relay attacks), pass-the-hash by design, no MFA binding — and Microsoft has **formally deprecated all NTLM versions** (2024), with IAKerb and the local KDC shipping to remove the last legitimate NTLM scenarios. Report v1 as a red finding; report the overall NTLM share as a reduction KPI with Microsoft's deprecation as the driver.

```kql
// Protocol mix: NTLM share vs Kerberos, split by NTLM version
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4624
| where AuthenticationPackageName in ("NTLM", "Kerberos")
| summarize Logons = count(), Accounts = dcount(TargetUserName)
         by AuthenticationPackageName, LmPackageName
| order by Logons desc
// LmPackageName == "NTLM V1" = immediate finding.
// NTLM-total ÷ (NTLM + Kerberos) = the quarterly reduction KPI.
```

```kql
// Attribution for the reduction program: where does NTLM come from, and to what
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4624 and AuthenticationPackageName == "NTLM"
| summarize Logons = count(),
            Accounts = make_set(TargetUserName, 15),
            Sources = make_set(WorkstationName, 15)
         by Computer, LmPackageName
| order by Logons desc
```

MDI equivalent: `IdentityLogonEvents | where Protocol == "Ntlm"` for the same split without DC event forwarding.

Report this as a **staged elimination ladder with a defined end state**, not an open-ended reduction — the share KPI measures progress toward zero:

1. **Eliminate NTLMv1** (immediate): smallest population, worst crypto, already removed from Windows 11 24H2 / Server 2025. No dependency justifies it surviving a quarter.
2. **Prepare the Kerberos landing zone** (parallel): AES-only `msDS-SupportedEncryptionTypes` on the service accounts NTLM traffic will migrate onto (section 2.1) — migrating NTLM dependencies onto RC4-Kerberos swaps one weak-crypto finding for another.
3. **Eliminate NTLMv2** (mid-term): Restrict-NTLM audit mode (NTLM operational log events 8001–8004 via DCR) names every dependency → remediate per dependency → restrict per server → disable. Typical residuals: auth by IP address, local accounts, cross-forest without Kerberos trust, appliances/NAS, hardcoded NTLM in legacy connection strings — IAKerb and the local KDC now cover the first two, removing the last legitimate excuses.
4. **End state:** Kerberos-only (Negotiate with NTLM disabled), AES-only tickets — which is also the identity layer's prepared position for eventual PQC evolution of Kerberos itself.

### 2.3 Negotiated Schannel protocol versions on servers

Windows logs the negotiated TLS version and cipher suite per connection (System log, Schannel Event ID 36880) — the internal equivalent of the EASM TLS scan.

> **Prerequisite:** verbose Schannel logging must be enabled on target servers
> (`HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\EventLogging` = 7)
> and the System log collected via DCR. Enable on a representative sample (DCs, Exchange, tier-0 servers) rather than fleet-wide — volume is significant.

```kql
Event
| where TimeGenerated > ago(7d)
| where Source == "Schannel" and EventID == 36880
| parse RenderedDescription with * "protocol is " Protocol ". The " *
| summarize ConnectionCount = count() by Computer, Protocol
| order by Computer asc, ConnectionCount desc
```

### 2.4a Active AD CS template crypto via CA security events (partial coverage)

If issuing CAs forward Security events to the workspace, template-load events (4898) expose the crypto configuration of **actively used** templates directly in KQL — check with `SecurityEvent | where isnotempty(TemplateInternalName) | distinct Computer` and compare against the known CA list (per-CA coverage gap if any are missing).

```kql
SecurityEvent
| where TimeGenerated > ago(30d)
| where EventID == 4898
| summarize arg_max(TimeGenerated, TemplateContent, TemplateSchemaVersion, Computer)
         by TemplateInternalName
| extend MinKeySize = toint(extract(@'msPKI-Minimal-Key-Size\D*(\d+)', 1, TemplateContent)),
         HashAlg    = extract(@'msPKI-Hash-Algorithm[^\r\n]*?(SHA\d+|MD5)', 1, TemplateContent),
         AsymAlg    = extract(@'msPKI-Asymmetric-Algorithm[^\r\n]*?(RSA|ECDSA_P\d+|ECDH_P\d+)', 1, TemplateContent),
         DefaultCSP = extract(@'pKIDefaultCSPs[^\r\n]+', 0, TemplateContent)
| project TemplateInternalName, TemplateSchemaVersion, MinKeySize, HashAlg, AsymAlg, DefaultCSP, Computer
| order by MinKeySize asc
```

Interpretation:

- **Empty `HashAlg`/`AsymAlg` + populated `DefaultCSPs` = schema v2 legacy CryptoAPI template.** These structurally cannot issue ECC (or future PQC) certificates; the signing hash is governed by the CA's own configuration, not the template. A PKI whose active templates are all v2/CSP-based is a **migration blocker finding**: modernization requires new v3+/KSP templates and re-enrollment, not an in-place change. Where issuance runs via Intune SCEP (NDES) or ConfigMgr, re-enrollment is a profile rotation — note this as a mitigating factor. NDES itself historically forces legacy-CSP templates; treat template modernization and the NDES → Microsoft Cloud PKI decision as one roadmap item.
- **Scope caveats:** 4898 fires on template *load* (cache refresh), not issuance — counts are not volumes, and dormant-but-published templates (including forgotten weak ones) never appear. Full template enumeration still requires PSPKI/certutil (2.4 below).
- **CA-side checks the logs cannot answer** — run on each issuing CA:
  `certutil -getreg ca\csp\CNGHashAlgorithm` (signing hash; SHA-1 = immediate finding) and
  `certutil -getreg ca\csp\Provider` (a CA key in a legacy CSP requires CA key migration before any template modernization helps).
- **Hygiene side-check:** compare template EKU sets in `TemplateContent` against purpose — SCEP/NDES device templates carrying EFS or Secure Email EKUs indicate cloning from the default User template; trim to the minimum EKU set.



### 2.4b AD CS / private PKI full inventory (gap-fill)

> **Gap-fill — the log-based view above covers only actively loaded templates.** Certificate issuance events (4886/4887) do not carry algorithm parameters. The complete private PKI inventory — the single longest-lead-time item in any PQC migration — requires direct enumeration:
>
> - Issued certificates: `certutil -view -restrict "NotAfter>=now" -out "SerialNumber,CommonName,PublicKeyAlgorithm,PublicKeyLength,SignatureAlgorithm,NotAfter" csv` on each issuing CA
> - Templates: PSPKI module `Get-CertificateTemplate | Select Name,@{n='Key';e={$_.Settings.Cryptography}}` — flag templates issuing RSA < 3072 or with SHA-1 signing
> - CA hierarchy itself: root and issuing CA key algorithms, CRL signing algorithm, and the root CA's remaining validity — a root expiring after ~2030 will likely need a PQC or hybrid re-issuance ceremony, and offline root ceremonies need 12–18 months of planning
>
> Deliverable for the report: a CA hierarchy diagram annotated with key algorithm, key size, and expiry per tier.

---

### 2.5 Defender for Identity — sensor-based coverage (when MDI is deployed)

If the customer runs MDI sensors on domain controllers, the AD crypto inventory gains a second telemetry path that is **independent of DC event forwarding** — the sensor parses traffic and ETW on the DC directly. This matters precisely when the `SecurityEvent` path above turns out to be a coverage gap. MDI also converts the config-side PowerShell gap-fill into continuous assessment.

**Sensor coverage first** (which DCs/servers actually report — the per-DC coverage check):

```kql
IdentityLogonEvents
| where Timestamp > ago(7d)
| summarize Events = count() by DestinationDeviceName
| order by Events desc
// Compare against the known DC list; missing DCs = sensor coverage gap.
// MDI also supports sensors on AD FS, AD CS, and Entra Connect servers —
// a sensor on each issuing CA adds continuous certificate-template
// misconfiguration assessment on top of the 4898 log parsing in 2.4a.
```

**Authentication protocol mix and weak-crypto hunting** — enumerate `AdditionalFields` keys before filtering; available detail varies by protocol and tenant:

```kql
// Step 1 — what detail does this tenant's sensor data carry?
IdentityLogonEvents
| where Timestamp > ago(7d)
| where Protocol in ("Kerberos", "Ntlm")
| extend AF = todynamic(AdditionalFields)
| mv-expand Key = bag_keys(AF)
| summarize Events = count() by Protocol, tostring(Key)
| order by Protocol asc, Events desc
```

```kql
// Step 2 — protocol/logon-type distribution (NTLM share is itself a KPI)
IdentityLogonEvents
| where Timestamp > ago(30d)
| summarize Logons = count(),
            Accounts = dcount(AccountUpn),
            Sources = dcount(DeviceName)
         by Protocol, LogonType
| order by Logons desc
```

**Config drift via directory events** — encryption-relevant configuration (DES flags, reversible encryption) lives in UserAccountControl; delegation state has its own ActionTypes. Enumerate what this tenant emits, then alert on the crypto-relevant subset:

```kql
IdentityDirectoryEvents
| where Timestamp > ago(30d)
| summarize Events = count() by ActionType
| order by Events desc
// Promote the relevant ActionTypes (UserAccountControl flag changes,
// delegation state changes) into a scheduled detection — config drift
// on encryption settings should page someone, not wait for the quarterly report.
```

**ISPM posture assessments (portal, not KQL)** — MDI continuously computes the identity crypto posture that otherwise requires the PowerShell gap-fill: *weak cipher usage* (accounts actively authenticating with RC4/DES), *unsecure account attributes* (DES-only enabled, reversible encryption, Kerberos pre-authentication disabled), and *legacy protocol usage* (NTLMv1). Defender portal → Identities → Security posture; results feed Secure Score, which gives the maturity table a Microsoft-computed corroborating source. The remaining PowerShell-only item is the full `msDS-SupportedEncryptionTypes` enumeration across all accounts — ISPM reports accounts *using* or *flagged with* weak crypto, not the complete attribute distribution.



---

## Layer 3 — Device

### 3.1 Cryptographic library inventory (the PQC-readiness KPI)

PQC capability arrives via libraries, not operating systems alone. OpenSSL 3.5+ ships ML-KEM/ML-DSA support; older branches never will. This query turns Defender TVM software inventory into a crypto-library dependency map — arguably the most forward-looking chart in the report.

```kql
DeviceTvmSoftwareInventory
| where SoftwareName has_any ("openssl", "gnutls", "libgcrypt", "mbedtls",
                              "wolfssl", "nss", "bouncy castle", "libssl",
                              "openssh")
| summarize DeviceCount = dcount(DeviceId)
         by SoftwareVendor, SoftwareName, SoftwareVersion, OSPlatform
| order by SoftwareName asc, DeviceCount desc
```

Note on OpenSSH: unlike TLS, SSH already ships post-quantum hybrid key exchange **preferred by default in stock builds** (`sntrup761x25519` since OpenSSH 9.0, `mlkem768x25519` since 9.9) — the OpenSSH version distribution is therefore the one inventory where "% of estate with PQC-protected transport" is a real, nonzero number today, and the strongest good-news KPI available to the report. Verify per estate rather than assuming: distro packaging and `KexAlgorithms` configuration can override defaults — `ssh -Q kex` on representative hosts plus effective-config sampling confirms what actually negotiates.

Interpretation rules for the raw inventory:

- **Windows rows are application-bundled DLLs**, not OS components (Windows uses Schannel/CNG natively). Remediation means updating the *owning application* via its vendor — this is the application-layer crypto dependency map, and the concrete justification for crypto-agility clauses in vendor contracts. Devices appear in multiple rows; never sum counts.
- **Version buckets:** 3.5+/3.6+ = PQC-capable (ML-KEM/ML-DSA present; capability ≠ enabled). 3.0.x LTS = **upstream EOL 7 September 2026** — a dated, near-term finding that outranks the PQC narrative for urgency. 3.1–3.4 non-LTS = EOL or approaching it. 1.x = EOL since September 2023; immediate finding, attribute and escalate.
- **Do not apply upstream EOL logic to enterprise Linux.** RHEL/Oracle EL8's `1.1.1k-el8` and Ubuntu LTS's `3.0.13-0ubuntu` are vendor-backported and supported — the Linux finding is instead that pre-3.5 distro crypto stacks have **no PQC path until the OS major upgrade** (EL9/EL10, next Ubuntu LTS). Report those as OS-migration roadmap items, not patching items.

Per-device KPI (deduplicated — the quarterly trend metrics):

```kql
DeviceTvmSoftwareInventory
| where SoftwareVendor == "openssl" and SoftwareName == "openssl"
| extend V = parse_version(SoftwareVersion)
| summarize BestVersion = max(V), WorstVersion = min(V) by DeviceId, OSPlatform
| extend PqcCapable = iff(BestVersion >= parse_version("3.5.0"), "PQC-capable lib present", "No PQC-capable lib"),
         EolRisk    = iff(WorstVersion < parse_version("3.0.0"), "EOL 1.x present", "No EOL lib")
| summarize Devices = dcount(DeviceId) by OSPlatform, PqcCapable, EolRisk
| order by Devices desc
```

Attribution — which applications bundle the EOL copies (disk path names the vendor to chase):

```kql
DeviceTvmSoftwareEvidenceBeta
| where SoftwareName == "openssl" and SoftwareVersion startswith "1.1.1"
| mv-expand DiskPaths
| summarize Devices = dcount(DeviceId) by DiskPath = tostring(DiskPaths)
| order by Devices desc
// re-run with startswith "3.0" — that list is the September 2026 EOL chase list
```

Triage pattern for the attribution output — the disk paths sort into categories with different owners and different urgency: **fleet-wide loaded components** (e.g. OEM-delivered agents like Intel iCLS under `driverstore\filerepository` — remediated in one driver-update wave, typically the bulk of the count); **application vendors** (versioned program folders — suite updates); **platform agents** (Azure extension paths — enable auto-upgrade); **internally built software** (deployment paths with bundled native runtimes — a package bump in the customer's own pipeline, and the concrete evidence for the app-embedded-crypto gap); **dead files** (installer staging folders, `temp` backups, stale profiles — cleanup that inflates the on-disk metric without carrying live risk); and **actively serving one-offs** (e.g. a web/app server binary next to the DLL — smallest counts, highest genuine risk, verify exposure first).

Because TVM inventories files on disk, refine with load evidence before locking report numbers:

```kql
DeviceImageLoadEvents
| where Timestamp > ago(7d)
| where FileName in~ ("libcrypto-1_1-x64.dll", "libssl-1_1-x64.dll",
                      "libcrypto-1_1.dll", "libssl-1_1.dll")
| summarize Devices = dcount(DeviceId), Loads = count()
         by InitiatingProcessFileName, FolderPath
| order by Devices desc
// MDE image-load telemetry is sampled, not exhaustive — treat as
// "confirmed loaded" evidence on top of the on-disk inventory, not a replacement.
// Absence is NOT exoneration: long-running services load DLLs once at boot,
// so a short window only catches devices that rebooted inside it. Rerun at 30d
// and cross-check whether the suspect component executes at all:
//   DeviceProcessEvents | where Timestamp > ago(30d)
//   | where FolderPath has "<component path fragment>"
//   | summarize Devices = dcount(DeviceId) by FileName
```

### 3.2 TLS / cipher configuration compliance

```kql
// ConfigurationName lives in the KB table, not the assessment table — join required.
// Enumerate available checks first: DeviceTvmSecureConfigurationAssessmentKB
//   | where ConfigurationName has_any ("TLS","SSL","cipher","SMB")
//   | project ConfigurationId, ConfigurationName
DeviceTvmSecureConfigurationAssessment
| where tobool(IsApplicable) and not(tobool(IsCompliant))   // flags are bool or int depending on tenant
| join kind=inner (
    DeviceTvmSecureConfigurationAssessmentKB
    | where ConfigurationName has_any ("TLS", "SSL", "cipher", "SMB")
    | project ConfigurationId, ConfigurationName, ConfigurationCategory
) on ConfigurationId
| summarize NonCompliantDevices = dcount(DeviceId)
         by ConfigurationName, ConfigurationCategory
| order by NonCompliantDevices desc
```

### 3.3 Schannel protocol configuration drift

Detects endpoints where legacy protocols are being (re-)enabled at the registry level — often by installers of legacy line-of-business software. This converts the inventory from a snapshot into continuous monitoring.

```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where RegistryKey has @"SecurityProviders\SCHANNEL\Protocols"
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any ("TLS 1.0", "TLS 1.1", "SSL 3.0", "SSL 2.0")
| where RegistryValueName == "Enabled" and RegistryValueData != "0"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName,
          RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

> **Known telemetry limit:** `DeviceFileCertificateInfo` records code-signing certificate observations (signer, issuer, validity, trust) but **not** signature or key algorithms. Code-signing crypto inventory — increasingly relevant as CNSA 2.0 pushes signing to PQC first — requires sampling binaries directly (`Get-AuthenticodeSignature` at scale, or signtool).

---

## Layer 4 — Application & cloud configuration

### 4.0 Resource existence first (Azure Resource Graph)

Before querying any Azure telemetry, establish what exists. The application layer follows a three-step decision tree per resource type — **exists? (ARG) → logs here? (workspace discovery) → what does it say? (telemetry query)** — producing three distinct report outcomes: *not applicable* (resource doesn't exist), *not measured* (exists, no diagnostics to this workspace — coverage gap), or *measured*. Querying telemetry for resources that don't exist produces column-resolution errors on schema-on-write tables and wastes time debugging queries that were never going to return data.

Run in Azure Resource Graph Explorer:

```kql
resources
| where type in~ (
    "microsoft.network/applicationgateways",
    "microsoft.network/frontdoors",
    "microsoft.cdn/profiles",
    "microsoft.network/loadbalancers",
    "microsoft.keyvault/vaults",
    "microsoft.keyvault/managedhsms",
    "microsoft.storage/storageaccounts",
    "microsoft.sql/servers",
    "microsoft.web/sites",
    "microsoft.web/serverfarms",
    "microsoft.apimanagement/service")
| summarize ResourceCount = count() by type
| order by ResourceCount desc
```

Then confirm which of the existing resources actually ship diagnostics to the workspace:

```kql
AzureDiagnostics
| where TimeGenerated > ago(7d)
| summarize Rows = count() by ResourceProvider, Category
| order by Rows desc
// Resource-specific table mode won't appear here — also check dedicated tables
// (AGWAccessLogs, etc.) for any resource type ARG confirmed exists
```

The delta between the two lists is the application-layer coverage gap table: every resource type present in ARG but absent from workspace telemetry is a diagnostic setting to configure before the next assessment cycle.

### 4.1 Negotiated TLS at Azure ingress points

Application Gateway and Front Door access logs record the actual negotiated protocol and cipher per request — real client behavior, not just policy. This is where you find the 0.4% of traffic still arriving over TLS 1.0 that blocks the policy change.

```kql
// AzureDiagnostics is schema-on-write: columns only exist once a resource has
// written them. If sslProtocol_s fails to resolve, no AGW access logs have
// landed here. Discover what flows first:
AzureDiagnostics
| where TimeGenerated > ago(7d)
| summarize Rows = count() by ResourceProvider, Category
| order by Rows desc
```

```kql
// Application Gateway — legacy AzureDiagnostics mode
AzureDiagnostics
| where TimeGenerated > ago(7d)
| where Category == "ApplicationGatewayAccessLog"
| summarize RequestCount = count() by sslProtocol_s, sslCipher_s
| order by RequestCount desc
```

```kql
// Application Gateway — resource-specific table mode (no _s suffixes)
AGWAccessLogs
| where TimeGenerated > ago(7d)
| summarize RequestCount = count() by SslProtocol, SslCipher
| order by RequestCount desc
```

If neither table has data, verify whether an Application Gateway exists at all
(ARG: `resources | where type =~ "microsoft.network/applicationgateways"`).
No gateway → mark 4.1 not-applicable and identify what actually terminates TLS
for web workloads. Gateway without diagnostics → coverage gap: "ingress TLS
telemetry not measured, diagnostic setting required."

```kql
// Azure Front Door
AzureDiagnostics
| where TimeGenerated > ago(7d)
| where Category == "FrontdoorAccessLog"
| summarize RequestCount = count() by securityProtocol_s
| order by RequestCount desc
```

### 4.2 Minimum TLS policy across the Azure estate (Azure Resource Graph)

Run in Azure Resource Graph Explorer (not Log Analytics) — same KQL dialect, resource configuration instead of telemetry.

```kql
resources
| where type in~ ("microsoft.storage/storageaccounts", "microsoft.sql/servers")
| extend MinTls = case(
    type =~ "microsoft.storage/storageaccounts", tostring(properties.minimumTlsVersion),
    tostring(properties.minimalTlsVersion))
| where isempty(MinTls) or MinTls in~ ("TLS1_0", "TLS1_1", "1.0", "1.1")
| project name, type, resourceGroup, subscriptionId, MinTls
| order by type asc
```

> **Note:** App Service `minTlsVersion` lives under `siteConfig`, which Resource Graph does not populate — enumerate via `az webapp config show` per app, or Azure Policy compliance data if the built-in "App Service apps should use the latest TLS version" policy is assigned.

### 4.3 Key Vault key inventory

> **Gap-fill:** Key Vault diagnostic logs record operations, not key parameters. Enumerate key material directly:
> `az keyvault key list --vault-name <vault> --query "[].{name:name,kid:kid}"` then `az keyvault key show` per key for `kty` (RSA/EC/RSA-HSM) and `n`/`crv` size. Every RSA/EC key here is quantum-vulnerable inventory; keys wrapping long-retention data (storage encryption, backup, database TDE) inherit the HNDL risk of that data and belong in the high-risk / 2030 bucket.

If Key Vault `AuditEvent` diagnostics flow to the workspace, layer a **usage overlay** on the CLI enumeration — audit logs answer which keys actively perform cryptography and for whom, which is the prioritization input the HNDL bucketing needs:

```kql
// Enumerate the operation mix first
AzureDiagnostics
| where TimeGenerated > ago(30d)
| where ResourceProvider == "MICROSOFT.KEYVAULT" and Category == "AuditEvent"
| summarize Ops = count() by OperationName
| order by Ops desc
```

```kql
// Active crypto operations per key.
// Normalize: the same key appears via multiple KV frontend ports (:8443/:8444/default) —
// extract the key name so volumes sum correctly; keep version count as rotation evidence.
AzureDiagnostics
| where TimeGenerated > ago(30d)
| where ResourceProvider == "MICROSOFT.KEYVAULT" and Category == "AuditEvent"
| where OperationName in ("KeySign", "KeyVerify", "KeyEncrypt", "KeyDecrypt",
                          "KeyWrap", "KeyUnwrap", "KeyGet")
| extend KeyName = extract(@"/keys/([^/?]+)", 1, requestUri_s),
         KeyVersion = extract(@"/keys/[^/]+/([0-9a-f]{32})", 1, requestUri_s)
| summarize Ops = count(),
            Versions = dcount(KeyVersion),
            Callers = dcount(identity_claim_appid_g),
            LastUsed = max(TimeGenerated)
         by VaultName = Resource, KeyName, OperationName
| order by Ops desc
```

Interpretation: `KeyWrap`/`KeyUnwrap` traffic marks keys wrapping data-encryption keys (CMK, disk encryption, backup) — the high-risk/2030 candidates per the gap-fill note above. `KeySign` marks signing keys on the separate signature-migration track; note Key Vault offers no PQC key types yet — a platform dependency outside the customer's control. Heavy `SecretGet` with little key traffic indicates a config store rather than active crypto. Cross-reference hot `KeyName` entries against the CLI type/size output to produce a prioritized key table rather than a flat dump.

---

## Symmetric cryptography — the reassuring half of the story

The inventory above is entirely about **asymmetric** cryptography, which Shor's algorithm breaks outright. **Symmetric** cryptography (AES) is only weakened by Grover's algorithm, which halves effective key strength: AES-256 remains post-quantum safe, AES-128 reduces to ~64-bit-equivalent security. This distinction belongs in the report explicitly — "all current cryptography is quantum-vulnerable" is only true of the asymmetric layer, and precision here builds credibility.

The actionable consequence, available today with no platform dependency: **BitLocker defaults to XTS-AES-128.** Moving the encryption-method policy to XTS-AES-256 for devices holding long-lived sensitive data (and AES-256 generally where configurable: IPsec proposals, backup encryption, storage) is typically the only PQC-readiness action a customer can *complete* this quarter, and aligns with CNSA 2.0's AES-256 mandate. Verify via Intune BitLocker policy / configuration baselines; note that changing the method only affects newly encrypted volumes, so existing devices migrate at re-encryption or reimage.

## Scope boundaries to name in the report

A cryptographic inventory that is silent on these invites a defensibility challenge; each deserves at least a named line with its gap-fill:

- **SSH estate** — external SSH endpoints (EASM-visible), Linux fleet, network devices, jump hosts. RSA/ECDSA host keys and classical kex where OpenSSH is old; hybrid PQC kex by default where it's current (see Layer 3 note). Gap-fill: OpenSSH version inventory + `ssh -Q kex` sampling on representative hosts.
- **Email transport** — outbound/inbound SMTP TLS posture, MTA-STS, TLS-RPT, DANE. Mail content is long-lived HNDL exposure. Gap-fill: DNS record review + Exchange Online SMTP TLS reports.
- **VPN / IPsec / network appliances** — IKE with classical DH on firewalls and VPN concentrators; long hardware lifecycles and slow vendor PQC roadmaps make these the likely last movers, yet they terminate exactly the traffic HNDL adversaries record. Gap-fill: appliance config export (IKE proposals, DH groups) + vendor PQC roadmap statements in procurement.
- **Backup encryption** — backups are the longest-lived data in the estate; on-prem backup platforms (encryption algorithm, key management) appeared in this assessment only via Azure Key Vault. Gap-fill: backup platform config review.
- **On-prem SQL Server TDE** — self-signed RSA certificates in `master`; enumerable via `SELECT name, key_length, algorithm_desc FROM master.sys.certificates` joined against `sys.dm_database_encryption_keys`.
- **DNSSEC** (if zones are signed) — signing algorithm review; RSA/SHA-1 zones still exist in the wild.
- **Container images & IaC** — bundled crypto libraries inside container images (Defender for Containers / registry scanning surfaces vulnerable OpenSSL in images, same interpretation rules as Layer 3); crypto parameters pinned in Terraform/Bicep (`minimumTlsVersion`, cipher policies) — enforce via Azure Policy so drift is prevented, not just detected.
- **AD config-side Kerberos audit** — the Layer 2 telemetry catches weak encryption *in use*; enumerate `msDS-SupportedEncryptionTypes` via AD PowerShell to find RC4-only accounts *before* they request tickets. Adjacent: LDAP signing/channel-binding events (2886/2887/2889).

## Migration validation

Inventory measures readiness; migrations need proof. Three practices to pair with any transition wave:

- **Handshake verification:** confirm hybrid negotiation end-to-end, not just capability — `openssl s_client -groups X25519MLKEM768` against migrated TLS endpoints, `ssh -Q kex` plus a verbose connection against migrated SSH hosts. "Library supports it" and "connection negotiated it" are different claims; report the second.
- **Canary before fleet:** enable hybrid key exchange on a representative endpoint subset first — old clients that cannot handle larger ClientHello messages or unknown groups fail here cheaply instead of fleet-wide.
- **Performance and MTU:** ML-KEM handshakes carry materially larger key material; high-connection-rate services (API gateways, VPN concentrators) and constrained links (fragmentation of large ClientHellos) deserve a load test before and after. Budget rollback per wave.

## Continuous monitoring — detection rule specifications

The assessment is point-in-time; this section keeps it true between cycles. No first-party rule pack exists for weak-crypto drift (MDI ISPM and the Insecure Protocols workbook cover posture and visualization, not alerting), so the following are custom rules. All share one design: **first-seen detection** — alert only on entities newly entering the weak population, never on known debt.

**Design constraint that shapes everything:** Sentinel scheduled rules cap query lookback at **14 days**, so long baselines cannot live inside the rule. The pattern used throughout: a **13-day rolling telemetry baseline** (suppresses recent known state) plus an **accepted-debt watchlist** (carries the older known state, seeded from this assessment). This makes the lifecycle explicit: the assessment populates the watchlists; remediation **removes** entries so any regression re-alerts; the rolling window covers everything in between.

**Watchlists to create (Sentinel, `SearchKey` = the listed field):**

| Watchlist | SearchKey | Seeded from | Feeds |
|---|---|---|---|
| `CryptoLegacyServices` | Kerberos service name | Assessment 2.1 output | R1 |
| `CryptoLegacyAuthIdentities` | UserPrincipalName | Assessment 1.2 drill-down | R2 |
| `AdcsKnownTemplates` | TemplateInternalName | Assessment 2.4a output | R3 |

(XDR custom detections cannot reference Sentinel watchlists — R7 maintains its exclusions inline; see maintenance.)

---

### R1 — First-seen weak Kerberos encryption per service
*Sentinel scheduled · frequency 1h · lookback 14d · MITRE T1558.003*

**What it detects and why it triggers:** a service principal receiving RC4/DES tickets that has not done so in 13 days and is not accepted debt. Fires on (a) new legacy systems entering the environment, or (b) an attacker forcing RC4 downgrade on an AES-capable account — the Kerberoasting preparation step. Dual-purpose by design: crypto governance and attack detection in one rule.

```kql
let Accepted = _GetWatchlist('CryptoLegacyServices') | project Service = tostring(SearchKey);
let Weak = SecurityEvent
| where EventID in (4768, 4769)
| extend EncType = tostring(coalesce(column_ifexists("TicketEncryptionType", ""),
                   extract(@'TicketEncryptionType">([^<]+)<', 1, EventData)))
| where EncType in ("0x17", "0x18", "0x1", "0x3")
| extend Service = tostring(coalesce(column_ifexists("ServiceName", ""),
                   extract(@'ServiceName">([^<]+)<', 1, EventData)))
| where Service !~ "krbtgt";
let Baseline = Weak | where TimeGenerated between (ago(13d) .. ago(1h)) | distinct Service;
Weak
| where TimeGenerated > ago(1h)
| where Service !in (Baseline) and Service !in (Accepted)
| summarize Tickets = count(), FirstSeen = min(TimeGenerated),
            Accounts = make_set(TargetUserName, 10), SourceIPs = make_set(IpAddress, 10)
         by Service, EncType
```

**Maintenance:** krbtgt exclusion is mandatory. After each assessment cycle, reconcile `CryptoLegacyServices` — remove remediated services. Severity suggestion: Medium; High when `EncType` is DES or the requesting account is privileged.

---

### R2 — New identity on legacy authentication
*Sentinel scheduled · frequency 24h · lookback 14d*

**What it detects and why it triggers:** a user or service identity successfully authenticating over a legacy protocol for the first time. New SMTP AUTH/IMAP/POP identities are either unmanaged devices entering service or abused credentials — legacy protocols are a known persistence and exfiltration channel precisely because they bypass modern token protections.

```kql
let LegacyApps = dynamic(["Exchange ActiveSync", "IMAP4", "POP3",
                          "Authenticated SMTP", "MAPI Over HTTP", "Other clients"]);
let Accepted = _GetWatchlist('CryptoLegacyAuthIdentities') | project UserPrincipalName = tostring(SearchKey);
let Src = union SigninLogs, AADNonInteractiveUserSignInLogs
| where ClientAppUsed in (LegacyApps) and ResultType == 0;
let Baseline = Src | where TimeGenerated between (ago(13d) .. ago(1d)) | distinct UserPrincipalName;
Src
| where TimeGenerated > ago(1d)
| where UserPrincipalName !in (Baseline) and UserPrincipalName !in (Accepted)
| summarize SignIns = count(), FirstSeen = min(TimeGenerated),
            Apps = make_set(ClientAppUsed, 5), SourceIPs = make_set(IPAddress, 5),
            Agents = make_set(UserAgent, 5)
         by UserPrincipalName
```

**Maintenance:** the non-interactive union is deliberate — service-style legacy usage concentrates there. UserAgent in the output usually names the device, making triage a one-look decision: add to watchlist (accepted device) or investigate (unexpected identity).

---

### R3 — AD CS template published or modified
*Sentinel scheduled · frequency 1h · lookback 14d · MITRE T1649-adjacent*

**What it detects and why it triggers:** any template modification (4899 — always alerted: rare, administrative, and the exact event both a crypto downgrade and ESC-style template tampering produce) and any template loading that isn't in the known set (4898 first-seen). Near-zero volume, high signal.

```kql
let Known = _GetWatchlist('AdcsKnownTemplates') | project TemplateInternalName = tostring(SearchKey);
SecurityEvent
| where EventID in (4898, 4899)
| where isnotempty(TemplateInternalName)
| where EventID == 4899 or TemplateInternalName !in (Known)
| project TimeGenerated, Computer, TemplateInternalName, TemplateOID, TemplateVersion,
          Change = iff(EventID == 4899, "Template modified", "New template loaded")
```

**Maintenance:** requires CA Security events flowing (verified in 2.4a). Every alert resolution updates `AdcsKnownTemplates`. Severity: High for 4899 on any template published for enrollment.

---

### R4 — Account crypto configuration downgrade
*Sentinel scheduled (NRT-eligible: single table, no joins if watchlist dropped) · frequency 1h · MITRE T1098 / T1556*

**What it detects and why it triggers:** directory changes enabling DES, reversible encryption, or disabling Kerberos pre-authentication on an account. These are attacker techniques (AS-REP roasting setup, downgrade for offline cracking) at least as often as admin mistakes — config drift on encryption settings should page, not wait for the quarterly report.

```kql
// Populate from the tenant's own enumeration (section 2.5):
//   IdentityDirectoryEvents | distinct ActionType
// ActionType strings vary by tenant/sensor version — do not deploy with guessed values.
let CryptoActionTypes = dynamic(["<UserAccountControl flag change ActionTypes from enumeration>",
                                 "<delegation state change ActionTypes from enumeration>"]);
IdentityDirectoryEvents
| where ActionType in (CryptoActionTypes)
| project Timestamp, ActionType, TargetAccountUpn, TargetAccountDisplayName,
          AdditionalFields
```

**Maintenance:** requires MDI. The ActionType list is the single tenant-specific element — filled once from the 2.5 enumeration, then stable. Fallback without MDI: SecurityEvent 4738, at the cost of parsing UserAccountControl message codes.

---

### R5 — New weak certificate on the external attack surface
*Sentinel scheduled · frequency 24h · lookback 14d*

**What it detects and why it triggers:** a certificate never seen before appearing on the external estate with SHA-1/MD5 signature, RSA < 2048, or self-signed — an external regression (new legacy service exposed, misdeployed endpoint) alerting within a day instead of surfacing in the next quarterly report.

```kql
let Baseline = EasmSslCertAsset_CL
| where TimeGenerated between (ago(13d) .. ago(1d))
| distinct Sha1_s;
EasmSslCertAsset_CL
| where TimeGenerated > ago(1d)
| summarize arg_max(TimeGenerated, *) by Sha1_s
| where Sha1_s !in (Baseline)
| where SigAlgName_s has_any ("SHA1", "MD5")
   or (KeyAlgorithm_s has "RSA" and KeySize_d < 2048)
   or SelfSigned_b == true
| project TimeGenerated, CertName = tostring(SubjectCommonNames_s),
          Issuer = tostring(IssuerCommonNames_s), SigAlgName_s,
          KeyAlgorithm_s, KeySize_d, SelfSigned_b, ValidUntil = InvalidAfter_t
```

**Maintenance:** frequency must match the EASM export cadence (daily snapshots → daily rule; slower ingestion → widen the detection window accordingly).

---

### R6 — Legacy TLS/SSL protocol enabled on an endpoint
*Defender XDR custom detection · frequency: Continuous (NRT) · MITRE T1562.001*

**What it detects and why it triggers:** the registry write that re-enables TLS 1.0/1.1/SSL on a device — fired at the moment of change, with the initiating process attached. Catches both legacy installers silently downgrading endpoints and deliberate security-control tampering.

```kql
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryKey has @"SecurityProviders\SCHANNEL\Protocols"
| where RegistryKey has_any ("TLS 1.0", "TLS 1.1", "SSL 3.0", "SSL 2.0")
| where RegistryValueName == "Enabled" and RegistryValueData != "0"
| project Timestamp, ReportId, DeviceId, DeviceName, RegistryKey,
          RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**Maintenance:** `Timestamp`/`ReportId`/`DeviceId` in the projection are mandatory for custom detections. `InitiatingProcessFileName` drives triage: known LOB installer → engage the vendor; unexpected process → treat as defense impairment. Add response action "isolate" only for tier-0 device groups, if at all.

---

### R7 — EOL crypto library written to disk
*Defender XDR custom detection · frequency 1h or 24h*

**What it detects and why it triggers:** new software introducing end-of-life OpenSSL (1.0.x/1.1.x) at install time — the prevention-adjacent complement to the quarterly inventory, catching debt as it arrives instead of counting it later.

```kql
// Custom detections cannot reference Sentinel watchlists — exclusions live inline.
// Seed from the assessment's attribution output (accepted-debt paths pending
// remediation). Illustrative examples below — replace with ⟨this estate's paths⟩:
let AcceptedPaths = dynamic([@"\driverstore\filerepository\⟨oem-component⟩.inf",
                             @"\⟨accepted-platform-agent-path⟩"]);
DeviceFileEvents
| where ActionType in ("FileCreated", "FileModified")
| where FileName in~ ("libssl-1_1-x64.dll", "libcrypto-1_1-x64.dll",
                      "libssl-1_1.dll", "libcrypto-1_1.dll",
                      "libeay32.dll", "ssleay32.dll")
| where not(FolderPath has_any (AcceptedPaths))
| project Timestamp, ReportId, DeviceId, DeviceName, FolderPath, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

**Maintenance:** expect bursts during software rollouts — the folder path names the application immediately, so triage is add-to-exclusions vs. open-vendor-conversation. When a driver/app wave remediates an accepted path, **remove it from `AcceptedPaths`** so reintroduction re-alerts. This inline list is the one exclusion set not managed as a watchlist; version it with the rule in the repository.

---

### Maintenance model

- **Infrequent authenticators (the 13-day trap):** entities that appear less often than the rolling window — monthly batch jobs on SMTP AUTH, monthly RC4 services — will false-positive on schedule. Fix structurally, not with watchlist sprawl: deploy a **summary rule** that writes the day's distinct weak population (R1 services, R2 identities) into a long-retention custom baseline table (e.g. `CryptoWeakBaseline_CL`, 90d+), and anti-join the detection rules against that table instead of raw telemetry — custom tables are not subject to the 14-day scheduled-rule lookback. Watchlists then hold only *deliberate* accepted debt, not frequency workarounds.
- **Triage automation:** attach a playbook offering "accept → add entity to watchlist" on incident closure, so watchlist upkeep happens inside triage rather than as a quarterly chore.
- **Assessment → watchlist reconciliation, quarterly:** each assessment refresh regenerates the watchlists and R7's inline list. Remediated items are *removed*, never left as tombstones — an entry that stays after remediation silently suppresses regression alerts, which defeats the entire design.
- **Thresholds frozen between reviews:** severity thresholds and the maturity-score cut-offs change only at the quarterly review, so trend lines stay honest.
- **Rule health:** monitor `SentinelHealth` for scheduled-rule failures (a silently failing R1 is indistinguishable from a clean environment) and the custom detection run status in the Defender portal for R6/R7.
- **Deployment as code:** Sentinel repositories for R1–R5 (rules + summary rule), custom detection API for R6–R7; watchlist content and the R7 path list are the only per-customer parameters. The engagement sequence this enforces: assessment produces the baseline → remediation shrinks the watchlists → rules guard the new floor → the quarterly workbook shows the trend.

---

## External dependencies — who actually controls the migration

The largest PQC migration blocker is not customer readiness; it is **vendor readiness**. The customer controls the inventory, the classical cleanup, and the pressure applied to vendors — the migration itself is queued behind third parties. Stating this explicitly prevents the report reading as a list of customer failures:

| Dependency | What's blocked on them | Customer action |
|---|---|---|
| Microsoft platform | PQC key types in Key Vault/Managed HSM, ML-DSA in AD CS/Windows PKI, Schannel hybrid TLS, Cloud PKI | Track roadmap; design so adoption is a config change |
| OS / runtime vendors (.NET, Java, OpenSSL distros) | PQC in runtime crypto stacks; apps inherit when they rebuild | Keep runtimes current; require rebuild cadence from app vendors |
| Application vendors (collaboration, CAD/engineering, print management, LOB tooling — fill from the Layer 3 attribution output) | Bundled crypto libraries — customer cannot patch these directly | Update cadence + crypto-agility clauses in contracts (CRA-aligned) |
| Network/security appliance vendors (firewalls, VPN, load balancers) | PQC IKE/TLS on long-lifecycle hardware — historically the last movers | PQC roadmap statement as procurement requirement; plan refresh cycles against 2030 |
| HSM & PKI vendors | FIPS-validated PQC key storage, CA software support | Include in root-ceremony planning; validated modules lag standards by years |
| Public CAs / CA-Browser Forum | No public PQC certificates issuable yet | None — monitor; agility (short-lived certs, ACME) is the preparation |
| Hardware/firmware (TPM, platform services) | Firmware crypto stacks updated only via OEM channels | Driver/firmware management as a crypto control, not just an ops task |

## Executive maturity score

Four domains, scored 1–5. Two are computable from telemetry; two are assessed against stated criteria — scoring those from queries would be false precision:

| Domain | Source | Example |
|---|---|---|
| Inventory completeness | Manual: measured cells ÷ total cells in the coverage table | 2/5 |
| Crypto agility | Manual: cert automation %, config-driven crypto, rotation evidence | 1/5 |
| Legacy crypto exposure | **Composite KQL below** | 3/5 |
| PQC readiness | **Composite KQL below** | 1/5 |

**Level criteria** (state them in the report so scores are auditable, and freeze them between quarters):

| Level | Inventory completeness | Crypto agility | Legacy crypto exposure | PQC readiness |
|---|---|---|---|---|
| 1 | < 25% of layers measured | Manual certs, hardcoded crypto | Widespread weak crypto in active use | No PQC-capable components |
| 2 | 25–50% measured | Partial automation, no rotation evidence | Significant weak population, unattributed | Isolated PQC-capable libraries |
| 3 | 50–75% measured | Automation on majority of certs | Weak crypto attributed, remediation planned | Meaningful capable share, nothing negotiating |
| 4 | 75–95% measured, gaps labeled | Rotation + short-lived certs standard | Only accepted, watchlisted debt remains | Majority capable; hybrid piloted |
| 5 | All layers measured or labeled N/A | Crypto fully config-driven, tested rotation | Verified clean + drift detection live | Hybrid negotiating in production where available |

**Coverage capping rule:** no telemetry-derived domain may score more than **Inventory completeness + 2**. A "clean" legacy-crypto result measured against 40% of the estate is not a 5 — this rule makes incomplete coverage mathematically unable to produce a green dashboard, which is the false-confidence failure mode of every heuristic scoring model.

Composite query for the two telemetry-scoreable domains — run in the **unified Defender portal** (Advanced Hunting with the Sentinel workspace onboarded, so `SigninLogs`, `SecurityEvent`, and `DeviceTvm*` share one query surface). Thresholds are heuristics; calibrate per customer and keep them stable across quarters so the trend is honest:

```kql
let WeakKerb = toscalar(
    SecurityEvent
    | where TimeGenerated > ago(7d) and EventID in (4768, 4769)
    | extend E = tostring(coalesce(column_ifexists("TicketEncryptionType", ""),
                 extract(@'TicketEncryptionType">([^<]+)<', 1, EventData)))
    | summarize countif(E in ("0x17", "0x18", "0x1", "0x3")));
let LegacyAuth = toscalar(
    SigninLogs
    | where TimeGenerated > ago(30d)
    | where ClientAppUsed in ("Exchange ActiveSync", "IMAP4", "POP3",
                              "Authenticated SMTP", "Other clients")
    | where ResultType == 0
    | summarize dcount(UserPrincipalName));
let SslDevices = toscalar(
    DeviceTvmSoftwareInventory
    | where SoftwareName == "openssl"
    | summarize dcount(DeviceId));
let EolDevices = toscalar(
    DeviceTvmSoftwareInventory
    | where SoftwareName == "openssl"
    | extend V = parse_version(SoftwareVersion)
    | where V < parse_version("3.0.0")
    | summarize dcount(DeviceId));
let PqcDevices = toscalar(
    DeviceTvmSoftwareInventory
    | where SoftwareName == "openssl"
    | extend V = parse_version(SoftwareVersion)
    | where V >= parse_version("3.5.0")
    | summarize dcount(DeviceId));
let EolPct = iff(SslDevices > 0, round(100.0 * EolDevices / SslDevices, 1), 0.0);
let PqcPct = iff(SslDevices > 0, round(100.0 * PqcDevices / SslDevices, 1), 0.0);
union
  (print Domain = "Legacy crypto exposure",
         Signals = strcat(WeakKerb, " weak Kerberos tickets (7d); ",
                          LegacyAuth, " legacy-auth identities (30d); ",
                          EolPct, "% devices with EOL 1.x OpenSSL"),
         Score = case(WeakKerb == 0 and LegacyAuth == 0 and EolPct == 0.0, 5,
                      WeakKerb < 100 and LegacyAuth <= 5 and EolPct < 10.0, 4,
                      WeakKerb < 1000 and LegacyAuth <= 25 and EolPct < 40.0, 3,
                      WeakKerb < 10000 and EolPct < 70.0, 2, 1)),
  (print Domain = "PQC readiness (transport libraries)",
         Signals = strcat(PqcPct, "% devices with PQC-capable OpenSSL (3.5+)"),
         Score = case(PqcPct >= 90.0, 5, PqcPct >= 70.0, 4,
                      PqcPct >= 40.0, 3, PqcPct >= 10.0, 2, 1))
| project Domain, Score, Signals
```

Extend the signal set as coverage grows (OpenSSH version share, SHA-1 cert counts from EASM once exported, Schannel drift events) — but never let a score cell fill from a domain the telemetry doesn't actually cover.

## Migration roadmap

| Phase | Window | Customer actions | Vendor-dependent | EU roadmap alignment |
|---|---|---|---|---|
| Inventory & cleanup | Now – end 2026 | Complete inventory + coverage table; remove SHA-1/TLS 1.0-1.1/EOL libraries/legacy auth; BitLocker AES-256; vendor roadmap requests | — | Inventory & national planning milestone (end 2026) |
| Agility & PKI modernization | 2027 – 2028 | ACME/CLM rollout; v3/KSP templates; NDES→Cloud PKI decision; root ceremony planning; HNDL data classification; CRA-aligned contract clauses | Hybrid TLS reaching platforms; validated PQC HSMs emerging | CRA applicable (Dec 2027) |
| High-risk migration | 2029 – 2030 | Hybrid key exchange on high-risk transit; KEK rewrap as Key Vault ships PQC types; begin PKI re-issuance | Platform PQC GA; appliance refresh cycles | High-risk use cases complete by 2030 |
| Completion | 2031 – 2035 | Medium/low-risk migration; retire classical-only paths | Public PQC certificates; long-tail vendors | Full migration by 2035 |

## Consolidated reporting view

For the customer report, roll the layers into a single maturity table — **with an explicit coverage status per cell**, because a zero means nothing until it is labeled *verified clean* (telemetry present, finding absent), *not measured* (telemetry gap — itself a finding), or *not applicable* (resource absent):

| Layer | Coverage status | Quantum-vulnerable footprint | Classical weaknesses found | Migration blockers | Data lifetime risk (HNDL) |
|---|---|---|---|---|---|
| External (EASM) | | All public certs (RSA/ECC) | SHA-1, weak keys, legacy TLS | Legacy endpoints | Public services carrying long-lived data |
| Entra ID | | App cert credentials | Legacy TLS sign-ins, legacy auth | Pinned legacy clients | Token/credential material |
| On-prem AD / PKI | | Entire CA hierarchy, Kerberos | RC4/DES tickets, NTLMv1 | AD CS templates, root CA lifetime | Domain secrets, archived keys |
| Device | | Crypto library estate | TLS config non-compliance, drift | Pre-3.5 OpenSSL, legacy LOB software | Local data-at-rest (BitLocker method) |
| Application/cloud | | Key Vault keys, TDE/CMK | Ingress TLS ≤ 1.1 traffic | App-embedded crypto | Backups, databases, archives |
| SSH / VPN / email / backup | | Host keys, IKE, SMTP TLS | Legacy kex, old appliances | Appliance lifecycles | Recorded transit traffic, backup archives |

Scoring per cell (coverage status, then red/amber/green on findings) gives the customer a repeatable quarterly maturity measurement — and gives the report a trend line rather than a one-off snapshot.

---

## Suggested follow-up engagements

- **Active PQC handshake scan** of the external estate to measure actual hybrid key-exchange (X25519MLKEM768) support per endpoint — the metric that will trend upward as migration progresses and makes a strong recurring KPI in this report.
- **External SSH and email transport review** — SSH endpoint host-key/kex algorithm assessment (SSH already ships hybrid PQC key exchange by default in current OpenSSH, making it a measurable early-adoption KPI), and SMTP TLS posture including MTA-STS, TLS-RPT, and DANE.
- **Crypto-agility assessment** of certificate lifecycle automation (ACME adoption, CLM tooling) as the enabling capability for the 2030 migration deadline.
