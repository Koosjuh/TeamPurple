# Findings Matrix — Cryptographic Inventory ⟨Customer⟩

Assessment date: ⟨date⟩ · Assessor: ⟨name⟩ · Workspaces/tenants in scope: ⟨list⟩

**Fill-in rules:** every row gets a Coverage label — **Measured** (state the number), **Not measured** (name the missing telemetry/prerequisite; this is a finding), **Not applicable** (resource/protocol absent — state how verified), or **Pending** (verification identified, not yet run). Never leave a cell implying a clean zero that wasn't measured. Phase values: Immediate / Mid-term / Long-term per the template's phased actions.

## Layer 1 — Entra ID

| Item | Template ref | Current state | Coverage | Action → target | Phase |
|---|---|---|---|---|---|
| Legacy TLS in sign-ins | 1.1 | ⟨0 of N sign-ins / key absent⟩ *(run enumeration first — determines whether zero is measured or platform-enforced)* | ⟨ ⟩ | ⟨ ⟩ | ⟨ ⟩ |
| Exchange ActiveSync usage | 1.2 | ⟨sign-ins / users⟩ *(modern-auth EAS ≠ basic auth; still a migration target)* | ⟨ ⟩ | Outlook mobile migration for ⟨N⟩ users | ⟨ ⟩ |
| Authenticated SMTP (live basic auth) | 1.2 | ⟨sign-ins / accounts⟩ *(expect devices — UserAgent names them)* | ⟨ ⟩ | Device OAuth/connector migration → disable SMTP AUTH | ⟨ ⟩ |
| Other legacy protocols | 1.2 | ⟨sign-ins / identities⟩ | ⟨ ⟩ | Attribute via drill-down, remediate per client | ⟨ ⟩ |
| Workload identity credentials | 1.3 | ⟨cert vs secret counts, key sizes⟩ *(Graph gap-fill — not in sign-in logs)* | ⟨ ⟩ | ⟨ ⟩ | ⟨ ⟩ |
| Non-interactive log export | 1.2 note | ⟨enabled / disabled⟩ | ⟨ ⟩ | ⟨ ⟩ | ⟨ ⟩ |

## Layer 2 — On-premises AD / PKI

| Item | Template ref | Current state | Coverage | Action → target | Phase |
|---|---|---|---|---|---|
| Kerberos RC4/DES tickets | 2.1 | ⟨tickets by enc type / service⟩ *(run coverage check first; expect parsed-column absence in older workspaces — EventData fallback)* | ⟨ ⟩ | AES-only rotation for flagged service accounts | ⟨ ⟩ |
| AES etype mix (128 vs 256) | 2.1b | ⟨AES256 share %⟩ *(prefer 256; HMAC-SHA1 is not a finding; RFC 8009 = Windows ceiling, vendor-blocked)* | ⟨ ⟩ | `msDS-SupportedEncryptionTypes` → AES256 preference (mind KB5021131) | Mid-term |
| Kerberos key material | 2.1b | ⟨SPN accounts: gMSA/dMSA vs password-based; krbtgt rotation date⟩ *(password-based SPN list = Kerberoastable surface regardless of etype)* | ⟨ ⟩ | gMSA/dMSA migration; scheduled krbtgt double-rotation | Immediate/Mid |
| PKINIT / cert-based auth | 2.1b | ⟨smartcard/WHfB cert-trust usage⟩ *(RSA/ECC — quantum-vulnerable; inherits PKI timeline)* | ⟨ ⟩ | Track PQ PKINIT; couple to PKI migration | Long-term |
| NTLMv1 | 2.2 | ⟨logons / sources⟩ *(ladder step 1 — any hit = immediate finding; removed from Server 2025)* | ⟨ ⟩ | Eliminate first | Immediate |
| NTLM-wide share (v2) | 2.2 | ⟨NTLM ÷ (NTLM+Kerberos) %; top sources/targets⟩ *(ladder steps 2–4: AES landing zone → audit → remediate → disable; KPI trends to zero)* | ⟨ ⟩ | Eliminate after v1 → Kerberos-only end state | Mid-term |
| Schannel negotiated TLS | 2.3 | ⟨protocol mix per server⟩ *(requires verbose logging — tier-0 sample)* | ⟨ ⟩ | ⟨ ⟩ | ⟨ ⟩ |
| Active AD CS templates | 2.4a | ⟨count, schema versions, CSPs, min key sizes⟩ *(all-v2/CSP = migration-blocker finding; SCEP/Intune issuance = mitigating factor)* | ⟨ ⟩ | v3/KSP templates or Cloud PKI decision | ⟨ ⟩ |
| Template EKU hygiene | 2.4a | ⟨sprawl observed y/n⟩ *(device templates carrying User-template EKUs)* | ⟨ ⟩ | Trim to minimum EKU set | ⟨ ⟩ |
| CA signing hash + key provider | 2.4a certutil | ⟨CNGHashAlgorithm / Provider per CA⟩ *(SHA-1 = immediate finding; CSP-based CA key = migrate before templates)* | ⟨ ⟩ | ⟨ ⟩ | ⟨ ⟩ |
| CA event-forwarding coverage | 2.4a | ⟨CAs reporting vs CA list⟩ | ⟨ ⟩ | ⟨ ⟩ | ⟨ ⟩ |
| Full template/cert inventory | 2.4b | ⟨PSPKI/certutil export ref⟩ *(dormant templates invisible to logs)* | ⟨ ⟩ | ⟨ ⟩ | ⟨ ⟩ |
| Root CA lifetime vs 2030 | 2.4b | ⟨root expiry, algorithm⟩ | ⟨ ⟩ | Ceremony planning window | ⟨ ⟩ |
| MDI coverage + detail | 2.5 | ⟨sensor DCs / AdditionalFields keys / ActionTypes⟩ *(feeds rule R4)* | ⟨ ⟩ | ⟨ ⟩ | ⟨ ⟩ |
| `msDS-SupportedEncryptionTypes` audit | scope | ⟨RC4-only account count⟩ *(PowerShell gap-fill — config side, pre-usage)* | ⟨ ⟩ | ⟨ ⟩ | ⟨ ⟩ |

## Layer 3 — Device

| Item | Template ref | Current state | Coverage | Action → target | Phase |
|---|---|---|---|---|---|
| OpenSSL estate KPI | 3.1 | ⟨devices; % PQC-capable (3.5+); % with EOL 1.x on disk⟩ *(per-device dedupe query, not raw rows)* | ⟨ ⟩ | Quarterly trend baseline | — |
| OpenSSL 3.0.x population | 3.1 | ⟨observations⟩ *(upstream EOL Sep 2026 — dated urgency)* | ⟨ ⟩ | Vendor chase list from evidence query | ⟨ ⟩ |
| EOL library attribution | 3.1 | ⟨per triage category: OEM/driver, app vendor, platform agent, internal build, dead files, serving one-offs⟩ *(climb the evidence ladder before locking severity: disk → attributed → executing → network)* | ⟨ ⟩ | One action per category with named owner | ⟨ ⟩ |
| Internally built apps bundling crypto | 3.1 | ⟨apps / packages⟩ *(NuGet native assets etc. — build-pipeline finding)* | ⟨ ⟩ | Package bump + redeploy | ⟨ ⟩ |
| TLS/crypto config compliance | 3.2 | ⟨non-compliant devices per check⟩ *(KB join; enumerate catalog to split clean vs not-covered)* | ⟨ ⟩ | GPO per finding | ⟨ ⟩ |
| Schannel drift events | 3.3 | ⟨events 30d⟩ | ⟨ ⟩ | Feeds rule R6 | ⟨ ⟩ |
| BitLocker encryption method | Symmetric section | ⟨XTS-AES-128 / 256, policy source⟩ | ⟨ ⟩ | Policy → XTS-AES-256 (new volumes) | Immediate |
| OpenSSH distribution | 3.1 note | ⟨versions; % ≥ 9.0/9.9; kex verified on sample⟩ *(the nonzero PQC KPI)* | ⟨ ⟩ | ⟨ ⟩ | ⟨ ⟩ |

## Layer 4 — Application / cloud

| Item | Template ref | Current state | Coverage | Action → target | Phase |
|---|---|---|---|---|---|
| ARG resource existence sweep | 4.0 | ⟨resource types present⟩ *(run before any telemetry query — splits N/A from Not measured)* | ⟨ ⟩ | Diagnostic settings for exists-but-silent resources | ⟨ ⟩ |
| Ingress negotiated TLS | 4.1 | ⟨protocol/cipher mix or N/A⟩ | ⟨ ⟩ | ⟨ ⟩ | ⟨ ⟩ |
| Minimum-TLS policy (storage/SQL) | 4.2 | ⟨non-compliant resources⟩ | ⟨ ⟩ | Azure Policy enforcement | ⟨ ⟩ |
| Key Vault estate | 4.3 | ⟨vaults, keys, kty/size, workload mapping, wrap/unwrap vs sign split⟩ *(usage overlay + CLI pass; port-triplicate and querystring normalization)* | ⟨ ⟩ | HNDL bucketing; rewrap when platform ships PQC types | Long-term |
| High-HNDL keys | 4.3 | ⟨keys wrapping long-retention data: SIEM/audit/backup/DC disks⟩ | ⟨ ⟩ | High-risk/2030 bucket | ⟨ ⟩ |
| Multi-caller anomalies | 4.3 | ⟨keys with unexpected caller counts⟩ | ⟨ ⟩ | Resolve app IDs; access review | ⟨ ⟩ |
| Vault architecture | 4.3 | ⟨vault count, purge protection, segmentation⟩ | ⟨ ⟩ | ⟨ ⟩ | ⟨ ⟩ |

## External & scope boundaries

| Item | Template ref | Current state | Coverage | Action | Phase |
|---|---|---|---|---|---|
| EASM certificate inventory (queries 1–7) | Part 1 | ⟨sig alg distribution, weak certs, key sizes, lifetimes⟩ | ⟨ ⟩ | ⟨ ⟩ | ⟨ ⟩ |
| SSH / VPN / email / backup / on-prem TDE / DNSSEC / containers | Scope boundaries | ⟨per item⟩ | ⟨ ⟩ | Gap-fill per template | ⟨ ⟩ |

## Maturity scores

| Domain | Score | Basis (auditable) |
|---|---|---|
| Inventory completeness | ⟨n⟩/5 | ⟨measured cells ÷ total⟩ |
| Crypto agility | ⟨n⟩/5 | ⟨criteria evidence⟩ |
| Legacy crypto exposure | ⟨n⟩/5 | ⟨composite query output⟩ — capped at Inventory + 2 |
| PQC readiness | ⟨n⟩/5 | ⟨composite query output⟩ — capped at Inventory + 2 |

## Monitoring deployment

| Rule | Deployed | Watchlist/baseline seeded | Notes |
|---|---|---|---|
| R1 weak Kerberos first-seen | ⟨ ⟩ | `CryptoLegacyServices` ⟨ ⟩ + summary-rule baseline ⟨ ⟩ | Depends on Kerberos coverage outcome |
| R2 legacy-auth first-seen | ⟨ ⟩ | `CryptoLegacyAuthIdentities` ⟨ ⟩ | |
| R3 AD CS template change | ⟨ ⟩ | `AdcsKnownTemplates` ⟨ ⟩ | Seed **before** enabling |
| R4 account crypto downgrade | ⟨ ⟩ | ActionTypes from 2.5 enumeration ⟨ ⟩ | MDI required |
| R5 new weak external cert | ⟨ ⟩ | — | Match EASM export cadence |
| R6 Schannel enable (NRT) | ⟨ ⟩ | — | |
| R7 EOL DLL written | ⟨ ⟩ | Inline `AcceptedPaths` ⟨ ⟩ | Versioned with rule |

## Standing summary

- **Measured and strong:** ⟨ ⟩
- **Measured and weak:** ⟨ ⟩
- **Biggest coverage gaps:** ⟨ ⟩
- **Fastest wins:** ⟨ ⟩
- **Genuinely urgent (dated):** ⟨ ⟩
- **Blocked on vendors:** ⟨ ⟩
