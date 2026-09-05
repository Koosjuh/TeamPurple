# OktaV2_CL in Microsoft Sentinel

> SOC reference for investigating Okta Identity Engine authentication activity in Microsoft Sentinel and correlating it with Microsoft Entra ID `SigninLogs`.

**Table:** `OktaV2_CL`  

---

## 1. Purpose

`OktaV2_CL` contains Okta System Log events ingested into Microsoft Sentinel. It can be used to reconstruct authentication flows, investigate MFA failures, identify the authenticator actually used, track Okta sessions and requests, evaluate risk/device context, and correlate Okta activity with Microsoft Entra ID sign-ins.

The main investigation principle is:

Okta and Entra normally do **not** share a common transaction ID, so cross-platform correlation is usually contextual. Because why would we make things easy.

---

## 2. Schema notes for this `OktaV2_CL` connector

Fields observed in this Sentinel environment include:

| Field | Purpose |
|---|---|
| `TimeGenerated` | UTC timestamp of the event |
| `ActorUsername` | User performing the action |
| `ActorDisplayName` | Display name of the actor |
| `ActorUserId` | Okta user ID |
| `ActorSessionId` | Okta session ID |
| `ActingAppName` | Client/application, e.g. `CHROMIUM_EDGE` |
| `ActingAppType` | Application type, e.g. `Browser` |
| `EventOriginalType` | Native Okta System Log event type |
| `EventMessage` | Human-readable event description |
| `EventResult` | Normalized result such as `Success`, `Failure`, `Partial` |
| `EventOriginalResultDetails` | Specific result, e.g. `INVALID_CREDENTIALS` |
| `OriginalOutcomeResult` | Original Okta outcome |
| `OriginalTarget` | Dynamic array of users/apps/authenticators/tokens/rules |
| `DebugData` | Dynamic authentication/request/risk/device data |
| `Request` | Dynamic request data including IP chain |
| `SrcIpAddr` | Source IP |
| `SrcDvcOs` | Source OS |
| `SrcDeviceType` | Source device type |
| `SrcDvcId` | Okta source-device identifier when available |
| `SrcDvcIdType` | Type of source-device identifier |
| `SrcGeoCity` | Source city |
| `SrcGeoRegion` | Source region |
| `SrcGeoCountry` | Source country |
| `SrcIsp` | ISP |
| `SecurityContextAsNumber` | Source ASN |
| `SecurityContextAsOrg` | Source AS organization |
| `SecurityContextIsProxy` | Whether Okta identified a proxy |
| `HttpUserAgent` | Browser/user-agent |
| `TransactionId` | Event/transaction identifier |
| `TransactionType` | Transaction type, e.g. `WEB` |
| `TransactionDetail` | Extra transaction data; often empty in auth events |

### Connector-specific observation

In this environment, `TransactionDetail` is frequently `{}` even when the event contains rich authentication evidence.

For authentication investigations, prioritize:

1. `DebugData`
2. `OriginalTarget`
3. `EventOriginalType`
4. `EventResult` / `EventOriginalResultDetails`
5. `ActorSessionId`
6. `SrcIpAddr`, `SrcDvcOs`, `HttpUserAgent`
7. `Request`
8. `TransactionId`

Do not assume `TransactionDetail` contains the authentication method. This is generally found in DebugData.

---

## 3. Important nested fields

### `DebugData`

Common values include:

```text
authnRequestId
requestId
traceId
deviceFingerprint
factor
factorIntent
keyTypeUsedForAuthentication
authMethodFirstType
authMethodFirstVerificationTime
authMethodFirstEnrollment
authMethodSecondType
authMethodSecondVerificationTime
authMethodSecondEnrollment
challengeAuthenticatorsList
risk
behaviors
logOnlySecurityData
threatSuspected
requestUri
url
origin
```

### `OriginalTarget`

Depending on the event, the array can contain:

- `User`
- `AuthenticatorEnrollment`
- `AuthenticatorMethod`
- `AppInstance`
- `AppUser`
- `Rule`
- tokens / authorization codes

Authenticator targets can expose:

```text
authenticatorKey
methodTypeUsed
methodUsedVerifiedProperties
authenticatorMethodVerificationTime
```

---

## 4. Okta identifiers

### `authnRequestId`

`DebugData.authnRequestId` is one of the best identifiers for reconstructing one authentication flow.

Related events can include:

- policy evaluation
- factor challenge
- factor verification
- user verification
- session creation
- authorization-code issuance
- token issuance
- SSO

### `requestId`

Usually identifies a more specific request/event within the larger authentication flow.

### `TransactionId`

Useful for grouping events emitted by the same Okta transaction.

### `ActorSessionId`

Useful for following an established Okta session after authentication into app access/token/SSO activity.

### `deviceFingerprint`

Useful as supporting evidence that Okta activity came from a previously observed client/device context.

Treat it as a **correlation attribute**, not as an Entra device ID. Do not equate an Okta fingerprint with `SigninLogs.DeviceDetail.deviceId`.

---

## 5. Important Okta authentication event types

| `EventOriginalType` | Meaning |
|---|---|
| `policy.evaluate_sign_on` | Sign-on/authentication policy evaluation |
| `user.authentication.auth_via_mfa` | Authenticator/factor verification attempt |
| `user.authentication.verify` | User identity successfully verified |
| `user.session.start` | Okta user session created |
| `system.push.send_factor_verify_push` | Okta Verify Push sent |
| `user.mfa.factor.activate` | Factor/authenticator enrolled |
| `user.authentication.sso` | SSO activity to an application |
| `app.oauth2.authorize.code` | OAuth/OIDC authorization code event |
| `app.oauth2.token.grant.id_token` | ID token granted |
| `app.oauth2.token.grant.access_token` | Access token granted |

### Password can appear as MFA-factor telemetry

In Okta Identity Engine, password is treated as an authenticator/factor. Therefore:

```text
EventOriginalType = user.authentication.auth_via_mfa
EventResult = Failure
```

does **not** automatically mean Push/TOTP/FastPass failed.

Always inspect:

```text
DebugData.factor
EventOriginalResultDetails
OriginalTarget
```

Example:

```text
factor = PASSWORD_AS_FACTOR
EventOriginalResultDetails = INVALID_CREDENTIALS
```

means an incorrect password attempt.

---

## 6. Authenticator interpretation

### Password

```text
factor = PASSWORD_AS_FACTOR
methodTypeUsed = Password
authMethod...Type = okta_password:password:...
```

### Okta Verify TOTP

```text
methodTypeUsed = totp
authMethod...Type = okta_verify:totp:...
```

### Okta Verify Push

Typical fields:

```text
factor = OKTA_VERIFY_PUSH
methodTypeUsed = push
pushOnlyResponseType = OV_RESPONSE_APPROVE
pushWithNumberChallengeResponseType = OV_WITH_CHALLENGE_RESPONSE_VALID
```

Per example in the SigninLogs within Azure AD / Entra ID we could be investigating a `WHFB` signin and we want to correlate that to our OKTA. Here we can find `USER_VERIFYING_BIO_OR_PIN` means biometric/PIN verification occurred on the authenticator device. It does **not** by itself prove Windows Hello for Business. However it is a strong indicator of a possible `Windows Hello for Business` sign in if the other details such as a time stamp and IP matches.

### Okta FastPass

Okta records FastPass as:

```text
SIGNED_NONCE
signed_nonce
okta_verify:signed_nonce:...
```

Prefer current authentication evidence such as:

```text
EventOriginalType = user.authentication.auth_via_mfa
DebugData.factor = SIGNED_NONCE
```

or an `OriginalTarget` entry showing FastPass as the method actually used.

#### Authentication-context caveat

A policy event can contain:

```text
authMethodFirstType = okta_verify:signed_nonce:...
authMethodFirstVerificationTime = <older timestamp>
```

This confirms FastPass exists in the authentication/session context, but an old verification time does **not** prove FastPass was freshly performed at the current event time.

### WebAuthn / FIDO

`fido_webauthn` can represent FIDO2/WebAuthn including `Windows Hello for business`, but it can also be another passkey/security-key/platform authenticator.

---

# 7. KQL investigation library

Replace example values before running.

## 7.1 Review the schema

```kusto
OktaV2_CL
| getschema
| order by ColumnOrdinal asc
```

---

## 7.2 Basic timeline for one user

```kusto
let User = "USER_ENTITY";
let Lookback = 24h;
OktaV2_CL
| where TimeGenerated > ago(Lookback)
| where ActorUsername =~ User
    or OriginalActorAlternateId =~ User
    or tostring(OriginalTarget) has User
| extend
    AuthnRequestId = tostring(DebugData.authnRequestId),
    RequestId = tostring(DebugData.requestId),
    Factor = tostring(DebugData.factor),
    FactorIntent = tostring(DebugData.factorIntent),
    DeviceFingerprint = tostring(DebugData.deviceFingerprint),
    ThreatSuspected = tostring(DebugData.threatSuspected),
    RiskRaw = tostring(DebugData.risk)
| project
    TimeGenerated,
    ActorUsername,
    EventOriginalType,
    EventMessage,
    EventResult,
    EventOriginalResultDetails,
    Factor,
    FactorIntent,
    SrcIpAddr,
    SrcDvcOs,
    SrcGeoCity,
    SrcGeoCountry,
    ActingAppName,
    ActorSessionId,
    AuthnRequestId,
    RequestId,
    TransactionId,
    DeviceFingerprint,
    RiskRaw,
    ThreatSuspected,
    OriginalTarget
| order by TimeGenerated asc
```

---

## 7.3 Reconstruct one authentication flow by `authnRequestId`

```kusto
let AuthnRequestId = "REPLACE_WITH_AUTHN_REQUEST_ID";
OktaV2_CL
| where TimeGenerated > ago(30d)
| where tostring(DebugData.authnRequestId) == AuthnRequestId
| extend
    Factor = tostring(DebugData.factor),
    FactorIntent = tostring(DebugData.factorIntent),
    DeviceFingerprint = tostring(DebugData.deviceFingerprint),
    RequestId = tostring(DebugData.requestId),
    FirstMethod = tostring(DebugData.authMethodFirstType),
    FirstVerified = todatetime(DebugData.authMethodFirstVerificationTime),
    SecondMethod = tostring(DebugData.authMethodSecondType),
    SecondVerified = todatetime(DebugData.authMethodSecondVerificationTime)
| project
    TimeGenerated,
    ActorUsername,
    EventOriginalType,
    EventMessage,
    EventResult,
    EventOriginalResultDetails,
    Factor,
    FactorIntent,
    FirstMethod,
    FirstVerified,
    SecondMethod,
    SecondVerified,
    SrcIpAddr,
    SrcDvcOs,
    ActingAppName,
    ActorSessionId,
    AuthnRequestId,
    RequestId,
    TransactionId,
    DeviceFingerprint,
    OriginalTarget,
    DebugData
| order by TimeGenerated asc
```

---

## 7.4 Follow an Okta session by `ActorSessionId`

```kusto
let SessionId = "REPLACE_WITH_OKTA_SESSION_ID";
OktaV2_CL
| where TimeGenerated > ago(30d)
| where ActorSessionId == SessionId
| extend
    AuthnRequestId = tostring(DebugData.authnRequestId),
    Factor = tostring(DebugData.factor)
| project
    TimeGenerated,
    ActorUsername,
    EventOriginalType,
    EventMessage,
    EventResult,
    EventOriginalResultDetails,
    ActingAppName,
    SrcIpAddr,
    SrcDvcOs,
    Factor,
    AuthnRequestId,
    TransactionId,
    OriginalTarget
| order by TimeGenerated asc
```

---

## 7.5 Summarize authentication sessions for a user

```kusto
let User = "USER_ENTITY";
let Lookback = 7d;
OktaV2_CL
| where TimeGenerated > ago(Lookback)
| where ActorUsername =~ User
    or OriginalActorAlternateId =~ User
    or tostring(OriginalTarget) has User
| extend
    AuthnRequestId = tostring(DebugData.authnRequestId),
    Factor = tostring(DebugData.factor),
    DeviceFingerprint = tostring(DebugData.deviceFingerprint)
| summarize
    SessionStart = min(TimeGenerated),
    SessionEnd = max(TimeGenerated),
    SourceIPs = make_set(SrcIpAddr, 10),
    OperatingSystems = make_set(SrcDvcOs, 10),
    Applications = make_set(ActingAppName, 20),
    EventTypes = make_set(EventOriginalType, 50),
    Results = make_set(EventResult, 10),
    Factors = make_set_if(Factor, isnotempty(Factor), 20),
    DeviceFingerprints = make_set_if(DeviceFingerprint, isnotempty(DeviceFingerprint), 10),
    TransactionIds = make_set(TransactionId, 50)
    by ActorUsername, ActorSessionId, AuthnRequestId
| order by SessionStart desc
```

---

## 7.6 Show all MFA/authenticator attempts

```kusto
let User = "USER_ENTITY";
OktaV2_CL
| where TimeGenerated > ago(7d)
| where ActorUsername =~ User
    or OriginalActorAlternateId =~ User
    or tostring(OriginalTarget) has User
| where EventOriginalType in (
    "user.authentication.auth_via_mfa",
    "user.authentication.verify"
)
| extend
    AuthnRequestId = tostring(DebugData.authnRequestId),
    Factor = tostring(DebugData.factor),
    FactorIntent = tostring(DebugData.factorIntent),
    KeyType = tostring(DebugData.keyTypeUsedForAuthentication),
    DeviceFingerprint = tostring(DebugData.deviceFingerprint)
| project
    TimeGenerated,
    ActorUsername,
    EventOriginalType,
    EventResult,
    EventOriginalResultDetails,
    Factor,
    FactorIntent,
    KeyType,
    SrcIpAddr,
    SrcDvcOs,
    ActingAppName,
    AuthnRequestId,
    ActorSessionId,
    DeviceFingerprint,
    OriginalTarget,
    DebugData
| order by TimeGenerated desc
```

---

## 7.7 Expand authenticator methods from `OriginalTarget`

```kusto
let User = "USER_ENTITY";
OktaV2_CL
| where TimeGenerated > ago(7d)
| where ActorUsername =~ User
    or OriginalActorAlternateId =~ User
    or tostring(OriginalTarget) has User
| where EventOriginalType in (
    "user.authentication.auth_via_mfa",
    "user.authentication.verify"
)
| mv-expand Target = OriginalTarget
| where tostring(Target.type) in ("AuthenticatorEnrollment", "AuthenticatorMethod")
| extend
    TargetType = tostring(Target.type),
    Authenticator = tostring(Target.displayName),
    AuthenticatorKey = tostring(Target.detailEntry.authenticatorKey),
    MethodTypeUsed = tostring(Target.detailEntry.methodTypeUsed),
    VerifiedProperties = tostring(Target.detailEntry.methodUsedVerifiedProperties),
    MethodVerificationTime = todatetime(Target.detailEntry.authenticatorMethodVerificationTime),
    AuthnRequestId = tostring(DebugData.authnRequestId),
    Factor = tostring(DebugData.factor)
| project
    TimeGenerated,
    ActorUsername,
    EventResult,
    EventOriginalResultDetails,
    Factor,
    Authenticator,
    AuthenticatorKey,
    MethodTypeUsed,
    VerifiedProperties,
    MethodVerificationTime,
    SrcIpAddr,
    SrcDvcOs,
    AuthnRequestId,
    ActorSessionId
| order by TimeGenerated desc
```

---

## 7.8 Find incorrect-password failures recorded as MFA events

```kusto
OktaV2_CL
| where TimeGenerated > ago(7d)
| where EventOriginalType == "user.authentication.auth_via_mfa"
| extend
    Factor = tostring(DebugData.factor),
    AuthnRequestId = tostring(DebugData.authnRequestId),
    DeviceFingerprint = tostring(DebugData.deviceFingerprint)
| where EventResult =~ "Failure"
| where Factor =~ "PASSWORD_AS_FACTOR"
    or EventOriginalResultDetails =~ "INVALID_CREDENTIALS"
    or tostring(OriginalTarget) has "Password"
| project
    TimeGenerated,
    ActorUsername,
    SrcIpAddr,
    SrcDvcOs,
    EventResult,
    EventOriginalResultDetails,
    Factor,
    AuthnRequestId,
    ActorSessionId,
    DeviceFingerprint
| order by TimeGenerated desc
```

---

## 7.9 Find Okta Verify Push authentications

```kusto
OktaV2_CL
| where TimeGenerated > ago(7d)
| where EventOriginalType == "user.authentication.auth_via_mfa"
| extend
    Factor = tostring(DebugData.factor),
    KeyType = tostring(DebugData.keyTypeUsedForAuthentication),
    PushResponse = tostring(DebugData.pushOnlyResponseType),
    NumberChallengeResponse = tostring(DebugData.pushWithNumberChallengeResponseType),
    AuthnRequestId = tostring(DebugData.authnRequestId)
| where Factor has "PUSH"
    or tostring(OriginalTarget) has "push"
| project
    TimeGenerated,
    ActorUsername,
    EventResult,
    Factor,
    KeyType,
    PushResponse,
    NumberChallengeResponse,
    SrcIpAddr,
    SrcDvcOs,
    AuthnRequestId,
    ActorSessionId,
    OriginalTarget
| order by TimeGenerated desc
```

---

## 7.10 Find FastPass / `SIGNED_NONCE`

```kusto
let User = "USER_ENTITY";
OktaV2_CL
| where TimeGenerated > ago(30d)
| where ActorUsername =~ User
    or OriginalActorAlternateId =~ User
    or tostring(OriginalTarget) has User
| extend
    Factor = tostring(DebugData.factor),
    FirstMethod = tostring(DebugData.authMethodFirstType),
    FirstVerificationTime = todatetime(DebugData.authMethodFirstVerificationTime),
    SecondMethod = tostring(DebugData.authMethodSecondType),
    SecondVerificationTime = todatetime(DebugData.authMethodSecondVerificationTime),
    TargetText = tostring(OriginalTarget),
    AuthnRequestId = tostring(DebugData.authnRequestId),
    DeviceFingerprint = tostring(DebugData.deviceFingerprint)
| where Factor =~ "SIGNED_NONCE"
    or FirstMethod has "signed_nonce"
    or SecondMethod has "signed_nonce"
    or TargetText has "SIGNED_NONCE"
    or TargetText has "FastPass"
| extend FastPassEvidence = case(
    Factor =~ "SIGNED_NONCE",
        "Current event factor is SIGNED_NONCE",
    EventOriginalType == "user.authentication.auth_via_mfa"
        and (TargetText has "SIGNED_NONCE" or TargetText has "FastPass"),
        "Current MFA event target indicates FastPass",
    FirstMethod has "signed_nonce"
        and isnotnull(FirstVerificationTime)
        and abs(datetime_diff("minute", TimeGenerated, FirstVerificationTime)) <= 5,
        "Fresh signed_nonce authentication context",
    SecondMethod has "signed_nonce"
        and isnotnull(SecondVerificationTime)
        and abs(datetime_diff("minute", TimeGenerated, SecondVerificationTime)) <= 5,
        "Fresh signed_nonce authentication context",
    "signed_nonce present in historical/session authentication context"
)
| project
    TimeGenerated,
    ActorUsername,
    EventOriginalType,
    EventResult,
    Factor,
    FirstMethod,
    FirstVerificationTime,
    SecondMethod,
    SecondVerificationTime,
    FastPassEvidence,
    SrcIpAddr,
    SrcDvcOs,
    DeviceFingerprint,
    AuthnRequestId,
    ActorSessionId,
    OriginalTarget
| order by TimeGenerated desc
```

---

## 7.11 Track an Okta device fingerprint

```kusto
let Fingerprint = "REPLACE_WITH_DEVICE_FINGERPRINT";
OktaV2_CL
| where TimeGenerated > ago(90d)
| where tostring(DebugData.deviceFingerprint) == Fingerprint
| extend
    AuthnRequestId = tostring(DebugData.authnRequestId),
    Factor = tostring(DebugData.factor)
| project
    TimeGenerated,
    ActorUsername,
    ActorUserId,
    EventOriginalType,
    EventResult,
    Factor,
    SrcIpAddr,
    SrcDvcOs,
    SrcGeoCity,
    SrcGeoCountry,
    ActingAppName,
    HttpUserAgent,
    ActorSessionId,
    AuthnRequestId
| order by TimeGenerated desc
```

---

## 7.12 Establish fingerprint history

```kusto
let User = "USER_ENTITY";
OktaV2_CL
| where TimeGenerated > ago(90d)
| where ActorUsername =~ User
| extend DeviceFingerprint = tostring(DebugData.deviceFingerprint)
| where isnotempty(DeviceFingerprint)
| summarize
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    EventCount = count(),
    SourceIPs = make_set(SrcIpAddr, 25),
    OperatingSystems = make_set(SrcDvcOs, 10),
    Cities = make_set(SrcGeoCity, 20),
    UserAgents = make_set(HttpUserAgent, 20)
    by ActorUsername, DeviceFingerprint
| order by LastSeen desc
```

---

## 7.13 Find fingerprints used by multiple users

```kusto
OktaV2_CL
| where TimeGenerated > ago(90d)
| extend DeviceFingerprint = tostring(DebugData.deviceFingerprint)
| where isnotempty(DeviceFingerprint)
| summarize
    DistinctUsers = dcount(ActorUsername),
    Users = make_set(ActorUsername, 25),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    IPs = make_set(SrcIpAddr, 25)
    by DeviceFingerprint
| where DistinctUsers > 1
| order by DistinctUsers desc
```

This is not automatically malicious; shared devices, VDI and kiosks may be legitimate.

---

## 7.14 Extract risk and behavior context

```kusto
OktaV2_CL
| where TimeGenerated > ago(7d)
| extend
    SecurityData = parse_json(tostring(DebugData.logOnlySecurityData)),
    RiskRaw = tostring(DebugData.risk),
    BehaviorsRaw = tostring(DebugData.behaviors),
    ThreatSuspected = tostring(DebugData.threatSuspected),
    DeviceFingerprint = tostring(DebugData.deviceFingerprint)
| extend
    RiskLevel = tostring(SecurityData.risk.level),
    NewDevice = tostring(SecurityData.behaviors["New Device"]),
    NewIP = tostring(SecurityData.behaviors["New IP"]),
    NewCountry = tostring(SecurityData.behaviors["New Country"]),
    NewCity = tostring(SecurityData.behaviors["New City"]),
    NewGeoLocation = tostring(SecurityData.behaviors["New Geo-Location"]),
    Velocity = tostring(SecurityData.behaviors["Velocity"])
| project
    TimeGenerated,
    ActorUsername,
    EventOriginalType,
    EventResult,
    SrcIpAddr,
    SrcDvcOs,
    RiskLevel,
    RiskRaw,
    NewDevice,
    NewIP,
    NewCountry,
    NewCity,
    NewGeoLocation,
    Velocity,
    BehaviorsRaw,
    ThreatSuspected,
    DeviceFingerprint
| order by TimeGenerated desc
```

---

# 8. Microsoft Entra ID correlation

Okta and Entra normally do not share:

- Okta `authnRequestId`
- Okta `TransactionId`
- Okta `ActorSessionId`
- Entra `OriginalRequestId`
- Entra `SessionId`
- Entra `DeviceDetail.deviceId`

Correlation should therefore combine several independent attributes.

## Recommended attributes

1. Same UPN
2. Same public IP
3. Tight timestamp proximity
4. Same OS family
5. Compatible geography
6. Compatible browser/client
7. Historical Okta `deviceFingerprint`
8. Okta risk/behavior context
9. Entra device identity/trust/managed state
10. Authentication method on both sides

### Suggested confidence model

| Evidence | Assessment |
|---|---|
| User only | Weak |
| User + close time | Weak to moderate |
| User + same IP + close time | Moderate |
| User + same IP + close time + compatible OS/location | Strong contextual correlation |
| Above + familiar Okta fingerprint + consistent managed Entra device | Strong contextual correlation |
| Shared cryptographic/device identifier | Exact correlation, if actually available |

Same IP is not the same as same endpoint. NAT, VPNs, proxies, VDI, and corporate egress can cause many devices to share an IP.

---

## 8.1 Entra timeline for one user

```kusto
let User = "USER_ENTITY";
SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName =~ User
| extend
    Auth = parse_json(tostring(AuthenticationDetails)),
    Device = parse_json(tostring(DeviceDetail)),
    SignInStatus = parse_json(tostring(Status))
| extend
    AuthenticationMethod = coalesce(
        tostring(Auth.authenticationMethod),
        tostring(Auth[0].authenticationMethod),
        tostring(AuthenticationMethodsUsed)
    ),
    AuthenticationSucceeded = coalesce(
        tostring(Auth.succeeded),
        tostring(Auth[0].succeeded)
    ),
    DeviceId = tostring(Device.deviceId),
    DeviceName = tostring(Device.displayName),
    DeviceOS = tostring(Device.operatingSystem),
    DeviceTrustType = tostring(Device.trustType),
    DeviceManaged = tostring(Device.isManaged),
    DeviceCompliant = tostring(Device.isCompliant),
    ErrorCode = toint(SignInStatus.errorCode),
    StatusDetails = tostring(SignInStatus.additionalDetails)
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    AppDisplayName,
    ClientAppUsed,
    IsInteractive,
    AuthenticationMethod,
    AuthenticationSucceeded,
    AuthenticationRequirement,
    ConditionalAccessStatus,
    RiskLevelDuringSignIn,
    RiskState,
    DeviceId,
    DeviceName,
    DeviceOS,
    DeviceTrustType,
    DeviceManaged,
    DeviceCompliant,
    IncomingTokenType,
    TokenProtectionStatusDetails,
    ErrorCode,
    StatusDetails,
    LocationDetails
| order by TimeGenerated desc
```

---

## 8.2 Correlate Okta and Entra by user + IP + time

```kusto
let User = "USER_ENTITY";
let Lookback = 24h;
let CorrelationWindowSeconds = 300;

let Okta =
    OktaV2_CL
    | where TimeGenerated > ago(Lookback)
    | where ActorUsername =~ User
        or OriginalActorAlternateId =~ User
        or tostring(OriginalTarget) has User
    | extend
        CorrUser = tolower(coalesce(ActorUsername, OriginalActorAlternateId)),
        CorrIP = SrcIpAddr,
        AuthnRequestId = tostring(DebugData.authnRequestId),
        Factor = tostring(DebugData.factor),
        DeviceFingerprint = tostring(DebugData.deviceFingerprint)
    | project
        CorrUser,
        CorrIP,
        OktaTime = TimeGenerated,
        OktaEventType = EventOriginalType,
        OktaResult = EventResult,
        OktaResultDetails = EventOriginalResultDetails,
        OktaFactor = Factor,
        OktaOS = SrcDvcOs,
        OktaCity = SrcGeoCity,
        OktaCountry = SrcGeoCountry,
        OktaApp = ActingAppName,
        OktaSessionId = ActorSessionId,
        OktaAuthnRequestId = AuthnRequestId,
        OktaDeviceFingerprint = DeviceFingerprint;

let Entra =
    SigninLogs
    | where TimeGenerated > ago(Lookback)
    | where UserPrincipalName =~ User
    | extend
        CorrUser = tolower(UserPrincipalName),
        CorrIP = IPAddress,
        Auth = parse_json(tostring(AuthenticationDetails)),
        Device = parse_json(tostring(DeviceDetail)),
        SignInStatus = parse_json(tostring(Status))
    | extend
        EntraAuthenticationMethod = coalesce(
            tostring(Auth.authenticationMethod),
            tostring(Auth[0].authenticationMethod),
            tostring(AuthenticationMethodsUsed)
        ),
        EntraDeviceId = tostring(Device.deviceId),
        EntraDeviceName = tostring(Device.displayName),
        EntraOS = tostring(Device.operatingSystem),
        EntraTrustType = tostring(Device.trustType),
        EntraManaged = tostring(Device.isManaged),
        EntraErrorCode = toint(SignInStatus.errorCode)
    | project
        CorrUser,
        CorrIP,
        EntraTime = TimeGenerated,
        EntraApp = AppDisplayName,
        EntraAuthenticationMethod,
        EntraDeviceId,
        EntraDeviceName,
        EntraOS,
        EntraTrustType,
        EntraManaged,
        EntraConditionalAccess = ConditionalAccessStatus,
        EntraRisk = RiskLevelDuringSignIn,
        IncomingTokenType,
        EntraErrorCode;

Okta
| join kind=inner Entra on CorrUser, CorrIP
| extend DeltaSeconds = abs(datetime_diff("second", OktaTime, EntraTime))
| where DeltaSeconds <= CorrelationWindowSeconds
| extend CorrelationAssessment = case(
    DeltaSeconds <= 120 and OktaOS has "Windows" and EntraOS has "Windows",
        "Strong contextual correlation",
    DeltaSeconds <= 300,
        "Moderate contextual correlation",
    "Weak"
)
| project
    CorrUser,
    CorrIP,
    OktaTime,
    EntraTime,
    DeltaSeconds,
    CorrelationAssessment,
    OktaEventType,
    OktaResult,
    OktaResultDetails,
    OktaFactor,
    OktaOS,
    OktaCity,
    OktaApp,
    OktaSessionId,
    OktaAuthnRequestId,
    OktaDeviceFingerprint,
    EntraApp,
    EntraAuthenticationMethod,
    EntraDeviceName,
    EntraDeviceId,
    EntraOS,
    EntraTrustType,
    EntraManaged,
    EntraConditionalAccess,
    EntraRisk,
    IncomingTokenType,
    EntraErrorCode
| order by OktaTime asc
```

---

# 9. Official references

- Okta System Log query documentation:  
  https://developer.okta.com/docs/reference/system-log-query/

- Okta FastPass is logged as `SIGNED_NONCE`:  
  https://support.okta.com/help/s/article/what-is-signed-nonce

- Okta factor information in System Log:  
  https://support.okta.com/help/s/article/how-to-locate-factor-information-in-okta-system-log

- Okta sign-in and recovery/System Log events:  
  https://support.okta.com/help/s/article/User-Signin-and-Recovery-Events-in-the-Okta-System-Log

- Okta desktop FastPass enrollment:  
  https://support.okta.com/help/s/article/generate-a-list-of-users-enrolled-in-okta-fastpass-via-desktop-okta-verify

- Microsoft `SigninLogs` reference:  
  https://learn.microsoft.com/azure/azure-monitor/reference/tables/signinlogs

- Microsoft Windows Hello for Business authentication:  
  https://learn.microsoft.com/windows/security/identity-protection/hello-for-business/how-it-works-authentication
