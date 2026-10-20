# Password Expiration

## Purpose

Assess the on-premises AD account setting **Password never expires**, and distinguish it from the effective password expiration policy and Microsoft Entra Password Protection.

## Recommendation

Microsoft recommends avoiding routine password expiration for user accounts, alongside MFA and strong password controls. Require password changes when compromise is suspected or confirmed. Where an explicit organisational or regulatory requirement mandates periodic expiration, document the requirement and the accepted deviation from this recommendation.

This guidance concerns user passwords. Managed service account and local administrator password rotation require separate assessment.

## Separate controls

| Control | Configuration | What it does |
| --- | --- | --- |
| Password expiration | AD domain password policy or Fine-Grained Password Policies | Sets the maximum password age. A maximum age of zero means passwords do not expire. |
| Password never expires | Individual AD account attribute | Exempts that account from normal password age expiration. |
| Password length, complexity and history | AD password policies | Applies traditional password requirements. |
| Microsoft Entra Password Protection | Entra configuration, proxy service and domain controller agents | Validates new passwords against global and custom banned-password lists, including weak variants. It does not configure expiration. |

Password Protection supplements AD policies. It does not retrospectively validate existing passwords or stop password-spray sign-in attempts. It reduces susceptibility by rejecting weak passwords during changes and resets.

## KQL: account flag summary

Run in **Microsoft Defender Advanced Hunting**, with on-premises identity data available in `IdentityInfo`.

```kusto
IdentityInfo
| where Timestamp > ago(30d)
| where isnotempty(OnPremSid)
| summarize arg_max(Timestamp, *) by OnPremSid
| extend PasswordExpirationSetting = case(
    isempty(UserAccountControl), "Unknown",
    UserAccountControl contains "PasswordNeverExpires", "Password never expires",
    "Password never expires flag not set"
)
| summarize Accounts = count() by PasswordExpirationSetting
| order by Accounts desc
```

The query selects the latest available record per on-premises SID within 30 days. It includes enabled and disabled accounts represented in the table. To count only enabled accounts, add the following immediately after `summarize arg_max(...)`:

```kusto
| where IsAccountEnabled == true
```

### Interpretation and limitations

- **Password never expires:** The reported AD attributes contain the `PasswordNeverExpires` flag.
- **Password never expires flag not set:** The reported attributes do not contain the flag. This does not prove that the password expires.
- **Unknown:** The record has no populated `UserAccountControl` value. Do not count this as confirmed expiration.
- The query assumes `UserAccountControl` contains named attributes, including `PasswordNeverExpires`. Inspect sample values before using the report; numeric or otherwise unexpected representations require a different parser.
- Results describe accounts available in the identity telemetry, not a guaranteed complete AD inventory. No results do not establish that no accounts exist.
- This query does not determine the applicable domain or Fine-Grained Password Policy. An account without the flag can still have a non-expiring password when its effective maximum password age is zero.
- This is not an assessment of the Microsoft 365 cloud password expiration policy. Assess cloud and on-premises policy separately for hybrid identities.
- The query has not been executed against a customer tenant. Validate table availability, field values and inventory coverage before reporting counts.

## Transition with Password Protection

1. Deploy Password Protection across all writable domain controllers and validate enforcement. Audit mode alone does not reject passwords.
2. Establish how existing user passwords will pass through validation. Microsoft documents a one-time manual password expiration as an option; plan the change and assess service dependencies before applying it.
3. Remove routine user password expiration where approved, retaining a process to change passwords when compromise is suspected or confirmed.

If expiration is removed before existing passwords are changed, existing weak passwords can remain unvalidated indefinitely. Password Protection only evaluates passwords during a change or reset.

## Suggested ASM note

> We recommend disabling routine user password expiration alongside MFA and strong password controls, and deploying Microsoft Entra Password Protection to reject known weak passwords during changes and resets. Validate existing-password transition arrangements and the effective AD policies before making changes. Where periodic expiration is explicitly required, document the justification and accepted deviation.

## Sources

- [Microsoft password policy recommendations](https://learn.microsoft.com/en-us/microsoft-365/admin/misc/password-policy-recommendations)
- [Maximum password age](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/maximum-password-age)
- [Microsoft Entra Password Protection for on-premises AD DS](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad-on-premises)
- [On-premises Password Protection FAQ](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-ban-bad-on-premises-faq)
- [IdentityInfo Advanced Hunting schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identityinfo-table)

Documentation reviewed: 20 October 2026. Recheck current guidance during future assessments rather than assuming a different recommendation for 2027.
