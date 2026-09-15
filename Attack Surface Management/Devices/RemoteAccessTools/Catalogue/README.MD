# Remote Access Catalogue

This folder contains the catalogue used by the Remote Access Tools KQL to identify installed and active remote assistance, remote access, and RMM products.

## Files

### RemoteAccessProducts.csv

Contains one row per remote access product.

- Header

- Description

- ProductId

Stable unique identifier used to join the product to its indicators. Do not change once in use.

#### Vendor

Vendor or manufacturer of the product.

#### Product

Product name shown in the ASM report.

#### Type

Product classification, for example RMM, Remote Access, Managed Remote Assistance, or Built-in Remote Assistance.

#### OfficialURL

Vendor or product documentation URL used as the primary reference.

#### LastVerified

Date the product information was last verified.

#### Notes

Additional information about the product, naming, rebranding, or limitations.

### RemoteAccessIndicators.csv

Contains the technical indicators used to identify products in Defender inventory and process telemetry.

A product can have multiple indicators. All indicators are linked to the product through ProductId.

- Header

- Description

- ProductId
  - References the matching entry in RemoteAccessProducts.csv.

- Platform
  - Operating system or platform the indicator applies to.

- IndicatorType
  - Telemetry field represented by the indicator, for example SoftwareName or ProcessName.

- IndicatorValue
  - Value searched for in Defender telemetry, such as an executable or software name.

- MatchType
  - Matching method, for example equals, contains, or startswith.

- ActivityRole
  - Purpose of the indicator, such as Installation, Agent, Service, Interactive, Viewer, or SessionComponent.

- PathPattern
  - Optional expected installation or executable path.

- CompanyPattern
  - Optional expected publisher/company metadata.

- Enabled
  - Determines whether the indicator is used by the production KQL.

- Confidence
  - Evidence level for the indicator, for example VendorVerified, VendorProduct, VendorCommunity, or Supplemental.

-SourceURL
  - Vendor documentation or other source used to verify the indicator.

- LastVerified
   - Date the indicator was last verified.

- Notes
  - Additional context or limitations for the indicator.

## Maintenance

Add new products to RemoteAccessProducts.csv first, then add one or more corresponding indicators to RemoteAccessIndicators.csv.

Prefer vendor documentation when adding or changing indicators. Set Enabled=false for indicators that are useful for hunting but have not been sufficiently verified.

Do not create duplicate ProductId values for the same product.
