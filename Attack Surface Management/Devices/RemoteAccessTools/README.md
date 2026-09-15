# Remote Access / RMM catalogue

Files:

- `RemoteAccessProducts.csv`: one canonical row per product.
- `RemoteAccessIndicators.csv`: normalized software/process indicators with evidence, activity role and optional qualifiers.
- `RemoteAccessTools.kql`: Defender XDR Advanced Hunting query that loads both CSV files through `externaldata()`.

## Evidence policy

- `VendorVerified`: exact executable/component documented by the vendor.
- `VendorCommunity`: vendor-operated support/community evidence.
- `VendorProduct`: the product/software name is vendor-confirmed; executable detail may not be explicitly enumerated.
- `Supplemental`: useful cross-check from a reputable external catalogue, disabled by default in KQL.

`Enabled=false` indicators remain in the catalogue for research/coverage but are excluded from the production query unless `IncludeSupplementalIndicators` is changed to `true`.

## Reporting semantics

- `InstalledDevices`: distinct devices from `DeviceTvmSoftwareInventory`.
- `ActiveDevices30d`: distinct devices with any matched product process in the last 30 days. Persistent agent/service activity is included.
- `InteractiveOrSessionDevices30d`: distinct devices where a user-facing or session-specific component was observed. This is stronger evidence of interactive use, but is still not equivalent to a confirmed successful remote-control session for every product.
- `LastObserved`: latest matching process event.

The catalogue is Windows-focused because the current report logic uses Windows executable/process telemetry.

## Query performance

`RemoteAccessTools.kql` uses equality joins for exact process filenames. Only the small set of `contains`/`startswith` process indicators uses pattern matching. This avoids a Cartesian join between the full 30-day `DeviceProcessEvents` dataset and the complete indicator catalogue.
