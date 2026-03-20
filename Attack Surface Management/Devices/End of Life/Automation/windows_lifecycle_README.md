# Windows lifecycle CSV

Files:
- `windows_lifecycle_extended_support.csv`
- `update_windows_lifecycle_csv.py`
- `update-windows-lifecycle-csv.yml`

## Purpose

The CSV is meant for enterprise lifecycle queries against Windows client and Windows Server versions.

## Key columns

- `product_family`
- `product`
- `version`
- `release_train`
- `availability_date`
- `mainstream_end_date`
- `extended_end_date`
- `enterprise_end_date`
- `iot_extended_end_date`
- `latest_build`
- `base_build`
- `support_status_as_of_2026_03_20`

## Notes

- Windows 10 22H2 is marked ended because the provided source block did not include a fixed extended-support end date for the paid ESU program.
- Windows 10 LTSC 2021 and Windows 11 LTSC 2024 are split logically between Enterprise and IoT Enterprise in the CSV through `enterprise_end_date` and `iot_extended_end_date`.
- Windows 11 LTSC source text included `24H21`; the scraper normalizes directly from the page table and keeps the page value.
