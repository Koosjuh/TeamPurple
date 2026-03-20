from __future__ import annotations

import csv
import re
from dataclasses import dataclass, asdict
from datetime import date
from pathlib import Path
from typing import Iterable

import requests
from bs4 import BeautifulSoup


WINDOWS10_URL = "https://learn.microsoft.com/en-us/windows/release-health/release-information"
WINDOWS11_URL = "https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information"
SERVER_URL = "https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info"

OUTFILE = Path("windows_lifecycle_extended_support.csv")
TODAY = date.today().isoformat()


@dataclass
class LifecycleRow:
    product_family: str
    product: str
    version: str
    release_train: str
    servicing_option: str
    editions: str
    availability_date: str
    mainstream_end_date: str
    extended_end_date: str
    extended_support_scope: str
    enterprise_end_date: str
    iot_extended_end_date: str
    latest_update_label: str
    latest_revision_date: str
    latest_build: str
    base_build: str
    support_status_as_of_2026_03_20: str
    notes: str


def fetch_html(url: str) -> str:
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    return response.text


def clean_text(value: str) -> str:
    value = re.sub(r"\s+", " ", value).strip()
    value = value.replace("\u00a0", " ")
    return value


def extract_tables(html: str) -> list[list[list[str]]]:
    soup = BeautifulSoup(html, "html.parser")
    tables = []
    for table in soup.find_all("table"):
        rows = []
        for tr in table.find_all("tr"):
            cells = [clean_text(td.get_text(" ", strip=True)) for td in tr.find_all(["th", "td"])]
            if cells:
                rows.append(cells)
        if rows:
            tables.append(rows)
    return tables


def find_table_by_headers(tables: list[list[list[str]]], expected_headers: list[str]) -> list[list[str]]:
    expected = [clean_text(x) for x in expected_headers]
    for table in tables:
        headers = table[0]
        if headers[: len(expected)] == expected:
            return table
    raise ValueError(f"Could not find table with headers: {expected_headers}")


def base_build_from_full_build(build: str) -> str:
    return build.split(".", 1)[0].strip() if build else ""


def status_from_end_date(end_date: str) -> str:
    if not end_date or end_date == "End of updates":
        return "ended"
    if end_date > "2026-03-20":
        return "supported"
    return "ended"


def add_windows_server_rows(rows: list[LifecycleRow], html: str) -> None:
    tables = extract_tables(html)
    table = find_table_by_headers(
        tables,
        [
            "Windows Server version",
            "Servicing option",
            "Editions",
            "Availability date",
            "Mainstream support end date",
            "Extended support end date",
            "Latest update for ESU",
            "Latest revision date",
            "Latest build",
        ],
    )

    for r in table[1:]:
        if len(r) < 9:
            continue
        product, servicing_option, editions, availability_date, mainstream_end_date, extended_end_date, latest_update_label, latest_revision_date, latest_build = r[:9]
        version_match = re.search(r"(\d{4}|\d{4} \(version \d+\)|version \d+)", product)
        version = version_match.group(1).replace("version ", "") if version_match else product
        release_train = "LTSC" if "LTSC" in servicing_option else "LTSB" if "LTSB" in servicing_option else ""
        status = "extended-support" if mainstream_end_date == "End of updates" and extended_end_date != "End of updates" else status_from_end_date(extended_end_date)

        note = "Mainstream support ended; extended support continues." if mainstream_end_date == "End of updates" and extended_end_date != "End of updates" else ""

        rows.append(
            LifecycleRow(
                product_family="Windows Server",
                product=product.replace(" (version ", " ").replace(")", ""),
                version=version,
                release_train=release_train,
                servicing_option=servicing_option,
                editions=editions,
                availability_date=availability_date,
                mainstream_end_date="" if mainstream_end_date == "End of updates" else mainstream_end_date,
                extended_end_date="" if extended_end_date == "End of updates" else extended_end_date,
                extended_support_scope=editions if extended_end_date != "End of updates" else "",
                enterprise_end_date="",
                iot_extended_end_date="",
                latest_update_label=latest_update_label,
                latest_revision_date=latest_revision_date,
                latest_build=latest_build,
                base_build=base_build_from_full_build(latest_build),
                support_status_as_of_2026_03_20=status,
                notes=note,
            )
        )


def add_windows10_rows(rows: list[LifecycleRow], html: str) -> None:
    tables = extract_tables(html)

    current_table = find_table_by_headers(
        tables,
        [
            "Version",
            "Servicing option",
            "Availability date",
            "End of updates: Home, Pro, Pro Education, and Pro for Workstations",
            "End of updates: Enterprise, Education, IoT Enterprise, and Enterprise multi-session",
            "Latest update for ESU",
            "Latest revision date",
            "Latest build",
        ],
    )
    for r in current_table[1:]:
        if len(r) < 8:
            continue
        version, servicing_option, availability_date, _, enterprise_end_date, latest_update_label, latest_revision_date, latest_build = r[:8]
        rows.append(
            LifecycleRow(
                product_family="Windows 10",
                product="Windows 10",
                version=version,
                release_train="GA",
                servicing_option=servicing_option,
                editions="Enterprise, Education, IoT Enterprise, Enterprise multi-session",
                availability_date=availability_date,
                mainstream_end_date="",
                extended_end_date="",
                extended_support_scope="",
                enterprise_end_date=enterprise_end_date,
                iot_extended_end_date="",
                latest_update_label=latest_update_label,
                latest_revision_date=latest_revision_date,
                latest_build=latest_build,
                base_build=base_build_from_full_build(latest_build),
                support_status_as_of_2026_03_20="ended" if enterprise_end_date == "End of updates" else status_from_end_date(enterprise_end_date),
                notes="Enterprise support ended. ESU exists as a paid program, but no fixed extended end date was present in this table.",
            )
        )

    ltsc_table = find_table_by_headers(
        tables,
        [
            "Version",
            "Servicing option",
            "Availability date",
            "Mainstream support end date",
            "Extended support end date",
            "Latest update for ESU",
            "Latest revision date",
            "Latest build",
        ],
    )
    for r in ltsc_table[1:]:
        if len(r) < 8:
            continue
        version, servicing_option, availability_date, mainstream_end_date, extended_end_date, latest_update_label, latest_revision_date, latest_build = r[:8]
        version_label = version
        product = f"Windows 10 {version_label}"
        release_train = "LTSC" if "LTSC" in servicing_option else "LTSB" if "LTSB" in servicing_option else ""
        notes = ""
        enterprise_end_date = ""
        iot_extended_end_date = ""
        extended_support_scope = "Enterprise LTSC/LTSB"

        if "IoT Enterprise only" in extended_end_date:
            iot_date = re.search(r"(\d{4}-\d{2}-\d{2})", extended_end_date)
            iot_extended_end_date = iot_date.group(1) if iot_date else ""
            enterprise_end_date = mainstream_end_date
            extended_end_date_clean = ""
            extended_support_scope = "IoT Enterprise only"
            notes = "Enterprise LTSC 2021 has no extended support. IoT Enterprise only extends beyond mainstream support."
            status = status_from_end_date(enterprise_end_date)
        else:
            extended_end_date_clean = "" if extended_end_date == "End of updates" else extended_end_date
            enterprise_end_date = mainstream_end_date if mainstream_end_date == "End of updates" else ""
            status = "extended-support" if mainstream_end_date == "End of updates" and extended_end_date_clean else status_from_end_date(extended_end_date_clean)
            if mainstream_end_date == "End of updates" and extended_end_date_clean:
                notes = "Mainstream support ended; extended support continues."

        rows.append(
            LifecycleRow(
                product_family="Windows 10",
                product=product,
                version=re.search(r"\(([^)]+)\)", version_label).group(1) if "(" in version_label else version_label,
                release_train=release_train,
                servicing_option=servicing_option,
                editions="Enterprise LTSC/LTSB, IoT Enterprise LTSC/LTSB",
                availability_date=availability_date,
                mainstream_end_date="" if mainstream_end_date == "End of updates" else mainstream_end_date,
                extended_end_date=extended_end_date_clean,
                extended_support_scope=extended_support_scope,
                enterprise_end_date=enterprise_end_date,
                iot_extended_end_date=iot_extended_end_date,
                latest_update_label=latest_update_label,
                latest_revision_date=latest_revision_date,
                latest_build=latest_build,
                base_build=base_build_from_full_build(latest_build),
                support_status_as_of_2026_03_20=status,
                notes=notes,
            )
        )


def add_windows11_rows(rows: list[LifecycleRow], html: str) -> None:
    tables = extract_tables(html)

    current_table = find_table_by_headers(
        tables,
        [
            "Version",
            "Servicing option",
            "Availability date",
            "End of updates: Home, Pro, Pro Education, and Pro for Workstations",
            "End of updates: Enterprise, Education, IoT Enterprise, and Enterprise multi-session",
            "Latest update for ESU",
            "Latest revision date",
            "Latest build",
        ],
    )
    for r in current_table[1:]:
        if len(r) < 8:
            continue
        version, servicing_option, availability_date, _, enterprise_end_date, latest_update_label, latest_revision_date, latest_build = r[:8]
        editions = "Enterprise, Education, IoT Enterprise, Enterprise multi-session"
        notes = ""
        if version == "26H1":
            editions = "Enterprise, Education"
            notes = "IoT Enterprise is not supported on Windows 11, version 26H1."

        rows.append(
            LifecycleRow(
                product_family="Windows 11",
                product="Windows 11",
                version=version,
                release_train="GA",
                servicing_option=servicing_option,
                editions=editions,
                availability_date=availability_date,
                mainstream_end_date="",
                extended_end_date="" if enterprise_end_date == "End of updates" else enterprise_end_date,
                extended_support_scope=editions,
                enterprise_end_date=enterprise_end_date,
                iot_extended_end_date="",
                latest_update_label=latest_update_label,
                latest_revision_date=latest_revision_date,
                latest_build=latest_build,
                base_build=base_build_from_full_build(latest_build),
                support_status_as_of_2026_03_20="ended" if enterprise_end_date == "End of updates" else status_from_end_date(enterprise_end_date),
                notes=notes,
            )
        )

    ltsc_table = find_table_by_headers(
        tables,
        [
            "Version",
            "Servicing option",
            "Availability date",
            "Mainstream support end date",
            "Extended support end date",
            "Latest update for ESU",
            "Latest revision date",
            "Latest build",
        ],
    )

    for r in ltsc_table[1:]:
        if len(r) < 8:
            continue
        version, servicing_option, availability_date, mainstream_end_date, extended_end_date, latest_update_label, latest_revision_date, latest_build = r[:8]
        notes = "Enterprise LTSC 2024 has no extended support beyond its mainstream/end-of-servicing date. IoT Enterprise LTSC 2024 extends to the listed extended date."
        rows.append(
            LifecycleRow(
                product_family="Windows 11",
                product="Windows 11 Enterprise LTSC 2024 / IoT Enterprise LTSC 2024",
                version=version.replace("¹", ""),
                release_train="LTSC",
                servicing_option=servicing_option,
                editions="Enterprise LTSC 2024, IoT Enterprise LTSC 2024",
                availability_date=availability_date,
                mainstream_end_date=mainstream_end_date,
                extended_end_date=extended_end_date,
                extended_support_scope="IoT Enterprise LTSC 2024 only",
                enterprise_end_date=mainstream_end_date,
                iot_extended_end_date=extended_end_date,
                latest_update_label=latest_update_label,
                latest_revision_date=latest_revision_date,
                latest_build=latest_build,
                base_build=base_build_from_full_build(latest_build),
                support_status_as_of_2026_03_20=status_from_end_date(mainstream_end_date),
                notes=notes,
            )
        )


def main() -> None:
    rows: list[LifecycleRow] = []
    add_windows_server_rows(rows, fetch_html(SERVER_URL))
    add_windows10_rows(rows, fetch_html(WINDOWS10_URL))
    add_windows11_rows(rows, fetch_html(WINDOWS11_URL))

    rows.sort(key=lambda x: (x.product_family, x.base_build, x.version))

    with OUTFILE.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(asdict(rows[0]).keys()))
        writer.writeheader()
        for row in rows:
            writer.writerow(asdict(row))


if __name__ == "__main__":
    main()
