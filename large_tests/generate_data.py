"""Generate deterministic, fictional datasets for the opt-in large tests."""

from __future__ import annotations

import csv
from datetime import date
from pathlib import Path


ROOT = Path(__file__).parent
DATA_DIR = ROOT / "data"
ROWS = 1000
DORAM_ROWS = 2048


def _write_csv(path: Path, fieldnames: list[str], rows) -> None:
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def generate_psi_data() -> None:
    rows = []
    for index in range(ROWS):
        rows.append({
            "role": "watchlist",
            "identifier": f"test-person-{index:06d}|19800101|US",
        })
    for index in range(500, 500 + ROWS):
        rows.append({
            "role": "customer",
            "identifier": f"test-person-{index:06d}|19800101|US",
        })
    _write_csv(DATA_DIR / "module_a_psi.csv", ["role", "identifier"], rows)


def generate_aml_data() -> None:
    rows = []
    for index in range(ROWS):
        row = {"case_id": f"aml-{index:06d}"}
        for bank in range(1, 4):
            row[f"bank{bank}_amount"] = (index * 17 + bank * 31) % 5000
            row[f"bank{bank}_count"] = (index * 3 + bank) % 20
        rows.append(row)
    fields = ["case_id"] + [
        f"bank{bank}_{feature}"
        for bank in range(1, 4)
        for feature in ("amount", "count")
    ]
    _write_csv(DATA_DIR / "module_b_aml.csv", fields, rows)


def generate_registry_data() -> None:
    rows = [
        {"index": index, "status": (index * 7 + 3) % 4}
        for index in range(DORAM_ROWS)
    ]
    _write_csv(DATA_DIR / "module_c_registry.csv", ["index", "status"], rows)


def generate_credential_data() -> None:
    rows = []
    for index in range(ROWS):
        kind = index % 4
        year = 2012 + index % 5 if kind == 1 else 1985 + index % 20
        dob = int(date(year, 1, 1).strftime("%Y%m%d"))
        nationality = 7 if kind == 2 else 91
        kyc_level = 1 if kind == 3 else 3
        rows.append({
            "case_id": f"credential-{index:06d}",
            "national_id": f"SYNTHETIC-{index:06d}",
            "dob": dob,
            "nationality": nationality,
            "kyc_level": kyc_level,
            "document_present": 1,
        })
    _write_csv(
        DATA_DIR / "module_d_credentials.csv",
        ["case_id", "national_id", "dob", "nationality", "kyc_level",
         "document_present"],
        rows,
    )


def main() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    generate_psi_data()
    generate_aml_data()
    generate_registry_data()
    generate_credential_data()
    print(f"Generated four synthetic datasets in {DATA_DIR}")
    print(f"  Module A: {ROWS} watchlist IDs + {ROWS} customer IDs")
    print(f"  Module B: {ROWS} customer cases")
    print(f"  Module C: {DORAM_ROWS} registry records")
    print(f"  Module D: {ROWS} credential cases")


if __name__ == "__main__":
    main()
