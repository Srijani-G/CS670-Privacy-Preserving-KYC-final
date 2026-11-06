"""Compare naive and privacy-preserving module results on synthetic CSV data."""

from __future__ import annotations

import argparse
import csv
import json
import secrets
import time
from pathlib import Path

from ppkyc.kyc_naive.v0 import V0System, sha256_id
from ppkyc.mpc.pipeline import run_pipeline
from ppkyc.oram.doram_ro import RegistryClient, RegistryServer
from ppkyc.psi.dh_psi import run_psi
from ppkyc.zkp import credential as cr


ROOT = Path(__file__).parent
DATA_DIR = ROOT / "data"
WEIGHTS = [2, 10]
THRESHOLD = 20_000
TODAY = 20261106
RP_ID = "large-test-bank"


def _rows(filename: str) -> list[dict[str, str]]:
    path = DATA_DIR / filename
    with path.open(newline="", encoding="utf-8") as file:
        return list(csv.DictReader(file))


def _limit(rows: list, limit: int) -> list:
    if limit <= 0:
        raise ValueError("--limit must be a positive integer")
    return rows[:limit]


def run_module_a(limit: int) -> dict:
    data = _rows("module_a_psi.csv")
    watchlist = [row["identifier"] for row in data if row["role"] == "watchlist"]
    customers = [row["identifier"] for row in data if row["role"] == "customer"]
    watchlist, customers = _limit(watchlist, limit), _limit(customers, limit)

    naive = V0System()
    naive.watchlist.update(sha256_id(identifier) for identifier in watchlist)
    start = time.perf_counter()
    naive_matches = [identifier for identifier in customers
                     if naive.is_sanctioned(identifier)]
    naive_seconds = time.perf_counter() - start

    start = time.perf_counter()
    private_matches = run_psi(watchlist, customers)
    private_seconds = time.perf_counter() - start
    matches_agree = set(naive_matches) == set(private_matches)
    return {
        "module": "A - PSI",
        "watchlist_rows": len(watchlist),
        "customer_rows": len(customers),
        "naive_matches": len(naive_matches),
        "private_matches": len(private_matches),
        "outputs_agree": matches_agree,
        "naive_seconds": naive_seconds,
        "private_seconds": private_seconds,
    }


def run_module_b(limit: int) -> dict:
    cases = _limit(_rows("module_b_aml.csv"), limit)
    naive = V0System()
    prepared = []
    for row in cases:
        banks = [
            [int(row[f"bank{bank}_amount"]), int(row[f"bank{bank}_count"])]
            for bank in range(1, 4)
        ]
        combined = [sum(bank[feature] for bank in banks) for feature in range(2)]
        customer_id = row["case_id"]
        id_hash = naive.add_customer(
            customer_id, customer_id, 19900101, "TEST", 1, amounts=combined
        )
        prepared.append((row["case_id"], banks, id_hash))

    start = time.perf_counter()
    naive_results = {
        case_id: naive.risk_engine(id_hash, WEIGHTS, THRESHOLD)
        for case_id, _, id_hash in prepared
    }
    naive_seconds = time.perf_counter() - start

    start = time.perf_counter()
    private_results = {
        case_id: run_pipeline(banks, WEIGHTS, THRESHOLD, bits=16)
        for case_id, banks, _ in prepared
    }
    private_seconds = time.perf_counter() - start
    agreements = sum(
        naive_results[case_id]["score"] == private_results[case_id]["score"]
        and naive_results[case_id]["flag"] == private_results[case_id]["flag"]
        for case_id, _, _ in prepared
    )
    return {
        "module": "B - MPC/AML",
        "cases": len(prepared),
        "outputs_agree": agreements == len(prepared),
        "matching_cases": agreements,
        "naive_seconds": naive_seconds,
        "private_seconds": private_seconds,
    }


def run_module_c(limit: int) -> dict:
    data = _limit(_rows("module_c_registry.csv"), 2048)
    database = [int(row["status"]) for row in data]
    query_rows = _limit(data, limit)

    naive = V0System()
    naive.registry = database.copy()
    start = time.perf_counter()
    naive_values = [naive.registry_read(int(row["index"])) for row in query_rows]
    naive_seconds = time.perf_counter() - start

    server0 = RegistryServer("S0", database)
    server1 = RegistryServer("S1", database)
    client = RegistryClient(server0, server1)
    start = time.perf_counter()
    private_values = [client.read(int(row["index"])) for row in query_rows]
    private_seconds = time.perf_counter() - start
    return {
        "module": "C - DORAM",
        "registry_rows": len(database),
        "queries": len(query_rows),
        "outputs_agree": naive_values == private_values,
        "naive_seconds": naive_seconds,
        "private_seconds": private_seconds,
        "server0_query_lengths": sorted(set(server0.query_log)),
        "server1_query_lengths": sorted(set(server1.query_log)),
        "naive_logged_indices": len(naive.registry_access_log),
    }


def run_module_d(limit: int) -> dict:
    cases = _limit(_rows("module_d_credentials.csv"), limit)
    issuer = cr.Issuer("large-test-issuer")
    relying_party = cr.RelyingParty(RP_ID, issuer.ipk)
    predicates = cr.Predicates(
        min_age=18, allowed_nats=[1, 44, 91], min_level=2
    )
    naive = V0System()
    naive_values = []
    private_values = []

    start = time.perf_counter()
    for row in cases:
        national_id = row["national_id"]
        naive.add_customer(
            national_id, row["case_id"], int(row["dob"]),
            str(row["nationality"]), int(row["kyc_level"]),
        )
        if row["document_present"] == "1":
            naive.documents[sha256_id(national_id)] = b"synthetic-document"
        naive_values.append(naive.present_age(national_id, claimed_age=18))
    naive_seconds = time.perf_counter() - start

    start = time.perf_counter()
    for index, row in enumerate(cases):
        wallet = cr.Wallet(
            dob=int(row["dob"]),
            nationality=int(row["nationality"]),
            kyc_level=int(row["kyc_level"]),
        )
        credential = cr.issue(
            issuer,
            wallet.issuance_request(),
            expiry=20301231,
            expected={
                "dob": wallet.dob,
                "nat": wallet.nationality,
                "level": wallet.kyc_level,
            },
        )
        wallet.store_credential(credential)
        request = cr.PresentationRequest(
            RP_ID, secrets.token_bytes(16), index, TODAY, predicates
        )
        try:
            presentation = cr.present(wallet, request)
            accepted = relying_party.verify(presentation, request)
        except ValueError:
            accepted = False
        private_values.append(accepted)
    private_seconds = time.perf_counter() - start
    naive_accepts = sum(naive_values)
    private_accepts = sum(private_values)
    return {
        "module": "D - ZKP credentials",
        "cases": len(cases),
        "naive_accepts": naive_accepts,
        "private_accepts": private_accepts,
        "naive_false_accepts": sum(
            naive_value and not private_value
            for naive_value, private_value in zip(naive_values, private_values)
        ),
        "outputs_agree": naive_values == private_values,
        "naive_seconds": naive_seconds,
        "private_seconds": private_seconds,
        "comparison_note": (
            "Intentional security comparison: v0 accepts any uploaded document; "
            "v1 accepts only credentials satisfying all configured predicates."
        ),
    }


RUNNERS = {
    "A": run_module_a,
    "B": run_module_b,
    "C": run_module_c,
    "D": run_module_d,
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--module", choices=["A", "B", "C", "D", "all"], default="all",
        help="module to run (default: all)",
    )
    parser.add_argument(
        "--limit", type=int, default=10,
        help="maximum rows/cases to process (default: 10); use 1000 for full case files",
    )
    parser.add_argument(
        "--output", type=Path,
        help="optional path to save the JSON results",
    )
    args = parser.parse_args()
    if args.limit <= 0:
        parser.error("--limit must be a positive integer")

    selected = list(RUNNERS) if args.module == "all" else [args.module]
    results = []
    for module in selected:
        result = RUNNERS[module](args.limit)
        results.append(result)
        print(
            f"{result['module']}: "
            f"rows/cases={result.get('cases', result.get('customer_rows', result.get('queries')))}, "
            f"outputs_agree={result['outputs_agree']}, "
            f"naive={result['naive_seconds']:.4f}s, "
            f"private={result['private_seconds']:.4f}s"
        )
        if module == "A":
            print(f"  matched rows: naive={result['naive_matches']}, "
                  f"private={result['private_matches']}")
        elif module == "D":
            print(f"  accepted: naive={result['naive_accepts']}, "
                  f"private={result['private_accepts']}, "
                  f"naive false accepts={result['naive_false_accepts']}")
            print("  Differences are expected when the naive document check "
                  "accepts a claim that fails a private credential predicate.")

    passed = all(
        result["outputs_agree"]
        for result in results
        if not result["module"].startswith("D -")
    )
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
        print(f"Saved results to {args.output}")
    if not passed:
        print("At least one correctness comparison failed.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
