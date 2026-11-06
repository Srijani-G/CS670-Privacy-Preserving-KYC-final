# Large-data module comparisons

This opt-in suite uses deterministic, fictional CSV files to compare the
existing naive (`v0`) and privacy-preserving implementations for all four
modules. It is separate from `python run_tests.py`.

## Generate the datasets

Run once from the repository root:

```powershell
python -m large_tests.generate_data
```

This creates:

- `large_tests/data/module_a_psi.csv`: 1,000 watchlist IDs and 1,000 customer IDs
  with a deterministic overlap.
- `large_tests/data/module_b_aml.csv`: 1,000 synthetic cross-bank AML cases.
- `large_tests/data/module_c_registry.csv`: 2,048 synthetic registry statuses.
- `large_tests/data/module_d_credentials.csv`: 1,000 synthetic credential cases,
  including valid and policy-invalid claims.

All data is generated for testing and is not real customer data.

## Run the large-data comparisons

From the repository root, run these five commands in order. The first command
generates the CSV files; run it again only if you want to recreate the
deterministic test data.

```powershell
python -m large_tests.generate_data
python -m large_tests.run_large_tests --module A --limit 1000
python -m large_tests.run_large_tests --module B --limit 10
python -m large_tests.run_large_tests --module C --limit 1000
python -m large_tests.run_large_tests --module D --limit 10
```

Module A processes 1,000 watchlist entries and 1,000 customer entries. Module C
uses the 2,048-record registry dataset and performs 1,000 reads. Modules B and D
also have 1,000 cases in their CSV files, but each case runs expensive
cryptographic operations: B executes the MPC pipeline, while D issues and
verifies a credential proof. For that reason, the commands intentionally limit
those runs to 10 cases. Based on initial local timings, each 10-case run may
take around a minute or longer; actual time depends on the computer and may
vary.

The runner reports the number of cases processed, elapsed time for the naive
plaintext and privacy-preserving implementations, and whether their results
agree. Module D applies the same age, nationality, and KYC-level predicates in
both implementations; a mismatch is reported as a failed comparison.
