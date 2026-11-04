#!/usr/bin/env python3
"""Minimal test runner: discovers and runs every ``test_*`` function in the
``tests`` package.  Works with or without pytest installed (``pytest`` also
discovers these files).
"""

import importlib
import pkgutil
import time
import traceback

import tests


def main() -> int:
    passed = failed = 0
    failures = []
    t_start = time.time()
    for mod_info in pkgutil.iter_modules(tests.__path__, tests.__name__ + "."):
        module = importlib.import_module(mod_info.name)
        for name in sorted(dir(module)):
            if not name.startswith("test_"):
                continue
            fn = getattr(module, name)
            if not callable(fn):
                continue
            label = f"{mod_info.name.split('.')[-1]}.{name}"
            t0 = time.time()
            try:
                fn()
                dt = time.time() - t0
                print(f"  PASS  {label}  ({dt:.2f}s)")
                passed += 1
            except Exception as exc:  # noqa: BLE001
                print(f"  FAIL  {label}: {exc}")
                failures.append((label, traceback.format_exc()))
                failed += 1
    print("-" * 70)
    print(f"{passed} passed, {failed} failed in {time.time() - t_start:.1f}s")
    for label, tb in failures:
        print(f"\n=== {label} ===\n{tb}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
