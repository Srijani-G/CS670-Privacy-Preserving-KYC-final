"""Run the full attack lab: every attack against v0 and v1, side by side."""

from attacks.attacks import build_attacks
from attacks.harness import run_all


def main():
    run_all(build_attacks())


if __name__ == "__main__":
    main()
