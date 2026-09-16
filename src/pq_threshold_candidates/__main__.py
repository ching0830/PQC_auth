"""Print research size estimates without generating cryptographic artifacts."""

import argparse
import json

from .accounting import comparison_report
from .contracts import uint


def nonnegative_bytes(text: str) -> int:
    try:
        return uint(int(text), "byte estimate")
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sigma-bytes", type=nonnegative_bytes, default=11644)
    parser.add_argument("--extra-bytes", type=nonnegative_bytes)
    parser.add_argument("--g-bytes", type=nonnegative_bytes)
    parser.add_argument("--delta-bytes", type=nonnegative_bytes)
    args = parser.parse_args()
    try:
        report = comparison_report(**vars(args))
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(report, indent=2, sort_keys=True, allow_nan=False))


if __name__ == "__main__":
    main()
