"""Offline verifier for export bundles. Needs only the standard library and app/chain.py.

Usage:  python -m app.verify_bundle bundle.json [--expected-head <trusted head hash>]
Exit code 0 = verified, 1 = verification failed.
"""

import argparse
import json
import sys

from app.chain import verify_bundle


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("bundle", help="path to the exported bundle JSON")
    parser.add_argument("--expected-head", help="head hash from a trusted checkpoint")
    args = parser.parse_args(argv)
    with open(args.bundle, encoding="utf-8") as f:
        result = verify_bundle(json.load(f))
    if result["valid"] and args.expected_head and result["headHash"] != args.expected_head:
        result |= {"valid": False, "violation": "HEAD_MISMATCH",
                   "detail": "bundle head differs from the trusted checkpoint"}
    print(json.dumps(result, indent=2))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
