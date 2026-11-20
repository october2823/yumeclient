"""Record (``--update``) or check the per-profile fingerprint fixtures in
tests/fixtures/profiles.json. Offline: a local TLS server behind a sniffing relay.

    python scripts/profile_fixtures.py            # print differences, exit 1 if any
    python scripts/profile_fixtures.py --update   # rewrite the fixture file
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]

from test_profile_fixtures import FIXTURES, generate  # noqa: E402
from test_wire import Sniffer  # noqa: E402
from yumeclient import fingerprint_diff  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--update", action="store_true", help="rewrite tests/fixtures/profiles.json")
    args = parser.parse_args()
    sniffer = Sniffer()
    try:
        fresh = generate(sniffer)
    finally:
        sniffer.close()
    if args.update:
        FIXTURES.parent.mkdir(parents=True, exist_ok=True)
        FIXTURES.write_text(json.dumps(fresh, indent=1, sort_keys=False) + "\n", encoding="utf-8")
        print(f"wrote {len(fresh['profiles'])} profiles to {FIXTURES.relative_to(ROOT)}")
        return 0
    old = json.loads(FIXTURES.read_text(encoding="utf-8"))["profiles"] if FIXTURES.exists() else {}
    changed = 0
    for name in sorted(set(old) | set(fresh["profiles"])):
        if name not in old or name not in fresh["profiles"]:
            print(f"{name}: {'added' if name not in old else 'removed'}"); changed += 1; continue
        expected, actual = old[name], fresh["profiles"][name]
        diff = [d for d in fingerprint_diff(expected, actual)
                if not (expected["shuffled"] and d["kind"] == "order")]
        if expected["handshake"] != actual["handshake"]:
            diff.append({"field": "handshake", "expected": expected["handshake"], "actual": actual["handshake"]})
        if diff:
            changed += 1
            print(f"{name}:")
            for d in diff: print(f"  {json.dumps(d)}")
    print(f"{changed} profile(s) differ" if changed else "all profiles match")
    return 1 if changed else 0


if __name__ == "__main__":
    raise SystemExit(main())
