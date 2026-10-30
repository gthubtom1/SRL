"""Public source verification only; complete local acceptance remains check.py.

Reuse the existing suite inventory, execution function and timeouts. The explicit
manifest must classify every suite; new/unclassified or changed commands fail.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("public_check_runtime", ROOT / "Tool/scripts/check.py")
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


def inventory(manifest, suites):
    available = {name: (argv, why) for name, argv, _fast, why in suites}
    included, excluded = manifest["included"], manifest["excluded"]
    if set(included) & set(excluded) or set(included) | set(excluded) != set(available):
        raise ValueError("every runtime suite must be explicitly included or excluded exactly once")
    if not all(isinstance(reason, str) and reason.strip() for reason in excluded.values()):
        raise ValueError("excluded suites require concrete reasons")
    for name, argv in included.items():
        if argv != available[name][0]:
            raise ValueError("suite command changed; review public dependencies: " + name)
    return available


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()
    manifest = json.loads((ROOT / ".github/public-suites.json").read_text(encoding="utf-8"))
    inventory(manifest, check.runtime_suites())
    report = {"scope": "public-source-verification", "full_acceptance": False,
              "excluded": manifest["excluded"], "outside_runtime": manifest["outside_runtime"], "suites": []}
    if args.list:
        report["included"] = manifest["included"]
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0
    for name, argv in manifest["included"].items():
        _n, ok, tail, seconds, rc, output = check.run_one(name, argv, timeout=check.runtime_timeout(name))
        skipped = re.search(r"^OK \(skipped=(\d+)\)", output, re.M)
        status = "FAIL" if not ok or rc != 0 else ("UNVERIFIED" if skipped else "PASS")
        report["suites"].append({"name": name, "status": status, "returncode": rc,
                                  "seconds": round(seconds, 3), "summary": tail, "output": output})
        print(f"{status} {name} ({seconds:.1f}s)", file=sys.stderr, flush=True)
    report["ok"] = all(s["status"] == "PASS" for s in report["suites"])
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
