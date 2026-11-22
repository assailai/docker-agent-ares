"""Score the agent's CREDENTIALED collector against the lab's answer keys (found N of M).

Runs the REAL agent parsers (agent.collectors.vendor.collect_control_fields, grammar-routed) over the
node running-configs captured live on the lab host, and diffs each answer key's field_expectation.
A fault must be read correctly (and, where wired, is a credentialed finding); a clean device must read
the clean value (no false positive). Import path: run from the docker-agent worktree root.
"""
from __future__ import annotations
import json, sys
import yaml
from agent.collectors import vendor


def _check(fields: dict | None, expectation: dict) -> tuple[bool, str]:
    if fields is None:
        return False, "no fields (control unsupported by parser)"
    for key, want in expectation.items():
        if key.endswith("_contains"):
            base = key[: -len("_contains")]
            actual = fields.get(base) or []
            if want not in actual:
                return False, f"{base}={actual!r} does not contain {want!r}"
        elif key.endswith("_excludes"):
            base = key[: -len("_excludes")]
            actual = fields.get(base) or []
            if want in actual:
                return False, f"{base}={actual!r} unexpectedly contains {want!r}"
        else:
            got = fields.get(key)
            if got != want:
                return False, f"{key}={got!r} != expected {want!r}"
    return True, "fields match"


def main() -> int:
    configs = json.loads(open(sys.argv[1]).read())
    keys = [yaml.safe_load(open(p).read()) for p in sys.argv[2:]]

    fault_total = fault_hit = 0
    clean_total = clean_ok = 0
    print("CREDENTIALED COLLECTOR ACCURACY (real agent parsers vs the planted answer keys)\n")
    for key in keys:
        print(f"-- {key.get('meta',{}).get('tier','?')} tier --")
        for fault in key.get("faults", []):
            node = fault["node"]; cid = fault["control_id"]
            cfg = configs.get(node, "")
            fields = vendor.collect_control_fields(cfg, cid)
            ok, why = _check(fields, fault.get("field_expectation", {}))
            fault_total += 1; fault_hit += ok
            print(f"  {'OK' if ok else 'XX'} {fault['id']} [{cid}] {'detected' if ok else 'MISSED'}: {why}")
        for clean in key.get("clean", []):
            node = clean["node"]; cid = clean["control_id"]
            cfg = configs.get(node, "")
            fields = vendor.collect_control_fields(cfg, cid)
            ok, why = _check(fields, clean.get("field_expectation", {}))
            clean_total += 1; clean_ok += ok
            print(f"  {'OK' if ok else 'XX'} clean {node} [{cid}] {'clean' if ok else 'FALSE READ'}: {why}")
        print()

    print(f"SUMMARY: faults detected {fault_hit}/{fault_total}; clean devices read clean {clean_ok}/{clean_total}.")
    ok = fault_hit == fault_total and clean_ok == clean_total
    print("CREDENTIALED ACCURACY GATE:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
