# Credentialed accuracy scoring (cohort-1, ARES-2267)

Scores the agent's **credentialed collectors** (`agent/collectors/`) against the Network Assessment
accuracy lab's planted answer keys, the "found N of M" the lab exists to measure. The lab itself and
the answer keys live in the `ares-v2` repo at `deploy/accuracy-lab/` (one host runs both the cEOS
containerlab and the discovery compose; see that repo's README). This is the agent-side half.

Two steps, split by where they run:

1. **On the lab host** (Python 3.9, SSM only, reaches the container networks directly):

   ```
   python3 capture_configs.py > node_configs.json
   ```

   Read-only `show running-config` per node (Arista EOS `Cli`, FRR `vtysh`), emitted as JSON.

2. **Locally** (Python 3.12, this worktree on `PYTHONPATH` so `agent.collectors` imports), against the
   answer keys in the `ares-v2` worktree:

   ```
   PYTHONPATH="$PWD" python3 deploy/accuracy-lab/score_credentialed.py \
     node_configs.json \
     ../ares-v2/deploy/accuracy-lab/ceos/answer-key-credentialed.yaml \
     ../ares-v2/deploy/accuracy-lab/ceos/answer-key-frr.yaml
   ```

   It runs the REAL `vendor.collect_control_fields` (grammar-routed to the Arista/FRR parser) over
   each captured config and diffs the answer key's `field_expectation`, so what it scores is exactly
   what the agent's collector reads. A planted fault must be read; a clean device must read clean (no
   false positive). Non-zero exit if any fault is missed or any clean device reads a false fault.

Result 2026-11-22 against the live lab: faults detected 13/13 (11 cEOS + 2 FRR), clean devices read
clean 11/11, 0 false positives. CREDENTIALED ACCURACY GATE: PASS. The discovery tier (telnet/ftp/snmp/
smtp) is scored by `ares-v2`'s `score_discovery.py` + `score_findings.py`.
