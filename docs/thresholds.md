# Threshold choices and tuning — RANSOM-LAB-2026-002

## 1. Velocity: 50 events / 5 s window
Lab10 default, kept. True-positive run (case1) produced 65 events in-window
(start → alert 0.58 s), comfortably over. Benign bulk copy of 200 files
produced 429 events (`logs/fp_test_20260928_032407.json`) — velocity alone
would false-alarm here, which is exactly why it is necessary but not
sufficient, and gates 2–3 below decide.

## 2. Entropy: ≥ 7.2, need 5 of last 10 sampled files
Lab10 Phase 4 default, kept. Plain-text fixtures sit ~4.3–6.1 bits/byte;
real AES output lands ~7.9, so 7.2 separates them with margin.
Honest caveat driving the tuning below: our simulator applies reversible
XOR (`byte ^ 0x41`), which only permutes byte values — the frequency
histogram and therefore Shannon entropy are bit-identical before/after
(fixtures ~6.13 → .locked ~6.13, 0 hits). A strict doc-faithful gate would
miss this simulator entirely. Entropy stays as the real-crypto signal;
burst corroboration covers the reversible-fixture case.

## 3. Burst corroboration (tuned): ≥ 20 renames/.locked + ≥ 10 deletes
New, documented deviation. True-positive showed 44 renames + 21 deletes;
false-positive showed 0 + 0. Thresholds set at roughly half the observed
attack values — far above benign bulk-copy behavior (pure creates, no
renames/deletes). Alert fires on velocity AND (entropy-gate OR burst-gate);
`threshold_basis` in the alert JSON records which path fired (`doc` vs
`tuned-rename-burst`).

## 4. Process correlation
`find_owning_process()`: primary match on open file handles
(`psutil.open_files()`), fallback to `ransomware_simulator` command-line
signature (handles are usually closed by the time the velocity gate trips).
Run the detector as Administrator so other processes' handles are visible.
Verdict carries `suspected_process` (offender) alongside `process`
(detector self) — the old code logged only the latter.

## 5. Evidence
- TP velocity/entropy/burst: prior `simulation_*.json` + `ransomware_alert_*.json`
- FP silence with 429 events observed: `logs/fp_test_20260928_032407.json`
- Next `run_attack.py` run emits alerts with `entropy_gate_passed`,
  `burst_gate_passed`, `threshold_basis`, `suspected_process` for the report.
