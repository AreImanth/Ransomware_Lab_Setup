# Ransomware Behavior Analysis Lab

A self-contained, reversible ransomware simulation and detection lab built as a
hands-on cybersecurity learning project. It demonstrates the full attack–detection–
forensics lifecycle in a safe, isolated environment.

---

## Overview

This project simulates ransomware behavior on a controlled set of benign files,
detects the attack in real time using a multi-signal behavioral detector, and
produces a forensic analysis report. Everything runs locally with no network
access, no persistence, and no real encryption — the "encryption" is a reversible
XOR transform that can be undone with a single operation.

**Key concepts covered:**

- Filesystem monitoring and behavioral detection
- Shannon entropy analysis for encryption detection
- Process correlation and attribution
- Forensic baseline collection and comparison
- False-positive testing and threshold tuning
- Automated report generation

---

## Project Structure

```
Ransom_Lab_Setup_complete/
├── lab_config.json              # Central configuration (paths, thresholds)
├── lab_paths.py                 # Single source of truth for all paths
├── run_attack.py                # Phase 1 orchestrator (baseline → detect → attack → post)
├── reset_lab.py                 # Wipes runtime artifacts, refills victim folder
├── build_report.py              # Phase 2: analysis + graphs + HTML report
├── report_data.py               # Data layer for the report (no HTML)
├── report_style.css             # Report styling
├── requirements.txt             # Python dependencies
│
├── simulator/
│   ├── generate_test_data.py    # Creates 200 benign victim files
│   ├── ransomware_simulator.py  # Benign XOR-0x41 "ransomware"
│   └── config.json              # Simulator-side config mirror
│
├── detector/
│   └── detector.py              # Watchdog behavior detector (3-gate)
│
├── analysis/
│   ├── collect_baseline.py      # Pre-attack snapshot
│   ├── collect_post.py          # Post-attack snapshot
│   ├── analyze_results.py       # Before/after diff → analysis_summary.json
│   ├── generate_graphs.py       # 3 matplotlib PNGs
│   └── false_positive_test.py   # Benign bulk-copy silence test
│
├── docs/
│   └── thresholds.md            # Why each threshold was chosen
│
├── evidence/
│   ├── baseline/                # Pre-attack evidence (generated)
│   └── post/                    # Post-attack evidence (generated)
│
├── logs/                        # Simulation + alert logs (generated)
├── reports/                     # Analysis output (generated)
└── runs/                        # Per-run bundles (generated)
```

---

## Prerequisites

- **Python 3.10+** (with "Add python.exe to PATH" enabled)
- **Regshot** (x64 Unicode) — optional, for registry comparison
- **Windows** (the lab uses Windows-specific paths and APIs)

---

## Setup

1. **Clone or download** this folder to your machine.

2. **Install dependencies:**
   ```powershell
   cd Ransom_Lab_Setup_complete
   pip install -r requirements.txt
   ```

3. **Edit the configuration** (if needed):
   - `lab_config.json` — change `project_root` and `lab_root` to match your setup
   - `simulator/config.json` — keep `lab_root` and `simulation_id` in sync

4. **Build the victim dataset:**
   ```powershell
   python simulator\generate_test_data.py
   ```
   This creates 200 synthetic files across 6 category folders.

---

## Running the Lab

### Quick Run (single window)

```powershell
python run_attack.py
```

This executes the full Phase 1 pipeline:
1. Collects a forensic baseline
2. Starts the behavior detector
3. Runs the ransomware simulator
4. Stops the detector and collects post-attack evidence
5. Bundles all artifacts into `runs/<timestamp>/`

### Split Mode (two windows, best for demos)

```powershell
# Window 1
python run_attack.py --baseline-only

# Window 2 (after detector starts)
python simulator\ransomware_simulator.py

# Back in Window 1: press Enter when done
```

### Generate the Report

After taking a Regshot comparison:

```powershell
python build_report.py --comparison "D:\path\to\comparison.txt"
```

This produces a self-contained HTML report in `reports/`.

### False-Positive Test

```powershell
python analysis\false_positive_test.py
```

Verifies the detector stays silent during benign bulk file operations.

### Reset the Lab

```powershell
python reset_lab.py              # wipe + regenerate victim files
python reset_lab.py --no-refill  # wipe only
```

---

## How It Works

### The Simulator

The "ransomware" performs a reversible XOR transform (`byte ^ 0x41`) on each file:

```
read original → XOR scramble → write .locked → delete original
```

This mimics real ransomware behavior (file modification + deletion) without
using actual cryptography. The transform is trivially reversible.

### The Detector

A watchdog-based filesystem monitor watches the victim folder and evaluates
three detection gates:

| Gate | Signal | Threshold |
|------|--------|-----------|
| 1 | File event velocity | ≥ 50 events in 5 seconds |
| 2 | High-entropy files | ≥ 5 of last 10 files above 7.2 bits/byte |
| 3 | Rename/delete burst | ≥ 20 renames AND ≥ 10 deletes |

An alert fires when **Gate 1 AND (Gate 2 OR Gate 3)** is satisfied. This
multi-gate approach prevents false positives from benign bulk operations.

### The Report

The HTML report includes:
- Executive summary with time-to-detection
- Execution timeline (simulator + detector fused)
- Before/after file comparison
- Entropy distribution analysis
- Regshot registry diff
- Full evidence explorer with search and filtering

---

## Safety

- **No network** — the simulator makes zero network connections
- **No persistence** — no registry keys, no scheduled tasks
- **No real encryption** — XOR-0x41 is reversible with `bytes(b ^ 0x41)`
- **Scoped target** — only touches the configured lab directory
- **Abort guards** — refuses to run on drive roots or system directories

---

## Learning Outcomes

By studying and running this lab, you will understand:

1. **How ransomware behaves** at the filesystem level
2. **How EDR/SIEM systems detect** malicious file activity
3. **Why single-signal detection fails** and multi-gate logic is needed
4. **How forensic baselines** are collected and compared
5. **How entropy analysis** distinguishes encrypted from plaintext data
6. **How to tune thresholds** to balance detection vs. false positives

---

## License

This project is provided for educational purposes. Use it responsibly in
isolated lab environments only.
