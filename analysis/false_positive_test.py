"""Gap 3 — false-positive test (Lab10 Phase 6 / deliverable).

Bulk-copies 200 benign low-entropy files through the REAL detector logic
(same RansomHandler + evaluate() + thresholds) in an isolated scratch dir
outside the victim folder. Pass = detector stays silent. Evidence -> logs/.
Usage: python analysis/false_positive_test.py [--count 200]
"""
import argparse
import json
import shutil
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "detector"))

from lab_paths import LOG_DIR  # noqa: E402
import detector  # noqa: E402 (reuses handler, thresholds, verdict — no duplication)
from watchdog.observers import Observer


def benign_text(i):
    return ("Quarterly operations summary for review. " * 40 + f"Record {i}.\n")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=200)
    args = ap.parse_args()

    scratch = Path(tempfile.mkdtemp(prefix="case2_fp_"))
    detector.events.clear()

    observer = Observer()
    observer.schedule(detector.RansomHandler(), str(scratch), recursive=True)
    observer.start()
    time.sleep(1.0)  # observer attach, mirrors run_attack.py
    try:
        for i in range(args.count):  # benign bulk op: plain copy-like writes
            (scratch / f"benign_{i:04d}.txt").write_text(benign_text(i), encoding="utf-8")
        deadline = time.time() + 6.0
        verdict = None
        while time.time() < deadline:  # observe a full velocity window
            verdict = detector.evaluate()
            if verdict:
                break
            time.sleep(0.25)
    finally:
        observer.stop()
        observer.join()
        shutil.rmtree(scratch, ignore_errors=True)
        observed = len(detector.events)
        detector.events.clear()

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    out = LOG_DIR / f"fp_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    out.write_text(json.dumps({
        "test": "false-positive bulk benign copy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "files_copied": args.count,
        "events_observed": observed,
        "velocity_threshold": detector.VELOCITY_THRESHOLD,
        "window_seconds": detector.VELOCITY_WINDOW,
        "verdict": "SILENT (pass)" if verdict is None else "ALERT (fail)",
        "alert": verdict,
    }, indent=2), encoding="utf-8")

    print("=" * 60)
    print("FALSE-POSITIVE TEST")
    print("=" * 60)
    print(f"Files copied : {args.count}")
    print(f"Events seen  : {observed}")
    print(f"Verdict      : {'SILENT (pass)' if verdict is None else 'ALERT (fail)'}")
    print(f"Evidence     : {out}")
    return 0 if verdict is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
