"""Phase 1 — case2 attack run.

Two modes, one code path for everything else:

  Default (single window):
      python run_attack.py
      baseline -> start detector -> run simulator in-process -> stop detector
      -> post-collect -> bundle artifacts

  Split (two windows, best for demos and PID attribution):
      python run_attack.py --baseline-only        (window 1)
      python simulator\\ransomware_simulator.py    (window 2)
      press Enter in window 1 to continue

Take Regshot Shot 1 BEFORE running this.
"""
import argparse
import json
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from lab_paths import CONFIG, LAB_ROOT, LOG_DIR, RUNS_DIR  # noqa: E402

DETECTOR = PROJECT_ROOT / "detector" / "detector.py"
SIMULATOR = PROJECT_ROOT / "simulator" / "ransomware_simulator.py"
DETECTOR_WARMUP_S = 2.0  # watchdog observer attach time


def parse_args():
    ap = argparse.ArgumentParser(
        description="Case2 phase 1: baseline, attack, post-attack collection")
    ap.add_argument("--baseline-only", action="store_true",
                    help="stop after baseline + detector; run the simulator "
                         "yourself in a second window, then press Enter here")
    return ap.parse_args()


def preflight() -> int:
    """Validate environment before touching anything. Returns exit code."""
    if not LAB_ROOT.exists():
        print(f"[!] Victim folder missing: {LAB_ROOT}")
        print("    Run: python simulator\\generate_test_data.py")
        return 1
    if LAB_ROOT.resolve() in (Path(LAB_ROOT.anchor), Path(r"C:\Windows")):
        print("[!] Safety stop: lab root resolves to a protected path.")
        return 1
    return 0


def start_detector():
    """Launch the detector and confirm it stays up."""
    det = subprocess.Popen([sys.executable, str(DETECTOR)])
    time.sleep(DETECTOR_WARMUP_S)
    if det.poll() is not None:
        print(f"[!] Detector exited early (code {det.returncode}). Check config.")
        return None
    return det


def stop_detector(det) -> None:
    """Terminate the detector, escalating to kill if it ignores the signal."""
    det.terminate()
    try:
        det.wait(timeout=10)
    except subprocess.TimeoutExpired:
        det.kill()
        det.wait(timeout=5)


def wait_for_external_simulator() -> None:
    """Block until the operator confirms the separate-window run finished."""
    sim = SIMULATOR
    print("\n" + "-" * 60)
    print("[3/4] Detector is live. Now, in a SECOND window, run:")
    print(f"    python {sim}")
    print("-" * 60)
    print(f"  Watching : {LAB_ROOT}")
    print("  Arm Sysmon / Procmon before you trigger it.")
    print("  Press Enter here only AFTER the simulator finishes.\n")
    try:
        input()
    except EOFError:  # non-interactive: continue rather than hang
        print("[!] No interactive input; continuing.")


def run_simulator_in_process() -> None:
    sys.path.insert(0, str(PROJECT_ROOT / "simulator"))
    import ransomware_simulator
    ransomware_simulator.main()


def bundle_artifacts(run_id: str, run_dir: Path) -> None:
    """Copy this run's artifacts into runs/<run_id>/ (canonicals stay put)."""
    manifest = {
        "run_id": run_id,
        "simulation_id": CONFIG["simulation_id"],
        "lab_root": str(LAB_ROOT),
        "finished": datetime.now(timezone.utc).isoformat(),
    }
    (run_dir / "run_manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8")

    sources = [
        PROJECT_ROOT / "evidence" / "baseline" / "baseline_files.json",
        PROJECT_ROOT / "evidence" / "baseline" / "baseline_system.json",
        PROJECT_ROOT / "evidence" / "post" / "post_attack_files.json",
    ]
    sources += sorted(LOG_DIR.glob("simulation_*.json"))
    sources += sorted(LOG_DIR.glob("ransomware_alert_*.json"))

    for src in sources:
        if src.exists():
            shutil.copy2(src, run_dir / src.name)


def main() -> int:
    args = parse_args()

    print("=" * 60)
    print("CASE2 PHASE 1 — ATTACK RUN")
    print("=" * 60)
    print(f"Victim : {LAB_ROOT}")
    print(f"Project: {PROJECT_ROOT}")
    print(f"Mode   : {'split (2 windows)' if args.baseline_only else 'single window'}")

    if preflight() != 0:
        return 1

    run_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    run_dir = RUNS_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    # 1. Baseline
    sys.path.insert(0, str(PROJECT_ROOT / "analysis"))
    import collect_baseline
    print("\n[1/4] Collecting baseline...")
    collect_baseline.main()

    # 2. Detector
    print("\n[2/4] Starting detector...")
    det = start_detector()
    if det is None:
        return 1
    print(f"      detector PID {det.pid}")

    # 3. Attack
    try:
        if args.baseline_only:
            wait_for_external_simulator()
        else:
            print("\n[3/4] Running simulator...")
            run_simulator_in_process()
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")

    # 4. Stop detector, post-collect
    print("\n[4/4] Stopping detector + post-collect...")
    stop_detector(det)
    import collect_post
    collect_post.main()

    bundle_artifacts(run_id, run_dir)

    alerts = sorted(LOG_DIR.glob("ransomware_alert_*.json"))
    print("\n" + "=" * 60)
    print("PHASE 1 COMPLETE")
    print("=" * 60)
    print(f"Run bundle   : {run_dir}")
    print(f"Detector alert: {alerts[-1].name if alerts else 'NONE — check detector output'}")
    print("NEXT: Regshot Shot 2 -> Compare -> save comparison.txt, then:")
    print(f'  python build_report.py --run "{run_dir}" --comparison "D:\\path\\comparison.txt"')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
