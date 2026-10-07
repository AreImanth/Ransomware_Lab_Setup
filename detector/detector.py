from pathlib import Path
from collections import deque, Counter
from datetime import datetime, timezone
import hashlib
import json
import math
import os
import threading
import time

import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lab_paths import LAB_ROOT, LOG_DIR, CONFIG as _C  # noqa: E402
VELOCITY_WINDOW = float(_C.get("velocity_window", 5.0))
VELOCITY_THRESHOLD = int(_C.get("velocity_threshold", 50))
ENTROPY_THRESHOLD = float(_C.get("entropy_threshold", 7.2))
ENTROPY_MIN_HITS = int(_C.get("entropy_min_hits", 5))  # Lab10 Phase 4 gate
ENTROPY_SAMPLE = int(_C.get("entropy_sample", 10))  # last-N events sampled, per Phase 4
# Tuned corroboration for reversible-XOR fixtures (see docs/thresholds.md):
# XOR preserves byte-frequency distribution, so entropy never crosses 7.2.
RENAME_BURST = int(_C.get("rename_burst", 20))
DELETE_BURST = int(_C.get("delete_burst", 10))

events = deque(maxlen=5000)
lock = threading.Lock()


def entropy(data: bytes) -> float:
    if not data:
        return 0.0

    counts = Counter(data)
    length = len(data)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def file_entropy(path: Path):
    try:
        data = path.read_bytes()
        return entropy(data)
    except (OSError, PermissionError):
        return None


def get_process_info():
    current_pid = os.getpid()

    try:
        proc = psutil.Process(current_pid)

        return {
            "pid": current_pid,
            "name": proc.name(),
            "exe": proc.exe(),
            "cmdline": proc.cmdline(),
            "username": proc.username()
        }

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return {
            "pid": current_pid
        }


def find_owning_process(filepath, budget=1.5):
    """Correlate a touched file back to the offending process (Lab10 Phase 4).

    Order matters for speed. A full open_files() sweep across every process
    costs tens of seconds on Windows, which would outlast the attack and
    starve the detection loop, so:

      1. Cheap command-line match against the victim path (milliseconds).
         Driven by the configured lab root, so it is independent of the
         script's filename or how it was launched.
      2. Open-handle match, but only until the time budget is spent.

    Run the detector as Administrator so other processes' handles are visible.
    Returns {"pid":..., "name":...} or None.
    """

    target = str(filepath).lower()
    deadline = time.time() + budget

    def describe(proc):
        """Safe identity lookup: the process may vanish mid-scan."""
        try:
            return {"pid": proc.pid, "name": proc.name()}
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None
        except OSError:
            return None

    try:
        candidates = list(psutil.process_iter(["pid", "name"]))
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None

    # 1. Command-line signature: any process invoked against the victim
    #    folder is a candidate. Matches on the configured lab root, not a
    #    script name, so renaming or relaunching the simulator changes nothing.
    lab_marker = str(LAB_ROOT).lower()

    for proc in candidates:
        if time.time() > deadline:
            return None
        try:
            if lab_marker in " ".join(proc.cmdline()).lower():
                found = describe(proc)
                if found:
                    return found
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
            continue

    # 2. Open-handle match within the remaining budget
    for proc in candidates:
        if time.time() > deadline:
            return None
        try:
            for handle in proc.open_files():
                if target in handle.path.lower():
                    found = describe(proc)
                    if found:
                        return found
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
            continue

    return None


class RansomHandler(FileSystemEventHandler):

    def record(self, event_type, path):

        if Path(path).is_dir():
            return

        now = time.time()

        event = {
            "time": now,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": event_type,
            "path": str(path)
        }

        with lock:
            events.append(event)

    def on_created(self, event):
        self.record("created", event.src_path)

    def on_modified(self, event):
        self.record("modified", event.src_path)

    def on_deleted(self, event):
        self.record("deleted", event.src_path)

    def on_moved(self, event):
        self.record(
            "renamed",
            event.dest_path
        )


def recent_events():

    cutoff = time.time() - VELOCITY_WINDOW

    with lock:
        return [
            event
            for event in events
            if event["time"] >= cutoff
        ]


def evaluate():
    """Three-signal verdict (Lab10 Phase 4), with documented tuning.

    Gate 1 (doc): velocity — VELOCITY_THRESHOLD events in VELOCITY_WINDOW s.
    Gate 2 (doc): entropy — ENTROPY_MIN_HITS of the last ENTROPY_SAMPLE files
        above ENTROPY_THRESHOLD.
    Gate 3 (tuned, see docs/thresholds.md): mass .locked-rename + delete
        burst corroboration. The benign simulator uses reversible XOR, which
        preserves Shannon entropy, so Gate 2 alone would miss it.
    Alert fires on Gate 1 AND (Gate 2 OR Gate 3).
    """

    recent = recent_events()

    if len(recent) < VELOCITY_THRESHOLD:
        return None

    sample = recent[-ENTROPY_SAMPLE:]

    entropy_hits = 0

    for event in sample:

        path = Path(event["path"])

        if not path.exists() or not path.is_file():
            continue

        value = file_entropy(path)

        if value is not None and value >= ENTROPY_THRESHOLD:
            entropy_hits += 1

    renamed = sum(
        1 for event in recent
        if event["type"] == "renamed"
        or str(event["path"]).endswith(".locked")
    )

    deleted = sum(
        1 for event in recent
        if event["type"] == "deleted"
    )

    entropy_gate = entropy_hits >= ENTROPY_MIN_HITS
    burst_gate = renamed >= RENAME_BURST and deleted >= DELETE_BURST

    if not (entropy_gate or burst_gate):
        return None

    anchor = next(
        (event["path"] for event in reversed(recent)
         if str(event["path"]).endswith(".locked")),
        recent[-1]["path"],
    )

    # Correlation is best-effort: never let it block or abort the alert.
    try:
        owner = find_owning_process(anchor)
    except Exception as exc:  # noqa: BLE001 - detection must not depend on psutil
        owner = None
        print(f"[!] process correlation failed: {exc}")

    return {
        "alert": "RANSOMWARE BEHAVIOR SUSPECTED",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "events_in_window": len(recent),
        "window_seconds": VELOCITY_WINDOW,
        "velocity_threshold": VELOCITY_THRESHOLD,
        "high_entropy_files": entropy_hits,
        "entropy_threshold": ENTROPY_THRESHOLD,
        "entropy_gate_passed": entropy_gate,
        "rename_events": renamed,
        "delete_events": deleted,
        "burst_gate_passed": burst_gate,
        "threshold_basis": "doc" if entropy_gate else "tuned-rename-burst (XOR preserves entropy)",
        "suspected_process": owner,
        "process": get_process_info()
    }


def write_alert(alert):

    LOG_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    output = LOG_DIR / f"ransomware_alert_{timestamp}.json"

    with output.open("w", encoding="utf-8") as f:
        json.dump(alert, f, indent=2)

    print()
    print("=" * 70)
    print("[!!!] RANSOMWARE BEHAVIOR SUSPECTED")
    print("=" * 70)
    print(json.dumps(alert, indent=2))
    print("=" * 70)
    print(f"Evidence: {output}")


def main():

    if not LAB_ROOT.exists():
        raise SystemExit(
            f"Lab directory does not exist: {LAB_ROOT}"
        )

    print("=" * 70)
    print("RANSOMWARE BEHAVIOR DETECTOR")
    print("=" * 70)
    print(f"Monitoring : {LAB_ROOT}")
    print(f"Window     : {VELOCITY_WINDOW}s / {VELOCITY_THRESHOLD} events")
    print(f"Entropy    : {ENTROPY_THRESHOLD} (need {ENTROPY_MIN_HITS}/{ENTROPY_SAMPLE})")
    print(f"Burst      : {RENAME_BURST} renames + {DELETE_BURST} deletes (tuned)")
    print()
    print("Waiting for activity...")
    print("Press CTRL+C to stop.")
    print("=" * 70)

    observer = Observer()

    observer.schedule(
        RansomHandler(),
        str(LAB_ROOT),
        recursive=True
    )

    observer.start()

    print(f"[+] Observer attached. PID {os.getpid()}")

    alerted = False
    last_beat = time.time()

    try:

        while True:

            if not alerted:

                try:
                    verdict = evaluate()
                except Exception as exc:  # noqa: BLE001 - never lose the detector
                    print(f"[!] evaluate() error: {exc}")
                    verdict = None

                if verdict:

                    write_alert(verdict)

                    alerted = True

            if time.time() - last_beat >= 15:
                with lock:
                    total = len(events)
                print(f"[.] alive | events buffered: {total}")
                last_beat = time.time()

            time.sleep(0.25)

    except KeyboardInterrupt:

        print("\n[+] Detector stopping...")

    finally:

        observer.stop()
        observer.join()


if __name__ == "__main__":
    main()