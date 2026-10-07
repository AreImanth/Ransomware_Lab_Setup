from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from collections import Counter


import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lab_paths import LAB_ROOT, BASELINE_DIR as OUTPUT  # noqa: E402


def entropy(data: bytes) -> float:
    if not data:
        return 0.0

    counts = Counter(data)
    length = len(data)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(block)

    return digest.hexdigest()


def collect_files():
    results = []

    for path in LAB_ROOT.rglob("*"):
        if not path.is_file():
            continue

        # Do not include previous analysis artifacts.
        if path.name == "LAB_BASELINE_MANIFEST.json":
            continue

        try:
            data = path.read_bytes()

            results.append(
                {
                    "path": str(path),
                    "name": path.name,
                    "extension": path.suffix.lower(),
                    "size": len(data),
                    "sha256": sha256(path),
                    "entropy": round(entropy(data), 4),
                    "modified_time": datetime.fromtimestamp(
                        path.stat().st_mtime,
                        timezone.utc
                    ).isoformat()
                }
            )

        except OSError as exc:
            print(f"[!] Could not read {path}: {exc}")

    return results


def collect_system_info():
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hostname": os.environ.get("COMPUTERNAME"),
        "username": os.environ.get("USERNAME"),
        "lab_root": str(LAB_ROOT)
    }


def main():
    OUTPUT.mkdir(parents=True, exist_ok=True)

    files = collect_files()
    system = collect_system_info()

    with (OUTPUT / "baseline_files.json").open("w", encoding="utf-8") as f:
        json.dump(files, f, indent=2)

    with (OUTPUT / "baseline_system.json").open("w", encoding="utf-8") as f:
        json.dump(system, f, indent=2)

    print("=" * 60)
    print("RANSOMWARE LAB BASELINE")
    print("=" * 60)
    print(f"Files:       {len(files)}")
    print(f"Evidence:    {OUTPUT}")
    print(f"Timestamp:   {system['timestamp']}")
    print("=" * 60)


if __name__ == "__main__":
    main()