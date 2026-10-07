from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import math
from collections import Counter


import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lab_paths import LAB_ROOT, POST_DIR as OUTPUT  # noqa: E402


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


def collect():
    results = []

    for path in LAB_ROOT.rglob("*"):

        if not path.is_file():
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


def main():

    OUTPUT.mkdir(parents=True, exist_ok=True)

    results = collect()

    output = OUTPUT / "post_attack_files.json"

    with output.open("w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print("=" * 60)
    print("POST-ATTACK COLLECTION")
    print("=" * 60)
    print(f"Files found : {len(results)}")
    print(f"Output      : {output}")
    print("=" * 60)


if __name__ == "__main__":
    main()