from pathlib import Path
import json
from collections import Counter


import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lab_paths import BASELINE_DIR, POST_DIR, REPORTS_DIR  # noqa: E402
BASELINE = BASELINE_DIR / "baseline_files.json"
POST = POST_DIR / "post_attack_files.json"
OUTPUT = REPORTS_DIR / "analysis_summary.json"


def load(path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def main():

    baseline = load(BASELINE)
    post = load(POST)

    before = {
        item["path"]: item
        for item in baseline
    }

    after = {
        item["path"]: item
        for item in post
    }

    original_paths = set(before)
    post_paths = set(after)

    deleted = original_paths - post_paths
    created = post_paths - original_paths

    modified = []

    for path in original_paths & post_paths:

        if (
            before[path]["sha256"]
            != after[path]["sha256"]
        ):
            modified.append(path)

    locked_files = [
        path
        for path in post_paths
        if path.lower().endswith(".locked")
    ]

    extensions = Counter(
        Path(path).suffix.lower()
        for path in locked_files
    )

    summary = {
        "baseline_file_count": len(baseline),
        "post_file_count": len(post),
        "deleted_files": len(deleted),
        "created_files": len(created),
        "modified_files": len(modified),
        "locked_files": len(locked_files),
        "locked_extensions": dict(extensions),
        "deleted_examples": sorted(deleted)[:20],
        "created_examples": sorted(created)[:20]
    }

    OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with OUTPUT.open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print("=" * 60)
    print("RANSOMWARE LAB ANALYSIS")
    print("=" * 60)

    for key, value in summary.items():
        print(f"{key}: {value}")

    print("=" * 60)
    print(f"Report: {OUTPUT}")


if __name__ == "__main__":
    main()