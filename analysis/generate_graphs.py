from pathlib import Path
import json
from collections import Counter

import matplotlib.pyplot as plt


import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lab_paths import BASELINE_DIR, POST_DIR, REPORTS_DIR as OUTPUT  # noqa: E402
BASELINE = BASELINE_DIR / "baseline_files.json"
POST = POST_DIR / "post_attack_files.json"


def load(path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def graph_file_counts(before, after):

    labels = [
        "Baseline",
        "Post-attack"
    ]

    values = [
        len(before),
        len(after)
    ]

    plt.figure(figsize=(8, 5))
    plt.bar(labels, values)
    plt.ylabel("Files")
    plt.title("Filesystem State: Before vs After")
    plt.tight_layout()

    plt.savefig(
        OUTPUT / "01_file_count_comparison.png",
        dpi=200
    )

    plt.close()


def graph_entropy(before, after):

    before_entropy = [
        item["entropy"]
        for item in before
        if "entropy" in item
    ]

    after_entropy = [
        item["entropy"]
        for item in after
        if "entropy" in item
    ]

    plt.figure(figsize=(10, 6))

    plt.hist(
        before_entropy,
        bins=20,
        alpha=0.7,
        label="Before"
    )

    plt.hist(
        after_entropy,
        bins=20,
        alpha=0.7,
        label="After"
    )

    plt.xlabel("Shannon entropy (bits/byte)")
    plt.ylabel("Number of files")
    plt.title("File Entropy Distribution")
    plt.legend()
    plt.tight_layout()

    plt.savefig(
        OUTPUT / "02_entropy_distribution.png",
        dpi=200
    )

    plt.close()


def graph_extensions(after):

    locked = [
        item
        for item in after
        if item["name"].lower().endswith(".locked")
    ]

    extensions = Counter()

    for item in locked:
        original_name = item["name"][:-7]
        extension = Path(original_name).suffix.lower()

        extensions[extension or "[no extension]"] += 1

    if not extensions:
        return

    labels = list(extensions.keys())
    values = list(extensions.values())

    plt.figure(figsize=(9, 6))
    plt.bar(labels, values)

    plt.xlabel("Original extension")
    plt.ylabel("Locked files")
    plt.title("Files Affected by Original File Type")
    plt.xticks(rotation=45)

    plt.tight_layout()

    plt.savefig(
        OUTPUT / "03_file_type_impact.png",
        dpi=200
    )

    plt.close()


def main():

    OUTPUT.mkdir(
        parents=True,
        exist_ok=True
    )

    before = load(BASELINE)
    after = load(POST)

    graph_file_counts(before, after)
    graph_entropy(before, after)
    graph_extensions(after)

    print("[+] Graphs generated:")
    print(OUTPUT / "01_file_count_comparison.png")
    print(OUTPUT / "02_entropy_distribution.png")
    print(OUTPUT / "03_file_type_impact.png")


if __name__ == "__main__":
    main()