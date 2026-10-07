from pathlib import Path
import random
import string
import json
import hashlib
import math
from collections import Counter


CONFIG = Path(__file__).with_name("config.json")


def load_config():
    with CONFIG.open("r", encoding="utf-8") as f:
        return json.load(f)


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


def random_text(length: int) -> str:
    chars = string.ascii_letters + string.digits + " .,;:-_()"
    return "".join(random.choices(chars, k=length))


def create_file(path: Path, content: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("wb") as f:
        f.write(content)


def main():
    config = load_config()

    root = Path(config["lab_root"])
    root.mkdir(parents=True, exist_ok=True)

    categories = {
        "Documents": [".txt", ".csv", ".docx"],
        "Reports": [".pdf", ".txt"],
        "Images": [".jpg", ".png"],
        "Finance": [".csv", ".txt"],
        "HR": [".txt", ".csv"],
        "Misc": [".txt", ".log"]
    }

    file_count = config["file_count"]

    print(f"[+] Creating {file_count} dummy files")
    print(f"[+] Target: {root}")

    created = 0

    category_names = list(categories.keys())

    for i in range(file_count):
        category = category_names[i % len(category_names)]
        extension = random.choice(categories[category])

        filename = f"LAB_FILE_{i + 1:04d}{extension}"
        path = root / category / filename

        # We deliberately create harmless synthetic content.
        content = (
            f"RANSOMWARE LAB TEST FILE\n"
            f"Simulation dataset file: {i + 1}\n"
            f"Category: {category}\n\n"
            + random_text(random.randint(1000, 3000))
        ).encode("utf-8")

        create_file(path, content)
        created += 1

    print(f"[+] Created {created} files")

    manifest = []

    for path in root.rglob("*"):
        if path.is_file():
            data = path.read_bytes()

            manifest.append(
                {
                    "path": str(path),
                    "size": path.stat().st_size,
                    "sha256": sha256(path),
                    "entropy": round(entropy(data), 4)
                }
            )

    manifest_path = root / "LAB_BASELINE_MANIFEST.json"

    with manifest_path.open("w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print(f"[+] Manifest: {manifest_path}")
    print("[+] Test dataset ready.")


if __name__ == "__main__":
    main()