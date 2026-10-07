"""Load case2 artifacts and build report-ready structures. No HTML here."""

import base64
import json
import statistics
from collections import Counter
from pathlib import Path, PureWindowsPath


def folder_of(entry):
    return PureWindowsPath(entry["path"]).parent.name


def b64(path):
    return base64.b64encode(Path(path).read_bytes()).decode()


def latest(pattern_dir, pattern):
    files = sorted(Path(pattern_dir).glob(pattern))
    if not files:
        return None
    return files[-1]


def load_all(project_root, lab_root, comparison_path=None):
    project_root = Path(project_root)
    lab_root = Path(lab_root)
    baseline_dir = project_root / "evidence" / "baseline"
    post_dir = project_root / "evidence" / "post"
    logs_dir = project_root / "logs"
    reports_dir = project_root / "reports"

    baseline = json.loads(
        (baseline_dir / "baseline_files.json").read_text(encoding="utf-8")
    )
    post = json.loads((post_dir / "post_attack_files.json").read_text(encoding="utf-8"))

    sim_file = latest(logs_dir, "simulation_*.json")
    alert_file = latest(logs_dir, "ransomware_alert_*.json")
    if sim_file is None:
        raise SystemExit("[!] No simulation log found. Run run_attack.py first.")
    sim = json.loads(sim_file.read_text(encoding="utf-8"))
    alert = json.loads(alert_file.read_text(encoding="utf-8")) if alert_file else None

    note_file = lab_root / "README_RANSOMWARE_SIMULATION.txt"
    ransom_note = (
        note_file.read_text(encoding="utf-8", errors="ignore")
        if note_file.exists()
        else "(ransom note not found)"
    )

    reg_txt = ""
    cmp_path = (
        Path(comparison_path)
        if comparison_path
        else (post_dir / "regshot_comparison.txt")
    )
    has_regshot = cmp_path.exists()
    if has_regshot:
        reg_txt = cmp_path.read_text(encoding="utf-16", errors="ignore")

    # Evidence rows: baseline original -> .locked match
    locked_lookup = {}
    for entry in post:
        if entry["name"].endswith(".locked"):
            locked_lookup[(folder_of(entry), entry["name"][:-7])] = entry
    rows = []
    for orig in baseline:
        key = (folder_of(orig), orig["name"])
        locked = locked_lookup.get(key)
        rows.append(
            {
                "folder": key[0],
                "name": key[1],
                "locked": locked["name"] if locked else "",
                "before_sha": orig["sha256"],
                "after_sha": locked["sha256"] if locked else "",
                "before_size": orig["size"],
                "after_size": locked["size"] if locked else 0,
                "before_ent": orig["entropy"],
                "after_ent": locked["entropy"] if locked else 0,
                "ext": orig["extension"],
                "status": "Encrypted + Original Deleted" if locked else "Missing",
            }
        )
    rows.sort(key=lambda r: (r["folder"], r["name"]))

    folders = sorted({r["folder"] for r in rows})
    folder_counts = {f: sum(1 for r in rows if r["folder"] == f) for f in folders}
    ext_counter = dict(Counter(r["ext"] for r in rows))
    entropies = [e["entropy"] for e in baseline]
    mean_entropy = round(statistics.mean(entropies), 4) if entropies else 0.0

    lab_added, lab_deleted = [], []
    if reg_txt:
        for section, bucket in (
            ("Files added:", lab_added),
            ("Files deleted:", lab_deleted),
        ):
            start = reg_txt.find(section)
            if start < 0:
                continue
            for line in reg_txt[start : start + 30000].splitlines()[2:200]:
                line = line.strip()
                if line.startswith("C:") and "Tests_reports" in line:
                    bucket.append(line)
                    if len(bucket) >= 40:
                        break

    images = {}
    for name in [
        "01_file_count_comparison.png",
        "02_entropy_distribution.png",
        "03_file_type_impact.png",
    ]:
        img = reports_dir / name
        if img.exists():
            images[name] = b64(img)

    return {
        "baseline": baseline,
        "post": post,
        "sim": sim,
        "alert": alert,
        "ransom_note": ransom_note,
        "regshot_available": has_regshot,
        "lab_added": lab_added,
        "lab_deleted": lab_deleted,
        "rows": rows,
        "folders": folders,
        "folder_counts": folder_counts,
        "ext_counter": ext_counter,
        "mean_entropy": mean_entropy,
        "images": images,
        "sim_id": sim.get("simulation_id", ""),
    }
