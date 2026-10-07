from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import time
import os


import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lab_paths import LAB_ROOT as _LAB, LOG_DIR as _LOGS  # noqa: E402
CONFIG = Path(__file__).with_name("config.json")


def load_config():
    with CONFIG.open("r", encoding="utf-8") as f:
        return json.load(f)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(block)

    return digest.hexdigest()


def xor_scramble(data: bytes) -> bytes:
    """
    Deliberately trivial and reversible transformation.

    This is NOT cryptography.
    The exact operation is the reversible XOR behavior
    specified by the lab document.
    """

    return bytes(byte ^ 0x41 for byte in data)


def desktop_dir() -> Path:
    """Resolve the current user's Desktop (OneDrive-redirect aware)."""
    home = Path(os.environ.get("USERPROFILE", str(Path.home())))
    for candidate in (home / "Desktop", home / "OneDrive" / "Desktop"):
        if candidate.is_dir():
            return candidate
    return home / "Desktop"


def write_ransom_note(root: Path, config: dict, encrypted_count: int):
    note_path = root / config["ransom_note"]

    content = f"""
====================================================
              RANSOMWARE SIMULATION
====================================================

THIS IS A CONTROLLED CYBERSECURITY LAB.

The files in the designated laboratory directory
were modified by the ransomware behavior simulator.

No real ransomware is present.

Simulation ID:
{config["simulation_id"]}

Files affected:
{encrypted_count}

Simulated deadline:
48 HOURS

Simulated payment identifier:
xxxxxxxxxxxxxxxxxxxxxxxx

IMPORTANT:
All the simulated data holds no real value
and was created especially for this instance.

What the simulation doesn't do:
- No network communication
- No persistence
- No credential theft
- No lateral movement
- No external command-and-control
- No real cryptographic ransomware

The transformation is intentionally reversible.

====================================================
"""

    note_path.write_text(content.strip() + "\n", encoding="utf-8")

    # Desktop copy: demo visual. The single sanctioned write outside lab root.
    desk_path = desktop_dir() / config["ransom_note"]
    desk_path.write_text(content.strip() + "\n", encoding="utf-8")

    return note_path, desk_path


def main():
    config = load_config()

    root = Path(config["lab_root"]).resolve()

    if not root.exists():
        raise SystemExit(f"[!] Lab directory does not exist: {root}")

    locked_extension = config["locked_extension"]
    delay = float(config["delay_seconds"])

    session = {
        "simulation_id": config["simulation_id"],
        "started": datetime.now(timezone.utc).isoformat(),
        "hostname": os.environ.get("COMPUTERNAME"),
        "pid": os.getpid(),
        "files": []
    }

    print("=" * 60)
    print("CONTROLLED RANSOMWARE SIMULATION")
    print("=" * 60)
    print(f"Simulation ID : {session['simulation_id']}")
    print(f"PID           : {session['pid']}")
    print(f"Target        : {root}")
    print()
    print("SAFETY: lab directory + one Desktop ransom-note copy only.")
    print()

    # Safety guard: resolved target must equal the configured lab root,
    # and never a drive root / Windows dir.
    if root != _LAB.resolve() or root in (Path(root.anchor), Path(r"C:\Windows")):
        raise SystemExit("[!] Safety stop: unexpected laboratory path.")

    files = [
        path
        for path in root.rglob("*")
        if path.is_file()
        and not path.name.endswith(locked_extension)
        and path.name != config["ransom_note"]
        and path.name != "LAB_BASELINE_MANIFEST.json"
    ]

    print(f"[+] Files selected: {len(files)}")
    print("[+] Starting simulation...\n")

    start = time.perf_counter()

    for index, path in enumerate(files, start=1):

        try:
            original_hash = sha256(path)

            data = path.read_bytes()

            scrambled = xor_scramble(data)

            new_path = Path(str(path) + locked_extension)

            new_path.write_bytes(scrambled)

            new_hash = sha256(new_path)

            path.unlink()

            event = {
                "index": index,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "original_path": str(path),
                "new_path": str(new_path),
                "original_size": len(data),
                "new_size": len(scrambled),
                "original_sha256": original_hash,
                "new_sha256": new_hash
            }

            session["files"].append(event)

            print(
                f"[{index:03d}/{len(files):03d}] "
                f"{path.name} -> {new_path.name}"
            )

            time.sleep(delay)

        except Exception as exc:
            print(f"[!] Error processing {path}: {exc}")

    note, note_desktop = write_ransom_note(
        root,
        config,
        len(session["files"])
    )

    session["ransom_note"] = str(note)
    session["ransom_note_desktop"] = str(note_desktop)
    session["ended"] = datetime.now(timezone.utc).isoformat()
    session["duration_seconds"] = round(
        time.perf_counter() - start,
        4
    )

    _LOGS.mkdir(parents=True, exist_ok=True)
    output = _LOGS / f"simulation_{config['simulation_id']}.json"

    with output.open("w", encoding="utf-8") as f:
        json.dump(session, f, indent=2)

    print()
    print("=" * 60)
    print("SIMULATION COMPLETE")
    print("=" * 60)
    print(f"Files processed : {len(session['files'])}")
    print(f"Ransom note     : {note}")
    print(f"Ransom note (Desktop): {note_desktop}")
    print(f"Evidence log    : {output}")
    print("=" * 60)


if __name__ == "__main__":
    main()