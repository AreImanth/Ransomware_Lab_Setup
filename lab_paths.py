"""Single source of truth for case2 paths. All scripts import this; nothing hardcodes C: everywhere."""
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent

def _cfg():
    with (PROJECT_ROOT / "lab_config.json").open("r", encoding="utf-8") as f:
        return json.load(f)

CONFIG = _cfg()
LAB_ROOT = Path(CONFIG["lab_root"])
LOG_DIR = PROJECT_ROOT / "logs"
EVIDENCE = PROJECT_ROOT / "evidence"
BASELINE_DIR = EVIDENCE / "baseline"
POST_DIR = EVIDENCE / "post"
REPORTS_DIR = PROJECT_ROOT / "reports"
RUNS_DIR = PROJECT_ROOT / "runs"
