import yaml
from pathlib import Path

def load_config(path):
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    with p.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def validate_config(path):
    cfg = load_config(path)
    if "scanner" not in cfg:
        raise ValueError("Missing 'scanner' section in config")
    if "database" not in cfg:
        raise ValueError("Missing 'database' section in config")
    if "path" not in cfg["database"]:
        raise ValueError("Missing 'database.path' in config")
    return True
