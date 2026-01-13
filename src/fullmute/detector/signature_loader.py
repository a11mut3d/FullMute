import json
import re
from pathlib import Path
from typing import Dict, Any, List
from fullmute.utils.logger import setup_logger

logger = setup_logger()

class SignatureLoader:
    def __init__(self, signatures_dir: str = None):
        if signatures_dir is None:
            base_dir = Path(__file__).parent.parent.parent.parent
            self.signatures_dir = base_dir / "config" / "signatures"
            if not self.signatures_dir.exists():
                self.signatures_dir = Path(__file__).parent.parent / "config" / "signatures"
        else:
            self.signatures_dir = Path(signatures_dir)

        self.signatures_dir.mkdir(parents=True, exist_ok=True)
        self._signatures = {}

    def load_all(self) -> Dict[str, Dict[str, Any]]:
        for file_path in self.signatures_dir.glob("*.json"):
            try:
                signature_type = file_path.stem
                with open(file_path, 'r', encoding='utf-8') as f:
                    self._signatures[signature_type] = json.load(f)
                logger.debug(f"Loaded signatures from {file_path}")
            except Exception as e:
                logger.error(f"Failed to load {file_path}: {e}")

        return self._signatures

    def load(self, signature_type: str) -> Dict[str, Any]:
        if signature_type in self._signatures:
            return self._signatures[signature_type]

        file_path = self.signatures_dir / f"{signature_type}.json"
        if not file_path.exists():
            logger.warning(f"Signature file not found: {file_path}")
            return {}

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                signatures = json.load(f)
            self._signatures[signature_type] = signatures
            return signatures
        except Exception as e:
            logger.error(f"Failed to load {signature_type} signatures: {e}")
            return {}

    def add_signature(self, signature_type: str, name: str, patterns: Dict[str, Any]) -> bool:
        signatures = self.load(signature_type)
        signatures[name] = patterns

        file_path = self.signatures_dir / f"{signature_type}.json"
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(signatures, f, indent=2, ensure_ascii=False)
            logger.info(f"Added signature {name} to {signature_type}")
            return True
        except Exception as e:
            logger.error(f"Failed to save signature: {e}")
            return False

    def get_cms_signatures(self):
        return self.load("cms")

    def get_server_signatures(self):
        return self.load("server")

    def get_framework_signatures(self):
        return self.load("framework")

    def get_camera_signatures(self):
        return self.load("camera")

    def get_sensitive_file_signatures(self):
        return self.load("sensitive_files")
