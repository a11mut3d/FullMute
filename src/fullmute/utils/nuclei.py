import asyncio
import json
import shutil
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from fullmute.utils.logger import setup_logger

logger = setup_logger()


class NucleiRunner:
    """Find CVE templates locally and run them without invoking a shell."""

    def __init__(
        self,
        binary: str = "nuclei",
        templates_path: str = "",
        timeout: int = 120,
        max_templates: int = 100,
    ):
        self.binary = binary.strip() or "nuclei"
        self.templates_path = Path(templates_path).expanduser() if templates_path else None
        self.timeout = max(1, min(int(timeout), 600))
        self.max_templates = max(1, min(int(max_templates), 500))

    def _resolve_binary(self) -> Optional[str]:
        path = Path(self.binary).expanduser()
        if path.is_absolute() or "/" in self.binary:
            return str(path) if path.is_file() else None
        return shutil.which(self.binary)

    def _find_templates(self, cve_id: str) -> List[Path]:
        if not self.templates_path or not self.templates_path.is_dir():
            return []
        needle = cve_id.lower()
        matches: List[Path] = []
        for template in self.templates_path.rglob("*"):
            if len(matches) >= self.max_templates:
                break
            if not template.is_file() or template.suffix.lower() not in {".yaml", ".yml"}:
                continue
            if needle in template.name.lower():
                matches.append(template)
                continue
            try:
                if needle in template.read_text(encoding="utf-8", errors="ignore")[:1_000_000].lower():
                    matches.append(template)
            except OSError:
                continue
        return matches

    async def run_for_cves(self, target: str, cves: Iterable[str]) -> List[Dict[str, Any]]:
        binary = self._resolve_binary()
        if not binary:
            logger.warning("Nuclei is enabled but the configured binary was not found")
            return [{"status": "error", "error": "Nuclei binary not found"}]
        if not self.templates_path or not self.templates_path.is_dir():
            logger.warning("Nuclei is enabled but templates path is missing or invalid")
            return [{"status": "error", "error": "Nuclei templates path is invalid"}]

        results: List[Dict[str, Any]] = []
        seen = set()
        for cve_id in cves:
            if not cve_id or cve_id in seen:
                continue
            seen.add(cve_id)
            templates = self._find_templates(cve_id)
            if not templates:
                results.append({"cve_id": cve_id, "status": "template_not_found"})
                continue
            for template in templates:
                template_name = str(template.relative_to(self.templates_path))
                command = [binary, "-u", target, "-t", str(template), "-jsonl", "-silent"]
                try:
                    process = await asyncio.create_subprocess_exec(
                        *command,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(), timeout=self.timeout
                    )
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
                    results.append({
                        "cve_id": cve_id,
                        "template": str(template),
                        "template_name": template_name,
                        "status": "timeout",
                    })
                    continue
                except OSError as exc:
                    results.append({
                        "cve_id": cve_id,
                        "template": str(template),
                        "template_name": template_name,
                        "status": "error",
                        "error": str(exc),
                    })
                    continue

                findings = []
                for line in stdout.decode("utf-8", errors="replace").splitlines():
                    try:
                        findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        if line.strip():
                            findings.append({"raw": line})
                results.append({
                    "cve_id": cve_id,
                    "template": str(template),
                    "template_name": template_name,
                    "status": "completed" if process.returncode == 0 else "failed",
                    "exit_code": process.returncode,
                    "findings": findings,
                    "stderr": stderr.decode("utf-8", errors="replace")[-2000:],
                })
        return results
