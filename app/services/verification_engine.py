import asyncio
import json
import logging
import os
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

class NucleiVerificationEngine:
    def __init__(self):
        self.nuclei_bin = Path("bin/nuclei.exe").absolute()
        if not self.nuclei_bin.exists():
            logger.warning(f"Nuclei binary not found at {self.nuclei_bin}")

    async def verify(self, target_url: str | list[str], tags: list[str]) -> list[dict]:
        if not self.nuclei_bin.exists():
            return []

        results = []
        if tags:
            # Always include general high-value tags alongside the detected technologies.
            # We omit 'cve' to avoid running thousands of unrelated CVE templates, 
            # but we still catch generic exposed files, default logins, and misconfigs.
            final_tags = set(tags) | {"misconfig", "exposure", "default-login", "takeover"}
            target_tags = ",".join(final_tags)
        else:
            target_tags = "misconfig,exposure,default-login,takeover"
            
        target_str = ",".join(target_url) if isinstance(target_url, list) else target_url
        
        # Nuclei CLI command
        # -u: target
        # -jsonl: JSON lines output
        # -silent: No extraneous output
        # -nc: No colors
        # -tags: comma separated tags to restrict templates
        cmd = [
            str(self.nuclei_bin),
            "-u", target_str,
            "-jsonl",
            "-silent",
            "-nc",
            "-duc",  # Disable update checks which can hang
            "-tags", target_tags
        ]

        try:
            logger.info(f"Running Nuclei verification on {target_url} with tags: {target_tags}")
            
            def run_nuclei():
                return subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    errors='replace',
                    timeout=180  # Hard timeout of 3 minutes per run
                )

            process = await asyncio.to_thread(run_nuclei)
            
            if process.stdout:
                for line in process.stdout.splitlines():
                    if not line.strip():
                        continue
                    try:
                        data = json.loads(line)
                        info = data.get("info", {})
                        
                        results.append({
                            "cve_id": data.get("matcher-name") or info.get("name", "Unknown Issue"),
                            "severity": info.get("severity", "info"),
                            "description": info.get("description", "Verified by Nuclei"),
                            "extracted_results": data.get("extracted-results", []),
                            "matched_at": data.get("matched-at"),
                            "template_id": data.get("template-id"),
                            "curl_command": data.get("curl-command")
                        })
                    except json.JSONDecodeError:
                        pass
                        
            if process.stderr:
                err = process.stderr
                if err.strip():
                    logger.debug(f"Nuclei stderr: {err}")
                    
        except Exception as e:
            logger.exception(f"Nuclei execution failed for {target_url}")

        return results
