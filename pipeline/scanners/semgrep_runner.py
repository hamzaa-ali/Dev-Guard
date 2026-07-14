import subprocess
import json
import logging
import os

logger = logging.getLogger(__name__)


def run_semgrep(repo_path):
    """
    Run Semgrep SAST scan on the cloned repository.

    What Semgrep does:
    - Reads every source code file in repo_path
    - Matches code patterns against security rules
    - Returns findings like: SQL injection, hardcoded passwords,
      insecure functions, XSS vulnerabilities, etc.

    Returns:
    - List of raw Semgrep finding dicts (empty list if scan fails)
    """
    logger.info(f"[SEMGREP] Starting scan on: {repo_path}")

    try:
        result = subprocess.run(
            [
                'semgrep',
                '--config', 'auto',   # auto-downloads best rules for detected languages
                '--json',             # output as JSON so we can parse it
                '--quiet',            # suppress progress messages
                '--timeout', '60',    # max 60 seconds per file
                repo_path
            ],
            capture_output=True,
            text=True,
            timeout=300             # max 5 minutes total
        )

        if result.stdout:
            try:
                data = json.loads(result.stdout)
                findings = data.get('results', [])
                logger.info(f"[SEMGREP] Scan complete. Raw findings: {len(findings)}")
                return findings
            except json.JSONDecodeError:
                logger.error("[SEMGREP] Failed to parse JSON output")
                return []

        if result.returncode not in [0, 1]:
            logger.error(f"[SEMGREP] Unexpected exit code: {result.returncode}")
            logger.error(f"[SEMGREP] stderr: {result.stderr[:500]}")

        return []

    except subprocess.TimeoutExpired:
        logger.error("[SEMGREP] Scan timed out after 5 minutes")
        return []

    except FileNotFoundError:
        logger.error("[SEMGREP] Semgrep not found. Is it installed? Run: pip install semgrep")
        return []

    except Exception as e:
        logger.error(f"[SEMGREP] Unexpected error: {str(e)}")
        return []