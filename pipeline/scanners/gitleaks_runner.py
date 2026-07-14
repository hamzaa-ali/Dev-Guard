import subprocess
import json
import logging
import os
import tempfile

logger = logging.getLogger(__name__)


def run_gitleaks(repo_path):
    """
    Run Gitleaks secrets detection scan.

    What Gitleaks does:
    - Scans every file in the repo for hardcoded secrets
    - Detects: API keys, passwords, tokens, private keys,
      AWS credentials, database URLs with passwords, etc.
    - Uses regex patterns to match known secret formats

    Exit codes from Gitleaks:
    - 0: No secrets found (clean scan)
    - 1: Secrets found (NOT an error — this is normal)
    - 126/127: Gitleaks not installed

    Returns:
    - List of raw secret finding dicts (empty list if none found or error)
    """
    logger.info(f"[GITLEAKS] Starting scan on: {repo_path}")

    output_file = os.path.join(tempfile.gettempdir(), 'gitleaks_output.json')

    # Remove old output file if it exists
    if os.path.exists(output_file):
        os.remove(output_file)

    try:
        result = subprocess.run(
            [
                'gitleaks', 'detect',
                '--source', repo_path,
                '--report-format', 'json',
                '--report-path', output_file,
                '--no-git',    # scan files directly, not git history
                '--exit-code', '0'  # always exit 0 so we handle results ourselves
            ],
            capture_output=True,
            text=True,
            timeout=120
        )

        if not os.path.exists(output_file):
            logger.info("[GITLEAKS] Scan complete. No secrets found.")
            return []

        with open(output_file, 'r', encoding='utf-8') as f:
            content = f.read().strip()

        # Clean up temp file
        os.remove(output_file)

        if not content or content == 'null':
            logger.info("[GITLEAKS] Scan complete. No secrets found.")
            return []

        data = json.loads(content)

        # Gitleaks returns a list directly (not nested)
        if isinstance(data, list):
            logger.info(f"[GITLEAKS] Scan complete. Raw findings: {len(data)}")
            return data

        return []

    except subprocess.TimeoutExpired:
        logger.error("[GITLEAKS] Scan timed out after 2 minutes")
        return []

    except FileNotFoundError:
        logger.error("[GITLEAKS] Gitleaks not found. Is it installed and in PATH?")
        return []

    except json.JSONDecodeError as e:
        logger.error(f"[GITLEAKS] JSON parse error: {str(e)}")
        return []

    except Exception as e:
        logger.error(f"[GITLEAKS] Unexpected error: {str(e)}")
        return []