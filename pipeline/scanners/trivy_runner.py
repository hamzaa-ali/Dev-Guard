import subprocess
import json
import logging
import os
import tempfile

logger = logging.getLogger(__name__)


def run_trivy(repo_path):
    """
    Run Trivy SCA (Software Composition Analysis) scan.

    What Trivy does:
    - Reads dependency files: requirements.txt, package.json,
      pom.xml, go.mod, Gemfile.lock, etc.
    - Looks up each dependency in the NVD (National Vulnerability Database)
    - Returns known CVEs with CVSS scores for vulnerable versions

    On first run: downloads its vulnerability database (~100MB).
    This takes 1-2 minutes. Subsequent runs are fast.

    Returns:
    - List of raw vulnerability dicts (empty list if scan fails)
    """
    logger.info(f"[TRIVY] Starting scan on: {repo_path}")

    # Use a temp file for output so we don't clutter the repo
    output_file = os.path.join(tempfile.gettempdir(), 'trivy_output.json')

    try:
        result = subprocess.run(
            [
                'trivy', 'fs',
                '--format', 'json',
                '--output', output_file,
                '--quiet',
                repo_path
            ],
            capture_output=True,
            text=True,
            timeout=300
        )

        if not os.path.exists(output_file):
            logger.warning("[TRIVY] No output file generated")
            return []

        with open(output_file, 'r', encoding='utf-8') as f:
            content = f.read().strip()

        # Clean up temp file
        os.remove(output_file)

        if not content:
            logger.info("[TRIVY] Scan complete. No vulnerabilities found.")
            return []

        data = json.loads(content)

        # Trivy output has a 'Results' array
        # Each result is one scanned file (e.g. requirements.txt)
        # Each result has a 'Vulnerabilities' array
        all_vulns = []
        for scan_result in data.get('Results', []):
            vulns = scan_result.get('Vulnerabilities') or []
            all_vulns.extend(vulns)

        logger.info(f"[TRIVY] Scan complete. Raw findings: {len(all_vulns)}")
        return all_vulns

    except subprocess.TimeoutExpired:
        logger.error("[TRIVY] Scan timed out after 5 minutes")
        return []

    except FileNotFoundError:
        logger.error("[TRIVY] Trivy not found. Is it installed and in PATH?")
        return []

    except json.JSONDecodeError as e:
        logger.error(f"[TRIVY] JSON parse error: {str(e)}")
        return []

    except Exception as e:
        logger.error(f"[TRIVY] Unexpected error: {str(e)}")
        return []