import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from pipeline.scanners.semgrep_runner  import run_semgrep
from pipeline.scanners.trivy_runner    import run_trivy
from pipeline.scanners.gitleaks_runner import run_gitleaks
from pipeline.scanners.parser          import parse_all_results

logger = logging.getLogger(__name__)


def run_all_scanners(repo_path, config):
    """
    Run all enabled scanners IN PARALLEL using ThreadPoolExecutor.

    Why parallel?
    - Sequential: Semgrep(60s) + Trivy(30s) + Gitleaks(10s) = 100 seconds
    - Parallel:   max(Semgrep(60s), Trivy(30s), Gitleaks(10s)) = 60 seconds
    - Same results, 40% faster

    Each scanner runs in its own thread simultaneously.
    If one scanner fails, others keep running.
    Failed scanners return empty lists — never crash the pipeline.

    Parameters:
    - repo_path: path to the cloned repository on disk
    - config:    dict of which scanners are enabled for this repo

    Returns:
    - Unified list of normalized Finding dicts
    """
    semgrep_raw  = []
    trivy_raw    = []
    gitleaks_raw = []

    # Build the list of scanner tasks based on repo config
    scanner_tasks = {}

    with ThreadPoolExecutor(max_workers=3, thread_name_prefix='Scanner') as executor:

        if config.get('run_semgrep', True):
            scanner_tasks['semgrep']  = executor.submit(run_semgrep,  repo_path)
            logger.info("[ENGINE] Semgrep thread started")

        if config.get('run_trivy', True):
            scanner_tasks['trivy']    = executor.submit(run_trivy,    repo_path)
            logger.info("[ENGINE] Trivy thread started")

        if config.get('run_gitleaks', True):
            scanner_tasks['gitleaks'] = executor.submit(run_gitleaks, repo_path)
            logger.info("[ENGINE] Gitleaks thread started")

        logger.info(f"[ENGINE] {len(scanner_tasks)} scanner(s) running in parallel...")

        # Collect results as each scanner finishes
        for name, future in scanner_tasks.items():
            try:
                result = future.result()  # blocks until this scanner finishes

                if name == 'semgrep':
                    semgrep_raw = result
                    logger.info(f"[ENGINE] Semgrep done: {len(result)} raw findings")

                elif name == 'trivy':
                    trivy_raw = result
                    logger.info(f"[ENGINE] Trivy done: {len(result)} raw findings")

                elif name == 'gitleaks':
                    gitleaks_raw = result
                    logger.info(f"[ENGINE] Gitleaks done: {len(result)} raw findings")

            except Exception as e:
                logger.error(f"[ENGINE] {name} raised an exception: {str(e)}")
                # Don't re-raise — other scanners should still complete

    logger.info("[ENGINE] All scanners finished. Parsing results...")

    # Normalize and unify all results into one list
    return parse_all_results(semgrep_raw, trivy_raw, gitleaks_raw)