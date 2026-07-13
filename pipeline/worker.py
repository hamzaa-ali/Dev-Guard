import os
import threading
import logging
import shutil
import stat
from datetime import datetime

from pipeline.queue_manager import get_job, mark_job_done

logger = logging.getLogger(__name__)

# Folder where repos will be cloned temporarily for scanning
CLONE_BASE_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    '..',
    'tmp_scans'
)


def handle_remove_readonly(func, path, exc):
    """
    Windows fix: .git folders contain read-only files.
    This function forces them to be writable before deleting.
    """
    os.chmod(path, stat.S_IWRITE)
    func(path)


def cleanup_clone(clone_path):
    """
    Safely delete the cloned repo folder after scanning.
    Uses handle_remove_readonly to handle Windows read-only .git files.
    """
    if os.path.exists(clone_path):
        shutil.rmtree(clone_path, onerror=handle_remove_readonly)
        logger.info(f"[WORKER] Cleaned up clone folder: {clone_path}")


def process_job(job, app):
    """
    Process one scan job from the queue.

    Steps:
    1. Find or create the repo record in the database
    2. Create a scan record with status 'running'
    3. Clone the repository to a temporary folder
    4. Run scanners (wired in on Day 5 — placeholder today)
    5. Mark scan as completed
    6. Clean up the cloned folder

    Parameters:
    - job: dict with repo_name, repo_url, commit_hash, config
    - app: the Flask app instance (needed for database access)
    """
    from shared.models import db, Scan, Repo

    repo_name   = job['repo_name']
    repo_url    = job['repo_url']
    commit_hash = job['commit_hash']

    logger.info(f"[WORKER] Starting job for: {repo_name} | commit: {commit_hash[:7]}")

    # Build a unique folder name for this scan
    timestamp  = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    clone_path = os.path.join(CLONE_BASE_DIR, f"{repo_name}_{timestamp}")

    with app.app_context():

        # ── STEP 1: Find or create repo record ──
        repo = Repo.query.filter_by(github_url=repo_url).first()

        if not repo:
            repo = Repo(name=repo_name, github_url=repo_url)
            db.session.add(repo)
            db.session.commit()
            logger.info(f"[WORKER] New repo registered: {repo_name}")

        # ── STEP 2: Create scan record ──
        scan = Scan(
            repo_id     = repo.id,
            commit_hash = commit_hash,
            status      = 'running'
        )
        db.session.add(scan)
        db.session.commit()
        logger.info(f"[WORKER] Scan record created. Scan ID: {scan.id}")

        try:
            # ── STEP 3: Clone the repository ──
            os.makedirs(CLONE_BASE_DIR, exist_ok=True)
            logger.info(f"[WORKER] Cloning {repo_url} into {clone_path}")

            import git
            git.Repo.clone_from(repo_url, clone_path)
            logger.info(f"[WORKER] Clone complete: {clone_path}")

            # ── STEP 4: SCANNER CALLS PLUG IN HERE ON DAY 5 ──
            logger.info(f"[WORKER] Repo ready for scanning at: {clone_path}")
            logger.info(f"[WORKER] Scanners will be wired here on Day 5")

            # ── STEP 5: Mark scan as completed ──
            scan.status       = 'completed'
            scan.completed_at = datetime.utcnow()
            db.session.commit()
            logger.info(f"[WORKER] Scan {scan.id} marked as completed")

        except Exception as e:
            # If anything fails, mark scan as failed
            # Never crash the worker — just log and move on
            logger.error(f"[WORKER] Scan failed for {repo_name}: {str(e)}")
            scan.status       = 'failed'
            scan.completed_at = datetime.utcnow()
            db.session.commit()

        finally:
            # ── STEP 6: Always clean up the cloned folder ──
            # This runs whether the scan succeeded or failed
            cleanup_clone(clone_path)


def worker_loop(app):
    """
    The main worker loop.

    Runs forever as a background thread.
    Checks the queue every second.
    When a job appears, processes it immediately.
    Never stops unless the program exits.
    """
    logger.info("[WORKER] Worker thread started. Waiting for jobs...")

    while True:
        job = get_job(timeout=1)

        if job is not None:
            try:
                process_job(job, app)
            except Exception as e:
                logger.error(f"[WORKER] Unexpected error processing job: {str(e)}")
            finally:
                mark_job_done()


def start_worker(app):
    """
    Launch the worker as a background daemon thread.

    daemon=True means this thread dies automatically
    when the main program exits — no manual cleanup needed.
    """
    thread = threading.Thread(
        target = worker_loop,
        args   = (app,),
        daemon = True,
        name   = 'DevGuardWorker'
    )
    thread.start()
    logger.info("[WORKER] Worker thread launched successfully")
    return thread