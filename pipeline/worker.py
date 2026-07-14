import os
import threading
import logging
import shutil
import stat
from datetime import datetime

from pipeline.queue_manager import get_job, mark_job_done
from pipeline.scan_engine   import run_all_scanners

logger = logging.getLogger(__name__)

CLONE_BASE_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    '..',
    'tmp_scans'
)


def handle_remove_readonly(func, path, exc):
    """Windows fix: force-delete read-only .git files."""
    os.chmod(path, stat.S_IWRITE)
    func(path)


def cleanup_clone(clone_path):
    """Safely delete the cloned repo folder."""
    if os.path.exists(clone_path):
        shutil.rmtree(clone_path, onerror=handle_remove_readonly)
        logger.info(f"[WORKER] Cleaned up: {clone_path}")


def save_findings_to_db(db, scan_id, findings, severity_threshold):
    """
    Save all normalized findings to the database.

    Parameters:
    - db:                 SQLAlchemy db instance
    - scan_id:            ID of the current scan record
    - findings:           list of normalized finding dicts from parser
    - severity_threshold: minimum severity to save (from repo config)
    """
    from shared.models import Finding

    saved_count   = 0
    skipped_count = 0

    for f in findings:
        # Skip findings below the configured severity threshold
        if f['normalized_severity'] < severity_threshold:
            skipped_count += 1
            continue

        finding = Finding(
            scan_id             = scan_id,
            tool                = f['tool'],
            rule_id             = f.get('rule_id', ''),
            file_path           = f.get('file_path', ''),
            line_number         = f.get('line_number'),
            message             = f.get('message', ''),
            raw_severity        = f.get('raw_severity', ''),
            normalized_severity = f.get('normalized_severity', 0.0),
            # Confidence filter comes in Day 8
            # For now default everything to Confirmed
            confidence_label    = 'Confirmed',
            confidence_score    = 8.0,
        )
        db.session.add(finding)
        saved_count += 1

    db.session.commit()
    logger.info(f"[WORKER] Saved {saved_count} findings. Skipped {skipped_count} below threshold.")
    return saved_count


def process_job(job, app):
    """
    Process one scan job end to end.

    Steps:
    1. Find or create repo record in DB
    2. Create scan record with status 'running'
    3. Clone the repository
    4. Run all three scanners in parallel
    5. Save all findings to database
    6. Mark scan as completed
    7. Clean up cloned folder
    """
    from shared.models import db, Scan, Repo

    repo_name         = job['repo_name']
    repo_url          = job['repo_url']
    commit_hash       = job['commit_hash']
    config            = job['config']
    severity_threshold = config.get('severity_threshold', 0.0)

    logger.info(f"[WORKER] ── Starting job: {repo_name} | commit: {commit_hash[:7]} ──")

    timestamp  = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    clone_path = os.path.join(CLONE_BASE_DIR, f"{repo_name}_{timestamp}")

    with app.app_context():

        # ── STEP 1: Find or register repo ──
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
        logger.info(f"[WORKER] Scan record created. ID: {scan.id}")

        try:
            # ── STEP 3: Clone the repository ──
            os.makedirs(CLONE_BASE_DIR, exist_ok=True)
            logger.info(f"[WORKER] Cloning {repo_url}...")

            import git
            git.Repo.clone_from(repo_url, clone_path)
            logger.info(f"[WORKER] Clone complete.")

            # ── STEP 4: Run all scanners in parallel ──
            logger.info(f"[WORKER] Running scanners on {clone_path}...")
            findings = run_all_scanners(clone_path, config)
            logger.info(f"[WORKER] Scan engine returned {len(findings)} total findings")

            # ── STEP 5: Save findings to database ──
            saved = save_findings_to_db(db, scan.id, findings, severity_threshold)
            logger.info(f"[WORKER] {saved} findings saved to database")

            # ── STEP 6: Mark scan as completed ──
            scan.status       = 'completed'
            scan.completed_at = datetime.utcnow()
            db.session.commit()
            logger.info(f"[WORKER] ── Scan {scan.id} completed successfully ──")

        except Exception as e:
            logger.error(f"[WORKER] Scan failed: {str(e)}")
            scan.status       = 'failed'
            scan.completed_at = datetime.utcnow()
            db.session.commit()

        finally:
            cleanup_clone(clone_path)


def worker_loop(app):
    """Runs forever. Checks queue every second. Processes jobs as they arrive."""
    logger.info("[WORKER] Worker thread started. Waiting for jobs...")

    while True:
        job = get_job(timeout=1)
        if job is not None:
            try:
                process_job(job, app)
            except Exception as e:
                logger.error(f"[WORKER] Unexpected error: {str(e)}")
            finally:
                mark_job_done()


def start_worker(app):
    """Launch worker as a background daemon thread."""
    thread = threading.Thread(
        target = worker_loop,
        args   = (app,),
        daemon = True,
        name   = 'DevGuardWorker'
    )
    thread.start()
    logger.info("[WORKER] Worker thread launched successfully")
    return thread