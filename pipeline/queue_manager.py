import queue
import logging

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────
# THE GLOBAL JOB QUEUE
#
# This is a thread-safe waiting list.
# The webhook receiver puts jobs IN here.
# The worker takes jobs OUT of here.
# Both happen at the same time without conflicts.
# ─────────────────────────────────────────────────────────
scan_queue = queue.Queue()


def add_job(repo_name, repo_url, commit_hash, config):
    """
    Add a new scan job to the queue.
    
    Parameters:
    - repo_name:   name of the repository (e.g. 'my-project')
    - repo_url:    full GitHub clone URL
    - commit_hash: the specific commit that triggered this scan
    - config:      dict of scanner settings for this repo
    """
    job = {
        'repo_name':   repo_name,
        'repo_url':    repo_url,
        'commit_hash': commit_hash,
        'config':      config,
    }

    scan_queue.put(job)
    logger.info(f"[QUEUE] Job added for repo: {repo_name} | commit: {commit_hash[:7]}")
    return job


def get_job(timeout=1):
    """
    Get the next job from the queue.
    Waits up to `timeout` seconds before giving up.
    Returns None if queue is empty after timeout.
    """
    try:
        job = scan_queue.get(timeout=timeout)
        return job
    except queue.Empty:
        return None


def mark_job_done():
    """
    Tell the queue that the current job finished.
    This is required by Python's queue system.
    """
    scan_queue.task_done()


def queue_size():
    """
    Returns how many jobs are currently waiting.
    """
    return scan_queue.qsize()