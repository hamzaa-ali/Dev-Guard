import hmac
import hashlib
import logging
import os

from flask import Blueprint, request, jsonify
from shared.models import db, Repo, RepoConfig
from pipeline.queue_manager import add_job, queue_size

logger = logging.getLogger(__name__)

# Blueprint lets us register these routes separately from the dashboard routes
pipeline_bp = Blueprint('pipeline', __name__)


def verify_github_signature(payload_body, signature_header):
    """
    Verify that the webhook request actually came from GitHub.
    GitHub signs every request with a secret you set.
    We re-compute the signature and compare.
    If they match — it's real. If not — reject it.
    """
    webhook_secret = os.getenv('WEBHOOK_SECRET', '')

    if not webhook_secret:
        # If no secret is set, skip verification (okay for local dev)
        logger.warning("[WEBHOOK] No WEBHOOK_SECRET set. Skipping signature check.")
        return True

    if not signature_header:
        logger.warning("[WEBHOOK] No signature header found in request.")
        return False

    # GitHub sends: "sha256=<hash>"
    # We need to extract just the hash part
    try:
        sha_name, signature = signature_header.split('=')
    except ValueError:
        return False

    if sha_name != 'sha256':
        return False

    # Compute expected signature using our secret
    mac = hmac.new(
        webhook_secret.encode('utf-8'),
        msg=payload_body,
        digestmod=hashlib.sha256
    )
    expected_signature = mac.hexdigest()

    # Compare safely (prevents timing attacks)
    return hmac.compare_digest(expected_signature, signature)


def get_repo_config(repo_name, repo_url):
    """
    Look up this repo's scanner settings from the database.
    If no config exists yet, return default settings (all scanners on).
    """
    repo = Repo.query.filter_by(github_url=repo_url).first()

    if repo and repo.config:
        return {
            'run_semgrep':        repo.config.run_semgrep,
            'run_trivy':          repo.config.run_trivy,
            'run_gitleaks':       repo.config.run_gitleaks,
            'severity_threshold': repo.config.severity_threshold,
        }

    # Default config — all scanners enabled, no minimum threshold
    logger.info(f"[WEBHOOK] No config found for {repo_name}. Using defaults.")
    return {
        'run_semgrep':        True,
        'run_trivy':          True,
        'run_gitleaks':       True,
        'severity_threshold': 0.0,
    }


@pipeline_bp.route('/webhook', methods=['POST'])
def webhook():
    """
    This is the main webhook endpoint.
    GitHub sends a POST request here every time code is pushed.

    What happens here:
    1. Verify the request came from GitHub
    2. Parse the payload (repo name, URL, commit hash)
    3. Look up scanner config for this repo
    4. Add job to queue
    5. Immediately return 200 OK to GitHub
    """

    # ── STEP 1: Verify signature ──
    signature = request.headers.get('X-Hub-Signature-256', '')
    if not verify_github_signature(request.data, signature):
        logger.warning("[WEBHOOK] Invalid signature — request rejected")
        return jsonify({'error': 'Invalid signature'}), 401

    # ── STEP 2: Only handle push events ──
    event_type = request.headers.get('X-GitHub-Event', '')
    if event_type != 'push':
        logger.info(f"[WEBHOOK] Ignoring event type: {event_type}")
        return jsonify({'message': f'Event {event_type} ignored'}), 200

    # ── STEP 3: Parse the payload ──
    payload = request.get_json()

    if not payload:
        logger.warning("[WEBHOOK] Empty or invalid JSON payload")
        return jsonify({'error': 'Invalid payload'}), 400

    # Extract key information from GitHub's payload
    repo_name   = payload.get('repository', {}).get('name', 'unknown')
    repo_url    = payload.get('repository', {}).get('clone_url', '')
    commit_hash = payload.get('after', '')
    branch      = payload.get('ref', '').replace('refs/heads/', '')
    pusher      = payload.get('pusher', {}).get('name', 'unknown')

    logger.info(f"[WEBHOOK] Push received: {repo_name} | branch: {branch} | pusher: {pusher}")

    if not repo_url or not commit_hash:
        logger.warning("[WEBHOOK] Missing repo_url or commit_hash in payload")
        return jsonify({'error': 'Missing required fields'}), 400

    # Ignore pushes to branches other than main/master
    if branch not in ['main', 'master']:
        logger.info(f"[WEBHOOK] Ignoring push to branch: {branch}")
        return jsonify({'message': f'Branch {branch} not monitored'}), 200

    # ── STEP 4: Get repo config from database ──
    config = get_repo_config(repo_name, repo_url)

    # ── STEP 5: Add job to queue ──
    job = add_job(
        repo_name   = repo_name,
        repo_url    = repo_url,
        commit_hash = commit_hash,
        config      = config
    )

    logger.info(f"[WEBHOOK] Job queued successfully. Queue size: {queue_size()}")

    # ── STEP 6: Return 200 immediately ──
    # This is critical — GitHub expects a fast response
    # The actual scanning happens in the background worker
    return jsonify({
        'message':     'Scan job queued successfully',
        'repo':        repo_name,
        'commit':      commit_hash[:7],
        'queue_size':  queue_size()
    }), 200


@pipeline_bp.route('/webhook/status', methods=['GET'])
def webhook_status():
    """
    A simple health check endpoint.
    Visit this in browser to confirm the pipeline is running.
    """
    return jsonify({
        'status':     'running',
        'queue_size': queue_size()
    }), 200


@pipeline_bp.route('/webhook/blocked-push', methods=['POST'])
def blocked_push():
    """
    Called when a push is blocked by the pre-push hook.
    Records the blocked push count for the dashboard.
    """
    from shared.models import db, Repo

    payload = request.get_json()
    if not payload:
        return jsonify({'error': 'Invalid payload'}), 400

    repo_name = payload.get('repo_name', '')
    repo_url  = payload.get('repo_url', '')

    if not repo_name:
        return jsonify({'error': 'Missing repo_name'}), 400

    repo = Repo.query.filter_by(github_url=repo_url).first()
    if repo:
        repo.blocked_pushes += 1
        db.session.commit()
        logger.info(
            f"[WEBHOOK] Blocked push recorded for: {repo_name} "
            f"| Total blocked: {repo.blocked_pushes}"
        )

    return jsonify({
        'message': 'Blocked push recorded',
        'repo':    repo_name
    }), 200