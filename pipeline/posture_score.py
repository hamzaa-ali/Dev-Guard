import logging
from datetime import datetime

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════
# POSTURE SCORE FORMULA
#
# Starting score: 10.0 (perfect security)
# Deductions applied per finding based on severity:
#
#   Critical (9.0-10.0) → deduct 2.0 per finding
#   High     (7.0-8.9)  → deduct 1.0 per finding
#   Medium   (4.0-6.9)  → deduct 0.5 per finding
#   Low      (0.1-3.9)  → deduct 0.1 per finding
#
# Only Confirmed and Review Needed findings are counted.
# Low Confidence findings do not affect the score.
#
# Score is capped at minimum 0.0.
# Score is rounded to 1 decimal place.
# ═══════════════════════════════════════════════════════════

DEDUCTION_WEIGHTS = {
    'critical': 2.0,
    'high':     1.0,
    'medium':   0.5,
    'low':      0.1,
}

def get_severity_category(normalized_severity):
    """
    Convert a 0-10 numerical severity score to a category name.
    Used to look up the deduction weight.
    """
    if normalized_severity >= 9.0:
        return 'critical'
    elif normalized_severity >= 7.0:
        return 'high'
    elif normalized_severity >= 4.0:
        return 'medium'
    else:
        return 'low'


def calculate_posture_score(findings):
    """
    Calculate the Security Posture Score for a scan.

    Parameters:
    - findings: list of Finding objects from the database
                (already saved, with confidence labels)

    Returns:
    - score: float between 0.0 and 10.0
    - breakdown: dict showing how many findings of each
                 severity contributed to the score
    """
    score = 10.0
    breakdown = {
        'critical': 0,
        'high':     0,
        'medium':   0,
        'low':      0,
        'skipped':  0,
    }

    for finding in findings:
        # Only count Confirmed and Review Needed findings
        # Low Confidence findings are likely false positives
        if finding.confidence_label == 'Low Confidence':
            breakdown['skipped'] += 1
            continue

        severity    = finding.normalized_severity or 0.0
        category    = get_severity_category(severity)
        deduction   = DEDUCTION_WEIGHTS[category]

        score -= deduction
        breakdown[category] += 1

    # Cap score at 0.0 minimum
    score = max(0.0, score)

    # Round to 1 decimal place
    score = round(score, 1)

    logger.info(
        f"[POSTURE] Score calculated: {score}/10 | "
        f"Critical: {breakdown['critical']} | "
        f"High: {breakdown['high']} | "
        f"Medium: {breakdown['medium']} | "
        f"Low: {breakdown['low']} | "
        f"Skipped (low conf): {breakdown['skipped']}"
    )

    return score, breakdown


def get_score_label(score):
    """
    Convert numerical score to a health status label
    with color category for the dashboard.

    Returns tuple of (label, color_class)
    """
    if score >= 8.0:
        return 'Excellent', 'score-excellent'
    elif score >= 6.0:
        return 'Good', 'score-good'
    elif score >= 4.0:
        return 'Fair', 'score-fair'
    elif score >= 2.0:
        return 'Poor', 'score-poor'
    else:
        return 'Critical', 'score-critical'


def save_posture_score(db, scan_id, repo_id, score):
    """
    Save the posture score to the database.
    Also retrieves the previous score for trend comparison.

    Parameters:
    - db:      SQLAlchemy db instance
    - scan_id: ID of the current scan
    - repo_id: ID of the repository
    - score:   calculated score (0.0 - 10.0)

    Returns:
    - PostureScore object
    """
    from shared.models import PostureScore

    # Get the previous score for this repo
    previous = PostureScore.query.filter_by(
        repo_id=repo_id
    ).order_by(
        PostureScore.created_at.desc()
    ).first()

    previous_score = previous.score if previous else None

    posture_record = PostureScore(
        scan_id        = scan_id,
        repo_id        = repo_id,
        score          = score,
        previous_score = previous_score,
    )

    db.session.add(posture_record)
    db.session.commit()

    if previous_score is not None:
        change = score - previous_score
        direction = "improved" if change > 0 else "declined" if change < 0 else "unchanged"
        logger.info(
            f"[POSTURE] Score {direction}: "
            f"{previous_score} → {score} "
            f"(change: {change:+.1f})"
        )
    else:
        logger.info(f"[POSTURE] First scan score: {score}/10")

    return posture_record