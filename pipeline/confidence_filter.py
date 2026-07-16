import os
import logging

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════
# CONFIDENCE SCORING RULES
#
# Each finding gets a confidence score from 1-10.
# Higher = more likely to be a real threat.
# Lower = more likely to be a false positive.
#
# Final classification:
#   8.0 - 10.0 → Confirmed
#   5.0 - 7.9  → Review Needed
#   1.0 - 4.9  → Low Confidence
#
# CRITICAL RULE: Critical and High severity findings
# (normalized_severity >= 7.0) are NEVER classified as
# Low Confidence. They always stay at minimum Review Needed.
# A real critical vulnerability must never be silently ignored.
# ═══════════════════════════════════════════════════════════

# Starting confidence score — deductions applied below
BASE_SCORE = 8.0

# Paths that indicate test/example code
TEST_PATH_PATTERNS = [
    'test', 'tests', 'spec', 'specs',
    '__test__', '__tests__',
    'example', 'examples',
    'demo', 'demos',
    'fixture', 'fixtures',
    'mock', 'mocks',
    'sample', 'samples',
]

# File extensions that are documentation, not executable code
DOC_EXTENSIONS = [
    '.md', '.txt', '.rst', '.html',
    '.css', '.json', '.yaml', '.yml',
    '.xml', '.csv', '.lock'
]


def is_test_file(file_path):
    """
    Check if the finding is in a test/example file.
    Test files generate many false positives because
    they intentionally use insecure patterns for testing.

    Example: a test file testing SQL injection resistance
    will contain SQL injection strings — Semgrep flags them
    but they are not real vulnerabilities.
    """
    if not file_path:
        return False

    path_lower = file_path.lower().replace('\\', '/')

    for pattern in TEST_PATH_PATTERNS:
        # Check if any path component matches
        parts = path_lower.split('/')
        if any(pattern in part for part in parts):
            return True

        # Also check for common test file naming conventions
        filename = parts[-1] if parts else ''
        if filename.startswith('test_') or filename.endswith('_test.py'):
            return True

    return False


def is_doc_file(file_path):
    """
    Check if the finding is in a documentation file.
    Semgrep sometimes flags URLs or code snippets in
    markdown files — these are never real vulnerabilities.
    """
    if not file_path:
        return False

    _, ext = os.path.splitext(file_path.lower())
    return ext in DOC_EXTENSIONS


def is_duplicate(finding, existing_findings):
    """
    Check if an identical finding already exists in
    the current scan's results.

    Duplicates happen when:
    - Same vulnerability is detected by multiple rules
    - Same file is scanned multiple times

    We identify duplicates by matching:
    tool + rule_id + file_path + line_number
    """
    for existing in existing_findings:
        if (existing.get('tool') == finding.get('tool') and
                existing.get('rule_id') == finding.get('rule_id') and
                existing.get('file_path') == finding.get('file_path') and
                existing.get('line_number') == finding.get('line_number')):
            return True
    return False


def score_finding(finding, processed_findings):
    """
    Calculate confidence score for a single finding.

    Applies deductions based on contextual signals.
    Returns a score between 1.0 and 10.0.

    Parameters:
    - finding:            normalized finding dict from parser
    - processed_findings: list of already-processed findings
                         (used for duplicate detection)
    """
    score = BASE_SCORE
    reasons = []

    file_path  = finding.get('file_path', '')
    tool       = finding.get('tool', '')
    message    = finding.get('message', '').lower()
    normalized_severity = finding.get('normalized_severity', 0.0)

    # ── DEDUCTION 1: Test file ──
    # Findings in test files are usually intentional,
    # not real vulnerabilities
    if is_test_file(file_path):
        score -= 3.0
        reasons.append("test file (-3.0)")

    # ── DEDUCTION 2: Documentation file ──
    # Findings in docs/markdown are almost never real
    if is_doc_file(file_path):
        score -= 4.0
        reasons.append("documentation file (-4.0)")

    # ── DEDUCTION 3: Duplicate finding ──
    # Same finding reported twice adds no new information
    if is_duplicate(finding, processed_findings):
        score -= 2.0
        reasons.append("duplicate finding (-2.0)")

    # ── DEDUCTION 4: Informational Semgrep rules ──
    # Some Semgrep rules are advisory, not actual security issues
    if tool == 'semgrep' and normalized_severity <= 2.0:
        score -= 1.5
        reasons.append("semgrep informational rule (-1.5)")

    # ── DEDUCTION 5: Generic/vague messages ──
    # Very generic messages often indicate low-confidence rules
    vague_terms = ['may', 'might', 'could', 'possible', 'potential']
    if any(term in message for term in vague_terms):
        score -= 1.0
        reasons.append("vague/potential language (-1.0)")

    # ── BONUS: Gitleaks findings are always high confidence ──
    # Hardcoded secrets are almost never false positives
    if tool == 'gitleaks':
        score += 1.0
        reasons.append("gitleaks secret detection (+1.0)")

    # ── BONUS: High CVSS score from Trivy NVD data ──
    # Real CVEs from NVD are verified, not speculative
    if tool == 'trivy' and normalized_severity >= 7.0:
        score += 0.5
        reasons.append("verified NVD CVE (+0.5)")

    # Cap score between 1.0 and 10.0
    score = max(1.0, min(10.0, score))

    # ── CRITICAL SAFETY RULE ──
    # High and Critical findings must never be Low Confidence
    # Even if score dropped below 5.0, floor it at 5.0
    # A security team must always review high-severity findings
    if normalized_severity >= 7.0 and score < 5.0:
        score = 5.0
        reasons.append("severity floor applied (critical/high protection)")

    if reasons:
        logger.debug(f"[FILTER] {file_path}: score={score:.1f} | {' | '.join(reasons)}")

    return round(score, 1)


def get_confidence_label(score):
    """
    Convert numerical confidence score to human-readable label.

    8.0-10.0 → Confirmed       (security team should fix this)
    5.0-7.9  → Review Needed   (human should look at this)
    1.0-4.9  → Low Confidence  (likely false positive, low priority)
    """
    if score >= 8.0:
        return 'Confirmed'
    elif score >= 5.0:
        return 'Review Needed'
    else:
        return 'Low Confidence'


def apply_confidence_filter(findings):
    """
    Main entry point for the confidence filter.

    Takes a list of normalized findings from the parser,
    adds confidence_score and confidence_label to each one,
    and returns the enriched list.

    Parameters:
    - findings: list of normalized finding dicts

    Returns:
    - Same list with confidence_score and confidence_label added
    """
    logger.info(f"[FILTER] Applying confidence filter to {len(findings)} findings...")

    processed    = []
    confirmed    = 0
    review       = 0
    low_conf     = 0

    for finding in findings:
        # Score this finding
        score = score_finding(finding, processed)
        label = get_confidence_label(score)

        # Add confidence data to the finding dict
        finding['confidence_score'] = score
        finding['confidence_label'] = label

        # Track counts for logging
        if label == 'Confirmed':
            confirmed += 1
        elif label == 'Review Needed':
            review += 1
        else:
            low_conf += 1

        processed.append(finding)

    logger.info(f"[FILTER] Results → Confirmed: {confirmed} | "
                f"Review Needed: {review} | "
                f"Low Confidence: {low_conf}")

    return processed