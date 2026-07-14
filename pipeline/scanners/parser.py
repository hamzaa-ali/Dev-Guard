import logging

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════
# SEVERITY MAPPING TABLES
#
# Each scanner uses different severity labels.
# We convert everything to a unified 0-10 scale.
# This is aligned with CVSS v3 conventions:
#   Critical: 9.0-10.0
#   High:     7.0-8.9
#   Medium:   4.0-6.9
#   Low:      0.1-3.9
# ═══════════════════════════════════════════════════════════

SEMGREP_SEVERITY_MAP = {
    'ERROR':   8.5,   # High — definite security issue
    'WARNING': 5.0,   # Medium — potential security issue
    'INFO':    2.0,   # Low — informational
}

TRIVY_SEVERITY_MAP = {
    'CRITICAL': 9.5,  # Use CVSS score if available, else this
    'HIGH':     7.5,
    'MEDIUM':   5.0,
    'LOW':      2.0,
    'UNKNOWN':  1.0,
}

# All Gitleaks findings are High by default
# A hardcoded secret is always a serious issue
GITLEAKS_DEFAULT_SEVERITY = 7.5


# ═══════════════════════════════════════════════════════════
# SEMGREP NORMALIZER
# ═══════════════════════════════════════════════════════════
def normalize_semgrep(raw_results):
    """
    Convert Semgrep raw JSON findings to common Finding format.

    Semgrep raw finding looks like:
    {
        "check_id": "python.lang.security.audit.subprocess-shell-true",
        "path": "app.py",
        "start": {"line": 42},
        "extra": {
            "message": "subprocess called with shell=True",
            "severity": "ERROR"
        }
    }
    """
    findings = []

    for r in raw_results:
        raw_severity = r.get('extra', {}).get('severity', 'INFO').upper()

        findings.append({
            'tool':                'semgrep',
            'rule_id':             r.get('check_id', 'unknown'),
            'file_path':           r.get('path', ''),
            'line_number':         r.get('start', {}).get('line'),
            'message':             r.get('extra', {}).get('message', ''),
            'raw_severity':        raw_severity,
            'normalized_severity': SEMGREP_SEVERITY_MAP.get(raw_severity, 2.0),
        })

    return findings


# ═══════════════════════════════════════════════════════════
# TRIVY NORMALIZER
# ═══════════════════════════════════════════════════════════
def normalize_trivy(raw_results):
    """
    Convert Trivy raw JSON findings to common Finding format.

    Trivy raw vulnerability looks like:
    {
        "VulnerabilityID": "CVE-2023-1234",
        "PkgName": "flask",
        "Severity": "HIGH",
        "Description": "A vulnerability in Flask...",
        "CVSS": {
            "nvd": {"V3Score": 7.8}
        }
    }

    We prefer the actual CVSS score over the label when available.
    """
    findings = []

    for v in raw_results:
        raw_severity = v.get('Severity', 'UNKNOWN').upper()

        # Try to get real CVSS v3 score from NVD
        cvss_score = None
        cvss_data = v.get('CVSS', {})
        for source_name, scores in cvss_data.items():
            if 'V3Score' in scores and scores['V3Score']:
                cvss_score = float(scores['V3Score'])
                break

        # Use real CVSS score if available, otherwise use our mapping
        normalized = cvss_score if cvss_score else TRIVY_SEVERITY_MAP.get(raw_severity, 1.0)
        normalized = min(normalized, 10.0)  # cap at 10

        findings.append({
            'tool':                'trivy',
            'rule_id':             v.get('VulnerabilityID', 'unknown'),
            'file_path':           v.get('PkgName', ''),
            'line_number':         None,   # Trivy doesn't give line numbers
            'message':             v.get('Description') or v.get('Title', ''),
            'raw_severity':        raw_severity,
            'normalized_severity': normalized,
        })

    return findings


# ═══════════════════════════════════════════════════════════
# GITLEAKS NORMALIZER
# ═══════════════════════════════════════════════════════════
def normalize_gitleaks(raw_results):
    """
    Convert Gitleaks raw JSON findings to common Finding format.

    Gitleaks raw finding looks like:
    {
        "RuleID": "aws-access-token",
        "File": "config.py",
        "StartLine": 15,
        "Secret": "AKIAIOSFODNN7EXAMPLE",
        "Description": "AWS Access Token"
    }

    We never store the actual secret value in the database —
    only the description and location.
    """
    findings = []

    for r in raw_results:
        description = r.get('Description') or r.get('RuleID', 'Unknown secret type')
        file_path   = r.get('File', '')
        line_number = r.get('StartLine')

        findings.append({
            'tool':                'gitleaks',
            'rule_id':             r.get('RuleID', 'unknown'),
            'file_path':           file_path,
            'line_number':         line_number,
            'message':             f"Hardcoded secret detected: {description}",
            'raw_severity':        'HIGH',
            'normalized_severity': GITLEAKS_DEFAULT_SEVERITY,
        })

    return findings


# ═══════════════════════════════════════════════════════════
# COMBINE ALL RESULTS
# ═══════════════════════════════════════════════════════════
def parse_all_results(semgrep_raw, trivy_raw, gitleaks_raw):
    """
    Normalize and combine results from all three scanners
    into one unified list of findings.

    This is the single handoff point between raw scanner
    output and your database schema.
    """
    semgrep_findings  = normalize_semgrep(semgrep_raw)
    trivy_findings    = normalize_trivy(trivy_raw)
    gitleaks_findings = normalize_gitleaks(gitleaks_raw)

    logger.info(f"[PARSER] Semgrep findings:  {len(semgrep_findings)}")
    logger.info(f"[PARSER] Trivy findings:    {len(trivy_findings)}")
    logger.info(f"[PARSER] Gitleaks findings: {len(gitleaks_findings)}")

    all_findings = semgrep_findings + trivy_findings + gitleaks_findings

    logger.info(f"[PARSER] Total unified findings: {len(all_findings)}")
    return all_findings