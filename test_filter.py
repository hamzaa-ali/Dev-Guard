"""
Test the confidence filter with sample findings.
Run with: python test_filter.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pipeline.confidence_filter import apply_confidence_filter

# Sample findings that simulate real scanner output
sample_findings = [
    {
        'tool': 'semgrep',
        'rule_id': 'python.flask.security.audit.debug-enabled',
        'file_path': 'dashboard/app.py',
        'line_number': 42,
        'message': 'Detected Flask app with debug=True.',
        'raw_severity': 'WARNING',
        'normalized_severity': 5.0,
    },
    {
        'tool': 'semgrep',
        'rule_id': 'python.lang.security.audit.subprocess-shell-true',
        'file_path': 'tests/test_runner.py',   # test file
        'line_number': 15,
        'message': 'subprocess called with shell=True',
        'raw_severity': 'ERROR',
        'normalized_severity': 8.5,
    },
    {
        'tool': 'gitleaks',
        'rule_id': 'aws-access-token',
        'file_path': 'config.py',
        'line_number': 8,
        'message': 'Hardcoded secret detected: AWS Access Token',
        'raw_severity': 'HIGH',
        'normalized_severity': 7.5,
    },
    {
        'tool': 'semgrep',
        'rule_id': 'generic.secrets.security.detected-generic-secret',
        'file_path': 'README.md',              # doc file
        'line_number': 23,
        'message': 'Possible hardcoded secret',
        'raw_severity': 'WARNING',
        'normalized_severity': 5.0,
    },
    {
        'tool': 'trivy',
        'rule_id': 'CVE-2023-30861',
        'file_path': 'flask',
        'line_number': None,
        'message': 'Flask vulnerable to response splitting',
        'raw_severity': 'HIGH',
        'normalized_severity': 7.5,
    },
]

print("\n" + "="*65)
print("  DevGuard Confidence Filter Test")
print("="*65)

results = apply_confidence_filter(sample_findings)

print(f"\n{'Tool':<12} {'Severity':<10} {'Score':<8} "
      f"{'Label':<18} {'File'}")
print("-"*65)

for f in results:
    print(
        f"{f['tool']:<12} "
        f"{f['normalized_severity']:<10} "
        f"{f['confidence_score']:<8} "
        f"{f['confidence_label']:<18} "
        f"{f['file_path'][:30]}"
    )

print("\n" + "="*65)

confirmed   = sum(1 for f in results if f['confidence_label'] == 'Confirmed')
review      = sum(1 for f in results if f['confidence_label'] == 'Review Needed')
low         = sum(1 for f in results if f['confidence_label'] == 'Low Confidence')

print(f"  Confirmed:      {confirmed}")
print(f"  Review Needed:  {review}")
print(f"  Low Confidence: {low}")
print("="*65 + "\n")