"""
Quick test to verify all three scanners are installed
and working correctly before wiring into the pipeline.

Run with: python test_scanners.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pipeline.scanners.semgrep_runner  import run_semgrep
from pipeline.scanners.trivy_runner    import run_trivy
from pipeline.scanners.gitleaks_runner import run_gitleaks
from pipeline.scanners.parser          import parse_all_results

# Use the current project folder as test target
TEST_PATH = os.path.dirname(os.path.abspath(__file__))

print("\n" + "="*60)
print("  DevGuard Scanner Test")
print(f"  Scanning: {TEST_PATH}")
print("="*60 + "\n")

# ── Test Semgrep ──
print("Testing Semgrep...")
semgrep_results = run_semgrep(TEST_PATH)
print(f"  Result: {len(semgrep_results)} raw findings\n")

# ── Test Trivy ──
print("Testing Trivy...")
print("  (First run downloads vulnerability database — may take 1-2 min)")
trivy_results = run_trivy(TEST_PATH)
print(f"  Result: {len(trivy_results)} raw findings\n")

# ── Test Gitleaks ──
print("Testing Gitleaks...")
gitleaks_results = run_gitleaks(TEST_PATH)
print(f"  Result: {len(gitleaks_results)} raw findings\n")

# ── Test Parser ──
print("Testing Parser (normalization)...")
unified = parse_all_results(semgrep_results, trivy_results, gitleaks_results)
print(f"  Result: {len(unified)} unified findings\n")

print("="*60)
print(f"  TOTAL FINDINGS: {len(unified)}")
print("="*60)

if unified:
    print("\n  Sample findings:")
    for f in unified[:3]:
        print(f"  [{f['tool'].upper()}] {f['raw_severity']} ({f['normalized_severity']}/10) — {f['message'][:80]}")

print("\n  All scanners working correctly if no errors above.\n")