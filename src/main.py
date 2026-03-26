"""Main script for Local LLM Policy Gap Analysis and Improvement Module."""

import os
import sys
import argparse
from datetime import datetime
from pathlib import Path

# Add src directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils import read_policy_document, save_output
from gap_analyzer import load_nist_framework, analyze_policy_gaps, extract_gaps_structured
from policy_reviser import revise_policy, generate_revision_summary
from roadmap_generator import generate_improvement_roadmap, generate_executive_summary
from pdf_generator import generate_all_pdfs


def analyze_policy(policy_path, output_dir='output', progress_callback=None, log_callback=None):
    """
    Main function to analyze policy document and generate comprehensive report.

    Args:
        policy_path: Path to policy document (TXT, PDF, or DOCX)
        output_dir: Directory to save output reports
        progress_callback: Optional callable(stage_number) for progress tracking
        log_callback: Optional callable(str) for detailed log streaming to the UI

    Returns:
        Dictionary containing all analysis results
    """
    def _progress(stage):
        if progress_callback:
            progress_callback(stage)

    def _log(msg):
        print(msg)
        if log_callback:
            log_callback(msg)

    _log(f"\n{'='*60}")
    _log("LOCAL LLM POLICY GAP ANALYSIS MODULE")
    _log(f"{'='*60}\n")

    # Load policy document
    _progress(1)
    _log(f"[1/6] Loading policy document: {policy_path}")
    policy_content = read_policy_document(policy_path)
    policy_name = Path(policy_path).stem
    _log(f"      Policy loaded: {len(policy_content)} characters\n")

    # Load NIST framework
    _progress(2)
    _log("[2/6] Loading NIST Cybersecurity Framework standards...")
    # Resolve data/reference relative to project root, not cwd
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    framework_path = os.path.join(project_root, 'data', 'reference')
    nist_framework = load_nist_framework(framework_path)
    _log(f"      Framework loaded: {len(nist_framework)} characters\n")

    # Analyze gaps
    _progress(3)
    _log("[3/6] Analyzing policy gaps (this may take 1-2 minutes)...")
    gap_analysis = analyze_policy_gaps(policy_content, nist_framework)
    _log(f"      Gap analysis complete: {len(gap_analysis)} characters\n")

    # Revise policy
    _progress(4)
    _log("[4/6] Generating revised policy (this may take 2-3 minutes)...")
    revised_policy = revise_policy(policy_content, gap_analysis, nist_framework)
    _log(f"      Revised policy generated: {len(revised_policy)} characters\n")

    # Generate roadmap
    _progress(5)
    _log("[5/6] Creating improvement roadmap (this may take 1-2 minutes)...")
    roadmap = generate_improvement_roadmap(gap_analysis, policy_name)
    _log(f"      Roadmap generated: {len(roadmap)} characters\n")

    # Generate executive summary
    _progress(6)
    _log("[6/6] Generating executive summary...")
    exec_summary = generate_executive_summary(gap_analysis, roadmap)
    _log(f"      Executive summary complete\n")

    # Save outputs
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_base = os.path.join(output_dir, f"{policy_name}_{timestamp}")

    _log(f"Saving reports to: {output_dir}/")
    save_output(gap_analysis, f"{output_base}_gap_analysis.txt")
    _log(f"  \u2713 Gap analysis saved")

    save_output(revised_policy, f"{output_base}_revised_policy.txt")
    _log(f"  \u2713 Revised policy saved")

    save_output(roadmap, f"{output_base}_roadmap.txt")
    _log(f"  \u2713 Improvement roadmap saved")

    save_output(exec_summary, f"{output_base}_executive_summary.txt")
    _log(f"  \u2713 Executive summary saved")

    # Generate comprehensive report
    comprehensive_report = f"""
{'='*80}
COMPREHENSIVE POLICY ANALYSIS REPORT
{'='*80}
Policy: {policy_name}
Analysis Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Framework: NIST Cybersecurity Framework (CIS MS-ISAC 2024)
{'='*80}

{exec_summary}

{'='*80}
DETAILED GAP ANALYSIS
{'='*80}

{gap_analysis}

{'='*80}
REVISED POLICY DOCUMENT
{'='*80}

{revised_policy}

{'='*80}
IMPLEMENTATION ROADMAP
{'='*80}

{roadmap}

{'='*80}
END OF REPORT
{'='*80}
"""

    save_output(comprehensive_report, f"{output_base}_comprehensive_report.txt")
    _log(f"  \u2713 Comprehensive report saved\n")

    # Generate PDF versions
    _log("Generating PDF reports with formatted output...")
    results_dict = {
        'policy_name': policy_name,
        'gap_analysis': gap_analysis,
        'revised_policy': revised_policy,
        'roadmap': roadmap,
        'executive_summary': exec_summary
    }

    try:
        pdf_files = generate_all_pdfs(results_dict, output_base)
        for pdf_file in pdf_files:
            _log(f"  \u2713 PDF saved: {Path(pdf_file).name}")
    except Exception as e:
        _log(f"  \u26a0 PDF generation failed: {e}")
        _log(f"  Note: Text reports are still available")

    _log(f"\n{'='*60}")
    _log("ANALYSIS COMPLETE")
    _log(f"{'='*60}\n")

    return {
        'policy_name': policy_name,
        'gap_analysis': gap_analysis,
        'revised_policy': revised_policy,
        'roadmap': roadmap,
        'executive_summary': exec_summary,
        'output_base': output_base
    }


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description='Local LLM Policy Gap Analysis and Improvement Module',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --policy data/test_policies/isms_policy.txt
  python main.py --policy data/test_policies/data_privacy_policy.txt --output results
  python main.py --batch data/test_policies/

Note: Requires Ollama with gemma3:4b model installed.
      System operates completely offline after initial setup.
        """
    )

    parser.add_argument(
        '--policy',
        type=str,
        help='Path to policy document (TXT, PDF, or DOCX)'
    )

    parser.add_argument(
        '--batch',
        type=str,
        help='Directory containing multiple policies to analyze'
    )

    parser.add_argument(
        '--output',
        type=str,
        default='output',
        help='Output directory for reports (default: output)'
    )

    parser.add_argument(
        '--serve',
        action='store_true',
        help='Start LAN web server for multi-device access'
    )

    parser.add_argument(
        '--port',
        type=int,
        default=5000,
        help='Port for web server (default: 5000)'
    )

    args = parser.parse_args()

    if args.serve:
        # Start the Flask web server
        from server import run_server
        run_server(host='0.0.0.0', port=args.port)
        return

    if not args.policy and not args.batch:
        parser.print_help()
        sys.exit(1)

    try:
        if args.batch:
            # Batch processing
            policy_dir = Path(args.batch)
            policies = list(policy_dir.glob('*.txt')) + list(policy_dir.glob('*.pdf')) + list(policy_dir.glob('*.docx'))

            print(f"\nFound {len(policies)} policies to analyze\n")

            for policy_path in policies:
                analyze_policy(str(policy_path), args.output)
                print("\n")
        else:
            # Single policy analysis
            analyze_policy(args.policy, args.output)

    except Exception as e:
        print(f"\nERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
