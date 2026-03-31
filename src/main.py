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
from docx_generator import generate_all_docx


def analyze_policy(policy_path, output_dir='output', job_id=None, progress_callback=None, log_callback=None, framework='nist'):
    """
    Main function to analyze policy document and generate comprehensive report.

    Args:
        policy_path: Path to policy document (TXT, PDF, or DOCX)
        output_dir: Directory to save output reports
        job_id: Optional job ID for naming output files
        progress_callback: Optional callable(stage_number) for progress tracking
        log_callback: Optional callable(str) for detailed log streaming to the UI
        framework: Security framework to analyze against (nist, iso27001, cis, pci)

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
    _log(f"[1/7] Loading policy document: {policy_path}")
    policy_content = read_policy_document(policy_path)
    policy_name = Path(policy_path).stem
    _log(f"      Policy loaded: {len(policy_content)} characters\n")

    # Load framework standards
    _progress(2)
    _log(f"[2/7] Loading {framework.upper()} framework standards...")
    # Resolve data/reference relative to project root, not cwd
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    framework_path = os.path.join(project_root, 'data', 'reference', framework)
    nist_framework = load_nist_framework(framework_path)
    _log(f"      Framework loaded: {len(nist_framework)} characters\n")

    # Analyze gaps
    _progress(3)
    _log(f"[3/7] Analyzing policy gaps (this may take 1-2 minutes)...")
    gap_analysis = analyze_policy_gaps(policy_content, nist_framework, framework)
    _log(f"      Gap analysis complete: {len(gap_analysis)} characters\n")

    # Analyze vulnerabilities
    _progress(4)
    _log("[4/7] Analyzing security vulnerabilities (this may take 1-2 minutes)...")
    from vulnerability_analyzer import analyze_policy_vulnerabilities
    vulnerability_analysis = analyze_policy_vulnerabilities(policy_content, policy_name)
    _log(f"      Vulnerability analysis complete: {len(vulnerability_analysis)} characters\n")

    # Revise policy
    _progress(5)
    _log("[5/7] Generating revised policy (this may take 2-3 minutes)...")
    revised_policy = revise_policy(policy_content, gap_analysis, nist_framework)
    _log(f"      Revised policy generated: {len(revised_policy)} characters\n")

    # Generate roadmap
    _progress(6)
    _log("[6/7] Creating improvement roadmap (this may take 1-2 minutes)...")
    roadmap = generate_improvement_roadmap(gap_analysis, policy_name)
    _log(f"      Roadmap generated: {len(roadmap)} characters\n")

    # Generate executive summary
    _progress(7)
    _log("[7/7] Generating executive summary...")
    exec_summary = generate_executive_summary(gap_analysis, roadmap)
    _log(f"      Executive summary complete\n")

    # Save outputs
    if job_id:
        output_base = os.path.join(output_dir, job_id)
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        policy_name = Path(policy_path).stem
        output_base = os.path.join(output_dir, f"{policy_name}_{timestamp}")

    _log(f"Saving reports to: {output_dir}/")
    
    # Generate DOCX versions
    _log("Generating DOCX reports with formatted output...")
    results_dict = {
        'policy_name': policy_name,
        'gap_analysis': gap_analysis,
        'vulnerability_analysis': vulnerability_analysis,
        'revised_policy': revised_policy,
        'roadmap': roadmap,
        'executive_summary': exec_summary
    }
    
    docx_files = []
    try:
        docx_files = generate_all_docx(results_dict, output_base)
        for docx_file in docx_files:
            _log(f"  ✓ DOCX saved: {Path(docx_file).name}")
    except Exception as e:
        _log(f"  ⚠ DOCX generation failed: {e}")

    # Generate comprehensive report
    framework_names = {
        'nist': 'NIST Cybersecurity Framework (CIS MS-ISAC 2024)',
        'iso27001': 'ISO 27001:2022',
        'cis': 'CIS Controls v8',
        'pci': 'PCI DSS v4.0'
    }
    framework_display = framework_names.get(framework, 'NIST Cybersecurity Framework')
    
    comprehensive_report = f"""
{'='*80}
COMPREHENSIVE POLICY ANALYSIS REPORT
{'='*80}
Policy: {policy_name}
Analysis Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Framework: {framework_display}
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

    # Generate PDF versions
    _log("Generating PDF reports with formatted output...")
    
    pdf_files = []
    try:
        pdf_files = generate_all_pdfs(results_dict, output_base)
        for pdf_file in pdf_files:
            _log(f"  ✓ PDF saved: {Path(pdf_file).name}")
    except Exception as e:
        _log(f"  ⚠ PDF generation failed: {e}")
    
    # Create ZIP archive with all reports
    _log("Creating ZIP archive...")
    try:
        import zipfile
        zip_path = f"{output_base}_all_reports.zip"
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file_path in docx_files + pdf_files:
                if os.path.exists(file_path):
                    zipf.write(file_path, os.path.basename(file_path))
        _log(f"  ✓ ZIP archive created: {Path(zip_path).name}")
    except Exception as e:
        _log(f"  ⚠ ZIP creation failed: {e}")

    _log(f"\n{'='*60}")
    _log("ANALYSIS COMPLETE")
    _log(f"{'='*60}\n")

    return {
        'policy_name': policy_name,
        'gap_analysis': gap_analysis,
        'vulnerability_analysis': vulnerability_analysis,
        'revised_policy': revised_policy,
        'roadmap': roadmap,
        'executive_summary': exec_summary,
        'output_base': output_base,
        'framework': framework
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
