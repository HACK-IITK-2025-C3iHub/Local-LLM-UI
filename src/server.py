"""Flask web server for LAN-hosted policy gap analysis.

Exposes a web UI so any device on the LAN can upload a policy document
and receive professional analysis reports. All LLM work is serialized
through the rate_limiter.JobQueue.
"""

import os
import sys
import uuid
import secrets
from pathlib import Path
from datetime import datetime

from flask import (
    Flask, request, render_template, redirect,
    url_for, jsonify, send_from_directory, flash, abort,
)
from werkzeug.utils import secure_filename

# Add src directory to path for sibling imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rate_limiter import JobQueue

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ALLOWED_EXTENSIONS = {'.txt', '.pdf', '.docx'}
MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50 MB (matches utils.MAX_FILE_SIZE)

BASE_DIR = Path(__file__).resolve().parent.parent          # project root
UPLOAD_DIR = BASE_DIR / 'uploads'
OUTPUT_DIR = BASE_DIR / 'output'
TEMPLATE_DIR = Path(__file__).resolve().parent / 'templates'

# Maps filename suffix -> human-readable document type label
_DOC_TYPE_MAP = {
    '_gap_analysis':        'Gap Analysis',
    '_revised_policy':      'Revised Policy',
    '_roadmap':             'Improvement Roadmap',
    '_executive_summary':   'Executive Summary',
    '_comprehensive_report':'Comprehensive Report',
}

_SUFFIXES = [
    ('_gap_analysis.txt',         'Gap Analysis'),
    ('_gap_analysis.pdf',         'Gap Analysis'),
    ('_revised_policy.txt',       'Revised Policy'),
    ('_revised_policy.pdf',       'Revised Policy'),
    ('_roadmap.txt',              'Improvement Roadmap'),
    ('_roadmap.pdf',              'Improvement Roadmap'),
    ('_executive_summary.txt',    'Executive Summary'),
    ('_executive_summary.pdf',    'Executive Summary'),
    ('_comprehensive_report.txt', 'Comprehensive Report'),
    ('_comprehensive_report.pdf', 'Comprehensive Report'),
]


def _collect_output_files(result):
    """Return list of file dicts for a completed job result."""
    files = []
    if not result or 'output_base' not in result:
        return files
    base = Path(result['output_base'])
    for suffix, doc_type in _SUFFIXES:
        fpath = Path(f"{result['output_base']}{suffix}")
        if fpath.exists():
            rel_path = fpath.relative_to(OUTPUT_DIR)
            files.append({
                'name':     fpath.name,
                'path':     str(rel_path).replace('\\', '/'),
                'size':     f"{fpath.stat().st_size / 1024:.1f} KB",
                'is_pdf':   fpath.suffix == '.pdf',
                'doc_type': doc_type,
            })
    return files


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def create_app():
    """Create and configure the Flask application."""

    app = Flask(
        __name__,
        template_folder=str(TEMPLATE_DIR),
        static_folder=str(TEMPLATE_DIR / 'static'),
        static_url_path='/static',
    )

    app.config['MAX_CONTENT_LENGTH'] = MAX_UPLOAD_SIZE
    app.secret_key = secrets.token_hex(32)

    # Security headers
    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        if request.path.startswith('/view/'):
            response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        else:
            response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        return response

    # Ensure directories exist
    UPLOAD_DIR.mkdir(exist_ok=True)
    OUTPUT_DIR.mkdir(exist_ok=True)

    # Initialize the job queue and wire up the analysis function
    queue = JobQueue()

    # Lazy import to avoid circular dependency
    from main import analyze_policy as _analyze_policy

    def _wrapped_analyze(policy_path, output_dir, job_id=None, progress_callback=None, log_callback=None):
        """Adapter bridging the job queue to the existing analyze_policy()."""
        return _analyze_policy(
            policy_path,
            output_dir=output_dir,
            job_id=job_id,
            progress_callback=progress_callback,
            log_callback=log_callback,
        )

    queue.set_analyze_function(_wrapped_analyze)

    # -------------------------------------------------------------------
    # Routes
    # -------------------------------------------------------------------

    @app.route('/')
    def index():
        """Upload form."""
        queue_info = queue.get_queue_info()
        return render_template('index.html', queue_info=queue_info)

    @app.route('/history')
    def history():
        """Show global history of all analysis jobs (all devices)."""
        all_jobs = queue.get_all_jobs()
        return render_template('history.html', jobs=all_jobs)

    @app.route('/upload', methods=['POST'])
    def upload():
        """Accept a policy file and enqueue an analysis job."""
        if 'policy_file' not in request.files:
            flash('No file selected.', 'error')
            return redirect(url_for('index'))

        file = request.files['policy_file']
        if file.filename == '':
            flash('No file selected.', 'error')
            return redirect(url_for('index'))

        # Validate extension
        ext = Path(file.filename).suffix.lower()
        if ext not in ALLOWED_EXTENSIONS:
            flash(
                f'Unsupported file type: {ext}. '
                f'Allowed: {", ".join(ALLOWED_EXTENSIONS)}',
                'error',
            )
            return redirect(url_for('index'))

        # Save uploaded file in a job-specific directory
        job_id = uuid.uuid4().hex[:12]
        job_upload_dir = UPLOAD_DIR / job_id
        job_upload_dir.mkdir(exist_ok=True)
        
        safe_name = secure_filename(file.filename)
        if not safe_name:
            safe_name = f"policy_{datetime.now().strftime('%Y%m%d_%H%M%S')}{ext}"

        upload_path = job_upload_dir / safe_name
        counter = 1
        while upload_path.exists():
            stem = Path(safe_name).stem
            upload_path = job_upload_dir / f"{stem}_{counter}{ext}"
            counter += 1

        file.save(str(upload_path))

        # Create job-specific output directory
        job_output_dir = OUTPUT_DIR / job_id
        job_output_dir.mkdir(exist_ok=True)

        # Submit to job queue
        client_ip = request.remote_addr or '0.0.0.0'
        try:
            job_id, position = queue.submit(
                job_id=job_id,
                ip=client_ip,
                policy_path=str(upload_path),
                policy_filename=file.filename,
                output_dir=str(job_output_dir),
            )
        except ValueError as exc:
            flash(str(exc), 'error')
            upload_path.unlink(missing_ok=True)
            return redirect(url_for('index'))

        return redirect(url_for('status', job_id=job_id))

    @app.route('/status/<job_id>')
    def status(job_id):
        """Job status page."""
        info = queue.get_status(job_id)
        if info is None:
            abort(404)

        output_files = []
        if info['status'] == 'done':
            output_files = _collect_output_files(queue.get_result(job_id))

        return render_template(
            'status.html',
            job=info,
            output_files=output_files,
        )

    @app.route('/download/<path:filename>')
    def download(filename):
        """Download a generated report file."""
        from urllib.parse import unquote
        # Decode URL encoding and normalize path separators for Windows
        filename = unquote(filename).replace('/', os.sep)
        safe = secure_filename(Path(filename).name)
        if not safe:
            abort(400)
        fpath = (OUTPUT_DIR / filename).resolve()
        if not str(fpath).startswith(str(OUTPUT_DIR.resolve())):
            abort(403)
        if not fpath.exists():
            abort(404)
        
        # Determine correct MIME type
        mime_type = 'application/pdf' if fpath.suffix == '.pdf' else 'text/plain'
        
        response = send_from_directory(str(fpath.parent), safe, as_attachment=True)
        response.headers['Content-Type'] = mime_type
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Content-Disposition'] = f'attachment; filename="{safe}"'
        return response

    @app.route('/queue')
    def queue_info():
        """JSON endpoint returning current queue state."""
        return jsonify(queue.get_queue_info())

    @app.route('/api/status/<job_id>')
    def api_status(job_id):
        """JSON endpoint for AJAX polling of job status (no page reload)."""
        info = queue.get_status(job_id)
        if info is None:
            abort(404)

        output_files = []
        if info['status'] == 'done':
            output_files = _collect_output_files(queue.get_result(job_id))

        return jsonify({**info, 'output_files': output_files})

    @app.route('/view/<path:filename>')
    def view_file_route(filename):
        """Serve a generated report file inline (for in-browser PDF viewing)."""
        from urllib.parse import unquote
        # Decode URL encoding and normalize path separators for Windows
        filename = unquote(filename).replace('/', os.sep)
        safe = secure_filename(Path(filename).name)
        if not safe:
            abort(400)
        fpath = (OUTPUT_DIR / filename).resolve()
        if not str(fpath).startswith(str(OUTPUT_DIR.resolve())):
            abort(403)
        if not fpath.exists():
            abort(404)
        
        response = send_from_directory(str(fpath.parent), safe, as_attachment=False)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response

    return app


def run_server(host='0.0.0.0', port=5000, debug=False):
    """Start the Flask development server."""
    app = create_app()
    print(f"\n{'='*60}")
    print("LOCAL LLM POLICY GAP ANALYZER — WEB SERVER")
    print(f"{'='*60}")
    print(f"  Listening on  : http://{host}:{port}")
    print(f"  LAN access    : http://<your-ip>:{port}")
    print(f"  Upload dir    : {UPLOAD_DIR}")
    print(f"  Output dir    : {OUTPUT_DIR}")
    print(f"{'='*60}\n")
    
    try:
        app.run(host=host, port=port, debug=debug, threaded=True)
    finally:
        # Save history on shutdown
        from rate_limiter import JobQueue
        queue = JobQueue()
        queue.force_save_history()
        print("\nServer shutdown - job history saved.")


if __name__ == '__main__':
    run_server()
