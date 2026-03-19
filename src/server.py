"""Flask web server for LAN-hosted policy gap analysis.

Exposes a web UI so any device on the LAN can upload a policy document
and receive professional analysis reports. All LLM work is serialized
through the rate_limiter.JobQueue.
"""

import os
import sys
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
        # Allow same-origin iframes on /view/ (in-browser PDF viewer).
        # All other routes keep the stricter DENY.
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

    def _wrapped_analyze(policy_path, output_dir, progress_callback=None):
        """Adapter bridging the job queue to the existing analyze_policy()."""
        return _analyze_policy(
            policy_path,
            output_dir=output_dir,
            progress_callback=progress_callback,
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

        # Save uploaded file
        safe_name = secure_filename(file.filename)
        if not safe_name:
            safe_name = f"policy_{datetime.now().strftime('%Y%m%d_%H%M%S')}{ext}"

        upload_path = UPLOAD_DIR / safe_name
        # Avoid overwrites
        counter = 1
        while upload_path.exists():
            stem = Path(safe_name).stem
            upload_path = UPLOAD_DIR / f"{stem}_{counter}{ext}"
            counter += 1

        file.save(str(upload_path))

        # Submit to job queue
        client_ip = request.remote_addr or '0.0.0.0'
        try:
            job_id, position = queue.submit(
                ip=client_ip,
                policy_path=str(upload_path),
                policy_filename=file.filename,
                output_dir=str(OUTPUT_DIR),
            )
        except ValueError as exc:
            flash(str(exc), 'error')
            # Clean up uploaded file
            upload_path.unlink(missing_ok=True)
            return redirect(url_for('index'))

        return redirect(url_for('status', job_id=job_id))

    @app.route('/status/<job_id>')
    def status(job_id):
        """Job status page — auto-refreshes while queued/running."""
        info = queue.get_status(job_id)
        if info is None:
            abort(404)

        # Collect download files if done
        output_files = []
        if info['status'] == 'done':
            result = queue.get_result(job_id)
            if result and 'output_base' in result:
                base = result['output_base']
                suffixes = [
                    '_gap_analysis.txt', '_gap_analysis.pdf',
                    '_revised_policy.txt', '_revised_policy.pdf',
                    '_roadmap.txt', '_roadmap.pdf',
                    '_executive_summary.txt', '_executive_summary.pdf',
                    '_comprehensive_report.txt', '_comprehensive_report.pdf',
                ]
                for suffix in suffixes:
                    fpath = Path(f"{base}{suffix}")
                    if fpath.exists():
                        output_files.append({
                            'name': fpath.name,
                            'path': fpath.name,
                            'size': f"{fpath.stat().st_size / 1024:.1f} KB",
                            'is_pdf': fpath.suffix == '.pdf',
                        })

        return render_template(
            'status.html',
            job=info,
            output_files=output_files,
        )

    @app.route('/download/<filename>')
    def download(filename):
        """Download a generated report file."""
        safe = secure_filename(filename)
        if not safe:
            abort(400)
        fpath = (OUTPUT_DIR / safe).resolve()
        # Path traversal protection: ensure resolved path is under OUTPUT_DIR
        if not str(fpath).startswith(str(OUTPUT_DIR.resolve())):
            abort(403)
        if not fpath.exists():
            abort(404)
        return send_from_directory(str(OUTPUT_DIR), safe, as_attachment=True)

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
            result = queue.get_result(job_id)
            if result and 'output_base' in result:
                base = result['output_base']
                suffixes = [
                    '_gap_analysis.txt', '_gap_analysis.pdf',
                    '_revised_policy.txt', '_revised_policy.pdf',
                    '_roadmap.txt', '_roadmap.pdf',
                    '_executive_summary.txt', '_executive_summary.pdf',
                    '_comprehensive_report.txt', '_comprehensive_report.pdf',
                ]
                for suffix in suffixes:
                    fpath = Path(f"{base}{suffix}")
                    if fpath.exists():
                        output_files.append({
                            'name': fpath.name,
                            'path': fpath.name,
                            'size': f"{fpath.stat().st_size / 1024:.1f} KB",
                            'is_pdf': fpath.suffix == '.pdf',
                        })

        return jsonify({**info, 'output_files': output_files})

    @app.route('/view/<filename>')
    def view_file_route(filename):
        """Serve a generated report file inline (for in-browser PDF viewing)."""
        safe = secure_filename(filename)
        if not safe:
            abort(400)
        fpath = (OUTPUT_DIR / safe).resolve()
        if not str(fpath).startswith(str(OUTPUT_DIR.resolve())):
            abort(403)
        if not fpath.exists():
            abort(404)
        # as_attachment=False → browser will render PDF inline
        return send_from_directory(str(OUTPUT_DIR), safe, as_attachment=False)

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
    app.run(host=host, port=port, debug=debug, threaded=True)


if __name__ == '__main__':
    run_server()
