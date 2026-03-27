"""Thread-safe job queue and rate limiter for LLM requests.

Serializes access to the Ollama LLM so only one analysis runs at a time.
Provides per-IP rate limiting to prevent queue flooding from a single client.
"""

import threading
import uuid
import time
import json
import os
from collections import OrderedDict
from datetime import datetime
from pathlib import Path


# Configuration
MAX_QUEUE_SIZE = 10          # Global max queued jobs
MAX_JOBS_PER_IP = 2          # Max concurrent queued jobs per IP
JOB_RESULT_TTL = 3600        # Keep completed job results for 1 hour

# Persistent storage path
BASE_DIR = Path(__file__).resolve().parent.parent
HISTORY_FILE = BASE_DIR / 'data' / 'job_history.json'


class Job:
    """Represents a single analysis job."""

    __slots__ = (
        'id', 'ip', 'policy_path', 'policy_filename', 'output_dir',
        'status', 'progress_stage', 'progress_total', 'result',
        'error_msg', 'submitted_at', 'started_at', 'completed_at',
        'logs', 'framework',
    )

    def __init__(self, job_id, ip, policy_path, policy_filename, output_dir, framework='nist'):
        self.id = job_id
        self.ip = ip
        self.policy_path = policy_path
        self.policy_filename = policy_filename
        self.output_dir = output_dir
        self.framework = framework
        self.status = 'queued'          # queued | running | done | error
        self.progress_stage = 0
        self.progress_total = 6
        self.result = None              # dict from analyze_policy()
        self.error_msg = None
        self.submitted_at = datetime.now()
        self.started_at = None
        self.completed_at = None
        self.logs = []

    @classmethod
    def from_dict(cls, data):
        """Restore a Job from a dictionary."""
        job = cls.__new__(cls)
        job.id = data['id']
        job.ip = data['ip']
        job.policy_path = data.get('policy_path', '')
        job.policy_filename = data['policy_filename']
        job.output_dir = data.get('output_dir', '')
        job.framework = data.get('framework', 'nist')
        job.status = data['status']
        job.progress_stage = data.get('progress_stage', 0)
        job.progress_total = data.get('progress_total', 6)
        job.result = data.get('result')
        job.error_msg = data.get('error_msg')
        job.submitted_at = datetime.fromisoformat(data['submitted_at']) if data.get('submitted_at') else None
        job.started_at = datetime.fromisoformat(data['started_at']) if data.get('started_at') else None
        job.completed_at = datetime.fromisoformat(data['completed_at']) if data.get('completed_at') else None
        job.logs = data.get('logs', [])
        return job

    def to_dict(self, include_full_result=False):
        """Serialize job state to a dictionary.
        
        Args:
            include_full_result: If True, include the full result dict (for persistence).
                                If False, only include has_result flag (for API responses).
        """
        data = {
            'id': self.id,
            'ip': self.ip,
            'policy_path': self.policy_path,
            'policy_filename': self.policy_filename,
            'output_dir': self.output_dir,
            'framework': self.framework,
            'status': self.status,
            'progress_stage': self.progress_stage,
            'progress_total': self.progress_total,
            'error_msg': self.error_msg,
            'submitted_at': self.submitted_at.isoformat() if self.submitted_at else None,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'has_result': self.result is not None,
            'logs': self.logs,
        }
        if include_full_result and self.result:
            data['result'] = self.result
        return data


class JobQueue:
    """Thread-safe singleton job queue with per-IP rate limiting.

    Only one job runs through the LLM at a time (via a Semaphore(1)).
    Jobs are processed in FIFO order by a background worker thread.
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True

        self._jobs = OrderedDict()          # job_id -> Job
        self._queue = []                    # list of job_ids awaiting processing
        self._queue_lock = threading.Lock()
        self._semaphore = threading.Semaphore(1)   # only 1 LLM call at a time
        self._event = threading.Event()            # signal new work
        self._analyze_fn = None                    # set via set_analyze_function()
        self._running = True

        # Load persisted job history
        self._load_history()

        # Start the background worker
        self._worker = threading.Thread(target=self._process_loop, daemon=True)
        self._worker.start()

        # Start the cleanup thread
        self._cleaner = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleaner.start()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_analyze_function(self, fn):
        """Register the analysis function (avoids circular imports).

        fn signature: fn(policy_path, output_dir, progress_callback, log_callback) -> dict
        """
        self._analyze_fn = fn

    def submit(self, job_id=None, ip=None, policy_path=None, policy_filename=None, output_dir='output', framework='nist'):
        """Submit a new analysis job.

        Args:
            job_id: Optional pre-generated job ID. If not provided, one will be generated.
            ip: Client IP address
            policy_path: Path to the policy file
            policy_filename: Original filename of the policy
            output_dir: Directory for output files
            framework: Security framework to analyze against (nist, iso27001, cis, pci)

        Returns:
            (job_id, queue_position) on success.

        Raises:
            ValueError if rate limit exceeded or queue full.
        """
        with self._queue_lock:
            # Per-IP rate limit
            active_for_ip = sum(
                1 for j in self._jobs.values()
                if j.ip == ip and j.status in ('queued', 'running')
            )
            if active_for_ip >= MAX_JOBS_PER_IP:
                raise ValueError(
                    f"Rate limit exceeded: you already have {active_for_ip} "
                    f"active job(s). Maximum is {MAX_JOBS_PER_IP} per device."
                )

            # Global queue limit
            queued_count = sum(1 for j in self._jobs.values() if j.status == 'queued')
            if queued_count >= MAX_QUEUE_SIZE:
                raise ValueError(
                    f"Server is busy: {queued_count} jobs already queued. "
                    f"Please try again later."
                )

            if job_id is None:
                job_id = uuid.uuid4().hex[:12]
            job = Job(job_id, ip, policy_path, policy_filename, output_dir, framework)
            self._jobs[job_id] = job
            self._queue.append(job_id)
            position = len(self._queue)

        # Wake the worker
        self._event.set()
        return job_id, position

    def force_save_history(self):
        """Manually trigger history save (useful for shutdown/testing)."""
        self._save_history()

    def get_status(self, job_id):
        """Get job status dict, or None if not found."""
        job = self._jobs.get(job_id)
        if job is None:
            return None
        info = job.to_dict()
        # Include queue position if still queued
        with self._queue_lock:
            if job_id in self._queue:
                info['queue_position'] = self._queue.index(job_id) + 1
            else:
                info['queue_position'] = 0
        return info

    def get_result(self, job_id):
        """Get the full result dict for a completed job, or None."""
        job = self._jobs.get(job_id)
        if job and job.status == 'done':
            return job.result
        return None

    def get_queue_info(self):
        """Return summary of queue state."""
        with self._queue_lock:
            queued = sum(1 for j in self._jobs.values() if j.status == 'queued')
            running = sum(1 for j in self._jobs.values() if j.status == 'running')
            done = sum(1 for j in self._jobs.values() if j.status == 'done')
            errored = sum(1 for j in self._jobs.values() if j.status == 'error')
        return {
            'queued': queued,
            'running': running,
            'done': done,
            'errored': errored,
            'max_queue_size': MAX_QUEUE_SIZE,
            'max_per_ip': MAX_JOBS_PER_IP,
        }

    def get_jobs_for_ip(self, ip):
        """Get all jobs for a specific IP, sorted newest first.
        Only returns jobs whose output files still exist.
        """
        with self._queue_lock:
            jids = [jid for jid, j in self._jobs.items() if j.ip == ip]

        user_jobs = []
        for jid in jids:
            job = self._jobs.get(jid)
            if not job:
                continue
            
            # For completed jobs, verify output files exist
            if job.status == 'done' and job.result and 'output_base' in job.result:
                output_base = Path(job.result['output_base'])
                # Check if at least one output file exists
                has_files = False
                for suffix in ['_gap_analysis.txt', '_gap_analysis.pdf', 
                              '_revised_policy.txt', '_revised_policy.pdf',
                              '_roadmap.txt', '_roadmap.pdf',
                              '_executive_summary.txt', '_executive_summary.pdf',
                              '_comprehensive_report.txt', '_comprehensive_report.pdf']:
                    if Path(f"{output_base}{suffix}").exists():
                        has_files = True
                        break
                
                # Skip this job if no output files exist
                if not has_files:
                    continue
            
            info = self.get_status(jid)
            if info:
                user_jobs.append(info)

        user_jobs.sort(key=lambda x: x['submitted_at'], reverse=True)
        return user_jobs

    def get_all_jobs(self):
        """Get all jobs across every IP, sorted newest first.
        Only returns jobs whose output files still exist.
        """
        with self._queue_lock:
            jids = list(self._jobs.keys())

        all_jobs = []
        for jid in jids:
            job = self._jobs.get(jid)
            if not job:
                continue
            
            # For completed jobs, verify output files exist
            if job.status == 'done' and job.result and 'output_base' in job.result:
                output_base = Path(job.result['output_base'])
                # Check if at least one output file exists
                has_files = False
                for suffix in ['_gap_analysis.txt', '_gap_analysis.pdf', 
                              '_revised_policy.txt', '_revised_policy.pdf',
                              '_roadmap.txt', '_roadmap.pdf',
                              '_executive_summary.txt', '_executive_summary.pdf',
                              '_comprehensive_report.txt', '_comprehensive_report.pdf']:
                    if Path(f"{output_base}{suffix}").exists():
                        has_files = True
                        break
                
                # Skip this job if no output files exist
                if not has_files:
                    continue
            
            info = self.get_status(jid)
            if info:
                all_jobs.append(info)

        all_jobs.sort(key=lambda x: x['submitted_at'], reverse=True)
        return all_jobs

    # ------------------------------------------------------------------
    # Background workers
    # ------------------------------------------------------------------

    def _process_loop(self):
        """Background thread: process jobs one at a time."""
        while self._running:
            self._event.wait(timeout=2.0)
            self._event.clear()

            while True:
                job_id = None
                with self._queue_lock:
                    if self._queue:
                        job_id = self._queue.pop(0)

                if job_id is None:
                    break  # nothing to do

                job = self._jobs.get(job_id)
                if job is None:
                    continue

                # Acquire semaphore (serialize LLM access)
                self._semaphore.acquire()
                try:
                    self._run_job(job)
                finally:
                    self._semaphore.release()

    def _run_job(self, job):
        """Execute a single analysis job."""
        job.status = 'running'
        job.started_at = datetime.now()

        def progress_callback(stage):
            job.progress_stage = stage

        def log_callback(msg):
            job.logs.append(msg)

        try:
            if self._analyze_fn is None:
                raise RuntimeError("Analysis function not registered")

            result = self._analyze_fn(
                job.policy_path,
                job.output_dir,
                job_id=job.id,
                progress_callback=progress_callback,
                log_callback=log_callback,
                framework=job.framework,
            )
            job.result = result
            job.status = 'done'
        except Exception as e:
            job.status = 'error'
            job.error_msg = str(e)
        finally:
            job.completed_at = datetime.now()
            # Save history after each job completion
            self._save_history()

    def _cleanup_loop(self):
        """Periodically remove old completed/errored jobs and save history."""
        while self._running:
            time.sleep(300)  # every 5 minutes
            now = time.time()
            with self._queue_lock:
                to_remove = []
                
                for jid, j in self._jobs.items():
                    # Remove jobs older than TTL
                    if (j.status in ('done', 'error') and j.completed_at and 
                        (now - j.completed_at.timestamp()) > JOB_RESULT_TTL):
                        to_remove.append(jid)
                        continue
                    
                    # Remove completed jobs whose output files no longer exist
                    if j.status == 'done' and j.result and 'output_base' in j.result:
                        output_base = Path(j.result['output_base'])
                        has_files = False
                        for suffix in ['_gap_analysis.txt', '_gap_analysis.pdf', 
                                      '_revised_policy.txt', '_revised_policy.pdf',
                                      '_roadmap.txt', '_roadmap.pdf',
                                      '_executive_summary.txt', '_executive_summary.pdf',
                                      '_comprehensive_report.txt', '_comprehensive_report.pdf']:
                            if Path(f"{output_base}{suffix}").exists():
                                has_files = True
                                break
                        
                        if not has_files:
                            to_remove.append(jid)
                            print(f"Removing job {jid} - output files deleted")
                
                for jid in to_remove:
                    del self._jobs[jid]
            
            # Persist history every cleanup cycle
            self._save_history()

    def _load_history(self):
        """Load job history from persistent storage."""
        if not HISTORY_FILE.exists():
            print(f"No history file found at {HISTORY_FILE}")
            return
        
        try:
            with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            loaded_count = 0
            skipped_count = 0
            with self._queue_lock:
                for job_data in data.get('jobs', []):
                    # Only load completed/errored jobs (not queued/running)
                    if job_data.get('status') in ('done', 'error'):
                        # Verify output files exist before loading
                        if job_data.get('status') == 'done' and job_data.get('result'):
                            output_base = job_data['result'].get('output_base')
                            if output_base:
                                output_base_path = Path(output_base)
                                has_files = False
                                for suffix in ['_gap_analysis.txt', '_gap_analysis.pdf', 
                                              '_revised_policy.txt', '_revised_policy.pdf',
                                              '_roadmap.txt', '_roadmap.pdf',
                                              '_executive_summary.txt', '_executive_summary.pdf',
                                              '_comprehensive_report.txt', '_comprehensive_report.pdf']:
                                    if Path(f"{output_base_path}{suffix}").exists():
                                        has_files = True
                                        break
                                
                                if not has_files:
                                    skipped_count += 1
                                    continue
                        
                        job = Job.from_dict(job_data)
                        self._jobs[job.id] = job
                        loaded_count += 1
            
            print(f"Loaded {loaded_count} jobs from history")
            if skipped_count > 0:
                print(f"Skipped {skipped_count} jobs with missing output files")
        except Exception as e:
            print(f"Warning: Failed to load job history: {e}")

    def _save_history(self):
        """Save job history to persistent storage."""
        try:
            # Ensure data directory exists
            HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
            
            with self._queue_lock:
                # Only save completed/errored jobs
                jobs_to_save = [
                    j.to_dict(include_full_result=True)
                    for j in self._jobs.values()
                    if j.status in ('done', 'error')
                ]
            
            data = {
                'version': '1.0',
                'last_updated': datetime.now().isoformat(),
                'jobs': jobs_to_save
            }
            
            # Write to temp file first, then rename (atomic operation)
            temp_file = HISTORY_FILE.with_suffix('.tmp')
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            temp_file.replace(HISTORY_FILE)
            print(f"Saved {len(jobs_to_save)} jobs to history")
        except Exception as e:
            print(f"Warning: Failed to save job history: {e}")
