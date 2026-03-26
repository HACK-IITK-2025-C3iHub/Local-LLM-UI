"""Thread-safe job queue and rate limiter for LLM requests.

Serializes access to the Ollama LLM so only one analysis runs at a time.
Provides per-IP rate limiting to prevent queue flooding from a single client.
"""

import threading
import uuid
import time
from collections import OrderedDict
from datetime import datetime


# Configuration
MAX_QUEUE_SIZE = 10          # Global max queued jobs
MAX_JOBS_PER_IP = 2          # Max concurrent queued jobs per IP
JOB_RESULT_TTL = 3600        # Keep completed job results for 1 hour


class Job:
    """Represents a single analysis job."""

    __slots__ = (
        'id', 'ip', 'policy_path', 'policy_filename', 'output_dir',
        'status', 'progress_stage', 'progress_total', 'result',
        'error_msg', 'submitted_at', 'started_at', 'completed_at',
        'logs',
    )

    def __init__(self, job_id, ip, policy_path, policy_filename, output_dir):
        self.id = job_id
        self.ip = ip
        self.policy_path = policy_path
        self.policy_filename = policy_filename
        self.output_dir = output_dir
        self.status = 'queued'          # queued | running | done | error
        self.progress_stage = 0
        self.progress_total = 6
        self.result = None              # dict from analyze_policy()
        self.error_msg = None
        self.submitted_at = datetime.now()
        self.started_at = None
        self.completed_at = None
        self.logs = []

    def to_dict(self):
        """Serialize job state to a dictionary."""
        return {
            'id': self.id,
            'ip': self.ip,
            'policy_filename': self.policy_filename,
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

    def submit(self, ip, policy_path, policy_filename, output_dir='output'):
        """Submit a new analysis job.

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

            job_id = uuid.uuid4().hex[:12]
            job = Job(job_id, ip, policy_path, policy_filename, output_dir)
            self._jobs[job_id] = job
            self._queue.append(job_id)
            position = len(self._queue)

        # Wake the worker
        self._event.set()
        return job_id, position

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
        """Get all jobs for a specific IP, sorted newest first."""
        with self._queue_lock:
            jids = [jid for jid, j in self._jobs.items() if j.ip == ip]

        user_jobs = []
        for jid in jids:
            info = self.get_status(jid)
            if info:
                user_jobs.append(info)

        user_jobs.sort(key=lambda x: x['submitted_at'], reverse=True)
        return user_jobs

    def get_all_jobs(self):
        """Get all jobs across every IP, sorted newest first."""
        with self._queue_lock:
            jids = list(self._jobs.keys())

        all_jobs = []
        for jid in jids:
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
                progress_callback=progress_callback,
                log_callback=log_callback,
            )
            job.result = result
            job.status = 'done'
        except Exception as e:
            job.status = 'error'
            job.error_msg = str(e)
        finally:
            job.completed_at = datetime.now()

    def _cleanup_loop(self):
        """Periodically remove old completed/errored jobs."""
        while self._running:
            time.sleep(300)  # every 5 minutes
            now = time.time()
            with self._queue_lock:
                to_remove = [
                    jid for jid, j in self._jobs.items()
                    if j.status in ('done', 'error')
                    and j.completed_at
                    and (now - j.completed_at.timestamp()) > JOB_RESULT_TTL
                ]
                for jid in to_remove:
                    del self._jobs[jid]
