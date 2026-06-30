import multiprocessing
import os

port = os.environ.get("PORT", "5000")
bind = f"0.0.0.0:{port}"

# Workers: Recommended to be (2 x $num_cores) + 1
# Use sync worker (gthread) for SQLite compatibility — avoids write conflicts
worker_class = "gthread"
workers = int(os.environ.get("GUNICORN_WORKERS", min(multiprocessing.cpu_count() * 2 + 1, 4)))
threads = int(os.environ.get("GUNICORN_THREADS", 4))

# Logging
accesslog = "-"
errorlog  = "-"
loglevel  = "warning"   # Use 'info' for debugging

# Timeouts
timeout        = 120
keepalive      = 5
graceful_timeout = 30

# Protect from memory leaks
max_requests        = 1000
max_requests_jitter = 100

# Worker lifecycle
preload_app = True   # Load app before forking — speeds up worker restarts

# Forwarded headers (used with ProxyFix in Flask)
forwarded_allow_ips = "*"

# ---- Rate Limiting Note ----
# The per-IP dicts (_failed_logins, _ck_ratelimit) inside legacy_admin.py are
# in-memory only.  Each worker process has its own copy, so the effective
# limit per IP is workers × configured_limit.
# • For low-traffic / single-worker: this is fine.
# • For multi-worker production with strict limits: set GUNICORN_WORKERS=1,
#   or migrate those dicts to a shared Redis store.
