# server.py / Admin_Server.py
import warnings
warnings.filterwarnings("ignore", category=SyntaxWarning, module=__name__)
from dotenv import load_dotenv
load_dotenv()
from flask import Flask, request, jsonify, session, redirect, url_for, render_template
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os, sqlite3, secrets, base64, datetime, math, threading, sys, re
import time as _time
import json as _json
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

# Real-time activity tracker: {app_name: {users: {username: last_seen_ts}, ...}}
_activity_lock = threading.Lock()
_bot_activity = {}  # {"FACEBOOK OTP SEND TOOLS": {"user1": 1708500000.0, ...}, "Legacy": {...}}

# ---------------- Config ----------------
import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

from flask import Blueprint, current_app
from . import limiter
legacy_bp = Blueprint('legacy', __name__)

@legacy_bp.after_app_request
def apply_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response



# SECRET_KEY: Strict enforcement from .env
_secret_key = os.environ.get("SECRET_KEY", "").strip()
if not _secret_key:
    print("[SECURITY] ERROR: SECRET_KEY not set in .env")
    sys.exit(1)
# app.secret_key = _secret_key

# NOTE: XOR-based _encrypt_pw/_decrypt_pw removed — insecure and deprecated.
# plain_password column is no longer read or written for security.

# Session timeout in minutes (default 60)
SESSION_LIFETIME = int(os.environ.get("SESSION_LIFETIME_MINUTES", "60"))
# app.permanent_session_lifetime = datetime.timedelta(minutes=SESSION_LIFETIME)

DB = os.environ.get("DB_PATH", "/data/users.db")

# Bootstrap SUPER_ADMIN credentials (used only to create the first SUPER_ADMIN in DB)
ADMIN_USER = os.environ.get("ADMIN_USER", "").strip()
ADMIN_PASS = os.environ.get("ADMIN_PASS", "").strip()
if not ADMIN_USER or not ADMIN_PASS:
    print("[SECURITY] ERROR: ADMIN_USER or ADMIN_PASS env var not set in .env."
          " You MUST set these for security. Aborting startup.")
    sys.exit(1)

# ---------------- DB init ----------------
def _add_column_if_missing(c: sqlite3.Cursor, table: str, column: str, col_type: str):
    c.execute(f"PRAGMA table_info({table})")
    cols = {r[1] for r in c.fetchall()}
    if column not in cols:
        c.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")


def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        activation_key TEXT,
        status TEXT,
        machine_id TEXT,
        expiry_date TEXT
    )''')

    # Admin accounts (SUPER_ADMIN or SUB_ADMIN)
    c.execute('''CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        max_users INTEGER,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL
    )''')

    # Which SUB_ADMIN can manage which users
    c.execute('''CREATE TABLE IF NOT EXISTS admin_user_access (
        admin_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        UNIQUE(admin_id, user_id)
    )''')

    # Migrations: keep ownership info even if sub-admin is deleted
    _add_column_if_missing(c, "users", "created_by_admin_id", "INTEGER")
    _add_column_if_missing(c, "users", "created_by_username", "TEXT")
    _add_column_if_missing(c, "users", "created_by_role", "TEXT")
    _add_column_if_missing(c, "users", "note", "TEXT")

    # Sub-admin max expiry days (0 = unlimited)
    _add_column_if_missing(c, "admins", "max_expiry_days", "INTEGER DEFAULT 0")
    # Sub-admin per-action permissions (JSON list, NULL = all allowed)
    _add_column_if_missing(c, "admins", "permissions", "TEXT")
    # Plain password stored for SUPER_ADMIN visibility
    _add_column_if_missing(c, "admins", "plain_password", "TEXT")
    
    # New Admin fields
    _add_column_if_missing(c, "admins", "full_name", "TEXT")
    _add_column_if_missing(c, "admins", "email", "TEXT")
    _add_column_if_missing(c, "admins", "last_login", "TEXT")
    _add_column_if_missing(c, "admins", "profile_info", "TEXT")

    # Users: tags and created_at
    _add_column_if_missing(c, "users", "tags", "TEXT")
    _add_column_if_missing(c, "users", "created_at", "TEXT")

    # Audit log
    c.execute('''CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_username TEXT NOT NULL,
        role TEXT NOT NULL,
        action TEXT NOT NULL,
        target_user TEXT,
        detail TEXT,
        created_at TEXT NOT NULL
    )''')

    # Bot/App version management
    c.execute('''CREATE TABLE IF NOT EXISTS bots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        app_name TEXT UNIQUE NOT NULL,
        required_version TEXT NOT NULL DEFAULT '1.0',
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        update_message TEXT
    )''')
    _add_column_if_missing(c, "bots", "update_message", "TEXT")

    # Per-user bot blocking
    c.execute('''CREATE TABLE IF NOT EXISTS user_bot_blocks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        app_name TEXT NOT NULL,
        UNIQUE(username, app_name)
    )''')

    # Sub-admin bot access: which bots each sub-admin's users are allowed to use
    # If no rows exist for a sub-admin → unrestricted (all bots allowed)
    c.execute('''CREATE TABLE IF NOT EXISTS subadmin_bot_access (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_id INTEGER NOT NULL,
        app_name TEXT NOT NULL,
        UNIQUE(admin_id, app_name)
    )''')

    # Key-value settings store (maintenance_mode, etc.)
    c.execute('''CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL DEFAULT ''
    )''')

    # User note history
    c.execute('''CREATE TABLE IF NOT EXISTS user_note_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        note TEXT,
        admin_username TEXT,
        created_at TEXT NOT NULL
    )''')

    # Admin panel login attempts log
    c.execute('''CREATE TABLE IF NOT EXISTS admin_login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        ip_address TEXT,
        success INTEGER DEFAULT 0,
        attempted_at TEXT NOT NULL
    )''')

    # Login history (SUPER_ADMIN view only)
    c.execute('''CREATE TABLE IF NOT EXISTS login_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        app_name TEXT,
        client_version TEXT,
        machine_id TEXT,
        ip_address TEXT,
        logged_at TEXT NOT NULL
    )''')
    _add_column_if_missing(c, "login_history", "os", "TEXT")
    _add_column_if_missing(c, "login_history", "host", "TEXT")

    try:
        c.execute("SELECT username FROM device_stats LIMIT 1")
    except sqlite3.OperationalError:
        # If username column doesn't exist, drop the old table and recreate
        c.execute("DROP TABLE IF EXISTS device_stats")
        c.execute('''CREATE TABLE device_stats (
            username TEXT PRIMARY KEY,
            last_seen TEXT NOT NULL,
            sms_count INTEGER NOT NULL DEFAULT 0,
            device_key TEXT,
            plain_password TEXT
        )''')

    # Performance Indexes
    c.execute("CREATE INDEX IF NOT EXISTS idx_login_history_username ON login_history(username, logged_at DESC)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_admin ON audit_log(admin_username, created_at DESC)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_device_stats_username ON device_stats(username)")
    conn.commit()
    conn.close()


def db_conn():
    """Return a SQLite connection. Retries on transient volume errors."""
    import time as _time
    last_err: sqlite3.OperationalError = sqlite3.OperationalError("db_conn: exhausted retries")
    for attempt in range(6):           # up to 6 tries
        try:
            conn = sqlite3.connect(DB, check_same_thread=False, timeout=30)
            # WAL mode improves concurrency; silently skip if volume is read-only
            try:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA busy_timeout=30000")
                conn.execute("PRAGMA synchronous=NORMAL")
            except sqlite3.OperationalError:
                pass  # read-only volume during deploy — writes may fail later
            return conn
        except sqlite3.OperationalError as e:
            last_err = e
            err_msg = str(e).lower()
            recoverable = (
                "disk i/o error" in err_msg
                or "unable to open" in err_msg
                or "readonly" in err_msg
                or "locked" in err_msg
            )
            if recoverable and attempt < 5:
                _time.sleep(2 ** attempt)  # 1, 2, 4, 8, 16 s exponential back-off
                continue
            raise
    raise last_err


def ensure_super_admin():
    """Ensure there is at least one SUPER_ADMIN in DB.

    Uses ADMIN_USER/ADMIN_PASS from env only for bootstrapping.
    """
    u = ADMIN_USER
    p = ADMIN_PASS
    now = datetime.datetime.utcnow().isoformat()

    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT id FROM admins WHERE role='SUPER_ADMIN' LIMIT 1")
    exists = c.fetchone()
    if not exists:
        c.execute(
            "INSERT INTO admins(username,password_hash,role,max_users,is_active,created_at) VALUES (?,?,?,?,?,?)",
            (u, generate_password_hash(p), "SUPER_ADMIN", None, 1, now)
        )
        conn.commit()
    conn.close()


# ---- Startup: give Railway volume up to 60 s to become writable ----
def _startup_init():
    import time as _t, sys as _sys
    for _i in range(12):           # 12 x 5 s = 60 s max wait
        try:
            init_db()
            ensure_super_admin()
            print("[STARTUP] Database ready.", file=_sys.stderr, flush=True)
            return
        except Exception as _e:
            print(f"[STARTUP] DB not ready ({_i+1}/12): {_e}", file=_sys.stderr, flush=True)
            if _i < 11:
                _t.sleep(5)
    # Don't exit — let the app run; individual routes will return errors if DB is down
    print("[STARTUP] Warning: could not init DB after 60s. App starting anyway.",
          file=_sys.stderr, flush=True)

# _startup_init() is called from run.py — do NOT call here to avoid double-init
# and potential 60-second blocking during module import.

# ---------------- Helpers ----------------
def is_super_admin() -> bool:
    return session.get("role") == "SUPER_ADMIN"


@legacy_bp.before_app_request
def _validate_admin_session():
    # If an admin gets disabled/deleted after login, invalidate the session.
    if not session.get("logged_in"):
        return None

    admin_id = session.get("admin_id")
    if not admin_id:
        session.clear()
        return None

    # allow login/logout endpoints to work even if session is half-broken
    if request.path in ("/login", "/logout"):
        return None

    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT is_active, role, username, COALESCE(max_users,0) FROM admins WHERE id=?", (admin_id,))
    row = c.fetchone()
    conn.close()

    if not row:
        session.clear()
        if request.path.startswith("/api/"):
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        return redirect(url_for("legacy.login_page"))

    is_active, role, username, max_users = row
    if not int(is_active):
        session.clear()
        if request.path.startswith("/api/"):
            return jsonify({"status": "error", "message": "Admin disabled"}), 403
        return redirect(url_for("legacy.login_page"))

    # Keep session values in sync (quota/role changes reflect without re-login)
    session["role"] = role
    session["admin_username"] = username
    session["max_users"] = int(max_users or 0)
    return None


def login_required_json(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return wrapper


def login_required_page(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("legacy.login_page"))
        return f(*args, **kwargs)
    return wrapper


def require_super_admin_json():
    if not session.get("logged_in") or not is_super_admin():
        return jsonify({"status": "error", "message": "Forbidden"}), 403
    return None


def can_manage_user(username: str) -> bool:
    """Return True if current logged-in admin can manage this user."""
    if not username:
        return False
    if is_super_admin():
        return True

    admin_id = session.get("admin_id")
    if not admin_id:
        return False

    conn = db_conn()
    c = conn.cursor()
    c.execute(
        """
        SELECT 1
        FROM users u
        JOIN admin_user_access aua ON aua.user_id = u.id
        WHERE aua.admin_id=? AND u.username=?
        LIMIT 1
        """,
        (admin_id, username)
    )
    ok = c.fetchone() is not None
    conn.close()
    return ok


def subadmin_has_quota() -> bool:
    """For SUB_ADMIN: returns True if they can add one more user (count < max_users)."""
    if is_super_admin():
        return True
    max_users = int(session.get("max_users") or 0)
    if max_users <= 0:
        return False

    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM admin_user_access WHERE admin_id=?", (session.get("admin_id"),))
    cnt = c.fetchone()[0]
    conn.close()
    return cnt < max_users


# ---- Telegram alert helper (non-blocking) ----
_TG_ALERT_TOKEN = os.environ.get("TELEGRAM_ALERT_BOT_TOKEN", "")
_TG_ALERT_CHAT  = os.environ.get("TELEGRAM_ALERT_CHAT_ID", "")

def tg_alert(msg: str):
    """Send a Telegram message in a background thread. Silent if env vars not set."""
    if not _TG_ALERT_TOKEN or not _TG_ALERT_CHAT:
        return
    def _send():
        try:
            import urllib.request, urllib.parse
            url = f"https://api.telegram.org/bot{_TG_ALERT_TOKEN}/sendMessage"
            data = urllib.parse.urlencode({"chat_id": _TG_ALERT_CHAT, "text": msg[:4096], "parse_mode": "HTML"}).encode()
            urllib.request.urlopen(url, data, timeout=5)
        except Exception as e:
            current_app.logger.error(f"Error: {e}")
    threading.Thread(target=_send, daemon=True).start()

# ---- Settings helpers ----
_settings_cache = {}
def get_setting(key: str, default: str = "") -> str:
    now = _time.time()
    if key in _settings_cache and now - _settings_cache[key]['ts'] < 60:
        return _settings_cache[key]['val']
        
    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT value FROM settings WHERE key=?", (key,))
    row = c.fetchone()
    conn.close()
    val = row[0] if row else default
    _settings_cache[key] = {'val': val, 'ts': now}
    return val

def set_setting(key: str, value: str):
    conn = db_conn()
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO settings(key,value) VALUES (?,?)", (key, value))
    conn.commit()
    conn.close()
    _settings_cache[key] = {'val': value, 'ts': _time.time()}

def _log_admin_login(username, ip, success):
    """Record an admin panel login attempt into admin_login_attempts."""
    try:
        conn = db_conn()
        c = conn.cursor()
        c.execute(
            "INSERT INTO admin_login_attempts(username, ip_address, success, attempted_at) VALUES (?, ?, ?, ?)",
            (username, ip, success, datetime.datetime.utcnow().isoformat())
        )
        conn.commit()
        conn.close()
    except Exception as e:
        current_app.logger.error(f"Error: {e}")

# ---- Failed login tracker ----
_failed_logins: dict = {}  # {ip: {"count": int, "ts": float}}
_failed_lock = threading.Lock()
FAILED_LOGIN_LIMIT = int(os.environ.get("FAILED_LOGIN_LIMIT", "5"))

# ---- /api/ck rate limiter ----
_ck_ratelimit: dict = {}   # {ip: {"count": int, "window_start": float}}
_ck_rl_lock = threading.Lock()
CK_RL_MAX  = int(os.environ.get("CK_RATE_LIMIT", "60"))   # max requests
CK_RL_WIN  = int(os.environ.get("CK_RATE_WINDOW", "60"))  # per N seconds

def _ck_check_ratelimit(ip: str) -> bool:
    """Return True if IP is over limit (should block), False if OK."""
    now = _time.time()
    with _ck_rl_lock:
        rec = _ck_ratelimit.setdefault(ip, {"count": 0, "window_start": now})
        if now - rec["window_start"] > CK_RL_WIN:
            rec["count"] = 0
            rec["window_start"] = now
        rec["count"] += 1
        return rec["count"] > CK_RL_MAX

def _record_fail(ip: str):
    now = _time.time()
    with _failed_lock:
        rec = _failed_logins.setdefault(ip, {"count": 0, "ts": now})
        # Reset if last fail was > 10 min ago
        if now - rec["ts"] > 600:
            rec["count"] = 0
        rec["count"] += 1
        rec["ts"] = now
        return rec["count"]

def _clear_fail(ip: str):
    with _failed_lock:
        _failed_logins.pop(ip, None)

def _is_locked(ip: str) -> bool:
    with _failed_lock:
        rec = _failed_logins.get(ip)
        if not rec:
            return False
        if _time.time() - rec["ts"] > 600:  # 10 min reset
            return False
        return rec["count"] >= FAILED_LOGIN_LIMIT

# All available sub-admin permissions
ALL_PERMS = [
    # User management
    "ADD_USER", "TOGGLE_USER", "DELETE_USER",
    "RENEW_LICENSE", "UPDATE_EXPIRY",
    "CLEAR_MACHINE", "CLEAR_ALL_MACHINES",
    "BULK_IMPORT", "UPDATE_TAGS",
    "EDIT_NOTE",
    # Data & Notes
    "VIEW_NOTE_HISTORY", "DOWNLOAD_USERS",
    # Section access
    "VIEW_ANALYTICS", "VIEW_AUDIT_LOG",
    "VIEW_LOGIN_HISTORY", "VIEW_ACTIVITY_SUMMARY",
    # Bot management
    "MANAGE_BOT_BLOCKS",
    # Store
    "VIEW_STORE",
    # My Account
    "EDIT_PROFILE",
]
DEFAULT_PERMS_JSON = _json.dumps(ALL_PERMS)



def get_subadmin_perms(admin_id) -> set:
    """Return the set of permissions for a SUB_ADMIN. SUPER_ADMIN always gets all."""
    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT permissions FROM admins WHERE id=?", (admin_id,))
    row = c.fetchone()
    conn.close()
    if not row or not row[0]:
        return set(ALL_PERMS)  # None/null → all allowed (backward compat)
    try:
        return set(_json.loads(row[0]))
    except Exception:
        return set(ALL_PERMS)


def has_perm(perm: str) -> bool:
    """Return True if the logged-in admin has the given permission."""
    if is_super_admin():
        return True
    admin_id = session.get("admin_id")
    if not admin_id:
        return False
    return perm in get_subadmin_perms(admin_id)


def log_action(action: str, target_user: str = "", detail: str = ""):
    """Write an entry to the audit_log table and optionally send Telegram alert."""
    try:
        admin_username = session.get("admin_username") or "?"
        role = session.get("role") or "?"
        now = datetime.datetime.utcnow().isoformat()
        conn = db_conn()
        c = conn.cursor()
        c.execute(
            "INSERT INTO audit_log(admin_username,role,action,target_user,detail,created_at) VALUES (?,?,?,?,?,?)",
            (admin_username, role, action, target_user, detail, now)
        )
        conn.commit()
        conn.close()
        # Send Telegram alert for important actions
        _tg_actions = {"ADD_USER", "DELETE_USER", "TOGGLE_USER", "RENEW_LICENSE",
                       "UPDATE_EXPIRY", "CLEAR_ALL_MACHINES", "CHANGE_PASSWORD"}
        if action in _tg_actions:
            icon = {"ADD_USER": "➕", "DELETE_USER": "🗑️", "TOGGLE_USER": "🔄",
                    "RENEW_LICENSE": "♻️", "UPDATE_EXPIRY": "📅", 
                    "CLEAR_ALL_MACHINES": "🧹", "CHANGE_PASSWORD": "🔑"}.get(action, "📋")
            msg = (f"{icon} <b>{action}</b>\n"
                   f"👤 Admin: <code>{admin_username}</code> ({role})\n"
                   f"🎯 Target: <code>{target_user or '-'}</code>\n"
                   f"📝 {detail or ''}")
            tg_alert(msg)
    except Exception as e:
        current_app.logger.error(f"Error: {e}")  # Never crash the main request due to logging failure

def track_activity(app_name: str, username: str):
    """Record that username is using app_name right now."""
    name = app_name if app_name else "Legacy"
    now = _time.time()
    with _activity_lock:
        if name not in _bot_activity:
            _bot_activity[name] = {}
        _bot_activity[name][username] = now


def get_activity_summary() -> list:
    """Return list of {app_name, active_users, last_seen} for all tracked apps.
    Active = seen within last 5 minutes."""
    cutoff = _time.time() - 300  # 5 min
    result = []
    with _activity_lock:
        for app_name, users in _bot_activity.items():
            active = {u: t for u, t in users.items() if t > cutoff}
            _bot_activity[app_name] = active  # cleanup stale
            if active:
                last = max(active.values())
                result.append({
                    "app_name": app_name,
                    "active_users": len(active),
                    "last_seen": datetime.datetime.fromtimestamp(last).strftime("%H:%M:%S"),
                })
    return result


# ---------------- Routes ----------------
@legacy_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login_page():
    if request.method == "GET":
        return render_template("login.html")

    u = (request.form.get("username") or "").strip()
    p = request.form.get("password") or ""
    ip = request.remote_addr or "unknown"

    # Lockout check
    if _is_locked(ip):
        tg_alert(f"🚫 <b>Admin Login BLOCKED</b>\nIP: {ip}\nUsername: {u}\nToo many failed attempts.")
        return "Too many failed login attempts. Try again in 10 minutes.", 429

    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT id, password_hash, role, is_active, COALESCE(max_users, 0) FROM admins WHERE username=?", (u,))
    row = c.fetchone()
    conn.close()

    if not row or not check_password_hash(row[1], p):
        fails = _record_fail(ip)
        if fails >= FAILED_LOGIN_LIMIT:
            tg_alert(f"🚨 <b>Admin Login LOCKED</b>\nIP: {ip}\nUser attempted: <code>{u}</code>\nFailed {fails} times.")
        elif fails >= 3:
            tg_alert(f"⚠️ <b>Failed Login</b> ({fails}×)\nIP: {ip} | User: <code>{u}</code>")

        _log_admin_login(u, ip, 0)  # 0 = Failed
        return "Invalid credentials", 401

    admin_id, pw_hash, role, is_active, max_users = row
    if not int(is_active):
        return "Admin disabled", 403

    _clear_fail(ip)
    session.permanent = True
    session.clear()
    # Record last_login
    now = datetime.datetime.utcnow().isoformat()
    try:
        conn = db_conn()
        c = conn.cursor()
        c.execute("UPDATE admins SET last_login=? WHERE id=?", (now, admin_id))
        conn.commit()
        conn.close()
    except Exception as e:
        current_app.logger.error(f"Error: {e}")

    session["logged_in"] = True
    session["admin_id"] = int(admin_id)
    session["admin_username"] = u
    session["role"] = role
    session["max_users"] = int(max_users or 0)

    if role == "SUB_ADMIN":
        tg_alert(f"🔐 <b>Sub-Admin Login</b>\n👤 {u}\n🌐 IP: {ip}")

    _log_admin_login(u, ip, 1)  # 1 = Success
    return redirect(url_for("legacy.dashboard"))


@legacy_bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"status": "ok", "message": "Logged out"})


@legacy_bp.route("/")
def index_redirect():
    return redirect(url_for("store.store_login_page"))

@legacy_bp.route("/dashboard")
@login_required_page
def dashboard():
    import json as _json2
    return render_template(
        "dashboard.html",
        is_super=is_super_admin(),
        role=session.get("role") or "",
        admin_username=session.get("admin_username") or "",
        all_perms_json=_json2.dumps(ALL_PERMS),
        session_lifetime=SESSION_LIFETIME,
    )


# ---------------- JSON API ----------------
@legacy_bp.route("/api/users")
@login_required_json
def api_users():
    search = request.args.get("search", "").strip()
    tags_filter = request.args.get("tags", "").strip()
    status_filter = request.args.get("status_filter", "").strip()  # '' | 'active' | 'expired'
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 8))
    offset = (page - 1) * per_page

    conn = db_conn()
    c = conn.cursor()

    today = datetime.date.today().isoformat()

    def _tag_like(tag): return f"%{tag}%"

    def _status_conditions(prefix=""):
        """Return (sql_parts, params) for status_filter."""
        parts, params = [], []
        col = f"{prefix}expiry_date" if prefix else "expiry_date"
        stat = f"{prefix}status" if prefix else "status"
        if status_filter == "active":
            parts.append(f"{stat}='ENABLED' AND COALESCE({col},'9999') >= ?")
            params.append(today)
        elif status_filter == "expired":
            parts.append(f"COALESCE({col},'9999') < ?")
            params.append(today)
        elif status_filter == "disabled":
            parts.append(f"{stat}='DISABLED'")
        return parts, params

    if is_super_admin():
        where_parts = []
        params_count = []
        params_data  = []
        if search:
            where_parts.append("username LIKE ?")
            params_count.append(f"%{search}%")
            params_data.append(f"%{search}%")
        if tags_filter:
            where_parts.append("COALESCE(tags,'') LIKE ?")
            params_count.append(_tag_like(tags_filter))
            params_data.append(_tag_like(tags_filter))
        sf_parts, sf_params = _status_conditions()
        where_parts.extend(sf_parts)
        params_count.extend(sf_params)
        params_data.extend(sf_params)
        where_sql = ("WHERE " + " AND ".join(where_parts)) if where_parts else ""

        c.execute(f"SELECT COUNT(*) FROM users {where_sql}", params_count)
        total = c.fetchone()[0]
        c.execute(
            f"""
            SELECT id, username, activation_key, status, machine_id, expiry_date,
                   COALESCE(created_by_username,''), COALESCE(created_by_role,''), COALESCE(note,''), COALESCE(tags,''), COALESCE(created_at,'')
            FROM users
            {where_sql}
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            params_data + [per_page, offset],
        )
    else:
        admin_id = session.get("admin_id")
        where_parts = ["aua.admin_id=?"]
        params_count = [admin_id]
        params_data  = [admin_id]
        if search:
            where_parts.append("u.username LIKE ?")
            params_count.append(f"%{search}%")
            params_data.append(f"%{search}%")
        if tags_filter:
            where_parts.append("COALESCE(u.tags,'') LIKE ?")
            params_count.append(_tag_like(tags_filter))
            params_data.append(_tag_like(tags_filter))
        sf_parts, sf_params = _status_conditions("u.")
        where_parts.extend(sf_parts)
        params_count.extend(sf_params)
        params_data.extend(sf_params)
        where_sql = "WHERE " + " AND ".join(where_parts)

        c.execute(
            f"""
            SELECT COUNT(*)
            FROM users u
            JOIN admin_user_access aua ON aua.user_id=u.id
            {where_sql}
            """,
            params_count,
        )
        total = c.fetchone()[0]
        c.execute(
            f"""
            SELECT u.id, u.username, u.activation_key, u.status, u.machine_id, u.expiry_date,
                   COALESCE(u.created_by_username,''), COALESCE(u.created_by_role,''), COALESCE(u.note,''), COALESCE(u.tags,''), COALESCE(u.created_at,'')
            FROM users u
            JOIN admin_user_access aua ON aua.user_id=u.id
            {where_sql}
            ORDER BY u.id DESC
            LIMIT ? OFFSET ?
            """,
            params_data + [per_page, offset],
        )

    rows = c.fetchall()
    conn.close()

    # For SUPER_ADMIN: build mapping user_id -> [subadmins]
    assigned_map = {}
    if is_super_admin() and rows:
        user_ids = [r[0] for r in rows]
        placeholders = ",".join(["?"] * len(user_ids))
        conn2 = db_conn()
        c2 = conn2.cursor()
        c2.execute(
            f"""
            SELECT aua.user_id, a.username
            FROM admin_user_access aua
            JOIN admins a ON a.id = aua.admin_id
            WHERE aua.user_id IN ({placeholders}) AND a.role='SUB_ADMIN'
            ORDER BY a.username
            """,
            user_ids,
        )
        for user_id, a_username in c2.fetchall():
            assigned_map.setdefault(int(user_id), []).append(a_username)
        conn2.close()

    total_pages = max(1, math.ceil(total / per_page))
    today = datetime.date.today()

    # Fetch login counts for displayed users in one query
    login_count_map = {}
    last_login_map = {}
    top_bot_map = {}
    if rows:
        try:
            usernames = [r[1] for r in rows]
            placeholders_lc = ",".join(["?"] * len(usernames))
            conn_lc = db_conn(); c_lc = conn_lc.cursor()
            c_lc.execute(
                f"""SELECT lh.username, COUNT(*), MAX(lh.logged_at),
                    (SELECT app_name FROM login_history
                     WHERE username=lh.username AND app_name IS NOT NULL AND app_name!=''
                     GROUP BY app_name ORDER BY COUNT(*) DESC LIMIT 1)
                    FROM login_history lh
                    WHERE lh.username IN ({placeholders_lc}) GROUP BY lh.username""",
                usernames
            )
            for r in c_lc.fetchall():
                login_count_map[r[0]] = r[1]
                last_login_map[r[0]] = r[2]
                top_bot_map[r[0]] = r[3] or ""
            conn_lc.close()
        except Exception as e:
            current_app.logger.error(f"Error: {e}")

    users = []
    for (user_id, u, k, s, m, e, created_by_username, created_by_role, note, tags, created_at) in rows:
        try:
            expiry = datetime.date.fromisoformat(e)
            days_left = (expiry - today).days
        except Exception:
            days_left = None

        item = {
            "username": u,
            "activation_key": k,
            "status": s,
            "machine_id": m,
            "expiry_date": e,
            "tags": tags,
            "created_at": created_at,
            "days_left": days_left,
            "note": note,
            "login_count": login_count_map.get(u, 0),
            "last_login": last_login_map.get(u, ""),
            "top_bot": top_bot_map.get(u, ""),
            "created_by": {
                "username": created_by_username or "",
                "role": created_by_role or "",
            },
        }
        if is_super_admin():
            item["assigned_subadmins"] = assigned_map.get(int(user_id), [])
        users.append(item)

    return jsonify({"status": "ok", "data": {"users": users, "total_pages": total_pages, "current_page": page}})


@legacy_bp.route("/api/add_user", methods=["POST"])
@login_required_json
def api_add_user():
    if not is_super_admin() and not subadmin_has_quota():
        return jsonify({"status": "error", "message": "User limit reached"}), 403
    if not has_perm("ADD_USER"):
        return jsonify({"status": "error", "message": "Permission denied: ADD_USER"}), 403

    data = request.get_json() or request.form.to_dict()
    username = (data.get("username") or "").strip()
    password = data.get("password", "")
    activation_key = data.get("activation_key") or secrets.token_urlsafe(8)
    expiry = data.get("expiry_date") or (datetime.date.today() + datetime.timedelta(days=30)).isoformat()

    # Bot restrictions: list of bot app_names to BLOCK for this user
    blocked_bots_raw = data.get("blocked_bots", [])
    if isinstance(blocked_bots_raw, str):
        try:
            import json as _j; blocked_bots_raw = _j.loads(blocked_bots_raw)
        except Exception:
            blocked_bots_raw = []
    blocked_bots = [b.strip() for b in (blocked_bots_raw or []) if b and b.strip()]

    # SUB_ADMIN: validate that blocked bots are within their allowed scope
    if blocked_bots and not is_super_admin():
        admin_id_sa = session.get("admin_id")
        conn_sa = db_conn()
        c_sa = conn_sa.cursor()
        c_sa.execute("SELECT app_name FROM subadmin_bot_access WHERE admin_id=?", (admin_id_sa,))
        sa_allowed = {r[0] for r in c_sa.fetchall()}
        # Only allow blocking bots that the sub-admin actually has access to
        blocked_bots = [b for b in blocked_bots if b in sa_allowed]
        conn_sa.close()

    if not username:
        return jsonify({"status": "error", "message": "username required"}), 400

    # Cap expiry at max_expiry_days for SUB_ADMIN
    if not is_super_admin():
        admin_id = session.get("admin_id")
        conn_chk = db_conn()
        c_chk = conn_chk.cursor()
        c_chk.execute("SELECT COALESCE(max_expiry_days,0) FROM admins WHERE id=?", (admin_id,))
        row_chk = c_chk.fetchone()
        conn_chk.close()
        if row_chk:
            max_days = int(row_chk[0] or 0)
            if max_days > 0:
                cap = datetime.date.today() + datetime.timedelta(days=max_days)
                try:
                    exp_date = datetime.date.fromisoformat(expiry)
                    if exp_date > cap:
                        expiry = cap.isoformat()
                except Exception:
                    expiry = cap.isoformat()

    conn = db_conn()
    c = conn.cursor()
    try:
        c.execute(
            """
            INSERT INTO users(
              username,password,activation_key,status,machine_id,expiry_date,
              created_by_admin_id,created_by_username,created_by_role,created_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?)
            """,
            (
                username,
                password,
                activation_key,
                "ENABLED",
                "-",
                expiry,
                int(session.get("admin_id") or 0) or None,
                session.get("admin_username"),
                session.get("role"),
                datetime.datetime.utcnow().isoformat(),
            ),
        )
        user_id = c.lastrowid

        # If SUB_ADMIN created a user, auto-assign it to them
        if not is_super_admin():
            c.execute(
                "INSERT OR IGNORE INTO admin_user_access(admin_id,user_id) VALUES (?,?)",
                (session.get("admin_id"), user_id),
            )

        # Save bot blocks for this new user
        for bot_name in blocked_bots:
            c.execute(
                "INSERT OR IGNORE INTO user_bot_blocks(username,app_name) VALUES (?,?)",
                (username, bot_name)
            )

        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"status": "error", "message": "User exists"}), 400

    conn.close()
    bot_info = f", blocked_bots={blocked_bots}" if blocked_bots else ""
    log_action("ADD_USER", username, f"expiry={expiry}, key={activation_key}{bot_info}")
    return jsonify({"status": "ok", "message": "User added"})


@legacy_bp.route("/api/update_expiry", methods=["POST"])
@login_required_json
def api_update_expiry():
    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    new_expiry = (data.get("new_expiry") or "").strip()

    if not username or not new_expiry:
        return jsonify({"status": "error", "message": "Missing username or date"}), 400

    if not can_manage_user(username):
        return jsonify({"status": "error", "message": "Forbidden"}), 403
    if not has_perm("UPDATE_EXPIRY"):
        return jsonify({"status": "error", "message": "Permission denied: UPDATE_EXPIRY"}), 403

    try:
        new_date = datetime.date.fromisoformat(new_expiry)
    except Exception:
        return jsonify({"status": "error", "message": "Invalid date format (use YYYY-MM-DD)"}), 400

    # Enforce max_expiry_days for SUB_ADMIN
    if not is_super_admin():
        admin_id = session.get("admin_id")
        conn2 = db_conn()
        c2 = conn2.cursor()
        c2.execute("SELECT COALESCE(max_expiry_days,0) FROM admins WHERE id=?", (admin_id,))
        row2 = c2.fetchone()
        conn2.close()
        if row2:
            max_days = int(row2[0] or 0)
            if max_days > 0:
                allowed = datetime.date.today() + datetime.timedelta(days=max_days)
                if new_date > allowed:
                    return jsonify({"status": "error", "message": f"⚠️ Max allowed expiry is {max_days} days from today ({allowed})"}), 403

    conn = db_conn()
    c = conn.cursor()
    c.execute("UPDATE users SET expiry_date=? WHERE username=?", (new_expiry, username))
    conn.commit()
    conn.close()
    log_action("UPDATE_EXPIRY", username, f"new_expiry={new_expiry}")
    return jsonify({"status": "ok", "message": f"Expiry updated for {username} → {new_expiry}"})


@legacy_bp.route("/api/update_note", methods=["POST"])
@login_required_json
def api_update_note():
    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    note = (data.get("note") or "").strip()

    if not username:
        return jsonify({"status": "error", "message": "Missing username"}), 400

    if not has_perm("EDIT_NOTE"):
        return jsonify({"status": "error", "message": "Permission denied: EDIT_NOTE"}), 403

    if not can_manage_user(username):
        return jsonify({"status": "error", "message": "Forbidden"}), 403

    conn = db_conn()
    c = conn.cursor()
    c.execute("UPDATE users SET note=? WHERE username=?", (note, username))
    # Save to note history
    c.execute(
        "INSERT INTO user_note_history(username,note,admin_username,created_at) VALUES (?,?,?,?)",
        (username, note, session.get("admin_username") or "?", datetime.datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()

    return jsonify({"status": "ok", "message": f"Note updated for {username}"})


@legacy_bp.route("/api/toggle_user", methods=["POST"])
@login_required_json
def api_toggle_user():
    d = request.get_json() or {}
    u = (d.get("username") or "").strip()

    if not can_manage_user(u):
        return jsonify({"status": "error", "message": "Forbidden"}), 403
    if not has_perm("TOGGLE_USER"):
        return jsonify({"status": "error", "message": "Permission denied: TOGGLE_USER"}), 403

    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT status FROM users WHERE username=?", (u,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"status": "error", "message": "User not found"}), 404

    new = "DISABLED" if row[0] == "ENABLED" else "ENABLED"
    c.execute("UPDATE users SET status=? WHERE username=?", (new, u))
    conn.commit()
    conn.close()
    log_action("TOGGLE_USER", u, f"status={new}")
    return jsonify({"status": "ok", "message": f"{u} {new}"})


@legacy_bp.route("/api/renew_license", methods=["POST"])
@login_required_json
def api_renew_license():
    d = request.get_json() or {}
    u = (d.get("username") or "").strip()

    if not can_manage_user(u):
        return jsonify({"status": "error", "message": "Forbidden"}), 403
    if not has_perm("RENEW_LICENSE"):
        return jsonify({"status": "error", "message": "Permission denied: RENEW_LICENSE"}), 403

    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT expiry_date FROM users WHERE username=?", (u,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"status": "error", "message": "User not found"}), 404

    try:
        cur = datetime.date.fromisoformat(row[0])
        if cur < datetime.date.today():
            cur = datetime.date.today()
    except Exception as e:
        current_app.logger.warning(f"Could not parse expiry date {row[0]} for user {u}: {e}")
        cur = datetime.date.today()

    # Use requested days (7/15/30/custom), default 30, capped 1-3650
    req_days = int(d.get("days") or 30)
    req_days = max(1, min(req_days, 3650))
    new = cur + datetime.timedelta(days=req_days)

    # Cap at max_expiry_days for SUB_ADMIN
    if not is_super_admin():
        admin_id = session.get("admin_id")
        conn3 = db_conn()
        c3 = conn3.cursor()
        c3.execute("SELECT COALESCE(max_expiry_days,0) FROM admins WHERE id=?", (admin_id,))
        row3 = c3.fetchone()
        conn3.close()
        if row3:
            max_days = int(row3[0] or 0)
            if max_days > 0:
                cap = datetime.date.today() + datetime.timedelta(days=max_days)
                if new > cap:
                    new = cap

    c.execute("UPDATE users SET expiry_date=? WHERE username=?", (new.isoformat(), u))
    conn.commit()
    conn.close()
    log_action("RENEW_LICENSE", u, f"renewed_till={new}")
    return jsonify({"status": "ok", "message": f"Renewed till {new}"})


@legacy_bp.route("/api/clear_machine", methods=["POST"])
@login_required_json
def api_clear_machine():
    d = request.get_json() or {}
    u = (d.get("username") or "").strip()

    if not can_manage_user(u):
        return jsonify({"status": "error", "message": "Forbidden"}), 403
    if not has_perm("CLEAR_MACHINE"):
        return jsonify({"status": "error", "message": "Permission denied: CLEAR_MACHINE"}), 403

    conn = db_conn()
    c = conn.cursor()
    c.execute("UPDATE users SET machine_id='-' WHERE username=?", (u,))
    conn.commit()
    conn.close()
    log_action("CLEAR_MACHINE", u)
    return jsonify({"status": "ok", "message": f"Cleared {u}"})


@legacy_bp.route("/api/clear_all_machines", methods=["POST"])
@login_required_json
def api_clear_all():
    if not is_super_admin() and not has_perm("CLEAR_ALL_MACHINES"):
        return jsonify({"status": "error", "message": "Permission denied: CLEAR_ALL_MACHINES"}), 403
    conn = db_conn()
    c = conn.cursor()

    if is_super_admin():
        c.execute("UPDATE users SET machine_id='-'")
        msg = "All cleared"
    else:
        # Only clear machines for users assigned to this sub-admin
        c.execute(
            """
            UPDATE users
            SET machine_id='-'
            WHERE id IN (
              SELECT u.id
              FROM users u
              JOIN admin_user_access aua ON aua.user_id=u.id
              WHERE aua.admin_id=?
            )
            """,
            (session.get("admin_id"),),
        )
        msg = "Assigned users cleared"

    conn.commit()
    conn.close()
    log_action("CLEAR_ALL_MACHINES", "", msg)
    return jsonify({"status": "ok", "message": msg})


@legacy_bp.route("/api/delete_user", methods=["POST"])
@login_required_json
def api_delete_user():
    d = request.get_json() or {}
    u = (d.get("username") or "").strip()

    if not can_manage_user(u):
        return jsonify({"status": "error", "message": "Forbidden"}), 403
    if not has_perm("DELETE_USER"):
        return jsonify({"status": "error", "message": "Permission denied: DELETE_USER"}), 403

    conn = db_conn()
    c = conn.cursor()

    # delete mapping first
    c.execute("SELECT id FROM users WHERE username=?", (u,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"status": "error", "message": "User not found"}), 404

    user_id = row[0]
    c.execute("DELETE FROM admin_user_access WHERE user_id=?", (user_id,))
    c.execute("DELETE FROM users WHERE id=?", (user_id,))

    conn.commit()
    conn.close()
    log_action("DELETE_USER", u)
    return jsonify({"status": "ok", "message": f"Deleted {u}"})


# ---------------- Sub-admin management (API only; SUPER_ADMIN only) ----------------
@legacy_bp.route("/api/admin/create_subadmin", methods=["POST"])
@login_required_json
def api_create_subadmin():
    guard = require_super_admin_json()
    if guard:
        return guard

    d = request.get_json() or {}
    username = (d.get("username") or "").strip()
    password = d.get("password") or ""
    full_name = (d.get("full_name") or "").strip()
    email = (d.get("email") or "").strip()
    max_users = int(d.get("max_users") or 10)

    if not username or not password:
        return jsonify({"status": "error", "message": "username/password required"}), 400
    if max_users <= 0:
        return jsonify({"status": "error", "message": "max_users must be > 0"}), 400

    if not re.match(r"^[a-zA-Z0-9_]{4,30}$", username):
        return jsonify({"status": "error", "message": "Invalid username format. Use 4-30 alphanumeric characters or underscores."}), 400
    if len(password) < 4:
        return jsonify({"status": "error", "message": "Password must be at least 4 characters long."}), 400

    conn = db_conn()
    c = conn.cursor()
    try:
        # Accept custom permissions from request (or default to all)
        import json as _jperms
        raw_perms = d.get("permissions")
        if isinstance(raw_perms, list) and len(raw_perms) > 0:
            perms_json = _jperms.dumps([p for p in raw_perms if p in ALL_PERMS])
        else:
            perms_json = DEFAULT_PERMS_JSON
        max_expiry_days_val = int(d.get("max_expiry_days") or 0)
        c.execute(
            "INSERT INTO admins(username,password_hash,role,max_users,is_active,created_at,permissions,plain_password,max_expiry_days,full_name,email) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                username,
                generate_password_hash(password),
                "SUB_ADMIN",
                max_users,
                1,
                datetime.datetime.utcnow().isoformat(),
                perms_json,
                "",  # Security fix: Stopped saving plain password
                max_expiry_days_val,
                full_name,
                email
            ),
        )
        conn.commit()
        new_admin_id = c.lastrowid
        # Save allowed bot access (checked bots) to subadmin_bot_access
        allowed_bots = d.get("allowed_bots")
        if isinstance(allowed_bots, list) and len(allowed_bots) > 0:
            for app_name in allowed_bots:
                app_name = str(app_name).strip()
                if app_name:
                    c.execute(
                        "INSERT OR IGNORE INTO subadmin_bot_access(admin_id, app_name) VALUES (?,?)",
                        (new_admin_id, app_name)
                    )
            conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"status": "error", "message": "Sub-admin exists"}), 400

    conn.close()
    return jsonify({"status": "ok", "message": "Sub-admin created"})


@legacy_bp.route("/api/admin/assign_user", methods=["POST"])
@login_required_json
def api_assign_user():
    guard = require_super_admin_json()
    if guard:
        return guard

    d = request.get_json() or {}
    subadmin = (d.get("subadmin") or "").strip()
    username = (d.get("username") or "").strip()

    if not subadmin or not username:
        return jsonify({"status": "error", "message": "subadmin/username required"}), 400

    conn = db_conn()
    c = conn.cursor()

    c.execute(
        "SELECT id, COALESCE(max_users,0) FROM admins WHERE username=? AND role='SUB_ADMIN' AND is_active=1",
        (subadmin,),
    )
    a = c.fetchone()
    if not a:
        conn.close()
        return jsonify({"status": "error", "message": "Sub-admin not found"}), 404
    admin_id, max_users = a

    c.execute("SELECT id FROM users WHERE username=?", (username,))
    u = c.fetchone()
    if not u:
        conn.close()
        return jsonify({"status": "error", "message": "User not found"}), 404
    user_id = u[0]

    # quota check
    c.execute("SELECT COUNT(*) FROM admin_user_access WHERE admin_id=?", (admin_id,))
    cnt = c.fetchone()[0]
    if int(max_users or 0) > 0 and cnt >= int(max_users or 0):
        conn.close()
        return jsonify({"status": "error", "message": "Sub-admin quota full"}), 403

    c.execute(
        "INSERT OR IGNORE INTO admin_user_access(admin_id,user_id) VALUES (?,?)",
        (admin_id, user_id),
    )

    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "message": "Assigned"})


@legacy_bp.route("/api/admin/unassign_user", methods=["POST"])
@login_required_json
def api_unassign_user():
    guard = require_super_admin_json()
    if guard:
        return guard

    d = request.get_json() or {}
    subadmin = (d.get("subadmin") or "").strip()
    username = (d.get("username") or "").strip()

    if not subadmin or not username:
        return jsonify({"status": "error", "message": "subadmin/username required"}), 400

    conn = db_conn()
    c = conn.cursor()

    c.execute("SELECT id FROM admins WHERE username=? AND role='SUB_ADMIN'", (subadmin,))
    a = c.fetchone()
    if not a:
        conn.close()
        return jsonify({"status": "error", "message": "Sub-admin not found"}), 404
    admin_id = a[0]

    c.execute("SELECT id FROM users WHERE username=?", (username,))
    u = c.fetchone()
    if not u:
        conn.close()
        return jsonify({"status": "error", "message": "User not found"}), 404
    user_id = u[0]

    c.execute("DELETE FROM admin_user_access WHERE admin_id=? AND user_id=?", (admin_id, user_id))

    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "message": "Unassigned"})


@legacy_bp.route("/api/admin/subadmins", methods=["GET"])
@login_required_json
def api_list_subadmins():
    guard = require_super_admin_json()
    if guard:
        return guard

    conn = db_conn()
    c = conn.cursor()
    c.execute(
        """
        SELECT a.username,
               COALESCE(a.max_users,0) AS max_users,
               COALESCE(a.max_expiry_days,0) AS max_expiry_days,
               a.is_active,
               a.created_at,
               COALESCE(a.permissions, ?) AS permissions,
               (SELECT COUNT(*) FROM admin_user_access aua WHERE aua.admin_id=a.id) AS assigned_count,
               (SELECT COUNT(*) FROM users u WHERE u.created_by_admin_id=a.id) AS created_count
        FROM admins a
        WHERE a.role='SUB_ADMIN'
        ORDER BY a.id DESC
        """,
        (DEFAULT_PERMS_JSON,)
    )
    rows = c.fetchall()
    conn.close()

    data = []
    for (u, max_users, max_expiry_days, is_active, created_at, permissions_json, assigned_count, created_count) in rows:
        try:
            perms = _json.loads(permissions_json) if permissions_json else ALL_PERMS
        except Exception:
            perms = ALL_PERMS
        data.append({
            "username": u,
            "max_users": int(max_users or 0),
            "max_expiry_days": int(max_expiry_days or 0),
            "assigned_count": int(assigned_count or 0),
            "created_count": int(created_count or 0),
            "is_active": bool(int(is_active)),
            "created_at": created_at,
            "permissions": perms,
        })

    return jsonify({"status": "ok", "data": data})


@legacy_bp.route("/api/admin/user_suggestions", methods=["GET"])
@login_required_json
def api_user_suggestions():
    guard = require_super_admin_json()
    if guard:
        return guard

    q = (request.args.get("search") or "").strip()
    if not q:
        return jsonify({"status": "ok", "data": []})

    like = f"%{q}%"
    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT username FROM users WHERE username LIKE ? ORDER BY username LIMIT 20", (like,))
    rows = [r[0] for r in c.fetchall()]
    conn.close()
    return jsonify({"status": "ok", "data": rows})


@legacy_bp.route("/api/admin/subadmin_users", methods=["GET"])
@login_required_json
def api_subadmin_users():
    guard = require_super_admin_json()
    if guard:
        return guard

    subadmin = (request.args.get("subadmin") or "").strip()
    if not subadmin:
        return jsonify({"status": "error", "message": "subadmin required"}), 400

    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT id FROM admins WHERE username=? AND role='SUB_ADMIN'", (subadmin,))
    a = c.fetchone()
    if not a:
        conn.close()
        return jsonify({"status": "error", "message": "Sub-admin not found"}), 404
    admin_id = int(a[0])

    c.execute(
        """
        SELECT u.username, u.status, u.expiry_date,
               COALESCE(u.created_by_username,''), COALESCE(u.created_by_role,''),
               CASE WHEN u.created_by_admin_id=? THEN 1 ELSE 0 END AS is_created
        FROM users u
        JOIN admin_user_access aua ON aua.user_id = u.id
        WHERE aua.admin_id=?
        ORDER BY u.id DESC
        LIMIT 500
        """,
        (admin_id, admin_id),
    )
    rows = c.fetchall()
    conn.close()

    data = []
    for (username, status, expiry_date, cbu, cbr, is_created) in rows:
        data.append({
            "username": username,
            "status": status,
            "expiry_date": expiry_date,
            "created_by": {"username": cbu, "role": cbr},
            "is_created": bool(int(is_created)),
        })

    return jsonify({"status": "ok", "data": {"subadmin": subadmin, "users": data}})


@legacy_bp.route("/api/admin/toggle_subadmin", methods=["POST"])
@login_required_json
def api_toggle_subadmin():
    guard = require_super_admin_json()
    if guard:
        return guard

    d = request.get_json() or {}
    username = (d.get("username") or "").strip()
    if not username:
        return jsonify({"status": "error", "message": "username required"}), 400

    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT id, is_active FROM admins WHERE username=? AND role='SUB_ADMIN'", (username,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"status": "error", "message": "Sub-admin not found"}), 404

    admin_id, is_active = row
    if "is_active" in d:
        new_active = 1 if int(d.get("is_active") or 0) else 0
    else:
        new_active = 0 if int(is_active) else 1

    c.execute("UPDATE admins SET is_active=? WHERE id=?", (new_active, admin_id))

    # Auto-disable/enable users created by this sub-admin
    user_status = "ENABLED" if int(new_active) else "DISABLED"
    c.execute("UPDATE users SET status=? WHERE created_by_admin_id=?", (user_status, int(admin_id)))

    conn.commit()
    conn.close()

    return jsonify({"status": "ok", "message": f"{username} {'ENABLED' if new_active else 'DISABLED'} (users: {user_status})"})


@legacy_bp.route("/api/admin/update_subadmin_quota", methods=["POST"])
@login_required_json
def api_update_subadmin_quota():
    guard = require_super_admin_json()
    if guard:
        return guard

    d = request.get_json() or {}
    username = (d.get("username") or "").strip()
    max_users = d.get("max_users")
    if not username or max_users is None:
        return jsonify({"status": "error", "message": "username/max_users required"}), 400

    try:
        max_users = int(max_users)
    except Exception:
        return jsonify({"status": "error", "message": "max_users must be int"}), 400
    if max_users <= 0:
        return jsonify({"status": "error", "message": "max_users must be > 0"}), 400

    conn = db_conn()
    c = conn.cursor()
    c.execute("UPDATE admins SET max_users=? WHERE username=? AND role='SUB_ADMIN'", (max_users, username))
    if c.rowcount <= 0:
        conn.close()
        return jsonify({"status": "error", "message": "Sub-admin not found"}), 404
    conn.commit()
    conn.close()

    return jsonify({"status": "ok", "message": f"Quota updated for {username} → {max_users}"})


@legacy_bp.route("/api/admin/update_subadmin_max_expiry", methods=["POST"])
@login_required_json
def api_update_subadmin_max_expiry():
    guard = require_super_admin_json()
    if guard:
        return guard

    d = request.get_json() or {}
    username = (d.get("username") or "").strip()
    max_expiry_days = d.get("max_expiry_days")
    if not username or max_expiry_days is None:
        return jsonify({"status": "error", "message": "username/max_expiry_days required"}), 400

    try:
        max_expiry_days = int(max_expiry_days)
    except Exception:
        return jsonify({"status": "error", "message": "max_expiry_days must be int"}), 400
    if max_expiry_days < 0:
        return jsonify({"status": "error", "message": "max_expiry_days must be >= 0"}), 400

    conn = db_conn()
    c = conn.cursor()
    c.execute("UPDATE admins SET max_expiry_days=? WHERE username=? AND role='SUB_ADMIN'", (max_expiry_days, username))
    if c.rowcount <= 0:
        conn.close()
        return jsonify({"status": "error", "message": "Sub-admin not found"}), 404
    conn.commit()
    conn.close()
    label = f"{max_expiry_days} days" if max_expiry_days > 0 else "Unlimited"
    return jsonify({"status": "ok", "message": f"Max expiry for {username} → {label}"})


@legacy_bp.route("/api/admin/update_subadmin_perms", methods=["POST"])
@login_required_json
def api_update_subadmin_perms():
    guard = require_super_admin_json()
    if guard:
        return guard

    d = request.get_json() or {}
    username = (d.get("username") or "").strip()
    perms = d.get("permissions")  # list of strings

    if not username or perms is None:
        return jsonify({"status": "error", "message": "username/permissions required"}), 400
    if not isinstance(perms, list):
        return jsonify({"status": "error", "message": "permissions must be a list"}), 400

    # Only allow known permissions
    valid = [p for p in perms if p in ALL_PERMS]
    conn = db_conn()
    c = conn.cursor()
    c.execute("UPDATE admins SET permissions=? WHERE username=? AND role='SUB_ADMIN'", (_json.dumps(valid), username))
    if c.rowcount <= 0:
        conn.close()
        return jsonify({"status": "error", "message": "Sub-admin not found"}), 404
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "message": f"Permissions updated for {username}", "permissions": valid})


@legacy_bp.route("/api/admin/my_perms", methods=["GET"])
@login_required_json
def api_my_perms():
    """Return the current admin's permission list. SUPER_ADMIN gets all."""
    if is_super_admin():
        return jsonify({"status": "ok", "data": ALL_PERMS})
    admin_id = session.get("admin_id")
    return jsonify({"status": "ok", "data": list(get_subadmin_perms(admin_id))})


@legacy_bp.route("/api/change_password", methods=["POST"])
@login_required_json
def api_change_password():
    """Allow any logged-in admin (SUPER or SUB) to change their own password."""
    d = request.get_json() or {}
    current_pw = d.get("current_password") or ""
    new_pw = (d.get("new_password") or "").strip()

    if not current_pw or not new_pw:
        return jsonify({"status": "error", "message": "current_password and new_password required"}), 400
    if len(new_pw) < 6:
        return jsonify({"status": "error", "message": "New password must be at least 6 characters"}), 400

    admin_id = session.get("admin_id")
    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT password_hash FROM admins WHERE id=?", (admin_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"status": "error", "message": "Admin not found"}), 404

    if not check_password_hash(row[0], current_pw):
        conn.close()
        return jsonify({"status": "error", "message": "Current password is incorrect"}), 403

# FIX #1: update password_hash AND plain_password in a single connection (no separate conn2)
    c.execute("UPDATE admins SET password_hash=?, plain_password=? WHERE id=?",
              (generate_password_hash(new_pw), "", admin_id))
    conn.commit()
    conn.close()
    # FIX #1: NEVER log the plain password in audit log or Telegram
    log_action("CHANGE_PASSWORD", session.get("admin_username") or "", "password changed")
    return jsonify({"status": "ok", "message": "Password changed successfully"})


@legacy_bp.route("/api/admin/audit_log", methods=["GET"])
@login_required_json
def api_audit_log():
    if not has_perm("VIEW_AUDIT_LOG"):
        return jsonify({"status": "error", "message": "Forbidden"}), 403

    limit = min(int(request.args.get("limit", 200)), 500)
    search = (request.args.get("search") or "").strip()

    conn = db_conn()
    c = conn.cursor()
    
    # Sub Admins can ONLY see their own logs
    user_filter_sql = ""
    user_filter_params = []
    if not is_super_admin():
        user_filter_sql = " AND admin_username = ? "
        user_filter_params = [session.get("admin_username")]
        
    if search:
        like = f"%{search}%"
        query = f"""
            SELECT id, admin_username, role, action, target_user, detail, created_at
            FROM audit_log
            WHERE (admin_username LIKE ? OR action LIKE ? OR target_user LIKE ?)
            {user_filter_sql}
            ORDER BY id DESC LIMIT ?
        """
        params = [like, like, like] + user_filter_params + [limit]
        c.execute(query, params)
    else:
        where_clause = f"WHERE 1=1 {user_filter_sql}"
        query = f"SELECT id, admin_username, role, action, target_user, detail, created_at FROM audit_log {where_clause} ORDER BY id DESC LIMIT ?"
        params = user_filter_params + [limit]
        c.execute(query, params)
        
    rows = c.fetchall()
    conn.close()

    data = []
    for (rid, au, role, action, target, detail, created_at) in rows:
        data.append({
            "id": rid,
            "admin_username": au,
            "role": role,
            "action": action,
            "target_user": target or "",
            "detail": detail or "",
            "created_at": created_at,
        })
    return jsonify({"status": "ok", "data": data})


@legacy_bp.route("/api/admin/delete_subadmin", methods=["POST"])
@login_required_json
def api_delete_subadmin():
    guard = require_super_admin_json()
    if guard:
        return guard

    d = request.get_json() or {}
    username = (d.get("username") or "").strip()
    if not username:
        return jsonify({"status": "error", "message": "username required"}), 400

    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT id FROM admins WHERE username=? AND role='SUB_ADMIN'", (username,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"status": "error", "message": "Sub-admin not found"}), 404
    admin_id = int(row[0])

    # Disable all users CREATED by this sub-admin (so license check stops working)
    c.execute("UPDATE users SET status='DISABLED' WHERE created_by_admin_id=?", (admin_id,))
    # Remove management mappings for this sub-admin
    c.execute("DELETE FROM admin_user_access WHERE admin_id=?", (admin_id,))
    # Finally delete the sub-admin account
    c.execute("DELETE FROM admins WHERE id=?", (admin_id,))

    conn.commit()
    conn.close()

    return jsonify({"status": "ok", "message": f"Deleted sub-admin {username} and disabled their created users"})


# ---------------- Summary Stats API ----------------
@legacy_bp.route("/api/admin/stats", methods=["GET"])
@login_required_json
def api_admin_stats():
    conn = db_conn()
    c = conn.cursor()
    
    today_str = datetime.date.today().isoformat()
    if is_super_admin():
        c.execute("SELECT count(*) FROM users")
        total_users = c.fetchone()[0]
        c.execute("SELECT count(*) FROM users WHERE status='ENABLED' AND expiry_date >= ?", (today_str,))
        active_users = c.fetchone()[0]
        c.execute("SELECT count(*) FROM users WHERE expiry_date < ?", (today_str,))
        expired_users = c.fetchone()[0]
        c.execute("SELECT count(*) FROM users WHERE status='DISABLED'")
        disabled_users = c.fetchone()[0]
        c.execute("SELECT count(*) FROM admins WHERE role='SUB_ADMIN'")
        total_subadmins = c.fetchone()[0]
        
        c.execute("SELECT count(*) FROM bots")
        total_bots = c.fetchone()[0]
        c.execute("SELECT count(*) FROM bots WHERE is_active=1")
        active_bots = c.fetchone()[0]
        
        c.execute("SELECT count(*) FROM login_history WHERE logged_at LIKE ?", (f"{today_str}%",))
        todays_logins = c.fetchone()[0]
        c.execute("SELECT count(*) FROM login_history")
        total_logins = c.fetchone()[0]
        
        c.execute("SELECT count(*) FROM audit_log")
        total_audit_logs = c.fetchone()[0]
    else:
        admin_id = session.get("admin_id")
        c.execute("SELECT count(*) FROM admin_user_access WHERE admin_id=?", (admin_id,))
        total_users = c.fetchone()[0]
        c.execute('''SELECT count(*) FROM users u JOIN admin_user_access a ON u.id = a.user_id WHERE a.admin_id=? AND u.status='ENABLED' AND u.expiry_date >= ?''', (admin_id, today_str))
        active_users = c.fetchone()[0]
        c.execute('''SELECT count(*) FROM users u JOIN admin_user_access a ON u.id = a.user_id WHERE a.admin_id=? AND u.expiry_date < ?''', (admin_id, today_str))
        expired_users = c.fetchone()[0]
        c.execute('''SELECT count(*) FROM users u JOIN admin_user_access a ON u.id = a.user_id WHERE a.admin_id=? AND u.status='DISABLED' ''', (admin_id,))
        disabled_users = c.fetchone()[0]
        total_subadmins = 0  # Subadmins don't see subadmin counts
        
        # Sub-admins bot counts (only what they have access to)
        c.execute("SELECT count(*) FROM subadmin_bot_access WHERE admin_id=?", (admin_id,))
        allowed_bot_count = c.fetchone()[0]
        if allowed_bot_count == 0:
            c.execute("SELECT count(*) FROM bots")
            total_bots = c.fetchone()[0]
            c.execute("SELECT count(*) FROM bots WHERE is_active=1")
            active_bots = c.fetchone()[0]
        else:
            total_bots = allowed_bot_count
            c.execute("SELECT count(*) FROM bots b JOIN subadmin_bot_access sa ON b.app_name=sa.app_name WHERE sa.admin_id=? AND b.is_active=1", (admin_id,))
            active_bots = c.fetchone()[0]

        # Login metrics are only for users managed by this subadmin
        # FIX: join via users table (TEXT username) instead of user_id (INTEGER)
        c.execute("""
            SELECT count(*) FROM login_history lh
            JOIN users u ON u.username = lh.username
            JOIN admin_user_access a ON a.user_id = u.id
            WHERE a.admin_id=? AND lh.logged_at LIKE ?""", (admin_id, f"{today_str}%"))
        todays_logins = c.fetchone()[0]
        c.execute("""
            SELECT count(*) FROM login_history lh
            JOIN users u ON u.username = lh.username
            JOIN admin_user_access a ON a.user_id = u.id
            WHERE a.admin_id=?""", (admin_id,))
        total_logins = c.fetchone()[0]
        
        c.execute("SELECT count(*) FROM audit_log WHERE admin_username=?", (session.get("admin_username"),))
        total_audit_logs = c.fetchone()[0]

    conn.close()

    return jsonify({
        "status": "ok",
        "data": {
            "total_users": total_users,
            "active_users": active_users,
            "expired_users": expired_users,
            "disabled_users": disabled_users,
            "total_subadmins": total_subadmins,
            "total_bots": total_bots,
            "active_bots": active_bots,
            "todays_logins": todays_logins,
            "total_logins": total_logins,
            "total_audit_logs": total_audit_logs
        }
    })

# ---------------- My Account API ----------------
@legacy_bp.route("/api/admin/my_account_info", methods=["GET"])
@login_required_json
def api_my_account_info():
    admin_id = session.get("admin_id")
    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT username, role, is_active, created_at, full_name, email, last_login, permissions FROM admins WHERE id=?", (admin_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"status": "error", "message": "Admin not found"}), 404

    username, role, is_active, created_at, full_name, email, last_login, perms_json = row
    
    # Sub Admin specific stats
    assigned_users = 0
    created_users = 0
    assigned_bots = []
    
    if role == "SUB_ADMIN":
        c.execute("SELECT count(*) FROM admin_user_access WHERE admin_id=?", (admin_id,))
        assigned_users = c.fetchone()[0]
        c.execute("SELECT count(*) FROM users WHERE created_by_admin_id=?", (admin_id,))
        created_users = c.fetchone()[0]
        
        c.execute("SELECT app_name FROM subadmin_bot_access WHERE admin_id=?", (admin_id,))
        bot_rows = c.fetchall()
        if not bot_rows:
            assigned_bots = ["All Bots"]
        else:
            assigned_bots = [r[0] for r in bot_rows]
    else:
        # SUPER ADMIN
        c.execute("SELECT count(*) FROM users")
        created_users = c.fetchone()[0]
        assigned_bots = ["All Bots"]

    conn.close()
    
    import json
    perms = []
    if perms_json:
        try:
            perms = json.loads(perms_json)
        except:
            perms = ALL_PERMS
    else:
        perms = ALL_PERMS

    return jsonify({
        "status": "ok",
        "data": {
            "full_name": full_name or "",
            "email": email or "",
            "username": username,
            "role": role,
            "is_active": "Active" if is_active else "Disabled",
            "created_at": created_at,
            "last_login": last_login or "Never",
            "assigned_users": assigned_users,
            "created_users": created_users,
            "assigned_bots": assigned_bots,
            "permissions": perms
        }
    })

# ---------------- Edit Profile API ----------------
@legacy_bp.route("/api/admin/edit_profile", methods=["POST"])
@login_required_json
def api_edit_profile():
    if not is_super_admin() and not has_perm("EDIT_PROFILE"):
        return jsonify({"status": "error", "message": "Permission denied. You do not have EDIT_PROFILE permission."}), 403

    admin_id = session.get("admin_id")
    data = request.json or {}
    new_full_name = data.get("full_name", "").strip()
    new_email = data.get("email", "").strip()
    new_username = data.get("username", "").strip()
    new_password = data.get("password", "").strip()

    if not new_username:
        return jsonify({"status": "error", "message": "Username cannot be empty"}), 400

    conn = db_conn()
    c = conn.cursor()

    # Check if the new username is already taken by someone else
    c.execute("SELECT id FROM admins WHERE username=? AND id!=?", (new_username, admin_id))
    if c.fetchone():
        conn.close()
        return jsonify({"status": "error", "message": "Username is already taken"}), 400

    try:
        if new_password:
            # Update password as well
            pw_hash = generate_password_hash(new_password)
            c.execute("UPDATE admins SET full_name=?, email=?, username=?, password_hash=? WHERE id=?", 
                      (new_full_name, new_email, new_username, pw_hash, admin_id))
        else:
            # Update without changing password
            c.execute("UPDATE admins SET full_name=?, email=?, username=? WHERE id=?", 
                      (new_full_name, new_email, new_username, admin_id))
        
        conn.commit()
        # Update session with new username if changed
        session["admin_username"] = new_username
        
        # Audit Log
        log_action("EDIT_PROFILE", new_username, "Profile updated successfully.")
    except Exception as e:
        conn.rollback()
        conn.close()
        return jsonify({"status": "error", "message": f"Database error: {str(e)}"}), 500

    conn.close()
    return jsonify({"status": "ok", "message": "Profile updated successfully"})

# ---------------- Per-user bot blocking API ----------------
@legacy_bp.route("/api/admin/user_bots", methods=["GET"])
@login_required_json
def api_user_bots():
    # SUPER_ADMIN sees all bots; SUB_ADMIN with MANAGE_BOT_BLOCKS perm sees only
    # the bots that SUPER_ADMIN allowed for them.
    if not is_super_admin() and not has_perm("MANAGE_BOT_BLOCKS"):
        return jsonify({"status": "error", "message": "Forbidden"}), 403

    username = (request.args.get("username") or "").strip()
    if not username:
        return jsonify({"status": "error", "message": "username required"}), 400

    # Ensure the sub-admin can manage this user
    if not is_super_admin() and not can_manage_user(username):
        return jsonify({"status": "error", "message": "Forbidden: user not in your scope"}), 403

    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT app_name, required_version FROM bots ORDER BY app_name")
    all_bots = c.fetchall()

    # For SUB_ADMIN: restrict to bots they are allowed to access
    if not is_super_admin():
        admin_id = session.get("admin_id")
        c.execute("SELECT app_name FROM subadmin_bot_access WHERE admin_id=?", (admin_id,))
        allowed_set = {r[0] for r in c.fetchall()}
        all_bots = [(n, v) for (n, v) in all_bots if n in allowed_set]

    c.execute("SELECT app_name FROM user_bot_blocks WHERE username=?", (username,))
    blocked = {r[0] for r in c.fetchall()}
    conn.close()

    data = []
    for (app_name, ver) in all_bots:
        data.append({"app_name": app_name, "required_version": ver, "blocked": app_name in blocked})
    return jsonify({"status": "ok", "data": data})


@legacy_bp.route("/api/admin/toggle_user_bot", methods=["POST"])
@login_required_json
def api_toggle_user_bot():
    # SUPER_ADMIN can toggle any bot; SUB_ADMIN with MANAGE_BOT_BLOCKS perm
    # can only toggle bots they are allowed to access.
    if not is_super_admin() and not has_perm("MANAGE_BOT_BLOCKS"):
        return jsonify({"status": "error", "message": "Forbidden"}), 403

    d = request.get_json() or {}
    username = (d.get("username") or "").strip()
    app_name = (d.get("app_name") or "").strip()
    action = (d.get("action") or "").strip()

    if not username or not app_name or action not in ("block", "unblock"):
        return jsonify({"status": "error", "message": "username/app_name/action required"}), 400

    # SUB_ADMIN: ensure user is in their scope
    if not is_super_admin() and not can_manage_user(username):
        return jsonify({"status": "error", "message": "Forbidden: user not in your scope"}), 403

    # SUB_ADMIN: ensure the bot is in their allowed list
    if not is_super_admin():
        admin_id = session.get("admin_id")
        conn2 = db_conn()
        try:
            c2 = conn2.cursor()
            c2.execute("SELECT COUNT(*) FROM subadmin_bot_access WHERE admin_id=?", (admin_id,))
            restriction_count = c2.fetchone()[0]
            if restriction_count > 0:
                c2.execute("SELECT 1 FROM subadmin_bot_access WHERE admin_id=? AND app_name=?", (admin_id, app_name))
                if not c2.fetchone():
                    return jsonify({"status": "error", "message": "Forbidden: bot not in your allowed list"}), 403
        finally:
            conn2.close()

    conn = db_conn()
    c = conn.cursor()
    if action == "block":
        c.execute("INSERT OR IGNORE INTO user_bot_blocks(username,app_name) VALUES (?,?)", (username, app_name))
        msg = f"{username} BLOCKED from {app_name}"
    else:
        c.execute("DELETE FROM user_bot_blocks WHERE username=? AND app_name=?", (username, app_name))
        msg = f"{username} UNBLOCKED from {app_name}"
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "message": msg})


# ---------------- Bot activity API ----------------
@legacy_bp.route("/api/admin/bot_activity", methods=["GET"])
@login_required_json
def api_bot_activity():
    activity = get_activity_summary()
    if not is_super_admin():
        admin_id = session.get("admin_id")
        conn = db_conn()
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM subadmin_bot_access WHERE admin_id=?", (admin_id,))
        if c.fetchone()[0] > 0:
            c.execute("SELECT app_name FROM subadmin_bot_access WHERE admin_id=?", (admin_id,))
        allowed_set = {r[0] for r in c.fetchall()}
        activity = [a for a in activity if a["app_name"] in allowed_set]
        conn.close()
    return jsonify({"status": "ok", "data": activity})


# --- My Available Bots (for Add User form bot selection) ---
@legacy_bp.route("/api/admin/my_available_bots")
@login_required_json
def api_my_available_bots():
    """Return the list of bots available to the current admin.
    SUPER_ADMIN: all bots.
    SUB_ADMIN: only the bots SUPER_ADMIN allowed for them.
    """
    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT app_name, required_version, is_active FROM bots ORDER BY app_name")
    all_bots = c.fetchall()

    if not is_super_admin():
        admin_id = session.get("admin_id")
        c.execute("SELECT app_name FROM subadmin_bot_access WHERE admin_id=?", (admin_id,))
        allowed_set = {r[0] for r in c.fetchall()}
        all_bots = [(n, v, a) for (n, v, a) in all_bots if n in allowed_set]

    conn.close()
    data = [{"app_name": n, "required_version": v, "is_active": a} for (n, v, a) in all_bots]
    return jsonify({"status": "ok", "data": data})


# ---------------- Bot management API ----------------
@legacy_bp.route("/api/admin/bots", methods=["GET"])
@login_required_json
def api_list_bots():
    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT app_name, required_version, is_active, created_at FROM bots ORDER BY id DESC")
    all_bots = c.fetchall()
    
    if not is_super_admin():
        admin_id = session.get("admin_id")
        c.execute("SELECT app_name FROM subadmin_bot_access WHERE admin_id=?", (admin_id,))
        allowed_set = {r[0] for r in c.fetchall()}
        all_bots = [(n, v, a, c) for (n, v, a, c) in all_bots if n in allowed_set]

    conn.close()
    data = []
    for (app_name, ver, is_active, created_at) in all_bots:
        data.append({"app_name": app_name, "required_version": ver, "is_active": bool(int(is_active)), "created_at": created_at})
    return jsonify({"status": "ok", "data": data})


@legacy_bp.route("/api/admin/add_bot", methods=["POST"])
@login_required_json
def api_add_bot():
    guard = require_super_admin_json()
    if guard:
        return guard
    d = request.get_json() or {}
    app_name = (d.get("app_name") or "").strip()
    ver = (d.get("required_version") or "1.0").strip()
    if not app_name:
        return jsonify({"status": "error", "message": "app_name required"}), 400
    conn = db_conn()
    c = conn.cursor()
    try:
        c.execute("INSERT INTO bots(app_name,required_version,is_active,created_at) VALUES (?,?,?,?)",
                  (app_name, ver, 1, datetime.datetime.utcnow().isoformat()))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"status": "error", "message": "Bot already exists"}), 400
    conn.close()
    return jsonify({"status": "ok", "message": f"Bot '{app_name}' added (v{ver})"})


@legacy_bp.route("/api/admin/toggle_bot", methods=["POST"])
@login_required_json
def api_toggle_bot():
    guard = require_super_admin_json()
    if guard:
        return guard
    d = request.get_json() or {}
    app_name = (d.get("app_name") or "").strip()
    if not app_name:
        return jsonify({"status": "error", "message": "app_name required"}), 400
    new_active = 1 if int(d.get("is_active", 0)) else 0
    conn = db_conn()
    c = conn.cursor()
    c.execute("UPDATE bots SET is_active=? WHERE app_name=?", (new_active, app_name))
    if new_active == 0:
        c.execute("UPDATE store_bot_pricing SET is_active=0 WHERE app_name=?", (app_name,))
    if c.rowcount <= 0:
        conn.close()
        return jsonify({"status": "error", "message": "Bot not found"}), 404
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "message": f"{app_name} {'ON' if new_active else 'OFF'}"})


@legacy_bp.route("/api/admin/update_bot_version", methods=["POST"])
@login_required_json
def api_update_bot_version():
    guard = require_super_admin_json()
    if guard:
        return guard
    d = request.get_json() or {}
    app_name = (d.get("app_name") or "").strip()
    ver = (d.get("required_version") or "").strip()
    if not app_name or not ver:
        return jsonify({"status": "error", "message": "app_name/version required"}), 400
    conn = db_conn()
    c = conn.cursor()
    c.execute("UPDATE bots SET required_version=? WHERE app_name=?", (ver, app_name))
    if c.rowcount <= 0:
        conn.close()
        return jsonify({"status": "error", "message": "Bot not found"}), 404
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "message": f"{app_name} → v{ver}"})


@legacy_bp.route("/api/admin/delete_bot", methods=["POST"])
@login_required_json
def api_delete_bot():
    guard = require_super_admin_json()
    if guard:
        return guard
    d = request.get_json() or {}
    app_name = (d.get("app_name") or "").strip()
    if not app_name:
        return jsonify({"status": "error", "message": "app_name required"}), 400
    conn = db_conn()
    c = conn.cursor()
    c.execute("DELETE FROM bots WHERE app_name=?", (app_name,))
    c.execute("DELETE FROM store_bot_pricing WHERE app_name=?", (app_name,))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "message": f"Deleted {app_name}"})


# ---------------- Download All Users ----------------
@legacy_bp.route("/api/download_users")
@login_required_json
def api_download_users():
    if not is_super_admin() and not has_perm("DOWNLOAD_USERS"):
        return jsonify({"status": "error", "message": "Permission denied: DOWNLOAD_USERS"}), 403

    conn = db_conn()
    c = conn.cursor()
    if is_super_admin():
        c.execute("SELECT username, activation_key, status, machine_id, expiry_date FROM users ORDER BY id")
    else:
        admin_id = session.get("admin_id")
        c.execute(
            "SELECT u.username, u.activation_key, u.status, u.machine_id, u.expiry_date "
            "FROM users u JOIN admin_user_access a ON a.user_id=u.id "
            "WHERE a.admin_id=? ORDER BY u.id",
            (admin_id,)
        )
    rows = c.fetchall()
    conn.close()

    today = datetime.date.today()
    lines = ["Username,Expiry,Activation Key,Status,Machine ID,Days Left"]
    for (u, k, s, m, e) in rows:
        try:
            days = (datetime.date.fromisoformat(e) - today).days
        except Exception:
            days = "N/A"
        lines.append(f"{u},{e},{k},{s},{m},{days}")

    from flask import Response
    return Response("\n".join(lines), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=users.csv"})


# ---------------- License check shared helper ----------------
def _perform_license_check(data: dict):
    """
    Core license validation logic shared by /api/ck and /api/ck/login.
    Normalises field names, runs all checks, records login history (including
    os/host fields) and returns a Flask response tuple (response, status_code).
    """
    username    = (data.get("usrname") or data.get("username") or "").strip()
    machine_id  = (data.get("key") or data.get("machine_id") or "").strip()
    license_key = (data.get("license") or data.get("activation_key") or "").strip()
    client_version = data.get("version", "")
    client_app  = data.get("app_name", "")

    if not username or not machine_id or not license_key:
        return jsonify({"error": "Missing fields"}), 400

    # --- Maintenance Mode Check ---
    if get_setting("maintenance_mode", "0") == "1":
        custom_msg = get_setting("maintenance_message", "System is under maintenance. Please try again later.")
        return jsonify({"error": custom_msg}), 503

    # --- Per-User Bot Blocking Check ---
    conn = db_conn(); c = conn.cursor()
    target_app = client_app if client_app else "__ALL__"
    c.execute("SELECT 1 FROM user_bot_blocks WHERE username=? AND app_name=?", (username, target_app))
    is_blocked = c.fetchone()
    conn.close()
    if is_blocked:
        return jsonify({"error": "You are blocked from using this bot/app."}), 403

    # --- Sub-Admin Bot Restriction Check ---
    if client_app:
        conn2 = db_conn()
        try:
            c2 = conn2.cursor()
            c2.execute("SELECT created_by_admin_id, created_by_role FROM users WHERE username=?", (username,))
            urow = c2.fetchone()
            if urow and urow[1] == 'SUB_ADMIN' and urow[0]:
                sub_admin_id = urow[0]
                c2.execute("SELECT COUNT(*) FROM subadmin_bot_access WHERE admin_id=?", (sub_admin_id,))
                restriction_count = c2.fetchone()[0]
                if restriction_count > 0:
                    c2.execute("SELECT 1 FROM subadmin_bot_access WHERE admin_id=? AND app_name=?", (sub_admin_id, client_app))
                    if not c2.fetchone():
                        return jsonify({"error": "This bot is not available for your account."}), 403
        except Exception as e:
            current_app.logger.error(f"Sub-admin bot restriction check error: {e}")
        finally:
            conn2.close()

    # --- Bot/App version check ---
    def _parse_ver(v):
        try:
            return tuple(int(x) for x in str(v).strip().split("."))
        except Exception:
            return (0,)

    if not client_app:
        return jsonify({"error": "Connection Error: You seem to be using an outdated or unsupported version. Please update your app or use the correct version to continue."}), 403

    conn = db_conn(); c = conn.cursor()
    c.execute("SELECT required_version, is_active FROM bots WHERE app_name=?", (client_app,))
    bot_row = c.fetchone()
    conn.close()

    if not bot_row:
        return jsonify({
            "error": "Access Denied: This bot or application is no longer available in our system. Please contact the admin for help.",
            "required_app": client_app
        }), 403

    req_ver, bot_active = bot_row
    if not int(bot_active):
        return jsonify({
            "error": "Service Suspended: This application is temporarily disabled or removed. Please contact your administrator.",
            "required_version": req_ver, "required_app": client_app
        }), 403

    # Block ONLY if client version is OLDER than required (not newer)
    if client_version and _parse_ver(client_version) < _parse_ver(req_ver):
        return jsonify({
            "error": f"Update Required! Current: v{client_version}, Required: v{req_ver}",
            "required_version": req_ver, "required_app": client_app
        }), 403

    # --- User lookup ---
    conn = db_conn(); c = conn.cursor()
    c.execute("SELECT activation_key, status, machine_id, expiry_date FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "User not found"}), 404

    db_license, status, db_machine, expiry_date = row

    # --- Expiry check ---
    today = datetime.date.today()
    try:
        expiry = datetime.date.fromisoformat(expiry_date)
        days_left = (expiry - today).days
    except Exception:
        days_left = None

    if days_left is not None and days_left < 0:
        return jsonify({"error": "License expired", "days_left": 0}), 403
    if status != "ENABLED":
        return jsonify({"error": "User disabled"}), 403

    # --- Machine ID check / first-time bind ---
    if db_machine in ("-", "", None):
        conn = db_conn(); c = conn.cursor()
        c.execute("UPDATE users SET machine_id=? WHERE username=?", (machine_id, username))
        conn.commit(); conn.close()
        db_machine = machine_id
    elif db_machine != machine_id:
        return jsonify({"error": "Machine mismatch"}), 403

    if db_license != license_key or db_machine != machine_id:
        return jsonify({"error": "Invalid license"}), 403

    # --- Build success response ---
    resp = {
        "status": "ok",
        "key":  base64.b64encode(machine_id.encode()).decode(),
        "key1": base64.b64encode(license_key.encode()).decode(),
        "key0": base64.b64encode(username.encode()).decode(),
        "days_left": days_left,
    }
    conn = db_conn(); c = conn.cursor()
    c.execute("SELECT required_version FROM bots WHERE app_name=? AND is_active=1", (client_app,))
    brow = c.fetchone()
    conn.close()
    if brow:
        resp["required_version"] = brow[0]
        resp["required_app"] = client_app

    # --- Record login history (os + host fields included for both endpoints) ---
    try:
        _ip   = request.remote_addr or ""
        _now  = datetime.datetime.utcnow().isoformat(timespec="seconds")
        _os   = data.get("os", "")
        _host = data.get("host", "")
        _lh = db_conn(); _lhc = _lh.cursor()
        _lhc.execute(
            "INSERT INTO login_history(username,app_name,client_version,machine_id,ip_address,logged_at,os,host) VALUES (?,?,?,?,?,?,?,?)",
            (username, client_app or "", client_version or "", machine_id, _ip, _now, _os, _host)
        )
        # Keep only last 40 days of login history to save database space
        _forty_days_ago = (datetime.datetime.utcnow() - datetime.timedelta(days=40)).isoformat()
        _lhc.execute("DELETE FROM login_history WHERE logged_at < ?", (_forty_days_ago,))
        _lh.commit(); _lh.close()
    except Exception as e:
        current_app.logger.error(f"Login history error: {e}")

    track_activity(client_app, username)
    return jsonify(resp), 200


# ---------------- Client license check API ----------------
@legacy_bp.route("/api/ck", methods=["POST"])
def api_ck():
    # IP-level rate limit (60 req / 60 s, in-memory per worker)
    client_ip = request.remote_addr or "0.0.0.0"
    if _ck_check_ratelimit(client_ip):
        return jsonify({"error": "Too many requests. Please wait and try again."}), 429
    return _perform_license_check(request.get_json() or {})


# ---------------- /api/ck/login (new-style client alias) ----------------
@legacy_bp.route("/api/ck/login", methods=["POST"])
def api_ck_login():
    """Alias endpoint that maps new-style field names to legacy names."""
    data = request.get_json() or {}
    # Normalise field names: new → legacy
    if "username" in data:       data.setdefault("usrname", data["username"])
    if "activation_key" in data: data.setdefault("license", data["activation_key"])
    if "machine_id" in data:     data.setdefault("key",     data["machine_id"])
    return _perform_license_check(data)


# --- Login History (SUPER_ADMIN only) ---
@legacy_bp.route("/api/admin/login_history", methods=["GET"])
@login_required_json
def api_login_history():
    if not (is_super_admin() or has_perm('VIEW_LOGIN_HISTORY')):
        return jsonify({"status": "error", "message": "Forbidden"}), 403
    username_f = (request.args.get("username") or "").strip()
    app_f      = (request.args.get("app_name") or "").strip()
    date_f     = (request.args.get("date") or "").strip()  # YYYY-MM-DD
    limit      = min(int(request.args.get("limit", "500")), 1000)

    conn = db_conn(); c = conn.cursor()
    query  = "SELECT id,username,app_name,client_version,machine_id,ip_address,logged_at,os,host FROM login_history WHERE 1=1"
    params = []
    if username_f:
        query += " AND username LIKE ?"; params.append(f"%{username_f}%")
    if app_f:
        query += " AND app_name LIKE ?";  params.append(f"%{app_f}%")
    if date_f:
        query += " AND logged_at LIKE ?"; params.append(f"{date_f}%")
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    c.execute(query, params)
    rows = c.fetchall(); conn.close()
    data = [{"id": r[0], "username": r[1], "app_name": r[2] or "-",
             "version": r[3] or "-", "machine_id": r[4] or "-",
             "ip": r[5] or "-", "time": r[6], "os": r[7] or "-", "host": r[8] or "-"} for r in rows]
    return jsonify({"status": "ok", "data": data, "total": len(data)})


# =================== NEW FEATURE ENDPOINTS ===================

# --- User Activity Summary ---
@legacy_bp.route("/api/admin/activity_summary")
@login_required_json
def api_activity_summary():
    if not is_super_admin() and not has_perm('VIEW_ACTIVITY_SUMMARY'):
        return jsonify({"status": "error", "message": "Permission denied"}), 403
    conn = db_conn()
    c = conn.cursor()
    try:
        if is_super_admin():
            # SUPER_ADMIN: all users
            c.execute("""
                SELECT u.username, u.status,
                       COUNT(lh.id) as login_count,
                       MAX(lh.logged_at) as last_login,
                       (SELECT lh2.app_name FROM login_history lh2
                        WHERE lh2.username=u.username AND lh2.app_name IS NOT NULL AND lh2.app_name!=''
                        GROUP BY lh2.app_name ORDER BY COUNT(*) DESC LIMIT 1) as top_bot
                FROM users u
                LEFT JOIN login_history lh ON lh.username = u.username
                GROUP BY u.username, u.status
                ORDER BY login_count DESC, u.username
            """)
        else:
            # SUB_ADMIN: only their assigned users
            admin_id = session.get("admin_id")
            c.execute("""
                SELECT u.username, u.status,
                       COUNT(lh.id) as login_count,
                       MAX(lh.logged_at) as last_login,
                       (SELECT lh2.app_name FROM login_history lh2
                        WHERE lh2.username=u.username AND lh2.app_name IS NOT NULL AND lh2.app_name!=''
                        GROUP BY lh2.app_name ORDER BY COUNT(*) DESC LIMIT 1) as top_bot
                FROM users u
                LEFT JOIN login_history lh ON lh.username = u.username
                WHERE u.created_by_admin_id = ?
                GROUP BY u.username, u.status
                ORDER BY login_count DESC, u.username
            """, (admin_id,))
        rows = c.fetchall()
    except Exception as ex:
        conn.close()
        return jsonify({"status": "error", "message": str(ex)}), 500
    conn.close()
    today = datetime.date.today()
    thirty_ago = (datetime.datetime.utcnow() - datetime.timedelta(days=30)).strftime('%Y-%m-%d')
    result = []
    for username, status, login_count, last_login, top_bot in rows:
        days_ago = None
        if last_login:
            try:
                ll_date = datetime.date.fromisoformat(last_login[:10])
                days_ago = (today - ll_date).days
            except Exception as e:
                current_app.logger.error(f"Error: {e}")
        result.append({
            "username": username,
            "status": status,
            "login_count": login_count or 0,
            "last_login": last_login[:16] if last_login else "",
            "days_ago": days_ago,
            "top_bot": top_bot or ""
        })
    # Top 10 active in last 30 days
    conn2 = db_conn()
    c2 = conn2.cursor()
    try:
        if is_super_admin():
            c2.execute("""
                SELECT lh.username, COUNT(*) as cnt, MAX(lh.logged_at) as last_login,
                       (SELECT lh2.app_name FROM login_history lh2
                        WHERE lh2.username=lh.username AND lh2.app_name IS NOT NULL AND lh2.app_name!=''
                        GROUP BY lh2.app_name ORDER BY COUNT(*) DESC LIMIT 1) as top_bot
                FROM login_history lh
                WHERE lh.logged_at >= ?
                GROUP BY lh.username ORDER BY cnt DESC LIMIT 10
            """, (thirty_ago,))
        else:
            admin_id2 = session.get("admin_id")
            c2.execute("""
                SELECT lh.username, COUNT(*) as cnt, MAX(lh.logged_at) as last_login,
                       (SELECT lh2.app_name FROM login_history lh2
                        WHERE lh2.username=lh.username AND lh2.app_name IS NOT NULL AND lh2.app_name!=''
                        GROUP BY lh2.app_name ORDER BY COUNT(*) DESC LIMIT 1) as top_bot
                FROM login_history lh
                JOIN users u ON u.username = lh.username
                WHERE lh.logged_at >= ? AND u.created_by_admin_id = ?
                GROUP BY lh.username ORDER BY cnt DESC LIMIT 10
            """, (thirty_ago, admin_id2))
        top10 = [{"username": r[0], "count": r[1],
                  "last_login": r[2][:16] if r[2] else "",
                  "top_bot": r[3] or ""} for r in c2.fetchall()]
    except Exception:
        top10 = []
    finally:
        conn2.close()
    return jsonify({"status": "ok", "data": result, "top10_30d": top10})


# --- Maintenance Mode ---
@legacy_bp.route("/api/admin/maintenance", methods=["GET", "POST"])
@login_required_json
def api_maintenance():
    guard = require_super_admin_json()
    if guard:
        return guard
    if request.method == "GET":
        on = get_setting("maintenance_mode", "0") == "1"
        msg = get_setting("maintenance_message", "System is under maintenance.")
        return jsonify({"status": "ok", "data": {"enabled": on, "message": msg}})
    d = request.get_json() or {}
    enabled = bool(int(d.get("enabled", 0)))
    msg = (d.get("message") or "System is under maintenance. Please try again later.").strip()
    set_setting("maintenance_mode", "1" if enabled else "0")
    set_setting("maintenance_message", msg)
    state = "ENABLED" if enabled else "DISABLED"
    tg_alert(f"Maintenance Mode {state}: {msg}")
    return jsonify({"status": "ok", "message": f"Maintenance mode {state}"})


# --- Bulk Enable / Disable ---
@legacy_bp.route("/api/bulk_action", methods=["POST"])
@login_required_json
def api_bulk_action():
    d = request.get_json() or {}
    usernames = d.get("usernames") or []
    action = (d.get("action") or "").strip()
    if not usernames or action not in ("enable", "disable", "delete"):
        return jsonify({"status": "error", "message": "usernames list and action required"}), 400
    if action in ("enable", "disable") and not has_perm("TOGGLE_USER"):
        return jsonify({"status": "error", "message": "Permission denied: TOGGLE_USER"}), 403
    if action == "delete" and not has_perm("DELETE_USER"):
        return jsonify({"status": "error", "message": "Permission denied: DELETE_USER"}), 403

    ok, fail = 0, 0
    conn = db_conn()
    c = conn.cursor()

    if action == "delete":
        for u in usernames:
            u = str(u).strip()
            if not u or not can_manage_user(u):
                fail += 1
                continue
            c.execute("SELECT id FROM users WHERE username=?", (u,))
            row = c.fetchone()
            if row:
                c.execute("DELETE FROM admin_user_access WHERE user_id=?", (row[0],))
                c.execute("DELETE FROM users WHERE id=?", (row[0],))
                ok += 1
            else:
                fail += 1
        conn.commit()
        conn.close()
        for u in usernames:
            u = str(u).strip()
            if u and can_manage_user(u):
                log_action("DELETE_USER", u, "bulk_delete")
        return jsonify({"status": "ok", "message": f"{ok} users deleted, {fail} failed"})
    else:
        new_status = "ENABLED" if action == "enable" else "DISABLED"
        for u in usernames:
            u = str(u).strip()
            if not u or not can_manage_user(u):
                fail += 1
                continue
            c.execute("UPDATE users SET status=? WHERE username=?", (new_status, u))
            ok += 1
        conn.commit()
        conn.close()
        for u in usernames:
            u = str(u).strip()
            if u and can_manage_user(u):
                log_action("TOGGLE_USER", u, f"bulk={new_status}")
        return jsonify({"status": "ok", "message": f"{ok} users {new_status}, {fail} failed"})


# --- Bulk CSV Import ---
@legacy_bp.route("/api/bulk_import", methods=["POST"])
@login_required_json
def api_bulk_import():
    if not has_perm("BULK_IMPORT") and not has_perm("ADD_USER"):
        return jsonify({"status": "error", "message": "Permission denied: ADD_USER"}), 403
    # SUB_ADMIN quota check: count how many rows will be imported vs remaining quota
    if not is_super_admin():
        if not subadmin_has_quota():
            return jsonify({"status": "error", "message": "User quota limit reached"}), 403
    d = request.get_json() or {}
    csv_text = (d.get("csv") or "").strip()
    if not csv_text:
        return jsonify({"status": "error", "message": "csv required"}), 400
    import csv, io as _io
    results = []
    for i, row in enumerate(csv.reader(_io.StringIO(csv_text))):
        if not row or str(row[0]).strip().startswith("#"):
            continue
        username = row[0].strip()
        expiry = row[1].strip() if len(row) > 1 and row[1].strip() else (datetime.date.today() + datetime.timedelta(days=30)).isoformat()
        key = row[2].strip() if len(row) > 2 and row[2].strip() else secrets.token_urlsafe(8)
        if not username:
            continue
        try:
            datetime.date.fromisoformat(expiry)
        except Exception:
            expiry = (datetime.date.today() + datetime.timedelta(days=30)).isoformat()
        now_iso = datetime.datetime.utcnow().isoformat()
        try:
            conn = db_conn(); c = conn.cursor()
            c.execute(
                "INSERT INTO users(username,activation_key,status,machine_id,expiry_date,created_by_admin_id,created_by_username,created_by_role,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (username, key, "ENABLED", "-", expiry, session.get("admin_id"), session.get("admin_username"), session.get("role"), now_iso)
            )
            uid = c.lastrowid
            if not is_super_admin():
                c.execute("INSERT OR IGNORE INTO admin_user_access(admin_id,user_id) VALUES (?,?)", (session.get("admin_id"), uid))
            conn.commit(); conn.close()
            log_action("ADD_USER", username, f"bulk_import expiry={expiry}")
            results.append({"row": i+1, "username": username, "status": "ok", "key": key})
        except sqlite3.IntegrityError:
            results.append({"row": i+1, "username": username, "status": "exists"})
        except Exception as ex:
            results.append({"row": i+1, "username": username, "status": "error", "reason": str(ex)})
    ok_count = sum(1 for r in results if r["status"] == "ok")
    return jsonify({"status": "ok", "imported": ok_count, "total": len(results), "results": results})


# --- User Tags ---
@legacy_bp.route("/api/update_user_tags", methods=["POST"])
@login_required_json
def api_update_user_tags():
    if not has_perm("UPDATE_TAGS"):
        return jsonify({"status": "error", "message": "Permission denied: UPDATE_TAGS"}), 403
    d = request.get_json() or {}
    username = (d.get("username") or "").strip()
    tags = (d.get("tags") or "").strip()
    if not username:
        return jsonify({"status": "error", "message": "username required"}), 400
    if not can_manage_user(username):
        return jsonify({"status": "error", "message": "Forbidden"}), 403
    conn = db_conn(); c = conn.cursor()
    c.execute("UPDATE users SET tags=? WHERE username=?", (tags, username))
    conn.commit(); conn.close()
    return jsonify({"status": "ok", "message": f"Tags updated for {username}"})


# --- User Note History ---
@legacy_bp.route("/api/admin/note_history", methods=["GET"])
@login_required_json
def api_note_history():
    if not has_perm("VIEW_NOTE_HISTORY"):
        return jsonify({"status": "error", "message": "Permission denied: VIEW_NOTE_HISTORY"}), 403
    username = (request.args.get("username") or "").strip()
    if not username:
        return jsonify({"status": "error", "message": "username required"}), 400
    if not can_manage_user(username):
        return jsonify({"status": "error", "message": "Forbidden"}), 403
    conn = db_conn(); c = conn.cursor()
    c.execute("SELECT note, admin_username, created_at FROM user_note_history WHERE username=? ORDER BY id DESC LIMIT 50", (username,))
    rows = c.fetchall(); conn.close()
    return jsonify({"status": "ok", "data": [{"note": r[0] or "", "admin": r[1] or "?", "time": r[2]} for r in rows]})



# --- Bot Update Message ---
@legacy_bp.route("/api/admin/update_bot_message", methods=["POST"])
@login_required_json
def api_update_bot_message():
    guard = require_super_admin_json()
    if guard:
        return guard
    d = request.get_json() or {}
    app_name_val = (d.get("app_name") or "").strip()
    msg = (d.get("update_message") or "").strip() or None
    if not app_name_val:
        return jsonify({"status": "error", "message": "app_name required"}), 400
    conn = db_conn(); c = conn.cursor()
    c.execute("UPDATE bots SET update_message=? WHERE app_name=?", (msg, app_name_val))
    if c.rowcount <= 0:
        conn.close()
        return jsonify({"status": "error", "message": "Bot not found"}), 404
    conn.commit(); conn.close()
    return jsonify({"status": "ok", "message": f"Update message set for {app_name_val}"})


# --- Expiry Calendar (30 days) ---
@legacy_bp.route("/api/admin/expiry_calendar", methods=["GET"])
@login_required_json
def api_expiry_calendar():
    today = datetime.date.today()
    end = today + datetime.timedelta(days=30)
    conn = db_conn(); c = conn.cursor()
    if is_super_admin():
        c.execute("SELECT expiry_date, COUNT(*) FROM users WHERE expiry_date BETWEEN ? AND ? GROUP BY expiry_date", (today.isoformat(), end.isoformat()))
    else:
        c.execute("SELECT u.expiry_date, COUNT(*) FROM users u JOIN admin_user_access a ON a.user_id=u.id WHERE a.admin_id=? AND u.expiry_date BETWEEN ? AND ? GROUP BY u.expiry_date", (session.get("admin_id"), today.isoformat(), end.isoformat()))
    by_date = {r[0]: r[1] for r in c.fetchall()}; conn.close()
    data = [{"date": (today + datetime.timedelta(days=i)).isoformat(), "count": by_date.get((today + datetime.timedelta(days=i)).isoformat(), 0)} for i in range(31)]
    return jsonify({"status": "ok", "data": data})


# --- Users by Expiry Date (calendar click) ---
@legacy_bp.route("/api/admin/users_by_expiry", methods=["GET"])
@login_required_json
def api_users_by_expiry():
    date_str = (request.args.get("date") or "").strip()
    if not date_str:
        return jsonify({"status": "error", "message": "date required"}), 400
    try:
        datetime.date.fromisoformat(date_str)
    except ValueError:
        return jsonify({"status": "error", "message": "invalid date format"}), 400
    conn = db_conn(); c = conn.cursor()
    if is_super_admin():
        c.execute(
            "SELECT username, activation_key, status, machine_id, expiry_date, COALESCE(tags,'') "
            "FROM users WHERE expiry_date=? ORDER BY username",
            (date_str,)
        )
    else:
        admin_id = session.get("admin_id")
        c.execute(
            "SELECT u.username, u.activation_key, u.status, u.machine_id, u.expiry_date, COALESCE(u.tags,'') "
            "FROM users u JOIN admin_user_access a ON a.user_id=u.id "
            "WHERE a.admin_id=? AND u.expiry_date=? ORDER BY u.username",
            (admin_id, date_str)
        )
    rows = c.fetchall(); conn.close()
    data = [{"username": r[0], "activation_key": r[1], "status": r[2],
             "machine_id": r[3], "expiry_date": r[4], "tags": r[5]} for r in rows]
    return jsonify({"status": "ok", "data": data})


# --- Dashboard Charts Data ---
@legacy_bp.route("/api/admin/dashboard_charts", methods=["GET"])
@login_required_json
def api_dashboard_charts():
    admin_id = session.get("admin_id")
    conn = db_conn()
    c = conn.cursor()
    
    # 1. User Growth (Last 30 Days)
    today = datetime.date.today()
    user_growth_labels = []
    user_growth_data = []
    for i in range(29, -1, -1):
        d = today - datetime.timedelta(days=i)
        user_growth_labels.append(d.strftime("%b %d"))
        if is_super_admin():
            c.execute("SELECT COUNT(*) FROM users WHERE created_at LIKE ?", (f"{d.isoformat()}%",))
        else:
            c.execute("SELECT COUNT(*) FROM users u JOIN admin_user_access a ON a.user_id=u.id WHERE a.admin_id=? AND u.created_at LIKE ?", (admin_id, f"{d.isoformat()}%"))
        user_growth_data.append(c.fetchone()[0])
        
    # 2. Bot Usage (Top 5 bots)
    if is_super_admin():
        c.execute("SELECT app_name, COUNT(*) FROM login_history GROUP BY app_name ORDER BY COUNT(*) DESC LIMIT 5")
    else:
        # FIX: join via users table (TEXT username) instead of user_id (INTEGER)
        c.execute("""
            SELECT lh.app_name, COUNT(*)
            FROM login_history lh
            JOIN users u ON u.username = lh.username
            JOIN admin_user_access a ON a.user_id = u.id
            WHERE a.admin_id=?
            GROUP BY lh.app_name ORDER BY COUNT(*) DESC LIMIT 5""", (admin_id,))
    bot_usage_rows = c.fetchall()
    bot_usage_labels = [r[0] or "Unknown" for r in bot_usage_rows]
    bot_usage_data = [r[1] for r in bot_usage_rows]
    if not bot_usage_labels:
        bot_usage_labels = ["No Data"]
        bot_usage_data = [1]
        
    # 3. Login Activity (Last 7 Days)
    login_labels = []
    login_data = []
    for i in range(6, -1, -1):
        d = today - datetime.timedelta(days=i)
        login_labels.append(d.strftime("%a"))
        if is_super_admin():
            c.execute("SELECT COUNT(*) FROM login_history WHERE logged_at LIKE ?", (f"{d.isoformat()}%",))
        else:
            # FIX: join via users table (TEXT username) instead of user_id (INTEGER)
            c.execute("""
                SELECT COUNT(*) FROM login_history lh
                JOIN users u ON u.username = lh.username
                JOIN admin_user_access a ON a.user_id = u.id
                WHERE a.admin_id=? AND lh.logged_at LIKE ?""", (admin_id, f"{d.isoformat()}%"))
        login_data.append(c.fetchone()[0])
        
    # 4. License Expiry (Within 7, 30, 30+)
    d7 = (today + datetime.timedelta(days=7)).isoformat()
    d30 = (today + datetime.timedelta(days=30)).isoformat()
    today_str = today.isoformat()
    
    if is_super_admin():
        c.execute("SELECT COUNT(*) FROM users WHERE expiry_date >= ? AND expiry_date <= ?", (today_str, d7))
        exp_7 = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM users WHERE expiry_date > ? AND expiry_date <= ?", (d7, d30))
        exp_30 = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM users WHERE expiry_date > ?", (d30,))
        exp_more = c.fetchone()[0]
    else:
        c.execute("SELECT COUNT(*) FROM users u JOIN admin_user_access a ON u.id = a.user_id WHERE a.admin_id=? AND u.expiry_date >= ? AND u.expiry_date <= ?", (admin_id, today_str, d7))
        exp_7 = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM users u JOIN admin_user_access a ON u.id = a.user_id WHERE a.admin_id=? AND u.expiry_date > ? AND u.expiry_date <= ?", (admin_id, d7, d30))
        exp_30 = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM users u JOIN admin_user_access a ON u.id = a.user_id WHERE a.admin_id=? AND u.expiry_date > ?", (admin_id, d30))
        exp_more = c.fetchone()[0]
        
    expiry_labels = ['Within 7 Days', 'Within 30 Days', '30+ Days']
    expiry_data = [exp_7, exp_30, exp_more]
    
    conn.close()
    
    return jsonify({
        "status": "ok",
        "data": {
            "user_growth": {"labels": user_growth_labels, "data": user_growth_data},
            "bot_usage": {"labels": bot_usage_labels, "data": bot_usage_data},
            "login_activity": {"labels": login_labels, "data": login_data},
            "license_expiry": {"labels": expiry_labels, "data": expiry_data}
        }
    })

# --- Monthly Stats ---
@legacy_bp.route("/api/admin/stats_chart", methods=["GET"])
@login_required_json
def api_stats_chart():
    result = []
    today = datetime.date.today()
    # FIX #8: safe month arithmetic using calendar to avoid m=0 or m=13 edge cases
    import calendar as _cal
    conn = db_conn(); c = conn.cursor()
    for i in range(5, -1, -1):
        # Calculate correct year/month by stepping back i months
        total_months = today.year * 12 + (today.month - 1) - i
        y = total_months // 12
        m = total_months % 12 + 1
        ms = datetime.date(y, m, 1)
        last_day = _cal.monthrange(y, m)[1]
        me = datetime.date(y, m, last_day) + datetime.timedelta(days=1)  # first day of next month
        label = ms.strftime("%b %Y")
        if is_super_admin():
            c.execute("SELECT COUNT(*) FROM users WHERE created_at >= ? AND created_at < ?", (ms.isoformat(), me.isoformat()))
        else:
            c.execute("SELECT COUNT(*) FROM users u JOIN admin_user_access a ON u.id = a.user_id WHERE a.admin_id=? AND u.created_at >= ? AND u.created_at < ?", (session.get("admin_id"), ms.isoformat(), me.isoformat()))
        new_u = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM users WHERE expiry_date >= ? AND expiry_date < ?", (ms.isoformat(), me.isoformat()))
        exp_u = c.fetchone()[0]
        result.append({"month": label, "new_users": new_u, "expired_users": exp_u})
    conn.close()
    return jsonify({"status": "ok", "data": result})


# --- Sub-Admin Report ---
@legacy_bp.route("/api/admin/subadmin_report", methods=["GET"])
@login_required_json
def api_subadmin_report():
    guard = require_super_admin_json()
    if guard:
        return guard
    conn = db_conn(); c = conn.cursor()
    c.execute("SELECT admin_username, action, COUNT(*) FROM audit_log WHERE role='SUB_ADMIN' GROUP BY admin_username, action ORDER BY admin_username")
    rows = c.fetchall(); conn.close()
    report = {}
    for (au, action, cnt) in rows:
        report.setdefault(au, {})[action] = cnt
    data = [{"username": k, "actions": v, "total": sum(v.values())} for k, v in report.items()]
    data.sort(key=lambda x: x["total"], reverse=True)
    return jsonify({"status": "ok", "data": data})


# --- Sub-Admin Activity Summary (SUPER_ADMIN only) ---
@legacy_bp.route("/api/admin/subadmin_activity", methods=["GET"])
@login_required_json
def api_subadmin_activity():
    guard = require_super_admin_json()
    if guard:
        return guard
    conn = db_conn(); c = conn.cursor()
    today = datetime.date.today().isoformat()
    c.execute("SELECT id, username, is_active FROM admins WHERE role='SUB_ADMIN' ORDER BY username")
    subadmins = c.fetchall()
    result = []
    for (admin_id, username, is_active) in subadmins:
        # Count total users created by this sub-admin
        c.execute("SELECT COUNT(*) FROM users WHERE created_by_username=?", (username,))
        total_users = c.fetchone()[0]
        # Count active (not expired, status=ENABLED)
        c.execute(
            "SELECT COUNT(*) FROM users WHERE created_by_username=? AND status='ENABLED' AND expiry_date >= ?",
            (username, today)
        )
        active_users = c.fetchone()[0]
        # Count expired
        c.execute(
            "SELECT COUNT(*) FROM users WHERE created_by_username=? AND expiry_date < ?",
            (username, today)
        )
        expired_users = c.fetchone()[0]
        # Count total logins from their users via login_history
        c.execute(
            """SELECT COUNT(*) FROM login_history lh
               JOIN users u ON u.username=lh.username
               WHERE u.created_by_username=?""",
            (username,)
        )
        login_count = c.fetchone()[0]
        result.append({
            "username": username,
            "is_active": bool(int(is_active)),
            "total_users": total_users,
            "active_users": active_users,
            "expired_users": expired_users,
            "login_count": login_count,
        })
    conn.close()
    return jsonify({"status": "ok", "data": result})


# --- Sub-Admin Bot Access: GET ---
@legacy_bp.route("/api/admin/subadmin_bots", methods=["GET"])
@login_required_json
def api_subadmin_bots_get():
    guard = require_super_admin_json()
    if guard:
        return guard
    subadmin = (request.args.get("subadmin") or "").strip()
    if not subadmin:
        return jsonify({"status": "error", "message": "subadmin required"}), 400
    conn = db_conn(); c = conn.cursor()
    c.execute("SELECT id FROM admins WHERE username=? AND role='SUB_ADMIN'", (subadmin,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"status": "error", "message": "Sub-admin not found"}), 404
    admin_id = int(row[0])
    c.execute("SELECT app_name FROM subadmin_bot_access WHERE admin_id=?", (admin_id,))
    bots = [r[0] for r in c.fetchall()]
    conn.close()
    return jsonify({"status": "ok", "data": bots})


# --- Sub-Admin Bot Access: POST (update) ---
@legacy_bp.route("/api/admin/update_subadmin_bots", methods=["POST"])
@login_required_json
def api_update_subadmin_bots():
    guard = require_super_admin_json()
    if guard:
        return guard
    d = request.get_json() or {}
    username = (d.get("username") or "").strip()
    bots = d.get("bots")  # list of app_name strings
    if not username or bots is None:
        return jsonify({"status": "error", "message": "username/bots required"}), 400
    if not isinstance(bots, list):
        return jsonify({"status": "error", "message": "bots must be a list"}), 400
    conn = db_conn(); c = conn.cursor()
    c.execute("SELECT id FROM admins WHERE username=? AND role='SUB_ADMIN'", (username,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"status": "error", "message": "Sub-admin not found"}), 404
    admin_id = int(row[0])
    # Validate bot names against known bots
    c.execute("SELECT app_name FROM bots")
    valid_bots = {r[0] for r in c.fetchall()}
    allowed = [b for b in bots if b in valid_bots]
    # Replace all restrictions for this sub-admin
    c.execute("DELETE FROM subadmin_bot_access WHERE admin_id=?", (admin_id,))
    for b in allowed:
        c.execute("INSERT OR IGNORE INTO subadmin_bot_access(admin_id, app_name) VALUES (?,?)", (admin_id, b))
    conn.commit(); conn.close()
    if allowed:
        msg = f"Bot access for {username} restricted to: {', '.join(allowed)}"
    else:
        msg = f"Bot restrictions removed for {username} (all bots allowed)"
    log_action("UPDATE_BOT_ACCESS", username, msg)
    return jsonify({"status": "ok", "message": msg, "bots": allowed})


# ---------------- Admin Login Attempts Log (SUPER_ADMIN ONLY) ----------------
@legacy_bp.route("/api/admin/login_attempts", methods=["GET"])
@login_required_json
def api_admin_login_attempts():
    guard = require_super_admin_json()
    if guard:
        return guard
    conn = db_conn(); c = conn.cursor()
    c.execute("SELECT id,username,ip_address,success,attempted_at FROM admin_login_attempts ORDER BY id DESC LIMIT 300")
    rows = c.fetchall(); conn.close()
    data = [{"id":r[0],"username":r[1],"ip":r[2],"success":bool(r[3]),"time":r[4]} for r in rows]
    return jsonify({"status":"ok","data":data})


# ---------------- Database Backup (SUPER_ADMIN ONLY) ----------------
@legacy_bp.route("/api/admin/backup_db", methods=["GET"])
def api_backup_db():
    if not session.get("logged_in") or not is_super_admin():
        return "Permission denied: SUPER_ADMIN only", 403

    from flask import send_file
    import os
    if not os.path.exists(DB):
        return "Database file not found", 404

    download_name = f"users_backup_{datetime.date.today().isoformat()}.db"
    return send_file(DB, as_attachment=True, download_name=download_name)



# ============================================================
# SUB-ADMIN PROFILE API
# ============================================================
@legacy_bp.route("/api/admin/subadmin_profile", methods=["GET"])
@login_required_json
def api_subadmin_profile():
    """Return full profile data for a single sub-admin. SUPER_ADMIN only."""
    guard = require_super_admin_json()
    if guard:
        return guard

    username = (request.args.get("username") or "").strip()
    if not username:
        return jsonify({"status": "error", "message": "username required"}), 400

    conn = db_conn()
    c = conn.cursor()
    c.execute("""
        SELECT id, username, full_name, email, role, is_active, created_at,
               last_login, permissions, max_users, max_expiry_days
        FROM admins WHERE username=? AND role='SUB_ADMIN'
    """, (username,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"status": "error", "message": "Sub-admin not found"}), 404

    (admin_id, uname, full_name, email, role, is_active, created_at,
     last_login, perms_json, max_users, max_expiry_days) = row

    # Assigned users count
    c.execute("SELECT count(*) FROM admin_user_access WHERE admin_id=?", (admin_id,))
    assigned_users = c.fetchone()[0]

    # Created users count
    c.execute("SELECT count(*) FROM users WHERE created_by_admin_id=?", (admin_id,))
    created_users = c.fetchone()[0]

    # Assigned bots
    c.execute("SELECT app_name FROM subadmin_bot_access WHERE admin_id=?", (admin_id,))
    bot_rows = c.fetchall()
    assigned_bots = [r[0] for r in bot_rows] if bot_rows else ["All Bots"]

    # Recent audit activity (last 10 actions)
    c.execute("""
        SELECT action, target_user, detail, created_at
        FROM audit_log WHERE admin_username=? ORDER BY id DESC LIMIT 10
    """, (uname,))
    recent_activity = [
        {"action": r[0], "target": r[1] or "", "detail": r[2] or "", "time": r[3]}
        for r in c.fetchall()
    ]

    # User stats
    today = datetime.date.today().isoformat()
    c.execute("""
        SELECT count(*) FROM users u JOIN admin_user_access a ON u.id=a.user_id
        WHERE a.admin_id=? AND u.status='ENABLED' AND u.expiry_date >= ?
    """, (admin_id, today))
    active_user_count = c.fetchone()[0]

    c.execute("""
        SELECT count(*) FROM users u JOIN admin_user_access a ON u.id=a.user_id
        WHERE a.admin_id=? AND u.expiry_date < ?
    """, (admin_id, today))
    expired_user_count = c.fetchone()[0]

    # Total logins from their users
    c.execute("""
        SELECT count(*) FROM login_history lh
        JOIN users u ON u.username=lh.username
        JOIN admin_user_access a ON a.user_id=u.id
        WHERE a.admin_id=?
    """, (admin_id,))
    total_logins = c.fetchone()[0]

    conn.close()

    try:
        perms = _json.loads(perms_json) if perms_json else ALL_PERMS
    except Exception:
        perms = []

    return jsonify({
        "status": "ok",
        "data": {
            "id": admin_id,
            "username": uname,
            "full_name": full_name or "",
            "email": email or "",
            "role": role,
            "is_active": bool(int(is_active)),
            "created_at": created_at or "",
            "last_login": last_login or "Never",
            "max_users": int(max_users or 0),
            "max_expiry_days": int(max_expiry_days or 0),
            "assigned_users": assigned_users,
            "created_users": created_users,
            "assigned_bots": assigned_bots,
            "permissions": perms,
            "recent_activity": recent_activity,
            "active_users": active_user_count,
            "expired_users": expired_user_count,
            "total_logins": total_logins,
        }
    })


# ============================================================
# STORE MODULE INTEGRATION
# ============================================================
# from store_module import store_bp
# app.register_blueprint(store_bp)

# ============================================================
# DEVICE & SMS SYNC INTEGRATION
# ============================================================
import re

# ---------------- Device Sync APIs ----------------

@legacy_bp.route("/api/admin/create_device", methods=["POST"])
def api_create_device():
    guard = require_super_admin_json()
    if guard:
        return guard

    conn = db_conn()
    c = conn.cursor()
    try:
        # Generate a random unique device username
        for _ in range(10):
            device_num = secrets.randbelow(900000) + 100000
            username = f"device_{device_num}"
            c.execute("SELECT id FROM admins WHERE username=?", (username,))
            if not c.fetchone():
                break
        else:
            conn.close()
            return jsonify({"status": "error", "message": "Failed to generate unique device username"}), 500

        # Generate random secure password
        password = secrets.token_urlsafe(8)
        device_key = "DK-" + secrets.token_hex(4).upper()
        
        c.execute(
            "INSERT INTO admins(username,password_hash,role,max_users,is_active,created_at) VALUES (?,?,?,?,?,?)",
            (
                username,
                generate_password_hash(password),
                "DEVICE",
                0,
                1,
                datetime.datetime.utcnow().isoformat(),
            ),
        )
        
        c.execute(
            "INSERT INTO device_stats (username, last_seen, sms_count, device_key, plain_password) VALUES (?, ?, 0, ?, ?)",
            (username, datetime.datetime.utcnow().isoformat(), device_key, password)
        )
        
        conn.commit()
    except Exception as e:
        conn.close()
        return jsonify({"status": "error", "message": str(e)}), 500

    conn.close()
    return jsonify({
        "status": "ok", 
        "message": "Device credentials generated",
        "device_key": device_key,
        "username": username,
        "password": password
    })

@legacy_bp.route("/api/admin/devices", methods=["GET"])
def api_admin_devices():
    guard = require_super_admin_json()
    if guard:
        return guard

    conn = db_conn()
    c = conn.cursor()
    c.execute(
        """
        SELECT a.username, a.created_at, ds.last_seen, ds.sms_count, ds.device_key, ds.plain_password
        FROM admins a
        LEFT JOIN device_stats ds ON a.username = ds.username
        WHERE a.role = 'DEVICE'
        ORDER BY a.id DESC
        """
    )
    rows = c.fetchall()
    conn.close()

    devices = []
    for username, created_at, last_seen, sms_count, device_key, plain_password in rows:
        devices.append({
            "username": username,
            "created_at": created_at,
            "last_seen": last_seen,
            "sms_count": sms_count or 0,
            "device_key": device_key or "N/A",
            "plain_password": plain_password or "N/A"
        })

    return jsonify({"status": "ok", "data": devices})

@legacy_bp.route("/api/admin/delete_device", methods=["POST"])
def api_admin_delete_device():
    guard = require_super_admin_json()
    if guard:
        return guard

    d = request.get_json() or {}
    username = (d.get("username") or "").strip()
    if not username:
        return jsonify({"status": "error", "message": "Missing username"}), 400

    conn = db_conn()
    c = conn.cursor()
    
    # Delete from admins and device_stats
    c.execute("DELETE FROM admins WHERE username=? AND role='DEVICE'", (username,))
    changes = c.rowcount
    if changes > 0:
        c.execute("DELETE FROM device_stats WHERE username=?", (username,))
        
    conn.commit()
    conn.close()
    
    if changes > 0:
        return jsonify({"status": "ok", "message": f"Deleted device {username}"})
    else:
        return jsonify({"status": "error", "message": "Device not found"}), 404

from app import csrf

@legacy_bp.route("/api/device/auth", methods=["POST"])
@csrf.exempt
def api_device_auth():
    """Authenticates the Admin Android App and returns the sync token."""
    d = request.get_json() or {}
    username = (d.get("username") or "").strip()
    password = d.get("password") or ""
    deviceKey = (d.get("deviceKey") or "").strip()
    
    if not username or not password or not deviceKey:
        return jsonify({"status": "error", "message": "Device Key, Username and password required"}), 400
        
    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT password_hash, role, is_active FROM admins WHERE username=?", (username,))
    row = c.fetchone()
    
    c.execute("SELECT device_key FROM device_stats WHERE username=?", (username,))
    ds_row = c.fetchone()
    conn.close()
    
    if not row or not check_password_hash(row[0], password):
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401
        
    if int(row[2]) != 1:
        return jsonify({"status": "error", "message": "Account disabled"}), 403

    if not ds_row or ds_row[0] != deviceKey:
        return jsonify({"status": "error", "message": "Invalid Device Key"}), 401
        
    # Upsert to device_stats
    conn = db_conn()
    c = conn.cursor()
    now_iso = datetime.datetime.utcnow().isoformat()
    c.execute(
        "UPDATE device_stats SET last_seen=? WHERE username=?",
        (now_iso, username)
    )
    conn.commit()
    conn.close()

    # Valid admin, return the WEBHOOK_SECRET so the app can use it for syncing SMS
    return jsonify({
        "status": "success", 
        "message": "Login successful",
        "token": os.getenv("WEBHOOK_SECRET", "testwebhook123"),
        "role": row[1]
    })

@legacy_bp.route("/api/device/ping", methods=["POST"])
@csrf.exempt
def api_device_ping():
    api_key = request.headers.get("X-App-Key")
    if api_key != os.getenv("WEBHOOK_SECRET", "testwebhook123"):
        return jsonify({"detail": "Invalid App Secret Key"}), 403
    
    device_user = request.headers.get("X-Device-User")
    if not device_user:
        return jsonify({"status": "error", "message": "Missing device user"}), 400

    conn = db_conn()
    c = conn.cursor()
    now_iso = datetime.datetime.utcnow().isoformat()
    c.execute(
        "INSERT INTO device_stats (username, last_seen, sms_count) VALUES (?, ?, 0) ON CONFLICT(username) DO UPDATE SET last_seen=?",
        (device_user, now_iso, now_iso)
    )
    conn.commit()
    conn.close()
    
    return jsonify({"status": "success", "message": "Ping received"})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    # Production security reminders
    if port != 5000 or os.environ.get("PRODUCTION"):
        print("[SECURITY] Production mode detected. Reminders:")
        print("[SECURITY]   • Put this server behind nginx + HTTPS (never expose Flask directly).")
        print("[SECURITY]   • SECRET_KEY is auto-generated and saved to .secret_key — back it up.")
        print("[SECURITY]   • Set FAILED_LOGIN_LIMIT and CK_RATE_LIMIT env vars to tune rate limits.")
    app.run(host="0.0.0.0", port=port, debug=False)
