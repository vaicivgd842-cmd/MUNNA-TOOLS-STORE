# store_module.py
import os
import sqlite3
import secrets
import hmac
import datetime
import re
import json
from flask import Blueprint, request, current_app, jsonify, session, render_template, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash

store_bp = Blueprint("store", __name__)
DB = os.environ.get("DB_PATH", "/data/users.db")
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "").strip()
if not WEBHOOK_SECRET:
    import sys
    print("[SECURITY] ERROR: WEBHOOK_SECRET not set in .env")
    sys.exit(1)

def db_conn():
    """Return a SQLite connection. Retries on transient volume errors."""
    import time as _time
    last_err = sqlite3.OperationalError("db_conn: exhausted retries")
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

def init_store_db():
    conn = db_conn()
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS store_customers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
    )''')
    
    c.execute("PRAGMA table_info(store_customers)")
    columns = [col[1] for col in c.fetchall()]
    if 'full_name' not in columns:
        c.execute("ALTER TABLE store_customers ADD COLUMN full_name TEXT")
    if 'phone_number' not in columns:
        c.execute("ALTER TABLE store_customers ADD COLUMN phone_number TEXT")
    if 'email' not in columns:
        c.execute("ALTER TABLE store_customers ADD COLUMN email TEXT")
    # plain_password column is DEPRECATED for security — nulled out if exists, never written
    if 'is_active' not in columns:
        c.execute("ALTER TABLE store_customers ADD COLUMN is_active INTEGER DEFAULT 1")
    if 'clear_limit' not in columns:
        c.execute("ALTER TABLE store_customers ADD COLUMN clear_limit INTEGER DEFAULT 5")
    if 'clear_count' not in columns:
        c.execute("ALTER TABLE store_customers ADD COLUMN clear_count INTEGER DEFAULT 0")
    if 'is_vip' not in columns:
        c.execute("ALTER TABLE store_customers ADD COLUMN is_vip INTEGER DEFAULT 0")
    if 'can_buy' not in columns:
        c.execute("ALTER TABLE store_customers ADD COLUMN can_buy INTEGER DEFAULT 0")
    # Wipe any previously stored plain passwords (one-time migration)
    try:
        if 'plain_password' in columns:
            c.execute("UPDATE store_customers SET plain_password=NULL WHERE plain_password IS NOT NULL")
    except Exception:
        pass

    c.execute('''CREATE TABLE IF NOT EXISTS store_bot_pricing (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        app_name TEXT NOT NULL,
        duration_days INTEGER NOT NULL,
        price REAL NOT NULL,
        UNIQUE(app_name, duration_days)
    )''')
    
    c.execute("PRAGMA table_info(store_bot_pricing)")
    p_columns = [col[1] for col in c.fetchall()]
    if 'is_active' not in p_columns:
        c.execute("ALTER TABLE store_bot_pricing ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1")
    if 'stock_status' not in p_columns:
        c.execute("ALTER TABLE store_bot_pricing ADD COLUMN stock_status TEXT NOT NULL DEFAULT 'Available'")

    c.execute('''CREATE TABLE IF NOT EXISTS store_payment_methods (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        method_name TEXT NOT NULL,
        account_details TEXT NOT NULL
    )''')
    
    c.execute("PRAGMA table_info(store_payment_methods)")
    pm_columns = [col[1] for col in c.fetchall()]
    if 'note' not in pm_columns:
        c.execute("ALTER TABLE store_payment_methods ADD COLUMN note TEXT")

    c.execute('''CREATE TABLE IF NOT EXISTS store_settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS user_bot_blocks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        app_name TEXT NOT NULL,
        UNIQUE(username, app_name)
    )''')

    # Table for Auto-Payment Sync via Webhook
    c.execute('''CREATE TABLE IF NOT EXISTS store_received_payments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        trx_id TEXT UNIQUE NOT NULL,
        amount REAL NOT NULL,
        sender_number TEXT,
        sms_text TEXT,
        is_used INTEGER DEFAULT 0,
        created_at TEXT NOT NULL
    )''')
    # Migrate: add new columns if they don't exist yet
    c.execute("PRAGMA table_info(store_received_payments)")
    rp_cols = [col[1] for col in c.fetchall()]
    if 'receiver_number' not in rp_cols:
        c.execute("ALTER TABLE store_received_payments ADD COLUMN receiver_number TEXT")
    if 'old_balance' not in rp_cols:
        c.execute("ALTER TABLE store_received_payments ADD COLUMN old_balance REAL")
    if 'new_balance' not in rp_cols:
        c.execute("ALTER TABLE store_received_payments ADD COLUMN new_balance REAL")

    c.execute('''CREATE TABLE IF NOT EXISTS store_orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_username TEXT NOT NULL,
        total_amount REAL NOT NULL DEFAULT 0.0,
        payment_method TEXT,
        sender_number TEXT,
        transaction_id TEXT,
        payment_screenshot TEXT,
        status TEXT DEFAULT 'PENDING',
        notes TEXT,
        created_at TEXT NOT NULL
    )''')
    
    # Migrate: add missing columns if store_orders was created in an older version
    c.execute("PRAGMA table_info(store_orders)")
    so_cols = [col[1] for col in c.fetchall()]
    if so_cols:
        if 'total_amount' not in so_cols:
            c.execute("ALTER TABLE store_orders ADD COLUMN total_amount REAL NOT NULL DEFAULT 0.0")
        if 'payment_method' not in so_cols:
            c.execute("ALTER TABLE store_orders ADD COLUMN payment_method TEXT")
        if 'sender_number' not in so_cols:
            c.execute("ALTER TABLE store_orders ADD COLUMN sender_number TEXT")
        if 'transaction_id' not in so_cols:
            c.execute("ALTER TABLE store_orders ADD COLUMN transaction_id TEXT")
        if 'payment_screenshot' not in so_cols:
            c.execute("ALTER TABLE store_orders ADD COLUMN payment_screenshot TEXT")
        if 'status' not in so_cols:
            c.execute("ALTER TABLE store_orders ADD COLUMN status TEXT DEFAULT 'PENDING'")
        if 'notes' not in so_cols:
            c.execute("ALTER TABLE store_orders ADD COLUMN notes TEXT")

    # Performance Indexes
    c.execute("CREATE INDEX IF NOT EXISTS idx_store_orders_customer ON store_orders(customer_username, id DESC)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_store_payments_trx ON store_received_payments(trx_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_store_pricing_active ON store_bot_pricing(is_active)")

    conn.commit()
    conn.close()

# NOTE: init_store_db() is called explicitly from run.py — NOT at import time

# =================== MAIN ADMIN CSS THEME & SIDEBAR ===================
# =================== TEMPLATES ===================

# =================== ROUTES ===================

from app import csrf, limiter

@store_bp.route('/api/admin/store/sms_webhook', methods=['POST'])
@store_bp.route('/api/app/sync-sms', methods=['POST'])
@csrf.exempt
def api_sms_webhook():
    # Support both JSON and URL-Encoded parameters safely
    data = request.get_json(silent=True)
    if not data:
        data = request.values.to_dict()

    # মূল পরিবর্তন: হেডার থেকে X-App-Key চেক করা হচ্ছে
    provided_str = (
        request.headers.get("X-App-Key") 
        or data.get("secret") 
        or request.args.get("secret") 
        or ""
    )
    
    provided = provided_str.encode()
    expected = WEBHOOK_SECRET.encode()

    print("WEBHOOK DATA:", data)
    print("SECRET:", provided)

    if not hmac.compare_digest(provided, expected):
        return jsonify({
            "status": "error",
            "message": "Unauthorized"
        }), 401

    # --- Update Device Stats (SMS Forwarded Count) ---
    device_user = request.headers.get("X-Device-User") or data.get("device_user") or request.args.get("device_user")
    if device_user:
        try:
            conn_ds = db_conn()
            c_ds = conn_ds.cursor()
            now_iso = datetime.datetime.utcnow().isoformat()
            c_ds.execute(
                "UPDATE device_stats SET sms_count = sms_count + 1, last_seen = ? WHERE username = ?",
                (now_iso, device_user)
            )
            conn_ds.commit()
            conn_ds.close()
        except Exception as e:
            current_app.logger.error(f"Failed to update device_stats: {e}")

    # Update to catch 'raw_message' based on your Android App logs
    msg = (
        data.get("raw_message")
        or data.get("message")
        or data.get("text")
        or data.get("body")
        or data.get("sms")
        or ""
    )

    # Update to catch 'gateway_number' based on your Android App logs
    sender = (
        data.get("gateway_number")
        or data.get("sender")
        or data.get("from")
        or data.get("phone")
        or data.get("number")
        or ""
    )

    # Receiver phone number (the SIM/account that received the payment)
    receiver_number = (
        data.get("receiver_number")
        or data.get("sim_number")
        or data.get("account_number")
        or ""
    )

    # --- EXTRA SECURITY: Block Fake SMS Senders ---
    sender_lower = sender.lower()
    if (
        "bkash" not in sender_lower
        and "nagad" not in sender_lower
        and "16216" not in sender_lower
        and "16167" not in sender_lower
    ):
        return jsonify({
            "status": "ignored",
            "message": "Fake SMS blocked"
        }), 200

    # --- Parse TrxID ---
    trx_match = re.search(r'(?:TrxID|TxnId|Trx ID|Trx)[\s:]*([A-Za-z0-9]{8,15})', msg, re.IGNORECASE)
    # --- Parse received Amount (first Tk/BDT/Amount occurrence) ---
    amt_match = re.search(r'(?:received\s+Tk|Amount|BDT)[\s:]*([0-9,]+(?:\.[0-9]+)?)', msg, re.IGNORECASE)
    if not amt_match:
        # Fallback: first Tk value
        amt_match = re.search(r'Tk[\s:]*([0-9,]+(?:\.[0-9]+)?)', msg, re.IGNORECASE)

    if not trx_match or not amt_match:
        return jsonify({
            "status": "ignored",
            "message": "Not a valid payment SMS"
        }), 200

    trx_id = trx_match.group(1).upper()
    amount_str = amt_match.group(1).replace(",", "")
    try:
        amount = float(amount_str)
    except Exception:
        amount = 0.0

    # --- Parse Sender Phone Number from SMS text (e.g. "from 01869928512") ---
    # If sender field is a gateway name (bKash/Nagad), try to extract actual phone from SMS
    if not re.match(r'^01[3-9]\d{8}$', sender.strip()):
        phone_in_msg = re.search(r'from\s+(01[3-9]\d{8})', msg, re.IGNORECASE)
        if phone_in_msg:
            sender = phone_in_msg.group(1)

    # --- Parse Old Balance (Balance before this transaction) ---
    # bKash format: "Balance Tk 241.31" or "Old Balance Tk 251.31"
    old_balance = None
    old_bal_match = re.search(r'Old\s*Balance\s*(?:Tk|BDT)?\s*([0-9,]+(?:\.[0-9]+)?)', msg, re.IGNORECASE)
    if old_bal_match:
        try:
            old_balance = float(old_bal_match.group(1).replace(",", ""))
        except Exception:
            pass

    # --- Parse New Balance (final balance after this transaction) ---
    # bKash format: "Balance Tk 241.31" at end of SMS (after amount deducted or credited)
    # Nagad format: "New Balance: Tk 241.31"
    new_balance = None
    new_bal_match = re.search(r'New\s*Balance\s*(?:Tk|BDT)?\s*([0-9,]+(?:\.[0-9]+)?)', msg, re.IGNORECASE)
    if new_bal_match:
        try:
            new_balance = float(new_bal_match.group(1).replace(",", ""))
        except Exception:
            pass
    if new_balance is None:
        # bKash: the last "Balance Tk X" is the post-transaction balance
        all_balances = re.findall(r'Balance\s*Tk\s*([0-9,]+(?:\.[0-9]+)?)', msg, re.IGNORECASE)
        if all_balances:
            try:
                new_balance = float(all_balances[-1].replace(",", ""))
            except Exception:
                pass
        # If exactly 2 balance values found, first = old, second = new
        if len(all_balances) >= 2 and old_balance is None:
            try:
                old_balance = float(all_balances[0].replace(",", ""))
                new_balance = float(all_balances[1].replace(",", ""))
            except Exception:
                pass
                
    # Auto-calculate old_balance if missing (New Balance - Amount)
    if old_balance is None and new_balance is not None:
        old_balance = new_balance - amount

    conn = db_conn()
    c = conn.cursor()
    try:
        c.execute(
            "INSERT INTO store_received_payments"
            "(trx_id, amount, sender_number, receiver_number, sms_text, old_balance, new_balance, created_at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (trx_id, amount, sender, receiver_number or None, msg,
             old_balance, new_balance, datetime.datetime.utcnow().isoformat())
        )
        conn.commit()
    except sqlite3.IntegrityError:
        pass  # Duplicate TrxID — ignore
    conn.close()

    return jsonify({
        "status": "ok",
        "message": "Saved",
        "trx": trx_id,
        "amount": amount,
        "sender": sender,
        "receiver": receiver_number or None,
        "old_balance": old_balance,
        "new_balance": new_balance,
    })


@store_bp.route("/api/admin/store/received_payments", methods=["GET"])
def api_admin_get_sms_payments():
    if session.get("role") != "SUPER_ADMIN": return jsonify({"status": "error"}), 403
    conn = db_conn(); c = conn.cursor()
    try:
        c.execute("""
            SELECT trx_id, amount, sender_number, sms_text, is_used, created_at,
                   receiver_number, old_balance, new_balance
            FROM store_received_payments
            ORDER BY id DESC LIMIT 100
        """)
        data = [
            {
                "trx_id":          r[0],
                "amount":          r[1],
                "sender":          r[2] or "",
                "sms_text":        r[3] or "",
                "is_used":         r[4],
                "date":            r[5],
                "receiver_number": r[6] or "",
                "old_balance":     r[7],
                "new_balance":     r[8],
            }
            for r in c.fetchall()
        ]
    except Exception as e:
        current_app.logger.error(f"received_payments query error: {e}")
        data = []
    conn.close()
    return jsonify({"status": "ok", "data": data})

@store_bp.route("/store/login")
def store_login_page():
    return render_template("store/login.html")

@store_bp.route("/store/signup")
def store_signup_page():
    return render_template("store/signup.html")

@store_bp.route("/store")
def store_dashboard():
    if not session.get("customer_logged_in"):
        return redirect("/store/login")
    return render_template("store/customer_store.html")

@store_bp.route("/api/store/payment_methods", methods=["GET"])
def api_store_get_payment_methods():
    conn = db_conn(); c = conn.cursor()
    c.execute("SELECT value FROM store_settings WHERE key='mobile_banking_gateways'")
    row = c.fetchone()
    conn.close()
    
    data = []
    if row and row[0]:
        try:
            gateways = json.loads(row[0])
            for i, gw in enumerate(gateways):
                if gw.get("enabled", True):
                    data.append({
                        "id": gw.get("id", i + 1),
                        "name": gw.get("name") or gw.get("method_name", ""),
                        "number": gw.get("number") or gw.get("account_details", ""),
                        "color": gw.get("color", "#0d6efd"),
                        "logo_url": gw.get("logo", ""),
                    })
        except Exception as e:
            current_app.logger.error(f"Error parsing gateways: {e}")
            
    return jsonify({"status": "ok", "data": data})

@store_bp.route("/api/store/signup", methods=["POST"])
@limiter.limit("10 per minute; 30 per hour")
def api_store_signup():
    data = request.get_json() or {}
    full_name = data.get("full_name", "").strip()
    phone_number = data.get("phone_number", "").strip()
    email = data.get("email", "").strip()
    u = data.get("username", "").strip()
    p = data.get("password", "")

    if not full_name or not email or not u or not p:
        return jsonify({"status": "error", "message": "All fields are required"}), 400
    if len(p) < 8:
        return jsonify({"status": "error", "message": "Password must be at least 8 characters long"}), 400
    if not re.match(r'^[a-zA-Z0-9_.@-]{3,30}$', u):
        return jsonify({"status": "error", "message": "Username: 3-30 characters, letters/numbers/._@- only"}), 400

    conn = db_conn(); c = conn.cursor()
    try:
        # plain_password is NOT stored — security fix
        c.execute("INSERT INTO store_customers(username, password_hash, created_at, full_name, phone_number, email, is_active, clear_limit, clear_count, is_vip, can_buy) VALUES (?, ?, ?, ?, ?, ?, 1, 5, 0, 0, 0)",
                  (u, generate_password_hash(p), datetime.datetime.utcnow().isoformat(), full_name, phone_number, email))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close(); return jsonify({"status": "error", "message": "Username already taken"}), 400
    conn.close()
    return jsonify({"status": "ok", "message": "Signup successful! You can now login."})

@store_bp.route("/api/store/login", methods=["POST"])
@limiter.limit("20 per minute; 100 per hour")
def api_store_login():
    data = request.get_json() or {}
    u = data.get("username", "").strip()
    p = data.get("password", "")

    conn = db_conn(); c = conn.cursor()
    c.execute("SELECT password_hash, is_active FROM store_customers WHERE username=?", (u,))
    row = c.fetchone()
    conn.close()

    if not row or not check_password_hash(row[0], p):
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401
    if not row[1]:
        return jsonify({"status": "error", "message": "Account has been disabled by Admin."}), 403

    session["customer_logged_in"] = True
    session["customer_username"] = u
    return jsonify({"status": "ok", "message": "Logged in successfully"})

@store_bp.route("/api/store/logout", methods=["POST"])
def api_store_logout():
    session.pop("customer_logged_in", None); session.pop("customer_username", None)
    return jsonify({"status": "ok", "message": "Logged out"})

@store_bp.route("/api/store/data", methods=["GET"])
def api_store_data():
    if not session.get("customer_logged_in"): return jsonify({"status": "error", "message": "Unauthorized"}), 401
    u = session.get("customer_username", "")
    conn = db_conn(); c = conn.cursor()
    
    c.execute("SELECT full_name, phone_number, email, created_at, clear_limit, clear_count, is_vip, can_buy FROM store_customers WHERE username=?", (u,))
        
    cust_info = c.fetchone()
    user_info = {"full_name": cust_info[0] if cust_info else "", "phone_number": cust_info[1] if cust_info else "", "email": cust_info[2] if cust_info else "", "created_at": cust_info[3][:10] if cust_info else "", "clear_limit": cust_info[4] if cust_info else 5, "clear_count": cust_info[5] if cust_info else 0, "is_vip": cust_info[6] if cust_info else 0, "can_buy": cust_info[7] if cust_info else 0}

    try:
        c.execute("SELECT s.id, s.app_name, s.duration_days, s.price, s.stock_status, b.required_version FROM store_bot_pricing s LEFT JOIN bots b ON s.app_name = b.app_name WHERE s.is_active=1 ORDER BY s.app_name, s.duration_days")
        pricing = [{"id": r[0], "app_name": r[1], "duration_days": r[2], "price": r[3], "stock_status": r[4], "version": r[5]} for r in c.fetchall()]
    except sqlite3.OperationalError:
        c.execute("SELECT id, app_name, duration_days, price FROM store_bot_pricing WHERE is_active=1 ORDER BY app_name, duration_days")
        pricing = [{"id": r[0], "app_name": r[1], "duration_days": r[2], "price": r[3], "stock_status": "Available", "version": "1.0"} for r in c.fetchall()]
    
    c.execute("SELECT id, notes, total_amount, status, created_at FROM store_orders WHERE customer_username=? ORDER BY id DESC", (u,))
    orders = []
    for r in c.fetchall():
        try:
            n = json.loads(r[1]) if r[1] else {}
        except:
            n = {}
        orders.append({
            "id": r[0], "app_name": n.get("app_name", ""), "duration_days": n.get("duration_days", 0),
            "price": r[2], "status": r[3], "license_key": n.get("license_key", ""), "created_at": r[4],
            "notes": r[1]
        })
    conn.close()
    return jsonify({"status": "ok", "data": {"pricing": pricing, "orders": orders, "username": u, "user_info": user_info}})

@store_bp.route("/api/store/subscriptions", methods=["GET"])
def api_store_subscriptions():
    if not session.get("customer_logged_in"): return jsonify({"status": "error", "message": "Unauthorized"}), 401
    u = session.get("customer_username", "")
    conn = db_conn(); c = conn.cursor()
    c.execute("SELECT notes FROM store_orders WHERE customer_username=? AND status='APPROVED'", (u,))
    orders = []
    for row in c.fetchall():
        try:
            n = json.loads(row[0]) if row[0] else {}
            if n.get("app_name") and n.get("license_key"):
                orders.append((n["app_name"], n["license_key"]))
        except:
            pass
    
    data = []
    for app_name, license_key in orders:
        if not license_key: continue
        c.execute("SELECT machine_id, expiry_date, status FROM users WHERE username=?", (license_key,))
        u_row = c.fetchone()
        if u_row:
            data.append({"app_name": app_name, "username": license_key, "machine_id": u_row[0] or "-", "expiry_date": u_row[1], "status": u_row[2]})
    conn.close()
    return jsonify({"status": "ok", "data": data})

@store_bp.route("/api/store/clear_machine", methods=["POST"])
def api_store_clear_machine():
    if not session.get("customer_logged_in"): return jsonify({"status": "error", "message": "Unauthorized"}), 401
    bot_username = request.get_json().get("bot_username"); u = session.get("customer_username", "")
    conn = db_conn(); c = conn.cursor()
    
    c.execute("SELECT id, notes FROM store_orders WHERE customer_username=?", (u,))
    order_id = None
    for row in c.fetchall():
        try:
            n = json.loads(row[1]) if row[1] else {}
            if n.get("license_key") == bot_username:
                order_id = row[0]
                break
        except:
            pass
    if not order_id: conn.close(); return jsonify({"status": "error", "message": "Unauthorized to clear this bot"}), 403
        
    c.execute("SELECT clear_limit, clear_count FROM store_customers WHERE username=?", (u,))
    row = c.fetchone()
    if not row: conn.close(); return jsonify({"status": "error", "message": "Customer not found"}), 404
        
    limit, count = row
    if count >= limit: conn.close(); return jsonify({"status": "error", "message": f"Machine ID clear limit reached ({limit}/{limit}). Please contact Admin."}), 403
        
    c.execute("UPDATE users SET machine_id='-' WHERE username=?", (bot_username,))
    c.execute("UPDATE store_customers SET clear_count=clear_count+1 WHERE username=?", (u,))
    conn.commit(); conn.close()
    return jsonify({"status": "ok", "message": f"Machine ID cleared successfully! Remaining clears: {limit - (count + 1)}"})

@store_bp.route("/api/store/buy", methods=["POST"])
def api_store_buy():
    try:
        if not session.get("customer_logged_in"): return jsonify({"status": "error", "message": "Unauthorized"}), 401
        
        u = session.get("customer_username", "")
        conn = db_conn(); c = conn.cursor()
        c.execute("SELECT can_buy FROM store_customers WHERE username=?", (u,))
            
        row = c.fetchone()
        if not row or row[0] == 0:
            conn.close()
            return jsonify({"status": "error", "message": "Your account is pending Admin approval for making purchases. Please contact Support!"}), 403
            
        d = request.get_json()
        pid = d.get("pricing_id")
        pmethod = d.get("payment_method", "").strip()
        snum = d.get("sender_number", "").strip()
        trx = d.get("transaction_id", "").strip().upper()
        proof_base64 = d.get("payment_screenshot", "")
        username_input = d.get("username", "").strip() # For SR VIP
    
        if not pmethod or not trx: 
            return jsonify({"status": "error", "message": "Payment Method and Transaction ID are required!"}), 400
    
        c.execute("SELECT app_name, duration_days, price FROM store_bot_pricing WHERE id=? AND is_active=1", (pid,))
        p = c.fetchone()
        if not p: conn.close(); return jsonify({"status": "error", "message": "Pricing item not found or currently unavailable"}), 404
    
        # ---------------- MACRODROID AUTO APPROVAL LOGIC ----------------
        c.execute("SELECT id, amount FROM store_received_payments WHERE trx_id=? AND is_used=0", (trx,))
        rx_row = c.fetchone()
    
        auto_approved = False
        rand_key = None
    
        if rx_row and rx_row[1] >= p[2]: 
            auto_approved = True
            rx_id = rx_row[0]
        
            is_sr_vip = "SR VIP" in p[0].upper()
            if is_sr_vip and username_input:
                rand_key = username_input
                c.execute("SELECT id FROM users WHERE username=?", (rand_key,))
                if c.fetchone():
                    return jsonify({"status": "error", "message": "This Username is already taken! Please choose another one."}), 400
            else:
                rand_key = f"{u}_{secrets.token_hex(2).upper()[:3]}"
                c.execute("SELECT id FROM users WHERE username=?", (rand_key,))
                while c.fetchone():
                    rand_key = f"{u}_{secrets.token_hex(2).upper()[:3]}"
                    c.execute("SELECT id FROM users WHERE username=?", (rand_key,))
        
            today = datetime.date.today()
            new_expiry = today + datetime.timedelta(days=p[1])
        
            c.execute("INSERT INTO users(username, activation_key, status, machine_id, expiry_date, created_by_username, created_by_role) VALUES (?,?,?,?,?,?,?)",
                (rand_key, rand_key, 'ENABLED', '-', new_expiry.isoformat(), u, 'STORE_CUSTOMER'))
            
            if 'ALL TOOLS' not in p[0].upper():
                try:
                    c.execute("SELECT app_name FROM bots WHERE app_name != ?", (p[0],))
                    other_bots = c.fetchall()
                    for b in other_bots:
                        c.execute("INSERT OR IGNORE INTO user_bot_blocks(username, app_name) VALUES (?,?)", (rand_key, b[0]))
                except Exception as e:
                    current_app.logger.error(f"Error: {e}")
        
            c.execute("UPDATE store_received_payments SET is_used=1 WHERE id=?", (rx_id,))
    
        final_status = 'APPROVED' if auto_approved else 'PENDING'
        appr_date = datetime.datetime.utcnow().isoformat() if auto_approved else None
    
        is_sr_vip = "SR VIP" in p[0].upper()
        notes_dict = {"app_name": p[0], "duration_days": p[1], "license_key": rand_key, "approved_at": appr_date, "payment_type": "Auto Payment" if auto_approved else "Manual Payment"}
        if is_sr_vip and username_input:
            notes_dict["requested_username"] = username_input
        
        c.execute("PRAGMA table_info(store_orders)")
        cols = [col[1] for col in c.fetchall()]
        
        insert_cols = ["customer_username", "total_amount", "payment_method", "sender_number", "transaction_id", "payment_screenshot", "status", "notes", "created_at"]
        insert_vals = [u, p[2], pmethod, snum, trx, proof_base64, final_status, json.dumps(notes_dict), datetime.datetime.utcnow().isoformat()]
        
        if 'app_name' in cols:
            insert_cols.append("app_name")
            insert_vals.append(p[0])
            
        if 'duration_days' in cols:
            insert_cols.append("duration_days")
            insert_vals.append(p[1])
            
        if 'price' in cols:
            insert_cols.append("price")
            insert_vals.append(p[2])
            
        placeholders = ",".join(["?"] * len(insert_vals))
        col_names = ",".join(insert_cols)
        
        c.execute(f"INSERT INTO store_orders({col_names}) VALUES ({placeholders})", tuple(insert_vals))
    
        conn.commit()
        conn.close()
    
        if auto_approved:
            return jsonify({"status": "ok", "message": "Payment verified automatically! Your License Key has been generated and activated."})
        else:
            return jsonify({"status": "ok", "message": "Order placed successfully! Waiting for admin manual verification."})
    except Exception as e:
        import traceback
        current_app.logger.error(f"Error in api_store_buy: {e}\n{traceback.format_exc()}")
        return jsonify({"status": "error", "message": f"Server Error: {str(e)}"}), 500

@store_bp.route("/api/store/support_info", methods=["GET"])
def api_store_support_info():
    conn = db_conn(); c = conn.cursor()
    c.execute("SELECT key, value FROM store_settings WHERE key IN ('support_telegram', 'support_whatsapp', 'support_facebook')")
    data = {r[0]: r[1] for r in c.fetchall()}
    conn.close()
    return jsonify({"status": "ok", "data": data})


# =================== ADMIN ROUTES ===================

@store_bp.route("/admin/store")
def admin_store_dashboard():
    if session.get("role") != "SUPER_ADMIN": return "Forbidden", 403
    return render_template("store/admin_store.html")

@store_bp.route("/api/admin/store/settings", methods=["GET", "POST"])
def api_admin_store_settings():
    if session.get("role") != "SUPER_ADMIN": return jsonify({"status": "error"}), 403
    conn = db_conn(); c = conn.cursor()
    if request.method == "POST":
        d = request.get_json() or {}
        for k, v in d.items():
            c.execute("INSERT OR REPLACE INTO store_settings(key, value) VALUES (?,?)", (k, v))
        conn.commit(); conn.close()
        return jsonify({"status": "ok", "message": "Support settings saved!"})
    else:
        c.execute("SELECT key, value FROM store_settings")
        data = {r[0]: r[1] for r in c.fetchall()}; conn.close()
        return jsonify({"status": "ok", "data": data})

@store_bp.route("/api/admin/store/dashboard_stats", methods=["GET"])
def api_admin_store_dashboard_stats():
    if session.get("role") != "SUPER_ADMIN": return jsonify({"status": "error"}), 403
    conn = db_conn(); c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM store_customers"); tot_cust = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM store_orders"); tot_ord = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM store_orders WHERE status='PENDING'"); pend_ord = c.fetchone()[0]
    c.execute("SELECT SUM(total_amount) FROM store_orders WHERE status='APPROVED'"); revenue = c.fetchone()[0] or 0.0
    conn.close()
    return jsonify({"status": "ok", "data": {"total_customers": tot_cust, "total_orders": tot_ord, "pending_orders": pend_ord, "total_revenue": round(revenue, 2)}})

@store_bp.route("/api/admin/store/customer_stats/<username>", methods=["GET"])
def api_admin_store_customer_stats(username):
    if session.get("role") != "SUPER_ADMIN": return jsonify({"status": "error"}), 403
    conn = db_conn(); c = conn.cursor()
    c.execute("SELECT COUNT(DISTINCT app_name) FROM store_bot_pricing WHERE is_active=1")
    avail_bots = c.fetchone()[0]
    
    c.execute("SELECT status, notes FROM store_orders WHERE customer_username=?", (username,))
    orders = []
    for row in c.fetchall():
        try:
            n = json.loads(row[1]) if row[1] else {}
            orders.append((row[0], n.get("license_key", "")))
        except:
            orders.append((row[0], ""))
    ord_comp = 0; ord_pend = 0; keys = []
    for status, key in orders:
        if status == 'APPROVED':
            ord_comp += 1
            if key: keys.append(key)
        elif status == 'PENDING': ord_pend += 1
            
    my_lic = len(keys); act_lic = 0; exp_lic = 0
    today = datetime.date.today().isoformat()
    if keys:
        placeholders = ",".join(["?"]*len(keys))
        c.execute(f"SELECT expiry_date, status FROM users WHERE username IN ({placeholders})", keys)
        for exp, st in c.fetchall():
            if exp and exp < today: exp_lic += 1
            elif st == 'ENABLED': act_lic += 1
                
    conn.close()
    return jsonify({"status": "ok", "data": {"avail_bots": avail_bots, "my_lic": my_lic, "act_lic": act_lic, "exp_lic": exp_lic, "ord_comp": ord_comp, "ord_pend": ord_pend}})

@store_bp.route("/api/admin/store/active_bots", methods=["GET"])
def api_admin_store_active_bots():
    if session.get("role") != "SUPER_ADMIN": return jsonify({"status": "error"}), 403
    conn = db_conn(); c = conn.cursor()
    try: c.execute("SELECT app_name FROM bots WHERE is_active=1"); bots = [r[0] for r in c.fetchall()]
    except Exception: bots = []
    conn.close()
    return jsonify({"status": "ok", "data": bots})

@store_bp.route("/api/admin/store/pricing_list", methods=["GET"])
def api_admin_store_pricing_list():
    if session.get("role") != "SUPER_ADMIN": return jsonify({"status": "error"}), 403
    conn = db_conn(); c = conn.cursor()
    main_bots_map = {}
    try:
        c.execute("SELECT app_name, required_version FROM bots")
        main_bots_map = {r[0]: r[1] for r in c.fetchall()}
        
        for b_name in main_bots_map.keys():
            for days in [30, 60, 90]:
                c.execute("SELECT id FROM store_bot_pricing WHERE app_name=? AND duration_days=?", (b_name, days))
                if not c.fetchone():
                    c.execute("INSERT INTO store_bot_pricing(app_name, duration_days, price, is_active, stock_status) VALUES (?, ?, 0.0, 0, 'Available')", (b_name, days))
        conn.commit()
    except Exception as e:
        print("Pricing sync error:", e)

    try:
        c.execute("SELECT app_name, duration_days, price, is_active, stock_status FROM store_bot_pricing ORDER BY app_name, duration_days")
    except sqlite3.OperationalError:
        # Fallback if stock_status migration didn't run cleanly on some old rows
        c.execute("SELECT app_name, duration_days, price, is_active, 'Available' FROM store_bot_pricing ORDER BY app_name, duration_days")

    data_dict = {}
    for r in c.fetchall():
        app, days, price, is_active, stock_status = r
        if app not in data_dict:
            data_dict[app] = {
                "app_name": app,
                "version": main_bots_map.get(app, "1.0"),
                "is_active": is_active,
                "stock_status": stock_status,
                "price_30": 0.0,
                "price_60": 0.0,
                "price_90": 0.0
            }
        if days == 30: data_dict[app]["price_30"] = price
        elif days == 60: data_dict[app]["price_60"] = price
        elif days == 90: data_dict[app]["price_90"] = price
        
        # Override with the latest row's metadata (ensures consistency)
        data_dict[app]["is_active"] = is_active
        data_dict[app]["stock_status"] = stock_status
        
    data = list(data_dict.values())
    conn.close()
    return jsonify({"status": "ok", "data": data})

@store_bp.route("/api/admin/store/customers", methods=["GET"])
def api_admin_store_customers():
    if session.get("role") != "SUPER_ADMIN": return jsonify({"status": "error"}), 403
    conn = db_conn(); c = conn.cursor()
    # plain_password column excluded — replaced by admin reset-password feature
    c.execute("SELECT id, username, full_name, phone_number, email, created_at, is_active, clear_limit, clear_count, is_vip, can_buy FROM store_customers ORDER BY id DESC")
    data = [{"id": r[0], "username": r[1], "full_name": r[2], "phone_number": r[3], "email": r[4], "created_at": r[5], "is_active": r[6], "clear_limit": r[7], "clear_count": r[8], "is_vip": r[9], "can_buy": r[10]} for r in c.fetchall()]
    conn.close()
    return jsonify({"status": "ok", "data": data})

@store_bp.route("/api/admin/store/add_customer", methods=["POST"])
def api_admin_store_add_customer():
    if session.get("role") != "SUPER_ADMIN": return jsonify({"status": "error"}), 403
    data = request.get_json() or {}
    full_name = data.get("full_name", "").strip()
    phone_number = data.get("phone_number", "").strip()
    email = data.get("email", "").strip()
    u = data.get("username", "").strip()
    p = data.get("password", "")
    if not full_name or not email or not u or not p: return jsonify({"status": "error", "message": "All fields are required"}), 400
    if len(p) < 8: return jsonify({"status": "error", "message": "Password must be at least 8 characters"}), 400
    conn = db_conn(); c = conn.cursor()
    try:
        # plain_password is NOT stored — use reset-password feature instead
        c.execute("INSERT INTO store_customers(username, password_hash, created_at, full_name, phone_number, email, is_active, clear_limit, clear_count, is_vip, can_buy) VALUES (?, ?, ?, ?, ?, ?, 1, 5, 0, 0, 1)",
                  (u, generate_password_hash(p), datetime.datetime.utcnow().isoformat(), full_name, phone_number, email))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close(); return jsonify({"status": "error", "message": "Username already exists"}), 400
    conn.close()
    return jsonify({"status": "ok", "message": "Customer added successfully."})

@store_bp.route("/api/admin/store/bulk_add_customers", methods=["POST"])
def api_admin_store_bulk_add_customers():
    if session.get("role") != "SUPER_ADMIN": return jsonify({"status": "error"}), 403
    csv_data = (request.get_json() or {}).get("csv", "")
    if not csv_data: return jsonify({"status": "error", "message": "No data provided"}), 400
    conn = db_conn(); c = conn.cursor(); lines = csv_data.strip().split("\n"); added = 0; failed = 0
    for line in lines:
        parts = [x.strip() for x in line.split(",")]
        if len(parts) >= 5:
            fname, phone, email, u, p = parts[0], parts[1], parts[2], parts[3], parts[4]
            if not u or not p or len(p) < 8: failed += 1; continue
            try:
                # plain_password is NOT stored — security fix
                c.execute("INSERT INTO store_customers(username, password_hash, created_at, full_name, phone_number, email, is_active, clear_limit, clear_count, is_vip, can_buy) VALUES (?, ?, ?, ?, ?, ?, 1, 5, 0, 0, 1)",
                          (u, generate_password_hash(p), datetime.datetime.utcnow().isoformat(), fname, phone, email))
                added += 1
            except Exception: failed += 1
        else: failed += 1
    conn.commit(); conn.close()
    return jsonify({"status": "ok", "message": f"Successfully added {added} customers. {failed} failed."})

@store_bp.route("/api/admin/store/toggle_can_buy", methods=["POST"])
def api_admin_store_toggle_can_buy():
    if session.get("role") != "SUPER_ADMIN": return jsonify({"status": "error"}), 403
    d = request.get_json() or {}
    cid, can_buy = d.get("id"), d.get("can_buy")
    conn = db_conn(); c = conn.cursor()
    c.execute("UPDATE store_customers SET can_buy=? WHERE id=?", (int(can_buy), cid))
    conn.commit(); conn.close()
    return jsonify({"status": "ok", "message": "Purchase permission updated"})

@store_bp.route("/api/admin/store/toggle_customer", methods=["POST"])
def api_admin_store_toggle_customer():
    if session.get("role") != "SUPER_ADMIN": return jsonify({"status": "error"}), 403
    d = request.get_json() or {}; cid, is_active = d.get("id"), d.get("is_active")
    conn = db_conn(); c = conn.cursor()
    c.execute("UPDATE store_customers SET is_active=? WHERE id=?", (int(is_active), cid)); conn.commit(); conn.close()
    return jsonify({"status": "ok", "message": "Customer status updated"})

@store_bp.route("/api/admin/store/toggle_vip", methods=["POST"])
def api_admin_store_toggle_vip():
    if session.get("role") != "SUPER_ADMIN": return jsonify({"status": "error"}), 403
    d = request.get_json() or {}; cid, is_vip = d.get("id"), d.get("is_vip")
    conn = db_conn(); c = conn.cursor()
    c.execute("UPDATE store_customers SET is_vip=? WHERE id=?", (int(is_vip), cid)); conn.commit(); conn.close()
    return jsonify({"status": "ok", "message": "VIP status updated"})

@store_bp.route("/api/admin/store/delete_customer", methods=["POST"])
def api_admin_store_delete_customer():
    if session.get("role") != "SUPER_ADMIN": return jsonify({"status": "error"}), 403
    cid = request.get_json().get("id")
    conn = db_conn(); c = conn.cursor()
    c.execute("DELETE FROM store_customers WHERE id=?", (cid,)); conn.commit(); conn.close()
    return jsonify({"status": "ok", "message": "Customer deleted successfully"})

@store_bp.route("/api/admin/store/update_clear_limit", methods=["POST"])
def api_admin_store_update_limit():
    if session.get("role") != "SUPER_ADMIN": return jsonify({"status": "error"}), 403
    d = request.get_json() or {}; cid, new_limit = d.get("id"), d.get("clear_limit")
    conn = db_conn(); c = conn.cursor()
    c.execute("UPDATE store_customers SET clear_limit=? WHERE id=?", (int(new_limit), cid)); conn.commit(); conn.close()
    return jsonify({"status": "ok", "message": "Clear limit updated"})

@store_bp.route("/api/store_admin/settings", methods=["POST"])
def api_store_admin_settings_save():
    if session.get("role") != "SUPER_ADMIN": return jsonify({"status": "error"}), 403
    data = request.get_json() or {}
    gateways = data.get("mobile_banking_gateways")
    if gateways is not None:
        conn = db_conn(); c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO store_settings(key, value) VALUES ('mobile_banking_gateways', ?)", (json.dumps(gateways),))
        conn.commit(); conn.close()
        return jsonify({"status": "ok", "message": "Settings saved successfully"})
    return jsonify({"status": "error", "message": "Invalid settings payload"}), 400

@store_bp.route("/api/admin/store/pricing_multi", methods=["POST"])
def api_admin_store_pricing_multi():
    if session.get("role") != "SUPER_ADMIN": return jsonify({"status": "error"}), 403
    d = request.get_json() or {}
    app_name, p30, p60, p90 = d.get("app_name"), d.get("price_30"), d.get("price_60"), d.get("price_90")
    if not app_name: return jsonify({"status": "error", "message": "App Name is required"}), 400
    conn = db_conn(); c = conn.cursor()
    if p30 and str(p30).strip(): c.execute("INSERT OR REPLACE INTO store_bot_pricing(app_name, duration_days, price, is_active) VALUES (?,30,?,1)", (app_name, float(p30)))
    if p60 and str(p60).strip(): c.execute("INSERT OR REPLACE INTO store_bot_pricing(app_name, duration_days, price, is_active) VALUES (?,60,?,1)", (app_name, float(p60)))
    if p90 and str(p90).strip(): c.execute("INSERT OR REPLACE INTO store_bot_pricing(app_name, duration_days, price, is_active) VALUES (?,90,?,1)", (app_name, float(p90)))
    conn.commit(); conn.close()
    return jsonify({"status": "ok", "message": f"Prices updated for {app_name}"})

@store_bp.route("/api/admin/store/update_pricing", methods=["POST"])
def api_admin_store_update_pricing():
    if session.get("role") != "SUPER_ADMIN": return jsonify({"status": "error"}), 403
    d = request.get_json() or {}
    app_name = d.get("app_name")
    
    if not app_name: return jsonify({"status": "error", "message": "App name required"}), 400
    
    price_30 = float(d.get("price_30", 0))
    price_60 = float(d.get("price_60", 0))
    price_90 = float(d.get("price_90", 0))
    is_active = int(d.get("is_active", 1))
    stock_status = d.get("stock_status", "Available")
    
    conn = db_conn(); c = conn.cursor()
    
    # Update or insert for 30 days
    c.execute("INSERT INTO store_bot_pricing (app_name, duration_days, price, is_active, stock_status) VALUES (?, 30, ?, ?, ?) ON CONFLICT(app_name, duration_days) DO UPDATE SET price=?, is_active=?, stock_status=?", (app_name, price_30, is_active, stock_status, price_30, is_active, stock_status))
    
    # Update or insert for 60 days
    c.execute("INSERT INTO store_bot_pricing (app_name, duration_days, price, is_active, stock_status) VALUES (?, 60, ?, ?, ?) ON CONFLICT(app_name, duration_days) DO UPDATE SET price=?, is_active=?, stock_status=?", (app_name, price_60, is_active, stock_status, price_60, is_active, stock_status))
    
    # Update or insert for 90 days
    c.execute("INSERT INTO store_bot_pricing (app_name, duration_days, price, is_active, stock_status) VALUES (?, 90, ?, ?, ?) ON CONFLICT(app_name, duration_days) DO UPDATE SET price=?, is_active=?, stock_status=?", (app_name, price_90, is_active, stock_status, price_90, is_active, stock_status))
    
    conn.commit(); conn.close()
    return jsonify({"status": "ok", "message": "Bot pricing updated successfully"})

@store_bp.route("/api/admin/store/delete_pricing", methods=["POST"])
def api_admin_store_delete_pricing():
    if session.get("role") != "SUPER_ADMIN": return jsonify({"status": "error"}), 403
    pid = request.get_json().get("id")
    conn = db_conn(); c = conn.cursor()
    c.execute("DELETE FROM store_bot_pricing WHERE id=?", (pid,)); conn.commit(); conn.close()
    return jsonify({"status": "ok", "message": "Bot removed from store."})

@store_bp.route("/api/admin/store/licenses", methods=["GET"])
def api_admin_store_licenses():
    if session.get("role") != "SUPER_ADMIN": return jsonify({"status": "error"}), 403
    conn = db_conn(); c = conn.cursor()
    # Single JOIN query — fixes N+1 query performance issue
    c.execute("""
        SELECT so.customer_username, so.notes, sc.email, u.machine_id, u.expiry_date, u.status
        FROM store_orders so
        LEFT JOIN store_customers sc ON sc.username = so.customer_username
        LEFT JOIN (
            SELECT o2.notes, u2.username, u2.machine_id, u2.expiry_date, u2.status
            FROM store_orders o2
            JOIN users u2 ON u2.username = json_extract(o2.notes, '$.license_key')
            WHERE o2.status='APPROVED'
        ) AS ul ON ul.notes = so.notes
        LEFT JOIN users u ON u.username = json_extract(so.notes, '$.license_key')
        WHERE so.status='APPROVED'
    """)
    data = []
    for row in c.fetchall():
        try:
            n = json.loads(row[1]) if row[1] else {}
        except Exception:
            continue
        license_key = n.get("license_key")
        if not license_key or not row[3]: continue  # skip if no user record
        app_name = n.get("app_name", "")
        plan_months = max(1, n.get("duration_days", 0) // 30)
        plan_type = "VIP" if "VIP" in app_name.upper() else "Regular"
        data.append({"tool_name": app_name, "customer_email": row[2] or row[0], "tools_version": n.get("version", "v1.0"), "username": license_key, "activation_key": license_key, "expiry_date": row[4], "machine_id": row[3] or "-", "plan_months": plan_months, "plan_type": plan_type, "status": row[5]})
    conn.close()
    return jsonify({"status": "ok", "data": data})

@store_bp.route("/api/admin/store/vip_licenses", methods=["GET"])
def api_admin_store_vip_licenses():
    if session.get("role") != "SUPER_ADMIN": return jsonify({"status": "error"}), 403
    conn = db_conn(); c = conn.cursor()
    c.execute("SELECT customer_username, notes FROM store_orders WHERE status='APPROVED'")
    orders = c.fetchall()
    c.execute("SELECT username, email FROM store_customers")
    customers = {r[0]: r[1] for r in c.fetchall()}
    data = []
    for row in orders:
        try:
            n = json.loads(row[1]) if row[1] else {}
        except:
            continue
        license_key = n.get("license_key")
        app_name = n.get("app_name", "")
        if not license_key or "VIP" not in app_name.upper(): continue
        c.execute("SELECT machine_id, expiry_date, status FROM users WHERE username=?", (license_key,))
        u = c.fetchone()
        if not u: continue
        plan_months = max(1, n.get("duration_days", 0) // 30)
        data.append({"tool_name": app_name, "customer_email": customers.get(row[0], row[0]), "tools_version": n.get("version", "v1.0"), "username": license_key, "activation_key": license_key, "expiry_date": u[1], "machine_id": u[0] or "-", "plan_months": plan_months, "plan_type": "VIP", "status": u[2]})
    conn.close()
    return jsonify({"status": "ok", "data": data})

@store_bp.route("/api/admin/store/orders", methods=["GET"])
def api_admin_store_orders():
    if session.get("role") != "SUPER_ADMIN": return jsonify({"status": "error"}), 403
    conn = db_conn(); c = conn.cursor()
    c.execute("SELECT id, customer_username, notes, total_amount, payment_method, sender_number, transaction_id, payment_screenshot, status, created_at FROM store_orders ORDER BY id DESC")
    data = []
    for r in c.fetchall():
        try:
            n = json.loads(r[2]) if r[2] else {}
        except:
            n = {}
        data.append({"id": r[0], "customer": r[1], "app_name": n.get("app_name", ""), "days": n.get("duration_days", 0), "price": r[3], "payment_method": r[4], "sender_number": r[5], "transaction_id": r[6], "payment_screenshot": r[7], "status": r[8], "created_at": r[9], "notes": r[2]})
    conn.close()
    return jsonify({"status": "ok", "data": data})

@store_bp.route("/api/admin/store/approve", methods=["POST"])
def api_admin_store_approve():
    if session.get("role") != "SUPER_ADMIN": return jsonify({"status": "error"}), 403
    oid = request.get_json().get("order_id")
    conn = db_conn(); c = conn.cursor()
    c.execute("SELECT customer_username, notes, status FROM store_orders WHERE id=?", (oid,))
    order = c.fetchone()
    
    if not order or order[2] != 'PENDING': 
        conn.close(); return jsonify({"status": "error", "message": "Invalid or already processed order"}), 400
        
    customer, n_str, _ = order
    try:
        n = json.loads(n_str) if n_str else {}
    except:
        n = {}
    app_name = n.get("app_name", "")
    days = n.get("duration_days", 0)
    rand_key = f"{customer}_{secrets.token_hex(2).upper()[:3]}"
    c.execute("SELECT id FROM users WHERE username=?", (rand_key,))
    while c.fetchone():
        rand_key = f"{customer}_{secrets.token_hex(2).upper()[:3]}"
        c.execute("SELECT id FROM users WHERE username=?", (rand_key,))
    
    today = datetime.date.today()
    new_expiry = today + datetime.timedelta(days=days)
    
    c.execute("INSERT INTO users(username, activation_key, status, machine_id, expiry_date, created_by_username, created_by_role) VALUES (?,?,?,?,?,?,?)",
        (rand_key, rand_key, 'ENABLED', '-', new_expiry.isoformat(), customer, 'STORE_CUSTOMER'))
        
    if 'ALL TOOLS' not in app_name.upper():
        try:
            c.execute("SELECT app_name FROM bots WHERE app_name != ?", (app_name,))
            other_bots = c.fetchall()
            for b in other_bots:
                c.execute("INSERT OR IGNORE INTO user_bot_blocks(username, app_name) VALUES (?,?)", (rand_key, b[0]))
        except Exception as e:
            current_app.logger.error(f"Error: {e}")
            
    c.execute("SELECT notes FROM store_orders WHERE id=?", (oid,))
    n_str = c.fetchone()[0]
    try:
        n = json.loads(n_str) if n_str else {}
    except:
        n = {}
    n["approved_at"] = datetime.datetime.utcnow().isoformat()
    n["license_key"] = rand_key
    n["payment_type"] = "Manual Payment"
    c.execute("UPDATE store_orders SET status='APPROVED', notes=? WHERE id=?", (json.dumps(n), oid))
    conn.commit(); conn.close()
    return jsonify({"status": "ok", "message": "Order approved & License auto-generated!"})


@store_bp.route("/api/admin/store/delete_order", methods=["POST"])
def api_admin_store_delete_order():
    if session.get("role") != "SUPER_ADMIN": return jsonify({"status": "error"}), 403
    oid = (request.get_json() or {}).get("order_id")
    conn = db_conn(); c = conn.cursor()
    c.execute("DELETE FROM store_orders WHERE id=?", (oid,))
    conn.commit(); conn.close()
    return jsonify({"status": "ok", "message": "Order deleted"})


# =================== ADMIN: RESET CUSTOMER PASSWORD ===================
# Replaces the insecure plain_password column feature

@store_bp.route("/api/admin/store/reset_customer_password", methods=["POST"])
def api_admin_store_reset_password():
    """Admin resets a store customer's password securely — no plain text stored."""
    if session.get("role") != "SUPER_ADMIN":
        return jsonify({"status": "error", "message": "Forbidden"}), 403

    d = request.get_json() or {}
    customer_id = d.get("id")
    new_password = (d.get("new_password") or "").strip()

    if not customer_id or not new_password:
        return jsonify({"status": "error", "message": "Customer ID and new password are required"}), 400
    if len(new_password) < 8:
        return jsonify({"status": "error", "message": "Password must be at least 8 characters"}), 400

    conn = db_conn(); c = conn.cursor()
    c.execute("SELECT id, username FROM store_customers WHERE id=?", (customer_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"status": "error", "message": "Customer not found"}), 404

    new_hash = generate_password_hash(new_password)
    c.execute("UPDATE store_customers SET password_hash=? WHERE id=?", (new_hash, customer_id))
    conn.commit(); conn.close()
    return jsonify({"status": "ok", "message": f"Password reset successfully for {row[1]}"})


# =================== HEALTH CHECK ===================

@store_bp.route("/health", methods=["GET"])
def health_check():
    """Docker/load-balancer health check endpoint."""
    try:
        conn = db_conn()
        conn.execute("SELECT 1")
        conn.close()
        return jsonify({"status": "healthy", "db": "ok"}), 200
    except Exception as e:
        return jsonify({"status": "unhealthy", "db": str(e)}), 503
