from dotenv import load_dotenv
load_dotenv()

import os
import logging

log = logging.getLogger('werkzeug')
log.setLevel(logging.INFO)

from app import create_app
# Use _startup_init which wraps init_db + ensure_super_admin with Railway-ready
# retry logic (up to 60 s) so the app handles a slow-mounting volume gracefully.
from app.legacy_admin import _startup_init
from app.store import init_store_db

app = create_app()

with app.app_context():
    db_path = os.environ.get("DB_PATH", "/data/users.db")
    db_dir = os.path.dirname(db_path)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    
    _startup_init()     # init_db() + ensure_super_admin() with retry
    
    # Add retry logic for init_store_db to handle concurrent gunicorn workers
    import time
    import sqlite3
    for _i in range(12):
        try:
            init_store_db()
            break
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e).lower() or "readonly" in str(e).lower():
                time.sleep(5)
            else:
                raise


if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=5000, debug=debug, threaded=True)
