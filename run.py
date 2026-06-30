from dotenv import load_dotenv
load_dotenv()

import os
import logging

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

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
    init_store_db()


if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=5000, debug=debug, threaded=True)
