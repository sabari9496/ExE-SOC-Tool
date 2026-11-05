"""Production entry point: gunicorn -k gthread --threads 8 -w 1 -b 127.0.0.1:5000 wsgi:app   (one worker: in-process state/threads). TLS is terminated by the reverse proxy."""
import os
os.environ.setdefault("SOC_ENV", "production")
import app as _a
import db
db.guard_foreign_db(); db.init_db(); _a.start_workers()      # raises CryptoError (refuses to start) when SOC_ENC_KEYS is missing in production
import syslogrx; syslogrx.start()
app = _a.app
