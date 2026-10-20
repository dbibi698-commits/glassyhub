import os, sqlite3, secrets, hashlib, hmac
from datetime import datetime
from functools import wraps
from flask import Flask, request, jsonify, session, send_from_directory, g

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "glasshub.db")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "dbibi698@gmail.com").strip().lower()
SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "CHANGE_THIS_TO_A_LONG_RANDOM_SECRET")
app = Flask(__name__, static_folder="static", static_url_path="/static")
app.secret_key = SECRET_KEY
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_=None):
    conn = g.pop("db", None)
    if conn is not None: conn.close()

def init_db():
    con = sqlite3.connect(DB_PATH)
    con.executescript("""
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL, salt TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user',
      blocked INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, last_seen TEXT
    );
    CREATE TABLE IF NOT EXISTS bookings(
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, name TEXT NOT NULL, email TEXT NOT NULL,
      service TEXT NOT NULL, details TEXT, status TEXT NOT NULL DEFAULT 'Pending', created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS events(
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, event TEXT NOT NULL, details TEXT,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS notifications(
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT NOT NULL,
      message TEXT NOT NULL, created_at TEXT NOT NULL, read_at TEXT
    );
    """)
    # Admin account is created only after the owner registers with the configured admin email.
    con.commit(); con.close()

def now(): return datetime.utcnow().isoformat(timespec="seconds") + "Z"
def password_hash(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 240000).hex()
def current_user():
    uid = session.get("uid")
    if not uid: return None
    row = db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not row or row["blocked"]:
        session.clear(); return None
    db().execute("UPDATE users SET last_seen=? WHERE id=?", (now(), uid)); db().commit()
    return row
def log_event(event, details=""):
    user = current_user()
    db().execute("INSERT INTO events(user_id,event,details,created_at) VALUES(?,?,?,?)",
                 (user["id"] if user else None, event[:100], details[:500], now()))
    db().commit()
def login_required(fn):
    @wraps(fn)
    def wrapped(*a, **kw):
        u = current_user()
        if not u: return jsonify(error="Please sign in first."), 401
        return fn(*a, **kw)
    return wrapped
def admin_required(fn):
    @wraps(fn)
    def wrapped(*a, **kw):
        u = current_user()
        if not u: return jsonify(error="Please sign in first."), 401
        if u["role"] != "admin" or u["email"].lower() != ADMIN_EMAIL:
            return jsonify(error="Admin access only."), 403
        return fn(*a, **kw)
    return wrapped

@app.get("/")
def home(): return send_from_directory(APP_DIR, "index.html")

@app.post("/api/register")
def register():
    data = request.get_json(silent=True) or {}
    name, email, password = (str(data.get(k, "")).strip() for k in ("name","email","password"))
    email = email.lower()
    if not name or len(name) > 80 or "@" not in email or len(password) < 8:
        return jsonify(error="Enter a name, valid email, and password of at least 8 characters."), 400
    salt = secrets.token_hex(16)
    role = "admin" if email == ADMIN_EMAIL else "user"
    try:
        cur = db().execute("INSERT INTO users(name,email,password_hash,salt,role,created_at) VALUES(?,?,?,?,?,?)",
             (name,email,password_hash(password,salt),salt,role,now()))
        db().commit(); session["uid"] = cur.lastrowid
        log_event("register", "Account created")
        return jsonify(ok=True, user={"name":name,"email":email,"role":role})
    except sqlite3.IntegrityError:
        return jsonify(error="That email is already registered."), 409

@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    email, password = str(data.get("email","")).strip().lower(), str(data.get("password",""))
    row = db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not row or not hmac.compare_digest(password_hash(password,row["salt"]), row["password_hash"]):
        return jsonify(error="Email or password is incorrect."), 401
    if row["blocked"]: return jsonify(error="This account has been blocked by the administrator."), 403
    session.clear(); session["uid"] = row["id"]
    log_event("login", "Signed in")
    return jsonify(ok=True, user={"name":row["name"],"email":row["email"],"role":row["role"]})

@app.post("/api/logout")
def logout():
    log_event("logout", "Signed out"); session.clear()
    return jsonify(ok=True)

@app.get("/api/me")
def me():
    u = current_user()
    return jsonify(user={"name":u["name"],"email":u["email"],"role":u["role"]} if u else None)

@app.post("/api/bookings")
def create_booking():
    data = request.get_json(silent=True) or {}
    u = current_user()
    name = (u["name"] if u else str(data.get("name","")).strip())[:80]
    email = (u["email"] if u else str(data.get("email","")).strip().lower())[:160]
    service = str(data.get("service","")).strip()[:120]
    details = str(data.get("details","")).strip()[:1000]
    if not name or "@" not in email or not service:
        return jsonify(error="Enter your name, email and select a service."), 400
    db().execute("INSERT INTO bookings(user_id,name,email,service,details,created_at) VALUES(?,?,?,?,?,?)",
                 (u["id"] if u else None,name,email,service,details,now()))
    db().commit(); log_event("booking", service)
    return jsonify(ok=True, message="Booking request submitted. Admin can review it.")

@app.get("/api/notifications")
@login_required
def notifications():
    u = current_user()
    rows = db().execute("SELECT id,title,message,created_at,read_at FROM notifications WHERE user_id IS NULL OR user_id=? ORDER BY id DESC LIMIT 100", (u["id"],)).fetchall()
    return jsonify(notifications=[dict(r) for r in rows])

@app.post("/api/notifications/<int:notification_id>/read")
@login_required
def notification_read(notification_id):
    u = current_user()
    db().execute("UPDATE notifications SET read_at=? WHERE id=? AND (user_id IS NULL OR user_id=?)", (now(), notification_id, u["id"]))
    db().commit()
    return jsonify(ok=True)

@app.get("/api/my-bookings")
@login_required
def my_bookings():
    u=current_user()
    rows=db().execute("SELECT id,service,details,status,created_at FROM bookings WHERE user_id=? ORDER BY id DESC",(u["id"],)).fetchall()
    return jsonify(bookings=[dict(r) for r in rows])

@app.post("/api/events")
def event():
    data=request.get_json(silent=True) or {}
    allowed={"tool_open","shortcut_add","page_open","download"}
    ev=str(data.get("event",""))
    if ev in allowed: log_event(ev,str(data.get("details","")))
    return jsonify(ok=True)

@app.get("/api/admin/summary")
@admin_required
def admin_summary():
    con=db()
    return jsonify(users=con.execute("SELECT id,name,email,role,blocked,created_at,last_seen FROM users ORDER BY id DESC").fetchall() and
       [dict(r) for r in con.execute("SELECT id,name,email,role,blocked,created_at,last_seen FROM users ORDER BY id DESC").fetchall()],
       bookings=[dict(r) for r in con.execute("SELECT id,name,email,service,details,status,created_at FROM bookings ORDER BY id DESC").fetchall()],
       events=[dict(r) for r in con.execute("SELECT e.id,u.email,e.event,e.details,e.created_at FROM events e LEFT JOIN users u ON u.id=e.user_id ORDER BY e.id DESC LIMIT 200").fetchall()])

@app.post("/api/admin/notifications")
@admin_required
def admin_notify():
    data = request.get_json(silent=True) or {}
    title = str(data.get("title", "")).strip()[:120]
    message = str(data.get("message", "")).strip()[:2000]
    audience = str(data.get("audience", "all"))
    if not title or not message:
        return jsonify(error="Enter both a title and message."), 400
    if audience == "all":
        db().execute("INSERT INTO notifications(user_id,title,message,created_at) VALUES(NULL,?,?,?)", (title, message, now()))
    else:
        try: target_id = int(audience)
        except (TypeError, ValueError): return jsonify(error="Invalid audience."), 400
        exists = db().execute("SELECT id FROM users WHERE id=?", (target_id,)).fetchone()
        if not exists: return jsonify(error="User not found."), 404
        db().execute("INSERT INTO notifications(user_id,title,message,created_at) VALUES(?,?,?,?)", (target_id, title, message, now()))
    db().commit()
    return jsonify(ok=True, message="Notification published.")

@app.post("/api/admin/users/<int:user_id>/block")
@admin_required
def block_user(user_id):
    u=current_user()
    if u["id"] == user_id: return jsonify(error="You cannot block your own admin account."), 400
    data=request.get_json(silent=True) or {}
    db().execute("UPDATE users SET blocked=? WHERE id=? AND role!='admin'",(1 if data.get("blocked") else 0,user_id))
    db().commit(); return jsonify(ok=True)

@app.post("/api/admin/bookings/<int:booking_id>")
@admin_required
def update_booking(booking_id):
    status=str((request.get_json(silent=True) or {}).get("status","Pending"))
    if status not in {"Pending","Accepted","Completed","Cancelled"}: return jsonify(error="Invalid status"),400
    db().execute("UPDATE bookings SET status=? WHERE id=?",(status,booking_id)); db().commit()
    return jsonify(ok=True)

@app.get("/health")
def health(): return jsonify(ok=True)

init_db()
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.getenv("PORT","5000")), debug=False)
