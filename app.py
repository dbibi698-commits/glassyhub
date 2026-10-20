import os, io, sqlite3, secrets, hashlib, hmac, zipfile
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, request, jsonify, session, send_file, render_template_string
from PIL import Image
import fitz

BASE=os.path.dirname(os.path.abspath(__file__))
DB=os.path.join(BASE,'glasshub.db')
ADMIN_EMAIL=os.environ.get('ADMIN_EMAIL','dbibi698@gmail.com').strip().lower()
app=Flask(__name__); app.secret_key=os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH']=35*1024*1024

def now(): return datetime.now(timezone.utc).isoformat(timespec='seconds')
def conn():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; c.execute('PRAGMA foreign_keys=ON'); return c
def phash(p,s): return hashlib.pbkdf2_hmac('sha256',p.encode(),s.encode(),240000).hex()
def init_db():
    with conn() as c:
        c.executescript('''CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,name TEXT NOT NULL,email TEXT UNIQUE NOT NULL,salt TEXT NOT NULL,pw TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'user',blocked INTEGER NOT NULL DEFAULT 0,created TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS bookings(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL,service TEXT NOT NULL,details TEXT DEFAULT '',status TEXT DEFAULT 'Pending',note TEXT DEFAULT '',created TEXT NOT NULL,updated TEXT NOT NULL,FOREIGN KEY(user_id) REFERENCES users(id));
        CREATE TABLE IF NOT EXISTS notices(id INTEGER PRIMARY KEY,user_id INTEGER,title TEXT NOT NULL,message TEXT NOT NULL,created TEXT NOT NULL,read_at TEXT);
        CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,user_id INTEGER,event TEXT,details TEXT,created TEXT);''')
        # Admin is provisioned only when the server owner sets ADMIN_PASSWORD (12+ chars).
        ap=os.environ.get('ADMIN_PASSWORD','')
        if len(ap)>=12:
            r=c.execute('SELECT id FROM users WHERE email=?',(ADMIN_EMAIL,)).fetchone()
            if not r:
                s=secrets.token_hex(16); c.execute('INSERT INTO users(name,email,salt,pw,role,created) VALUES(?,?,?,?,?,?)',('GlassHub Admin',ADMIN_EMAIL,s,phash(ap,s),'admin',now()))
            else: c.execute("UPDATE users SET role='admin' WHERE email=?",(ADMIN_EMAIL,))
def user():
    uid=session.get('uid')
    if not uid:return None
    with conn() as c:r=c.execute('SELECT id,name,email,role,blocked,created FROM users WHERE id=?',(uid,)).fetchone()
    if not r or r['blocked']:session.clear();return None
    return dict(r)
def event(kind,detail=''):
    u=user()
    with conn() as c:c.execute('INSERT INTO events(user_id,event,details,created) VALUES(?,?,?,?)',(u['id'] if u else None,kind,detail[:500],now()))
def body():return request.get_json(silent=True) or {}
def login_required(f):
    @wraps(f)
    def w(*a,**k):
        if not user():return jsonify(error='Please log in first.'),401
        return f(*a,**k)
    return w
def admin_required(f):
    @wraps(f)
    def w(*a,**k):
        u=user()
        if not u or u['role']!='admin':return jsonify(error='Administrator access required.'),403
        return f(*a,**k)
    return w

@app.get('/')
def home():return render_template_string(HTML)
@app.get('/health')
def health():return jsonify(ok=True,app='GlassHub',time=now())
@app.get('/api/me')
def me():return jsonify(user=user())
@app.post('/api/register')
def register():
    d=body(); name=str(d.get('name','')).strip()[:80]; email=str(d.get('email','')).strip().lower(); p=str(d.get('password',''))
    if len(name)<2 or '@' not in email or len(p)<8:return jsonify(error='Enter name, valid email and password of at least 8 characters.'),400
    if email==ADMIN_EMAIL:return jsonify(error='Admin account must be securely provisioned by the server owner.'),403
    s=secrets.token_hex(16)
    try:
        with conn() as c:cur=c.execute("INSERT INTO users(name,email,salt,pw,role,created) VALUES(?,?,?,?, 'user',?)",(name,email,s,phash(p,s),now())); uid=cur.lastrowid
        session['uid']=uid; event('register',email); return jsonify(ok=True,user=user()),201
    except sqlite3.IntegrityError:return jsonify(error='Email already registered.'),409
@app.post('/api/login')
def login():
    d=body(); email=str(d.get('email','')).strip().lower(); p=str(d.get('password',''))
    with conn() as c:r=c.execute('SELECT * FROM users WHERE email=?',(email,)).fetchone()
    if not r or r['blocked'] or not hmac.compare_digest(phash(p,r['salt']),r['pw']):return jsonify(error='Invalid login or account blocked.'),401
    session['uid']=r['id'];event('login',email);return jsonify(ok=True,user=user())
@app.post('/api/logout')
def logout():session.clear();return jsonify(ok=True)
@app.post('/api/profile')
@login_required
def profile():
    d=body(); n=str(d.get('name','')).strip()[:80]; e=str(d.get('email','')).strip().lower()
    if len(n)<2 or '@' not in e:return jsonify(error='Enter a valid name and email.'),400
    u=user()
    if e==ADMIN_EMAIL and u['role']!='admin':return jsonify(error='Reserved admin email.'),403
    try:
        with conn() as c:c.execute('UPDATE users SET name=?,email=? WHERE id=?',(n,e,u['id']))
        return jsonify(ok=True,user=user())
    except sqlite3.IntegrityError:return jsonify(error='Email already used.'),409
@app.post('/api/password')
@login_required
def password():
    d=body();u=user();old=str(d.get('old',''));new=str(d.get('new',''))
    with conn() as c:r=c.execute('SELECT salt,pw FROM users WHERE id=?',(u['id'],)).fetchone()
    if not hmac.compare_digest(phash(old,r['salt']),r['pw']):return jsonify(error='Current password is incorrect.'),400
    if len(new)<8:return jsonify(error='New password must be at least 8 characters.'),400
    s=secrets.token_hex(16)
    with conn() as c:c.execute('UPDATE users SET salt=?,pw=? WHERE id=?',(s,phash(new,s),u['id']))
    return jsonify(ok=True,message='Password changed.')

@app.post('/api/jpg-to-pdf')
def jpg_to_pdf():
    files=request.files.getlist('images')
    if not files:return jsonify(error='Upload one or more JPG/PNG images.'),400
    if len(files)>40:return jsonify(error='Maximum 40 images per conversion.'),400
    try:
        out=fitz.open()
        for f in files:
            im=Image.open(f.stream).convert('RGB'); b=io.BytesIO(); im.save(b,'JPEG',quality=94,optimize=True)
            p=out.new_page(width=im.width,height=im.height);p.insert_image(p.rect,stream=b.getvalue())
        data=out.tobytes(garbage=4,deflate=True);out.close()
        return send_file(io.BytesIO(data),mimetype='application/pdf',as_attachment=True,download_name='GlassHub_images.pdf')
    except Exception:return jsonify(error='Invalid image file. Use JPG or PNG.'),400
@app.post('/api/pdf-to-jpg')
def pdf_to_jpg():
    f=request.files.get('pdf')
    if not f:return jsonify(error='Upload a PDF first.'),400
    try:
        doc=fitz.open(stream=f.read(),filetype='pdf')
        if doc.page_count>80:doc.close();return jsonify(error='Maximum 80 pages.'),400
        z=io.BytesIO()
        with zipfile.ZipFile(z,'w',zipfile.ZIP_DEFLATED) as arc:
            for i,p in enumerate(doc):arc.writestr(f'page_{i+1:03}.jpg',p.get_pixmap(matrix=fitz.Matrix(2,2),alpha=False).tobytes('jpeg'))
        doc.close();z.seek(0);return send_file(z,mimetype='application/zip',as_attachment=True,download_name='GlassHub_PDF_to_JPG.zip')
    except Exception:return jsonify(error='Invalid or encrypted PDF.'),400
@app.post('/api/image-resize')
def image_resize():
    f=request.files.get('image')
    if not f:return jsonify(error='Upload an image first.'),400
    try:
        im=Image.open(f.stream);w=int(request.form.get('width',im.width));h=int(request.form.get('height',im.height));q=max(30,min(100,int(request.form.get('quality',92))))
        if not(1<=w<=6000 and 1<=h<=6000):return jsonify(error='Width/height must be 1–6000 pixels.'),400
        im=im.convert('RGB').resize((w,h),Image.Resampling.LANCZOS);o=io.BytesIO();im.save(o,'JPEG',quality=q,optimize=True)
        return send_file(io.BytesIO(o.getvalue()),mimetype='image/jpeg',as_attachment=True,download_name='GlassHub_resized.jpg')
    except Exception:return jsonify(error='Invalid image or dimensions.'),400
@app.post('/api/pdf-resize')
def pdf_resize():
    f=request.files.get('pdf')
    if not f:return jsonify(error='Upload a PDF first.'),400
    try:
        scale=float(request.form.get('scale','1'))
        if scale not in (.5,.6,.8,1.0):return jsonify(error='Select 50%, 60%, 80% or 100%.'),400
        src=fitz.open(stream=f.read(),filetype='pdf')
        if src.page_count>100:src.close();return jsonify(error='Maximum 100 pages.'),400
        out=fitz.open()
        for p in src:
            rect=p.rect; pix=p.get_pixmap(matrix=fitz.Matrix(scale,scale),alpha=False)
            page=out.new_page(width=rect.width,height=rect.height);page.insert_image(page.rect,stream=pix.tobytes('png'))
        data=out.tobytes(garbage=4,deflate=True);src.close();out.close()
        return send_file(io.BytesIO(data),mimetype='application/pdf',as_attachment=True,download_name='GlassHub_resized.pdf')
    except Exception:return jsonify(error='Invalid or encrypted PDF.'),400

@app.post('/api/bookings')
@login_required
def booking_create():
    d=body();service=str(d.get('service','')).strip()[:120];details=str(d.get('details','')).strip()[:1500]
    if not service:return jsonify(error='Select a service.'),400
    with conn() as c:
        cur=c.execute("INSERT INTO bookings(user_id,service,details,status,created,updated) VALUES(?,?,?,'Pending',?,?)",(user()['id'],service,details,now(),now()));bid=cur.lastrowid
        c.execute('INSERT INTO notices(user_id,title,message,created) VALUES(?,?,?,?)',(user()['id'],'Booking received',f'Booking #{bid} is pending review.',now()))
    event('booking_created',f'{bid}:{service}');return jsonify(ok=True,id=bid,status='Pending'),201
@app.get('/api/bookings')
@login_required
def my_bookings():
    with conn() as c:rows=c.execute('SELECT id,service,details,status,note,created,updated FROM bookings WHERE user_id=? ORDER BY id DESC',(user()['id'],)).fetchall()
    return jsonify(bookings=[dict(x) for x in rows])
@app.get('/api/notices')
@login_required
def notices():
    with conn() as c:r=c.execute('SELECT * FROM notices WHERE user_id IS NULL OR user_id=? ORDER BY id DESC LIMIT 100',(user()['id'],)).fetchall()
    return jsonify(notices=[dict(x) for x in r])
@app.post('/api/notices/<int:nid>/read')
@login_required
def notice_read(nid):
    with conn() as c:c.execute('UPDATE notices SET read_at=? WHERE id=? AND (user_id IS NULL OR user_id=?)',(now(),nid,user()['id']))
    return jsonify(ok=True)
@app.get('/api/admin/summary')
@admin_required
def admin_summary():
    with conn() as c:
        us=[dict(x) for x in c.execute('SELECT id,name,email,role,blocked,created FROM users ORDER BY id DESC')]
        bs=[dict(x) for x in c.execute('SELECT b.*,u.name AS user_name,u.email AS user_email FROM bookings b JOIN users u ON u.id=b.user_id ORDER BY b.id DESC')]
        ev=[dict(x) for x in c.execute('SELECT * FROM events ORDER BY id DESC LIMIT 250')]
    return jsonify(users=us,bookings=bs,events=ev)
@app.post('/api/admin/users/<int:uid>/block')
@admin_required
def block(uid):
    val=1 if body().get('blocked',True) else 0
    with conn() as c:
        r=c.execute('SELECT role FROM users WHERE id=?',(uid,)).fetchone()
        if not r:return jsonify(error='User not found.'),404
        if r['role']=='admin':return jsonify(error='Cannot block admin.'),403
        c.execute('UPDATE users SET blocked=? WHERE id=?',(val,uid))
    return jsonify(ok=True)
@app.post('/api/admin/users/<int:uid>/edit')
@admin_required
def edit_user(uid):
    d=body();n=str(d.get('name','')).strip()[:80];e=str(d.get('email','')).strip().lower()
    with conn() as c:
        r=c.execute('SELECT role FROM users WHERE id=?',(uid,)).fetchone()
        if not r:return jsonify(error='User not found.'),404
        if r['role']=='admin':return jsonify(error='Admin cannot be edited here.'),403
        if len(n)<2 or '@' not in e:return jsonify(error='Valid name/email required.'),400
        try:c.execute('UPDATE users SET name=?,email=? WHERE id=?',(n,e,uid))
        except sqlite3.IntegrityError:return jsonify(error='Email already in use.'),409
    return jsonify(ok=True)
@app.post('/api/admin/bookings/<int:bid>/review')
@admin_required
def review_booking(bid):
    d=body();status=str(d.get('status',''));note=str(d.get('note','')).strip()[:1000]
    if status not in ('Accepted','Rejected','In Review','Completed','Cancelled'):return jsonify(error='Invalid status.'),400
    with conn() as c:
        r=c.execute('SELECT user_id,service FROM bookings WHERE id=?',(bid,)).fetchone()
        if not r:return jsonify(error='Booking not found.'),404
        c.execute('UPDATE bookings SET status=?,note=?,updated=? WHERE id=?',(status,note,now(),bid))
        c.execute('INSERT INTO notices(user_id,title,message,created) VALUES(?,?,?,?)',(r['user_id'],f'Booking #{bid} updated',f'{r["service"]}: {status}. {note}',now()))
    return jsonify(ok=True)
@app.post('/api/admin/notices')
@admin_required
def publish_notice():
    d=body();title=str(d.get('title','')).strip()[:120];msg=str(d.get('message','')).strip()[:1500];aud=d.get('audience','all')
    if not title or not msg:return jsonify(error='Title and message required.'),400
    with conn() as c:
        if aud=='all':c.execute('INSERT INTO notices(user_id,title,message,created) VALUES(NULL,?,?,?)',(title,msg,now()))
        else:
            try:uid=int(aud)
            except Exception:return jsonify(error='Invalid audience.'),400
            if not c.execute('SELECT id FROM users WHERE id=?',(uid,)).fetchone():return jsonify(error='User not found.'),404
            c.execute('INSERT INTO notices(user_id,title,message,created) VALUES(?,?,?,?)',(uid,title,msg,now()))
    return jsonify(ok=True)
@app.get('/api/admin/export')
@admin_required
def admin_export():
    with conn() as c:return jsonify(exported_at=now(),users=[dict(x) for x in c.execute('SELECT id,name,email,role,blocked,created FROM users')],bookings=[dict(x) for x in c.execute('SELECT * FROM bookings')],notices=[dict(x) for x in c.execute('SELECT * FROM notices')],events=[dict(x) for x in c.execute('SELECT * FROM events')])
@app.errorhandler(413)
def too_large(_):return jsonify(error='Maximum upload size is 35 MB.'),413

HTML=r'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>GlassHub</title><style>
:root{--bg:#0b1020;--panel:#151c31e8;--line:#aab9ff35;--txt:#edf1ff;--muted:#9ca9c9;--a:#8e8aff;--b:#5be1d1}*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 15% 0%,#262448 0,transparent 38%),var(--bg);color:var(--txt);font:15px/1.5 system-ui,Segoe UI,sans-serif}button,input,select,textarea{font:inherit}button{cursor:pointer;color:var(--txt);background:#121a30;border:1px solid #7180b0;border-radius:12px;padding:10px 13px;transition:.18s}button:hover{transform:translateY(-2px);border-color:var(--b);box-shadow:0 8px 24px #0004}input,select,textarea{width:100%;padding:11px;border:1px solid var(--line);border-radius:11px;background:#0b1224;color:var(--txt);margin-top:5px}label{display:block;color:var(--muted);font-size:13px;margin:12px 0}.app{max-width:1450px;margin:auto;padding:16px;display:grid;grid-template-columns:230px 1fr;gap:15px}.glass{background:var(--panel);border:1px solid var(--line);backdrop-filter:blur(16px);border-radius:20px;box-shadow:0 18px 55px #0002}.side{padding:16px;position:sticky;top:16px;height:calc(100vh - 32px);overflow:auto}.brand{font-size:22px;font-weight:850;margin-bottom:15px}.brand span,.accent{color:var(--b)}.nav{display:block;width:100%;text-align:left;margin:5px 0;background:transparent;border-color:transparent}.nav.active,.nav:hover{background:#ffffff0b;border-color:var(--line)}.main{min-width:0}.top{display:flex;align-items:center;justify-content:space-between;padding:14px 18px;margin-bottom:15px;gap:10px}.top h1{font-size:20px;margin:0}.page{display:none}.page.active{display:block;animation:fade .22s ease}@keyframes fade{from{opacity:0;transform:translateY(5px)}to{opacity:1;transform:none}}.hero,.panel{padding:22px;margin-bottom:15px}.hero h2{font-size:clamp(28px,4vw,46px);line-height:1.1;margin:12px 0}.muted,small{color:var(--muted)}.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:11px}.tile{min-height:115px;padding:15px;text-align:left;display:flex;flex-direction:column;gap:7px;background:var(--panel);border:1px solid var(--line);border-radius:16px}.ico{font-size:24px}.tile small{font-size:12px}.row{display:flex;gap:8px;flex-wrap:wrap}.primary{background:linear-gradient(120deg,#5b56a9,#237f85);border-color:#aaaaff}.danger{border-color:#d96c85}.result{white-space:pre-wrap;overflow-wrap:anywhere;background:#070d1b99;padding:12px;border-radius:11px;margin-top:12px}.hidden{display:none!important}.table-wrap{overflow:auto}table{border-collapse:collapse;width:100%;min-width:600px}td,th{text-align:left;padding:9px;border-bottom:1px solid var(--line);font-size:12px}th{color:var(--b)}.badge{border:1px solid var(--line);border-radius:30px;padding:4px 8px;color:var(--b);font-size:11px}.preview{max-width:100%;max-height:220px;border-radius:12px;margin-top:10px}footer{text-align:center;color:var(--muted);padding:20px;font-size:12px}@media(max-width:850px){.app{grid-template-columns:1fr;padding:9px}.side{height:auto;position:relative;top:0}.navs{display:grid;grid-template-columns:repeat(3,1fr);gap:4px}.nav{text-align:center;font-size:12px;padding:8px 3px}.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.panel,.hero{padding:15px}}@media(max-width:420px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
</style></head><body><div class="app"><aside class="side glass"><div class="brand">◈ Glass<span>Hub</span></div><small>NO WALLPAPER · GLASS UI</small><div class="navs"><button class="nav active" data-page="home">◫ Dashboard</button><button class="nav" data-page="tools">▧ All Tools</button><button class="nav" data-page="browser">⌕ Search Browser</button><button class="nav" data-page="cyber">▣ Cyber Cafe</button><button class="nav" data-page="bookings">▤ My Bookings</button><button class="nav" data-page="notices">♧ Notifications</button><button class="nav" data-page="profile">◉ Profile</button><button class="nav" data-page="settings">⚙ Settings</button><button class="nav hidden" id="adminNav" data-page="admin">⬡ Admin Panel</button></div><div class="result" id="sideStatus">Guest mode</div></aside><main class="main"><header class="top glass"><div><h1 id="pageTitle">Dashboard</h1><small>Tools · bookings · account</small></div><div class="row"><span class="badge" id="userBadge">Guest</span><button id="authOpen">Login</button></div></header>
<section class="page active" id="page-home"><div class="hero glass"><span class="badge">ALL-IN-ONE WORKSPACE</span><h2>Make work <span class="accent">simpler.</span></h2><p class="muted">A unique animated dashboard for documents, image conversion and cyber cafe bookings.</p><div class="row"><button class="primary" data-goto="tools">Open tools</button><button data-goto="cyber">Book a service</button></div></div><div class="grid"><button class="tile" data-goto="tools"><span class="ico">📄</span><b>PDF & Image Tools</b><small>Convert, resize and download</small></button><button class="tile" data-goto="browser"><span class="ico">🔎</span><b>Search Browser</b><small>Google, Bing, Brave, YouTube</small></button><button class="tile" data-goto="cyber"><span class="ico">🏪</span><b>Cyber Cafe Booking</b><small>Cards, print and recharge requests</small></button><button class="tile" data-goto="bookings"><span class="ico">📋</span><b>Booking Status</b><small>Track your requests</small></button><button class="tile" data-goto="profile"><span class="ico">👤</span><b>Profile & Security</b><small>Edit profile and password</small></button><button class="tile" data-goto="settings"><span class="ico">⚙️</span><b>Settings</b><small>Theme and local export</small></button></div></section>
<section class="page" id="page-tools"><div class="panel glass"><h2>All Tools</h2><p class="muted">Choose a tool and upload your file. Conversion runs on this Python server.</p><div class="grid"><button class="tile" data-goto="jpgpdf"><span class="ico">🖼️</span><b>JPG / PNG → PDF</b><small>Multiple images</small></button><button class="tile" data-goto="pdfjpg"><span class="ico">📑</span><b>PDF → JPG</b><small>Download page images as ZIP</small></button><button class="tile" data-goto="pdfresize"><span class="ico">↔️</span><b>PDF Resizer</b><small>Scale content</small></button><button class="tile" data-goto="imageresize"><span class="ico">🧩</span><b>Image Resizer</b><small>Custom dimensions and quality</small></button></div></div></section>
<section class="page" id="page-jpgpdf"><div class="panel glass"><h2>JPG / PNG to PDF</h2><label>Select images<input id="jpgFiles" type="file" accept="image/jpeg,image/png,image/webp" multiple></label><div id="jpgPreview" class="muted"></div><button class="primary" id="jpgConvert">Convert & Download PDF</button><div id="jpgResult" class="result">Choose images first.</div></div></section>
<section class="page" id="page-pdfjpg"><div class="panel glass"><h2>PDF to JPG</h2><label>Upload PDF<input id="pdfJpgFile" type="file" accept="application/pdf"></label><p class="muted">Each PDF page is converted to a JPG and placed in one ZIP download.</p><button class="primary" id="pdfJpgConvert">Convert & Download ZIP</button><div id="pdfJpgResult" class="result">Choose PDF first.</div></div></section>
<section class="page" id="page-pdfresize"><div class="panel glass"><h2>PDF Resizer</h2><label>Upload PDF<input id="pdfResizeFile" type="file" accept="application/pdf"></label><label>Content scale<select id="pdfScale"><option value="1">100% original</option><option value="0.8">80%</option><option value="0.6">60%</option><option value="0.5">50%</option></select></label><button class="primary" id="pdfResizeBtn">Resize & Download PDF</button><div id="pdfResizeResult" class="result">Choose a PDF first.</div></div></section>
<section class="page" id="page-imageresize"><div class="panel glass"><h2>Image Resizer</h2><label>Upload image<input id="resizeFile" type="file" accept="image/*"></label><div id="imagePreview"></div><div class="grid"><label>Width px<input id="resizeWidth" type="number" min="1" max="6000" value="1080"></label><label>Height px<input id="resizeHeight" type="number" min="1" max="6000" value="1080"></label><label>Quality %<input id="resizeQuality" type="number" min="30" max="100" value="92"></label></div><button class="primary" id="resizeBtn">Resize & Download JPG</button><div id="resizeResult" class="result">Choose an image first.</div></div></section>
<section class="page" id="page-browser"><div class="panel glass"><h2>Search Browser</h2><label>Search anything<input id="searchQuery" placeholder="Type search query"></label><label>Search engine<select id="searchEngine"><option value="google">Google</option><option value="bing">Bing</option><option value="duck">DuckDuckGo</option><option value="brave">Brave Search</option><option value="youtube">YouTube</option></select></label><button class="primary" id="searchBtn">Search in new tab</button><p class="muted">External websites may not allow opening inside this app.</p></div></section>
<section class="page" id="page-cyber"><div class="panel glass"><h2>Cyber Cafe Services & Booking</h2><p class="muted">Select a service to request a booking. Government services require official portals and eligibility.</p><div class="grid" id="serviceGrid"></div><label>Selected service<input id="bookingService" placeholder="Select a service card"></label><label>Details<textarea id="bookingDetails" rows="3" placeholder="Instructions (do not enter sensitive ID numbers)"></textarea></label><button class="primary" id="bookBtn">Submit Booking</button><div id="bookingResult" class="result">Login required.</div></div></section>
<section class="page" id="page-bookings"><div class="panel glass"><h2>My Bookings</h2><button id="refreshBookings">Refresh</button><div id="bookingList" class="result">Sign in to see bookings.</div></div></section><section class="page" id="page-notices"><div class="panel glass"><h2>Notifications</h2><button id="refreshNotices">Refresh</button><div id="noticeList" class="result">Sign in to see notifications.</div></div></section>
<section class="page" id="page-profile"><div class="panel glass"><h2>Profile</h2><div id="profileInfo" class="result">Sign in to manage your profile.</div><label>Name<input id="profileName"></label><label>Email<input id="profileEmail" type="email"></label><button class="primary" id="saveProfile">Save profile</button><h3>Change password</h3><label>Current password<input id="oldPass" type="password"></label><label>New password (8+ chars)<input id="newPass" type="password"></label><button id="changePass">Change password</button><div id="profileResult" class="result"></div><button class="danger" id="logoutBtn">Logout</button></div></section>
<section class="page" id="page-settings"><div class="panel glass"><h2>Settings</h2><label>Theme<select id="theme"><option value="dark">Dark glass</option><option value="light">Light</option></select></label><label>Display mode<select id="displayMode"><option value="auto">Automatic</option><option value="mobile">Mobile preview</option><option value="pc">PC mode</option></select></label><label>Homepage banner title<input id="banner" value="Make work simpler."></label><label>About / usage guide<textarea id="about" rows="3"></textarea></label><label>Privacy notice<textarea id="privacy" rows="3"></textarea></label><button class="primary" id="saveSettings">Save settings on this device</button><button id="exportLocal">Download settings JSON</button><div id="settingsResult" class="result"></div><p class="muted">Settings are saved in this browser only, not synced to other devices.</p></div></section>
<section class="page" id="page-admin"><div class="panel glass"><h2>Admin Dashboard</h2><div class="row"><button class="primary" id="adminRefresh">Refresh users & bookings</button><button id="adminExport">Download all admin data</button></div><div id="adminData" class="result"></div></div><div class="panel glass"><h2>Publish notification</h2><label>Title<input id="noticeTitle"></label><label>Message<textarea id="noticeMessage" rows="3"></textarea></label><label>Audience<select id="audience"><option value="all">All users</option></select></label><button class="primary" id="publishNotice">Publish</button><div id="publishResult" class="result"></div></div></section><footer>GlassHub · no wallpaper · protect private identity information</footer></main></div>
<div id="modal" class="hidden" style="position:fixed;inset:0;background:#050816dd;z-index:5;place-items:center;padding:15px"><div class="panel glass" style="width:min(430px,100%)"><div class="row" style="justify-content:space-between"><h2 id="authTitle">Login</h2><button id="closeModal">✕</button></div><div id="regFields" class="hidden"><label>Name<input id="regName"></label></div><label>Email<input id="authEmail" type="email"></label><label>Password<input id="authPassword" type="password"></label><button class="primary" id="authSubmit">Login</button><button id="toggleAuth">Create account</button><div id="authResult" class="result"></div></div></div>
<script>
const $=id=>document.getElementById(id);let me=null,mode='login';const services=['PVC Card Printing','Aadhaar Assistance','Voter ID Assistance','PAN Card Assistance','Ration Card Assistance','Ayushman / ABHA Guidance','Photo Scan & Print','Document Printing','JPG / PDF Conversion','Bill Payment Assistance','Mobile Recharge Assistance','Wi-Fi Recharge Assistance','Passport Photo','Website Building Request','Photo Editing','Other Cyber Cafe Service'],icons=['🪪','🪪','🗳️','💳','🏠','🏥','📸','🖨️','📄','🧾','📱','📶','🖼️','🌐','🎨','➕'];
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));function msg(id,s){$(id).textContent=s}async function api(url,opt={}){let h={...(opt.body instanceof FormData?{}:{'Content-Type':'application/json'}),...(opt.headers||{})};let r=await fetch(url,{...opt,headers:h}),d;try{d=await r.json()}catch{d={error:'Unexpected response'}}if(!r.ok)throw Error(d.error||'Request failed');return d}function go(p){document.querySelectorAll('.page').forEach(x=>x.classList.toggle('active',x.id==='page-'+p));document.querySelectorAll('[data-page]').forEach(x=>x.classList.toggle('active',x.dataset.page===p));$('pageTitle').textContent=({home:'Dashboard',tools:'All Tools',jpgpdf:'JPG to PDF',pdfjpg:'PDF to JPG',pdfresize:'PDF Resizer',imageresize:'Image Resizer',browser:'Search Browser',cyber:'Cyber Cafe',bookings:'My Bookings',notices:'Notifications',profile:'Profile',settings:'Settings',admin:'Admin Panel'})[p]||p;if(p==='bookings')loadBookings();if(p==='notices')loadNotices();if(p==='admin')loadAdmin()}document.querySelectorAll('[data-page]').forEach(x=>x.onclick=()=>go(x.dataset.page));document.querySelectorAll('[data-goto]').forEach(x=>x.onclick=()=>go(x.dataset.goto));function dl(name,blob){let u=URL.createObjectURL(blob),a=document.createElement('a');a.href=u;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(u),1500)}async function postFile(url,form,id,name){msg(id,'Processing file…');try{let r=await fetch(url,{method:'POST',body:form});if(!r.ok){let d={};try{d=await r.json()}catch{}throw Error(d.error||'Conversion failed')}let b=await r.blob();dl(name,b);msg(id,'Done. Download started · '+Math.round(b.size/1024)+' KB')}catch(e){msg(id,e.message)}}
$('jpgFiles').onchange=()=>msg('jpgPreview',[...$('jpgFiles').files].map(f=>f.name).join(' · ')||'No images selected');$('jpgConvert').onclick=()=>{let fs=[...$('jpgFiles').files];if(!fs.length)return msg('jpgResult','Choose images first.');let f=new FormData();fs.forEach(x=>f.append('images',x));postFile('/api/jpg-to-pdf',f,'jpgResult','GlassHub_images.pdf')};$('pdfJpgConvert').onclick=()=>{let x=$('pdfJpgFile').files[0];if(!x)return msg('pdfJpgResult','Choose a PDF first.');let f=new FormData();f.append('pdf',x);postFile('/api/pdf-to-jpg',f,'pdfJpgResult','GlassHub_PDF_to_JPG.zip')};$('pdfResizeBtn').onclick=()=>{let x=$('pdfResizeFile').files[0];if(!x)return msg('pdfResizeResult','Choose a PDF first.');let f=new FormData();f.append('pdf',x);f.append('scale',$('pdfScale').value);postFile('/api/pdf-resize',f,'pdfResizeResult','GlassHub_resized.pdf')};$('resizeFile').onchange=()=>{let f=$('resizeFile').files[0];if(!f)return;let u=URL.createObjectURL(f);$('imagePreview').innerHTML=`<img class="preview" src="${u}" alt="Image preview">`;let im=new Image();im.onload=()=>{$('resizeWidth').value=im.width;$('resizeHeight').value=im.height};im.src=u};$('resizeBtn').onclick=()=>{let x=$('resizeFile').files[0];if(!x)return msg('resizeResult','Choose an image first.');let f=new FormData();f.append('image',x);f.append('width',$('resizeWidth').value);f.append('height',$('resizeHeight').value);f.append('quality',$('resizeQuality').value);postFile('/api/image-resize',f,'resizeResult','GlassHub_resized.jpg')};
$('searchBtn').onclick=()=>{let q=$('searchQuery').value.trim();if(!q)return;let u={google:'https://www.google.com/search?q=',bing:'https://www.bing.com/search?q=',duck:'https://duckduckgo.com/?q=',brave:'https://search.brave.com/search?q=',youtube:'https://www.youtube.com/results?search_query='};window.open(u[$('searchEngine').value]+encodeURIComponent(q),'_blank','noopener,noreferrer')};$('searchQuery').onkeydown=e=>{if(e.key==='Enter')$('searchBtn').click()};$('serviceGrid').innerHTML=services.map((s,i)=>`<button class="tile" data-service="${esc(s)}"><span class="ico">${icons[i]}</span><b>${esc(s)}</b><small>Click to select</small></button>`).join('');$('serviceGrid').querySelectorAll('[data-service]').forEach(b=>b.onclick=()=>{$('bookingService').value=b.dataset.service;$('serviceGrid').querySelectorAll('button').forEach(x=>x.style.borderColor='');b.style.borderColor='var(--b)'});$('bookBtn').onclick=async()=>{try{let d=await api('/api/bookings',{method:'POST',body:JSON.stringify({service:$('bookingService').value,details:$('bookingDetails').value})});msg('bookingResult',`Booking #${d.id} submitted · ${d.status}`)}catch(e){msg('bookingResult',e.message)}};
async function loadBookings(){if(!me)return msg('bookingList','Sign in to view bookings.');try{let d=await api('/api/bookings');$('bookingList').innerHTML=d.bookings.length?`<div class="table-wrap"><table><tr><th>ID</th><th>Service</th><th>Status</th><th>Created</th><th>Admin note</th></tr>${d.bookings.map(b=>`<tr><td>${b.id}</td><td>${esc(b.service)}</td><td>${esc(b.status)}</td><td>${esc(b.created)}</td><td>${esc(b.note)}</td></tr>`).join('')}</table></div>`:'No bookings yet.'}catch(e){msg('bookingList',e.message)}}$('refreshBookings').onclick=loadBookings;async function loadNotices(){if(!me)return msg('noticeList','Sign in to view notifications.');try{let d=await api('/api/notices');$('noticeList').innerHTML=d.notices.length?d.notices.map(n=>`<article class="result"><b>${esc(n.title)}</b><p>${esc(n.message)}</p><small>${esc(n.created)} · ${n.read_at?'Read':'New'}</small><button onclick="markRead(${n.id})">Mark read</button></article>`).join(''):'No notifications.'}catch(e){msg('noticeList',e.message)}}$('refreshNotices').onclick=loadNotices;window.markRead=async id=>{try{await api('/api/notices/'+id+'/read',{method:'POST',body:'{}'});loadNotices()}catch(e){alert(e.message)}};
function updateUser(){let label=me?me.name+' · '+me.role:'Guest';$('userBadge').textContent=label;$('sideStatus').textContent=me?me.email+'\n'+me.role:'Guest mode';$('adminNav').classList.toggle('hidden',!me||me.role!=='admin');$('authOpen').textContent=me?'Profile':'Login';$('profileInfo').textContent=me?me.name+' · '+me.email+' · '+me.role:'Sign in to manage profile.';if(me){$('profileName').value=me.name;$('profileEmail').value=me.email}}async function refreshMe(){try{me=(await api('/api/me')).user}catch{me=null}updateUser()}$('authOpen').onclick=()=>{if(me)return go('profile');mode='login';$('authTitle').textContent='Login';$('authSubmit').textContent='Login';$('regFields').classList.add('hidden');$('toggleAuth').textContent='Create account';$('modal').classList.remove('hidden');$('modal').style.display='grid'};$('closeModal').onclick=()=>{$('modal').classList.add('hidden');$('modal').style.display='none'};$('toggleAuth').onclick=()=>{mode=mode==='login'?'register':'login';$('authTitle').textContent=mode==='login'?'Login':'Register';$('authSubmit').textContent=mode==='login'?'Login':'Register';$('regFields').classList.toggle('hidden',mode==='login');$('toggleAuth').textContent=mode==='login'?'Create account':'Back to login'};$('authSubmit').onclick=async()=>{let d={email:$('authEmail').value,password:$('authPassword').value};if(mode==='register')d.name=$('regName').value;try{let r=await api('/api/'+mode,{method:'POST',body:JSON.stringify(d)});me=r.user;updateUser();$('modal').classList.add('hidden');$('modal').style.display='none';msg('authResult','')}catch(e){msg('authResult',e.message)}};$('logoutBtn').onclick=async()=>{try{await api('/api/logout',{method:'POST',body:'{}'})}catch{}me=null;updateUser();go('home')};$('saveProfile').onclick=async()=>{try{let d=await api('/api/profile',{method:'POST',body:JSON.stringify({name:$('profileName').value,email:$('profileEmail').value})});me=d.user;updateUser();msg('profileResult','Profile saved.')}catch(e){msg('profileResult',e.message)}};$('changePass').onclick=async()=>{try{let d=await api('/api/password',{method:'POST',body:JSON.stringify({old:$('oldPass').value,new:$('newPass').value})});msg('profileResult',d.message);$('oldPass').value='';$('newPass').value=''}catch(e){msg('profileResult',e.message)}};
function loadSettings(){let s=JSON.parse(localStorage.getItem('ghsettings')||'{}');$('theme').value=s.theme||'dark';$('displayMode').value=s.display||'auto';$('banner').value=s.banner||'Make work simpler.';$('about').value=s.about||'';$('privacy').value=s.privacy||'';document.body.style.filter=s.theme==='light'?'brightness(1.25) saturate(.7)':'';document.body.style.maxWidth=s.display==='mobile'?'520px':s.display==='pc'?'none':'';document.body.style.margin=s.display==='mobile'?'auto':''}$('saveSettings').onclick=()=>{localStorage.setItem('ghsettings',JSON.stringify({theme:$('theme').value,display:$('displayMode').value,banner:$('banner').value,about:$('about').value,privacy:$('privacy').value}));loadSettings();msg('settingsResult','Settings saved in this browser.')};$('exportLocal').onclick=()=>dl('GlassHub-settings.json',new Blob([JSON.stringify({settings:JSON.parse(localStorage.getItem('ghsettings')||'{}'),exported:new Date().toISOString()},null,2)],{type:'application/json'}));
async function loadAdmin(){if(!me||me.role!=='admin')return msg('adminData','Administrator access required.');try{let d=await api('/api/admin/summary');$('audience').innerHTML='<option value="all">All users</option>'+d.users.filter(x=>x.role!=='admin').map(x=>`<option value="${x.id}">${esc(x.name)} (${esc(x.email)})</option>`).join('');$('adminData').innerHTML=`<h3>Users (${d.users.length})</h3><div class="table-wrap"><table><tr><th>ID</th><th>Name</th><th>Email</th><th>Role</th><th>State</th><th>Actions</th></tr>${d.users.map(x=>`<tr><td>${x.id}</td><td>${esc(x.name)}</td><td>${esc(x.email)}</td><td>${esc(x.role)}</td><td>${x.blocked?'Blocked':'Active'}</td><td>${x.role==='admin'?'Admin':`<button onclick="editUser(${x.id},'${esc(x.name).replace(/'/g,'&#39;')}','${esc(x.email)}')">Edit</button><button onclick="blockUser(${x.id},${x.blocked?0:1})">${x.blocked?'Unblock':'Block'}</button>`}</td></tr>`).join('')}</table></div><h3>Bookings (${d.bookings.length})</h3><div class="table-wrap"><table><tr><th>ID</th><th>User</th><th>Service</th><th>Status</th><th>Review</th></tr>${d.bookings.map(b=>`<tr><td>${b.id}</td><td>${esc(b.user_name)}<br>${esc(b.user_email)}</td><td>${esc(b.service)}<br>${esc(b.details)}</td><td>${esc(b.status)}</td><td><select id="status${b.id}"><option>Accepted</option><option>Rejected</option><option>In Review</option><option>Completed</option><option>Cancelled</option></select><input id="note${b.id}" placeholder="Admin note"><button onclick="reviewBooking(${b.id})">Save review</button></td></tr>`).join('')}</table></div><h3>Recent activity (${d.events.length})</h3><div class="table-wrap"><table><tr><th>Time</th><th>User</th><th>Event</th><th>Details</th></tr>${d.events.map(e=>`<tr><td>${esc(e.created)}</td><td>${e.user_id??'Guest'}</td><td>${esc(e.event)}</td><td>${esc(e.details)}</td></tr>`).join('')}</table></div>`}catch(e){msg('adminData',e.message)}}$('adminRefresh').onclick=loadAdmin;window.blockUser=async(id,v)=>{try{await api('/api/admin/users/'+id+'/block',{method:'POST',body:JSON.stringify({blocked:!!v})});loadAdmin()}catch(e){alert(e.message)}};window.editUser=async(id,name,email)=>{let n=prompt('Edit name',name);if(n===null)return;let em=prompt('Edit email',email);if(em===null)return;try{await api('/api/admin/users/'+id+'/edit',{method:'POST',body:JSON.stringify({name:n,email:em})});loadAdmin()}catch(e){alert(e.message)}};window.reviewBooking=async id=>{try{await api('/api/admin/bookings/'+id+'/review',{method:'POST',body:JSON.stringify({status:$('status'+id).value,note:$('note'+id).value})});loadAdmin()}catch(e){alert(e.message)}};$('publishNotice').onclick=async()=>{try{await api('/api/admin/notices',{method:'POST',body:JSON.stringify({title:$('noticeTitle').value,message:$('noticeMessage').value,audience:$('audience').value})});msg('publishResult','Notification published.')}catch(e){msg('publishResult',e.message)}};$('adminExport').onclick=async()=>{try{let d=await api('/api/admin/export');dl('GlassHub-admin-backup.json',new Blob([JSON.stringify(d,null,2)],{type:'application/json'}))}catch(e){alert(e.message)}};loadSettings();refreshMe();
</script></body></html>'''

if __name__=='__main__':
    init_db()
    print('GlassHub: http://127.0.0.1:5000')
    print('Set ADMIN_PASSWORD to a private password of 12+ characters before first run to provision admin',ADMIN_EMAIL)
    app.run(host='127.0.0.1',port=int(os.environ.get('PORT','5000')),debug=False)
