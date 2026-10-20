import os, sqlite3, secrets, hashlib, hmac, base64
from datetime import datetime
from functools import wraps
from flask import Flask, request, jsonify, session, send_from_directory, g
ROOT=os.path.dirname(os.path.abspath(__file__)); DB=os.path.join(ROOT,'glasshub.db')
ADMIN_EMAIL=os.getenv('ADMIN_EMAIL','dbibi698@gmail.com').lower().strip()
app=Flask(__name__,static_folder='static',static_url_path='/static'); app.secret_key=os.getenv('FLASK_SECRET_KEY','change-this-secret-before-deployment')
app.config['MAX_CONTENT_LENGTH']=5*1024*1024

def now(): return datetime.utcnow().isoformat(timespec='seconds')+'Z'
def conn():
 if 'db' not in g: g.db=sqlite3.connect(DB); g.db.row_factory=sqlite3.Row
 return g.db
@app.teardown_appcontext
def close(_=None):
 c=g.pop('db',None)
 if c: c.close()
def init():
 c=sqlite3.connect(DB); c.executescript('''CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,name TEXT,email TEXT UNIQUE,password TEXT,salt TEXT,role TEXT DEFAULT 'user',blocked INTEGER DEFAULT 0,photo TEXT DEFAULT '',created TEXT,last_seen TEXT);
 CREATE TABLE IF NOT EXISTS bookings(id INTEGER PRIMARY KEY,name TEXT,email TEXT,user_id INTEGER,service TEXT,details TEXT,status TEXT DEFAULT 'Pending',review TEXT DEFAULT '',created TEXT);
 CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,user_id INTEGER,event TEXT,details TEXT,created TEXT);
 CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY,user_id INTEGER,title TEXT,message TEXT,created TEXT,read_at TEXT);
 CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT);
 CREATE TABLE IF NOT EXISTS features(id INTEGER PRIMARY KEY,name TEXT,description TEXT,icon TEXT,page TEXT,enabled INTEGER DEFAULT 1);''')
 if not c.execute('SELECT 1 FROM settings WHERE key="site_name"').fetchone(): c.execute('INSERT INTO settings VALUES("site_name","GlassHub")')
 defaults=[('PDF Resizer','Compress PDF to a smaller copy','▤','pdf'),('Image Resizer','Resize and download images','▧','image'),('Images to PDF','Convert multiple images to PDF','▧','convert'),('Background Remover','API connection required','✂','background'),('Cyber Cafe Booking','Book printing and document assistance','▣','cyber'),('Wallpapers','Download phone and PC wallpapers','▦','wallpapers'),('Social & Search','Social sites and search engines','◎','social'),('AI Directory','Open AI websites','✦','ai')]
 for x in defaults: c.execute('INSERT OR IGNORE INTO features(name,description,icon,page,enabled) VALUES(?,?,?,?,1)',x)
 c.commit(); c.close()
def pw(p,s): return hashlib.pbkdf2_hmac('sha256',p.encode(),s.encode(),200000).hex()
def me():
 uid=session.get('uid')
 if not uid:return None
 u=conn().execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone()
 if not u or u['blocked']: session.clear(); return None
 conn().execute('UPDATE users SET last_seen=? WHERE id=?',(now(),uid)); conn().commit(); return u
def log(ev,detail=''):
 u=me(); conn().execute('INSERT INTO events(user_id,event,details,created) VALUES(?,?,?,?)',(u['id'] if u else None,ev[:80],detail[:300],now())); conn().commit()
def auth(f):
 @wraps(f)
 def w(*a,**k):
  if not me(): return jsonify(error='Please sign in.'),401
  return f(*a,**k)
 return w
def admin(f):
 @wraps(f)
 def w(*a,**k):
  u=me()
  if not u:return jsonify(error='Please sign in.'),401
  if u['role']!='admin' or u['email'].lower()!=ADMIN_EMAIL:return jsonify(error='Admin access only.'),403
  return f(*a,**k)
 return w
def user_json(u): return {'id':u['id'],'name':u['name'],'email':u['email'],'role':u['role'],'blocked':u['blocked'],'photo':u['photo'] or '','created':u['created'],'last_seen':u['last_seen']}
@app.get('/')
def home(): return send_from_directory(ROOT,'index.html')
@app.post('/api/register')
def register():
 d=request.get_json() or {}; name=str(d.get('name','')).strip(); email=str(d.get('email','')).strip().lower(); p=str(d.get('password',''))
 if not name or '@' not in email or len(p)<8:return jsonify(error='Name, valid email and password (8+ characters) required.'),400
 salt=secrets.token_hex(16); role='admin' if email==ADMIN_EMAIL else 'user'
 try:
  cur=conn().execute('INSERT INTO users(name,email,password,salt,role,created) VALUES(?,?,?,?,?,?)',(name,email,pw(p,salt),salt,role,now()));conn().commit();session['uid']=cur.lastrowid;log('register','Account created');return jsonify(user=user_json(me()))
 except sqlite3.IntegrityError:return jsonify(error='Email already registered.'),409
@app.post('/api/login')
def login():
 d=request.get_json() or {}; email=str(d.get('email','')).lower().strip(); u=conn().execute('SELECT * FROM users WHERE email=?',(email,)).fetchone()
 if not u or not hmac.compare_digest(pw(str(d.get('password','')),u['salt']),u['password']):return jsonify(error='Email or password incorrect.'),401
 if u['blocked']:return jsonify(error='Account blocked by admin.'),403
 session.clear();session['uid']=u['id'];log('login','Signed in');return jsonify(user=user_json(u))
@app.post('/api/logout')
def logout(): log('logout');session.clear();return jsonify(ok=True)
@app.get('/api/me')
def getme(): return jsonify(user=user_json(me()) if me() else None)
@app.post('/api/profile')
@auth
def profile():
 d=request.get_json() or {}; u=me(); name=str(d.get('name',u['name'])).strip()[:80]; photo=str(d.get('photo',u['photo'] or ''))
 if len(photo)>400000:return jsonify(error='Profile image is too large (max about 300 KB).'),400
 if photo and not photo.startswith('data:image/'):return jsonify(error='Use an image file.'),400
 conn().execute('UPDATE users SET name=?,photo=? WHERE id=?',(name,photo,u['id']));conn().commit();return jsonify(user=user_json(me()))
@app.post('/api/change-password')
@auth
def change_password():
 d=request.get_json() or {};u=me()
 if not hmac.compare_digest(pw(str(d.get('current','')),u['salt']),u['password']):return jsonify(error='Current password is incorrect.'),400
 p=str(d.get('new',''))
 if len(p)<8:return jsonify(error='New password must be at least 8 characters.'),400
 salt=secrets.token_hex(16);conn().execute('UPDATE users SET password=?,salt=? WHERE id=?',(pw(p,salt),salt,u['id']));conn().commit();return jsonify(ok=True)
@app.get('/api/features')
def features():return jsonify(features=[dict(r) for r in conn().execute('SELECT * FROM features ORDER BY id')])
@app.get('/api/settings')
def getsettings():return jsonify(settings={r['key']:r['value'] for r in conn().execute('SELECT * FROM settings')})
@app.post('/api/bookings')
def booking():
 d=request.get_json() or {};u=me();name=(u['name'] if u else str(d.get('name','')).strip());email=(u['email'] if u else str(d.get('email','')).strip().lower());service=str(d.get('service','')).strip();details=str(d.get('details','')).strip()
 if not name or '@' not in email or not service:return jsonify(error='Name, email and service required.'),400
 conn().execute('INSERT INTO bookings(name,email,user_id,service,details,created) VALUES(?,?,?,?,?,?)',(name,email,u['id'] if u else None,service,details,now()));conn().commit();log('booking',service);return jsonify(ok=True,message='Booking submitted. Admin can review it.')
@app.get('/api/my-bookings')
@auth
def mybookings():
 u=me();return jsonify(bookings=[dict(r) for r in conn().execute('SELECT * FROM bookings WHERE user_id=? ORDER BY id DESC',(u['id'],))])
@app.get('/api/notifications')
@auth
def notifications():
 u=me();return jsonify(notifications=[dict(r) for r in conn().execute('SELECT * FROM notifications WHERE user_id IS NULL OR user_id=? ORDER BY id DESC',(u['id'],))])
@app.get('/api/admin/summary')
@admin
def summary():
 c=conn();return jsonify(users=[user_json(x) for x in c.execute('SELECT * FROM users ORDER BY id DESC')],bookings=[dict(x) for x in c.execute('SELECT * FROM bookings ORDER BY id DESC')],events=[dict(x) for x in c.execute('SELECT e.*,u.email FROM events e LEFT JOIN users u ON u.id=e.user_id ORDER BY e.id DESC LIMIT 300')],features=[dict(x) for x in c.execute('SELECT * FROM features ORDER BY id')],settings={x['key']:x['value'] for x in c.execute('SELECT * FROM settings')})
@app.post('/api/admin/users/<int:i>')
@admin
def edituser(i):
 d=request.get_json() or {}; target=conn().execute('SELECT * FROM users WHERE id=?',(i,)).fetchone()
 if not target:return jsonify(error='User not found.'),404
 if target['role']=='admin' and i!=me()['id']:return jsonify(error='Cannot edit another admin.'),400
 conn().execute('UPDATE users SET name=?,blocked=? WHERE id=?',(str(d.get('name',target['name'])).strip()[:80],int(bool(d.get('blocked',target['blocked']))),i));conn().commit();return jsonify(ok=True)
@app.post('/api/admin/bookings/<int:i>')
@admin
def editbooking(i):
 d=request.get_json() or {};status=d.get('status','Pending');review=str(d.get('review',''))[:500]
 if status not in ['Pending','Accepted','Rejected','In Review','Completed']:return jsonify(error='Invalid status.'),400
 conn().execute('UPDATE bookings SET status=?,review=? WHERE id=?',(status,review,i));b=conn().execute('SELECT user_id,service FROM bookings WHERE id=?',(i,)).fetchone()
 if b and b['user_id']:conn().execute('INSERT INTO notifications(user_id,title,message,created) VALUES(?,?,?,?)',(b['user_id'],'Booking update',f"{b['service']}: {status}. {review}",now()))
 conn().commit();return jsonify(ok=True)
@app.post('/api/admin/features')
@admin
def editfeature():
 d=request.get_json() or {}; name=str(d.get('name','')).strip()[:100]; desc=str(d.get('description','')).strip()[:250]; icon=str(d.get('icon','✦'))[:8];page=str(d.get('page','dashboard'))[:40]; enabled=int(bool(d.get('enabled',True)));i=d.get('id')
 if not name:return jsonify(error='Feature name required.'),400
 if i:conn().execute('UPDATE features SET name=?,description=?,icon=?,page=?,enabled=? WHERE id=?',(name,desc,icon,page,enabled,i))
 else:conn().execute('INSERT INTO features(name,description,icon,page,enabled) VALUES(?,?,?,?,?)',(name,desc,icon,page,enabled))
 conn().commit();return jsonify(ok=True)
@app.post('/api/admin/settings')
@admin
def editsettings():
 d=request.get_json() or {}
 for k,v in d.items():
  if k in ['site_name','banner_title','about','privacy','guidelines']:conn().execute('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',(k,str(v)[:3000]))
 conn().commit();return jsonify(ok=True)
@app.post('/api/admin/notifications')
@admin
def sendnotice():
 d=request.get_json() or {};title=str(d.get('title','')).strip();msg=str(d.get('message','')).strip()
 if not title or not msg:return jsonify(error='Title and message required.'),400
 conn().execute('INSERT INTO notifications(title,message,created) VALUES(?,?,?)',(title,msg,now()));conn().commit();return jsonify(ok=True)
@app.post('/api/events')
def events():
 d=request.get_json() or {};u=me();conn().execute('INSERT INTO events(user_id,event,details,created) VALUES(?,?,?,?)',(u['id'] if u else None,str(d.get('event',''))[:80],str(d.get('details',''))[:300],now()));conn().commit();return jsonify(ok=True)
init()
if __name__=='__main__':app.run(host='127.0.0.1',port=int(os.getenv('PORT','5000')))
