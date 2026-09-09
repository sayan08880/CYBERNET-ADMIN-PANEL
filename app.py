# CYBERNET - internal admin/user workstation (Flask + SQLite)
import os, sqlite3, time, datetime, secrets, functools
from flask import (Flask, request, redirect, url_for, session,
                   render_template, jsonify, abort, flash)

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, 'data', 'cybernet.db')
os.makedirs(os.path.join(BASE, 'data'), exist_ok=True)

app = Flask(__name__)
KEYFILE = os.path.join(BASE, 'data', 'secret_key.txt')
if not os.path.exists(KEYFILE):
    with open(KEYFILE, 'w') as f:
        f.write(secrets.token_hex(32))
app.secret_key = open(KEYFILE).read().strip()

# ---------------- DB ----------------
def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    con.execute('PRAGMA foreign_keys=ON')
    return con

def now():
    return time.time()

def hm(ts=None):
    return datetime.datetime.fromtimestamp(ts or now()).strftime('%H:%M')

def today():
    return datetime.datetime.now().strftime('%d/%m/%Y')

def init_db():
    con = db()
    con.executescript("""
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      status TEXT NOT NULL DEFAULT 'active',
      s_start TEXT NOT NULL DEFAULT '07:00',
      s_end   TEXT NOT NULL DEFAULT '19:00',
      must_change_pw INTEGER NOT NULL DEFAULT 0,
      session_token TEXT,
      last_seen REAL DEFAULT 0,
      created REAL NOT NULL
    );
    CREATE TABLE IF NOT EXISTS files(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL,
      description TEXT DEFAULT '',
      flag TEXT NOT NULL DEFAULT 'N',
      content TEXT DEFAULT '',
      created REAL NOT NULL,
      modified REAL NOT NULL
    );
    CREATE TABLE IF NOT EXISTS file_perms(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      perm TEXT NOT NULL DEFAULT '',
      UNIQUE(file_id, user_id)
    );
    CREATE TABLE IF NOT EXISTS works(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      description TEXT DEFAULT '',
      priority TEXT DEFAULT 'Normal',
      due TEXT DEFAULT '',
      progress INTEGER NOT NULL DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'working',
      created REAL NOT NULL
    );
    CREATE TABLE IF NOT EXISTS messages(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      receiver_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      body TEXT NOT NULL,
      ts REAL NOT NULL,
      read INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS requests(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      type TEXT NOT NULL,
      payload TEXT DEFAULT '',
      status TEXT NOT NULL DEFAULT 'pending',
      created REAL NOT NULL,
      resolved REAL
    );
    CREATE TABLE IF NOT EXISTS logs(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts REAL NOT NULL,
      actor TEXT NOT NULL,
      action TEXT NOT NULL,
      detail TEXT DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS settings(
      key TEXT PRIMARY KEY,
      value TEXT
    );
    """)
    row = con.execute("SELECT COUNT(*) c FROM users WHERE role='admin'").fetchone()
    if row['c'] == 0:
        from werkzeug.security import generate_password_hash
        con.execute("""INSERT INTO users(username,password_hash,role,status,s_start,s_end,
                       must_change_pw,created) VALUES(?,?,?,?,?,?,?,?)""",
                    ('admin', generate_password_hash('admin'), 'admin', 'active',
                     '06:00', '23:00', 1, now()))
    for k, v in [('admin_s_start', '06:00'), ('admin_s_end', '23:00')]:
        con.execute("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)", (k, v))
    con.commit()
    con.close()

def log(action, detail=''):
    con = db()
    con.execute("INSERT INTO logs(ts,actor,action,detail) VALUES(?,?,?,?)",
                (now(), session.get('username', 'system'), action, detail))
    con.commit(); con.close()

def setting(key, default=''):
    con = db()
    r = con.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    con.close()
    return r['value'] if r else default

def set_setting(key, value):
    con = db()
    con.execute("INSERT INTO settings(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
    con.commit(); con.close()

def get_user(uid):
    con = db()
    r = con.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    con.close(); return r

def in_stime(u):
    t = datetime.datetime.now().strftime('%H:%M')
    s, e = u['s_start'], u['s_end']
    if s <= e:
        return s <= t <= e
    return t >= s or t <= e

# ---------------- auth ----------------
def current_user():
    uid = session.get('uid')
    tok = session.get('token')
    if not uid or not tok:
        return None
    u = get_user(uid)
    if not u or u['session_token'] != tok:
        session.clear()
        return None
    con = db()
    con.execute("UPDATE users SET last_seen=? WHERE id=?", (now(), uid))
    con.commit(); con.close()
    return u

def login_required(role=None):
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*a, **kw):
            u = current_user()
            if not u:
                return redirect(url_for('admin_login' if role == 'admin' else 'user_login'))
            if role and u['role'] != role:
                abort(403)
            if u['must_change_pw'] and request.endpoint not in ('change_password', 'logout'):
                return redirect(url_for('change_password'))
            return fn(u, *a, **kw)
        return wrapper
    return deco

ATTEMPTS = {}
def rate_limited(ip, max_tries=5, window=300):
    t = now()
    ATTEMPTS[ip] = [x for x in ATTEMPTS.get(ip, []) if t - x < window]
    if len(ATTEMPTS[ip]) >= max_tries:
        return True
    ATTEMPTS[ip].append(t)
    return False

@app.context_processor
def inject_csrf():
    if 'csrf' not in session:
        session['csrf'] = secrets.token_hex(16)
    return {'csrf_token': session['csrf'], 'hm': hm, 'today': today}

@app.before_request
def csrf_protect():
    if request.method == 'POST':
        tok = session.get('csrf')
        sent = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
        if not tok or sent != tok:
            abort(400, 'CSRF token mismatch')

from werkzeug.security import generate_password_hash, check_password_hash

def do_login(username, password, role):
    if rate_limited(request.remote_addr or 'local'):
        return None, 'Too many attempts. Wait 5 minutes.'
    con = db()
    u = con.execute("SELECT * FROM users WHERE username=? AND role=?",
                    (username, role)).fetchone()
    con.close()
    if not u or not check_password_hash(u['password_hash'], password):
        log('LOGIN FAILED', username + ' (' + role + ')')
        return None, 'Invalid username or password.'
    if u['status'] != 'active':
        log('LOGIN BLOCKED', username + ' status=' + u['status'])
        return None, 'Account is ' + u['status'] + '. Contact admin.'
    if not in_stime(u):
        log('LOGIN DENIED', username + ' outside S-Time ' + u['s_start'] + '-' + u['s_end'])
        return None, 'Login denied: outside S-Time (' + u['s_start'] + ' - ' + u['s_end'] + ').'
    tok = secrets.token_hex(24)
    con = db()
    con.execute("UPDATE users SET session_token=?, last_seen=? WHERE id=?",
                (tok, now(), u['id']))
    con.commit(); con.close()
    session.clear()
    session['uid'] = u['id']; session['token'] = tok
    session['username'] = u['username']; session['role'] = u['role']
    session['csrf'] = secrets.token_hex(16)
    log('LOGIN', username + ' (' + role + ')')
    return u, None

# ---------------- auth routes ----------------
@app.route('/')
def index():
    u = current_user()
    if not u:
        return redirect(url_for('user_login'))
    return redirect(url_for('admin_dashboard' if u['role'] == 'admin' else 'user_dashboard'))

@app.route('/login/admin', methods=['GET', 'POST'])
def admin_login():
    err = None
    if request.method == 'POST':
        u, err = do_login(request.form['username'].strip(),
                          request.form['password'], 'admin')
        if u:
            return redirect(url_for('change_password' if u['must_change_pw'] else 'admin_dashboard'))
    return render_template('login.html', title='ADMIN LOGIN', role='admin', err=err,
                           s_start=setting('admin_s_start'), s_end=setting('admin_s_end'))

@app.route('/login/user', methods=['GET', 'POST'])
def user_login():
    err = None
    if request.method == 'POST':
        u, err = do_login(request.form['username'].strip(),
                          request.form['password'], 'user')
        if u:
            return redirect(url_for('change_password' if u['must_change_pw'] else 'user_dashboard'))
    return render_template('login.html', title='USER LOGIN', role='user', err=err)

@app.route('/logout')
def logout():
    u = current_user()
    if u:
        con = db()
        con.execute("UPDATE users SET session_token=NULL WHERE id=?", (u['id'],))
        con.commit(); con.close()
        log('LOGOUT', u['username'])
    session.clear()
    return redirect(url_for('user_login'))

@app.route('/change-password', methods=['GET', 'POST'])
@login_required()
def change_password(u):
    err = None
    if request.method == 'POST':
        p1, p2 = request.form['p1'], request.form['p2']
        if len(p1) < 6:
            err = 'Password must be at least 6 characters.'
        elif p1 != p2:
            err = 'Passwords do not match.'
        else:
            con = db()
            con.execute("UPDATE users SET password_hash=?, must_change_pw=0 WHERE id=?",
                        (generate_password_hash(p1), u['id']))
            con.commit(); con.close()
            log('PASSWORD CHANGED', u['username'])
            return redirect(url_for('admin_dashboard' if u['role'] == 'admin' else 'user_dashboard'))
    return render_template('change_password.html', u=u, err=err)

# ---------------- ADMIN ----------------
@app.route('/admin')
@login_required('admin')
def admin_dashboard(u):
    con = db()
    stats = {
        'users': con.execute("SELECT COUNT(*) c FROM users WHERE role='user'").fetchone()['c'],
        'online': con.execute("SELECT COUNT(*) c FROM users WHERE role='user' AND last_seen>?",
                              (now() - 60,)).fetchone()['c'],
        'files': con.execute("SELECT COUNT(*) c FROM files").fetchone()['c'],
        'pending': con.execute("SELECT COUNT(*) c FROM requests WHERE status='pending'").fetchone()['c'],
        'works': con.execute("SELECT COUNT(*) c FROM works WHERE status='working'").fetchone()['c'],
        'sessions': con.execute("SELECT COUNT(*) c FROM users WHERE session_token IS NOT NULL").fetchone()['c'],
        'failed': con.execute("SELECT COUNT(*) c FROM logs WHERE action='LOGIN FAILED' AND ts>?",
                              (now() - 86400,)).fetchone()['c'],
    }
    activity = con.execute("""SELECT l.*, u.username uname FROM logs l LEFT JOIN users u
        ON u.username=l.actor WHERE l.action IN ('LOGIN','LOGIN DENIED','LOGIN FAILED',
        'FILE EDIT','FILE OPEN','LOGOUT','REQUEST SENT') ORDER BY l.ts DESC LIMIT 15""").fetchall()
    recent_files = con.execute("SELECT * FROM files ORDER BY modified DESC LIMIT 6").fetchall()
    notifs = con.execute("""SELECT * FROM logs WHERE action IN
        ('LOGIN DENIED','LOGIN BLOCKED','LOGIN FAILED') ORDER BY ts DESC LIMIT 8""").fetchall()
    con.close()
    return render_template('admin/dashboard.html', u=u, stats=stats, activity=activity,
                           recent_files=recent_files, notifs=notifs, hm=hm)

@app.route('/admin/control')
@login_required('admin')
def admin_control(u):
    con = db()
    users = con.execute("SELECT * FROM users WHERE role='user' ORDER BY username").fetchall()
    con.close()
    return render_template('admin/control.html', u=u, users=users, now_ts=now())

@app.route('/admin/control/create', methods=['POST'])
@login_required('admin')
def admin_create_user(u):
    username = request.form['username'].strip().upper()
    if not username:
        flash('Username required'); return redirect(url_for('admin_control'))
    try:
        con = db()
        con.execute("""INSERT INTO users(username,password_hash,status,s_start,s_end,
                       must_change_pw,created) VALUES(?,?,?,?,?,?,?)""",
                    (username, generate_password_hash('user123'), 'active',
                     request.form.get('s_start', '07:00'), request.form.get('s_end', '19:00'),
                     1, now()))
        con.commit(); con.close()
        log('USER CREATED', username)
        flash('User ' + username + ' created. Default password: user123 (must change on first login).')
    except Exception:
        flash('Username already exists.')
    return redirect(url_for('admin_control'))

@app.route('/admin/control/<int:uid>')
@login_required('admin')
def admin_user_detail(u, uid):
    t = get_user(uid)
    if not t or t['role'] != 'user':
        abort(404)
    con = db()
    activity = con.execute("SELECT * FROM logs WHERE actor=? ORDER BY ts DESC LIMIT 20",
                           (t['username'],)).fetchall()
    files = con.execute("""SELECT f.*, p.perm FROM files f JOIN file_perms p ON p.file_id=f.id
        WHERE p.user_id=? AND p.perm!='' """, (uid,)).fetchall()
    works = con.execute("SELECT * FROM works WHERE user_id=? ORDER BY created DESC", (uid,)).fetchall()
    con.close()
    return render_template('admin/user_detail.html', u=u, t=t, activity=activity,
                           files=files, works=works, hm=hm)

@app.route('/admin/control/<int:uid>/action', methods=['POST'])
@login_required('admin')
def admin_user_action(u, uid):
    t = get_user(uid)
    if not t or t['role'] != 'user':
        abort(404)
    action = request.form['action']
    con = db()
    if action == 'block':
        con.execute("UPDATE users SET status='blocked' WHERE id=?", (uid,))
    elif action == 'unblock':
        con.execute("UPDATE users SET status='active' WHERE id=?", (uid,))
    elif action == 'disable':
        con.execute("UPDATE users SET status='disabled' WHERE id=?", (uid,))
    elif action == 'enable':
        con.execute("UPDATE users SET status='active' WHERE id=?", (uid,))
    elif action == 'delete':
        con.execute("DELETE FROM users WHERE id=?", (uid,))
        con.commit(); con.close()
        log('USER DELETED', t['username'])
        flash('User deleted.')
        return redirect(url_for('admin_control'))
    elif action == 'kick':
        con.execute("UPDATE users SET session_token=NULL WHERE id=?", (uid,))
    elif action == 'resetpw':
        con.execute("UPDATE users SET password_hash=?, must_change_pw=1 WHERE id=?",
                    (generate_password_hash('user123'), uid))
    con.commit(); con.close()
    log('USER ' + action.upper(), t['username'])
    return redirect(url_for('admin_user_detail', uid=uid))

@app.route('/admin/control/<int:uid>/stime', methods=['POST'])
@login_required('admin')
def admin_user_stime(u, uid):
    t = get_user(uid)
    con = db()
    con.execute("UPDATE users SET s_start=?, s_end=? WHERE id=?",
                (request.form['s_start'], request.form['s_end'], uid))
    con.commit(); con.close()
    log('S-TIME CHANGED', t['username'] + ' -> ' + request.form['s_start'] + '-' + request.form['s_end'])
    return redirect(url_for('admin_user_detail', uid=uid))

# ---------------- files ----------------
@app.route('/admin/files')
@login_required('admin')
def admin_files(u):
    con = db()
    files = [dict(f) for f in con.execute("SELECT * FROM files ORDER BY name").fetchall()]
    for f in files:
        f['perms'] = con.execute("""SELECT p.perm, us.username FROM file_perms p
            JOIN users us ON us.id=p.user_id WHERE p.file_id=? AND p.perm!=''""",
            (f['id'],)).fetchall()
    users = con.execute("SELECT id, username FROM users WHERE role='user' ORDER BY username").fetchall()
    con.close()
    return render_template('admin/files.html', u=u, files=files, users=users)

@app.route('/admin/files/create', methods=['POST'])
@login_required('admin')
def admin_file_create(u):
    name = request.form['name'].strip()
    if not name.endswith('.txt'):
        name += '.txt'
    try:
        con = db()
        cur = con.execute("INSERT INTO files(name,description,flag,content,created,modified) "
                          "VALUES(?,?,?,?,?,?)",
                          (name, request.form.get('description', ''), 'N', '', now(), now()))
        fid = cur.lastrowid
        for us in con.execute("SELECT id FROM users WHERE role='user'").fetchall():
            p = request.form.get('perm_' + str(us['id']), '')
            con.execute("INSERT OR IGNORE INTO file_perms(file_id,user_id,perm) VALUES(?,?,?)",
                        (fid, us['id'], p))
        con.commit(); con.close()
        log('FILE CREATED', name)
        flash('File created.')
    except Exception:
        flash('A file with that name already exists.')
    return redirect(url_for('admin_files'))

@app.route('/admin/files/<int:fid>')
@login_required('admin')
def admin_file_edit(u, fid):
    con = db()
    f = con.execute("SELECT * FROM files WHERE id=?", (fid,)).fetchone()
    if not f: abort(404)
    users = con.execute("""SELECT us.*, COALESCE((SELECT perm FROM file_perms p
        WHERE p.file_id=? AND p.user_id=us.id),'') perm FROM users us
        WHERE us.role='user' ORDER BY us.username""", (fid,)).fetchall()
    con.close()
    return render_template('admin/file_edit.html', u=u, f=f, users=users)

@app.route('/admin/files/<int:fid>/save', methods=['POST'])
@login_required('admin')
def admin_file_save(u, fid):
    con = db()
    con.execute("UPDATE files SET name=?, description=?, flag=?, content=?, modified=? WHERE id=?",
                (request.form['name'], request.form.get('description', ''),
                 request.form.get('flag', 'N'), request.form.get('content', ''), now(), fid))
    for us in con.execute("SELECT id FROM users WHERE role='user'").fetchall():
        p = request.form.get('perm_' + str(us['id']), '')
        con.execute("INSERT OR IGNORE INTO file_perms(file_id,user_id,perm) VALUES(?,?,?)",
                    (fid, us['id'], p))
        con.execute("UPDATE file_perms SET perm=? WHERE file_id=? AND user_id=?",
                    (p, fid, us['id']))
    con.commit(); con.close()
    log('FILE EDIT', request.form['name'])
    flash('File saved.')
    return redirect(url_for('admin_file_edit', fid=fid))

@app.route('/admin/files/<int:fid>/delete', methods=['POST'])
@login_required('admin')
def admin_file_delete(u, fid):
    con = db()
    f = con.execute("SELECT name FROM files WHERE id=?", (fid,)).fetchone()
    con.execute("DELETE FROM files WHERE id=?", (fid,))
    con.commit(); con.close()
    log('FILE DELETED', f['name'] if f else str(fid))
    flash('File deleted (admin only action).')
    return redirect(url_for('admin_files'))

# ---------------- WORKP ----------------
@app.route('/admin/work', methods=['GET', 'POST'])
@login_required('admin')
def admin_work(u):
    con = db()
    if request.method == 'POST':
        con.execute("""INSERT INTO works(user_id,title,description,priority,due,created)
                       VALUES(?,?,?,?,?,?)""",
                    (request.form['user_id'], request.form['title'],
                     request.form.get('description', ''), request.form.get('priority', 'Normal'),
                     request.form.get('due', ''), now()))
        con.commit()
        t = get_user(int(request.form['user_id']))
        log('WORK ASSIGNED', t['username'] + ': ' + request.form['title'])
        flash('Work assigned.')
    works = con.execute("""SELECT w.*, us.username FROM works w JOIN users us ON us.id=w.user_id
        ORDER BY w.created DESC""").fetchall()
    users = con.execute("SELECT id, username FROM users WHERE role='user' AND status='active' "
                        "ORDER BY username").fetchall()
    con.close()
    return render_template('admin/work.html', u=u, works=works, users=users)

# ---------------- requests ----------------
@app.route('/admin/requests')
@login_required('admin')
def admin_requests(u):
    con = db()
    reqs = con.execute("""SELECT r.*, us.username FROM requests r JOIN users us ON us.id=r.user_id
        ORDER BY (r.status='pending') DESC, r.created DESC""").fetchall()
    con.close()
    return render_template('admin/requests.html', u=u, reqs=reqs, hm=hm)

@app.route('/admin/requests/<int:rid>', methods=['POST'])
@login_required('admin')
def admin_request_resolve(u, rid):
    action = request.form['action']
    con = db()
    r = con.execute("SELECT * FROM requests WHERE id=?", (rid,)).fetchone()
    if r and r['status'] == 'pending':
        con.execute("UPDATE requests SET status=?, resolved=? WHERE id=?",
                    ('approved' if action == 'approve' else 'rejected', now(), rid))
        if action == 'approve' and r['type'] in ('CF access', 'Read permission',
                                                 'Write permission', 'Read + Write permission'):
            try:
                fid, target = r['payload'].split('|', 1)
                perm = {'CF access': 'R', 'Read permission': 'R',
                        'Write permission': 'W', 'Read + Write permission': 'RW'}[r['type']]
                tu = con.execute("SELECT id FROM users WHERE username=?", (target,)).fetchone()
                if tu:
                    con.execute("INSERT OR IGNORE INTO file_perms(file_id,user_id,perm) VALUES(?,?,?)",
                                (int(fid), tu['id'], perm))
                    con.execute("UPDATE file_perms SET perm=? WHERE file_id=? AND user_id=?",
                                (perm, int(fid), tu['id']))
            except Exception:
                pass
        con.commit()
        log('REQUEST ' + action.upper(), r['type'] + ' by user#' + str(r['user_id']))
    con.close()
    return redirect(url_for('admin_requests'))

# ---------------- ADMIN account ----------------
@app.route('/admin/account', methods=['GET', 'POST'])
@login_required('admin')
def admin_account(u):
    if request.method == 'POST':
        set_setting('admin_s_start', request.form['s_start'])
        set_setting('admin_s_end', request.form['s_end'])
        con = db()
        con.execute("UPDATE users SET s_start=?, s_end=? WHERE id=?",
                    (request.form['s_start'], request.form['s_end'], u['id']))
        con.commit(); con.close()
        log('ADMIN S-TIME SET', request.form['s_start'] + ' - ' + request.form['s_end'])
        flash('Admin S-Time updated.')
        return redirect(url_for('admin_account'))
    con = db()
    logs_ = con.execute("SELECT * FROM logs ORDER BY ts DESC LIMIT 30").fetchall()
    sessions = con.execute("SELECT username, role, last_seen FROM users WHERE session_token IS NOT NULL").fetchall()
    con.close()
    return render_template('admin/account.html', u=u, logs=logs_, sessions=sessions,
                           hm=hm, s_start=setting('admin_s_start'), s_end=setting('admin_s_end'))

# ---------------- USER panel ----------------
@app.route('/user')
@login_required('user')
def user_dashboard(u):
    con = db()
    files = con.execute("""SELECT f.*, p.perm FROM files f JOIN file_perms p ON p.file_id=f.id
        WHERE p.user_id=? AND p.perm!='' ORDER BY f.name""", (u['id'],)).fetchall()
    works = con.execute("SELECT * FROM works WHERE user_id=? AND status='working' ORDER BY created DESC",
                        (u['id'],)).fetchall()
    reqs = con.execute("SELECT COUNT(*) c FROM requests WHERE user_id=? AND status='pending'",
                       (u['id'],)).fetchone()['c']
    unread = con.execute("SELECT COUNT(*) c FROM messages WHERE receiver_id=? AND read=0",
                         (u['id'],)).fetchone()['c']
    denied = con.execute("""SELECT * FROM logs WHERE actor=? AND action='LOGIN DENIED'
        ORDER BY ts DESC LIMIT 3""", (u['username'],)).fetchall()
    con.close()
    online = (now() - u['last_seen']) < 60
    return render_template('user/dashboard.html', u=u, files=files, works=works,
                           reqs=reqs, unread=unread, denied=denied, hm=hm, online=online)

@app.route('/user/files/<int:fid>', methods=['GET', 'POST'])
@login_required('user')
def user_file(u, fid):
    con = db()
    f = con.execute("SELECT * FROM files WHERE id=?", (fid,)).fetchone()
    perm = con.execute("SELECT perm FROM file_perms WHERE file_id=? AND user_id=?",
                       (fid, u['id'])).fetchone()
    if not f or not perm or perm['perm'] not in ('R', 'RW', 'W'):
        abort(403)
    if request.method == 'POST':
        if 'W' not in perm['perm']:
            abort(403)
        con.execute("UPDATE files SET content=?, modified=? WHERE id=?",
                    (request.form['content'], now(), fid))
        con.commit()
        log('FILE EDIT', f['name'])
        flash('File saved.')
        return redirect(url_for('user_file', fid=fid))
    log('FILE OPEN', f['name'])
    can_write = 'W' in perm['perm']
    con.close()
    return render_template('user/file_view.html', u=u, f=f, can_write=can_write)

@app.route('/user/work', methods=['GET', 'POST'])
@login_required('user')
def user_work(u):
    con = db()
    if request.method == 'POST':
        wid = int(request.form['work_id'])
        progress = int(request.form['progress'])
        status = request.form.get('status', 'working')
        con.execute("UPDATE works SET progress=?, status=? WHERE id=? AND user_id=?",
                    (progress, status, wid, u['id']))
        con.commit()
        con.close()
        log('WORK UPDATED', '#' + str(wid) + ' -> ' + str(progress) + '%')
        return redirect(url_for('user_work'))
    works = con.execute("SELECT * FROM works WHERE user_id=? ORDER BY created DESC",
                        (u['id'],)).fetchall()
    con.close()
    return render_template('user/work.html', u=u, works=works)

@app.route('/user/account', methods=['GET', 'POST'])
@login_required('user')
def user_account(u):
    if request.method == 'POST':
        rtype = request.form['type']
        payload = request.form.get('payload', '')
        con = db()
        con.execute("INSERT INTO requests(user_id,type,payload,created) VALUES(?,?,?,?)",
                    (u['id'], rtype, payload, now()))
        con.commit(); con.close()
        log('REQUEST SENT', u['username'] + ': ' + rtype)
        flash('Request sent to admin.')
        return redirect(url_for('user_account'))
    con = db()
    reqs = con.execute("SELECT * FROM requests WHERE user_id=? ORDER BY created DESC LIMIT 10",
                       (u['id'],)).fetchall()
    files = con.execute("""SELECT f.id, f.name, f.flag FROM files f JOIN file_perms p
        ON p.file_id=f.id WHERE p.user_id=? AND p.perm='' """, (u['id'],)).fetchall()
    con.close()
    return render_template('user/account.html', u=u, reqs=reqs, files=files, hm=hm)

# ---------------- CHAT API ----------------
def chat_contacts(u):
    con = db()
    others = con.execute("""SELECT id, username, role, last_seen FROM users
        WHERE id!=? AND status='active' ORDER BY role DESC, username""",
                         (u['id'],)).fetchall()
    out = []
    for o in others:
        last = con.execute("""SELECT body, ts FROM messages WHERE
            (sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?)
            ORDER BY ts DESC LIMIT 1""",
            (u['id'], o['id'], o['id'], u['id'])).fetchone()
        unread = con.execute("SELECT COUNT(*) c FROM messages WHERE sender_id=? AND receiver_id=? AND read=0",
                             (o['id'], u['id'])).fetchone()['c']
        out.append({'id': o['id'], 'username': o['username'], 'role': o['role'],
                    'online': (now() - o['last_seen']) < 60,
                    'last': last['body'] if last else '', 'unread': unread})
    con.close()
    return out

@app.route('/api/contacts')
@login_required()
def api_contacts(u):
    return jsonify(chat_contacts(u))

@app.route('/api/messages/<int:peer>')
@login_required()
def api_messages(u, peer):
    con = db()
    msgs = con.execute("""SELECT m.*, s.username sender FROM messages m JOIN users s ON s.id=m.sender_id
        WHERE (m.sender_id=? AND m.receiver_id=?) OR (m.sender_id=? AND m.receiver_id=?)
        ORDER BY m.ts""", (u['id'], peer, peer, u['id'])).fetchall()
    con.execute("UPDATE messages SET read=1 WHERE sender_id=? AND receiver_id=?",
                (peer, u['id']))
    con.commit(); con.close()
    return jsonify([{'id': m['id'], 'sender': m['sender'], 'mine': m['sender_id'] == u['id'],
                     'body': m['body'], 'ts': hm(m['ts'])} for m in msgs])

@app.route('/api/send', methods=['POST'])
@login_required()
def api_send(u):
    body = request.form['body'].strip()
    peer = int(request.form['peer'])
    if body:
        con = db()
        con.execute("INSERT INTO messages(sender_id,receiver_id,body,ts) VALUES(?,?,?,?)",
                    (u['id'], peer, body, now()))
        con.commit(); con.close()
    return jsonify({'ok': True})

@app.route('/admin/chat')
@login_required('admin')
def admin_chat(u):
    return render_template('chat.html', u=u, title='MESSEGE / CHAT')

@app.route('/user/contact')
@login_required('user')
def user_contact(u):
    return render_template('chat.html', u=u, title='CONTACT')

init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
