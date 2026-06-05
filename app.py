"""
Newsletter Extractor - Flask backend (Render-ready)
Local:  pip install -r requirements.txt && python app.py
Render: gunicorn app:app
"""
import os, re, imaplib, email, socket, datetime, threading, uuid, secrets, hmac, time
from functools import wraps
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
from flask import Flask, request, jsonify, send_from_directory, send_file, session, redirect, url_for
import zipfile

app = Flask(__name__)
app.secret_key = os.environ.get('APP_SECRET') or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=bool(os.environ.get('RENDER')),
    PERMANENT_SESSION_LIFETIME=3600,
)

# --- AUTH ---------------------------------------------------------------
AUTH_USER = os.environ.get('APP_USER', 'admin')
AUTH_PASS = os.environ.get('APP_PASS', 'changeme')
MAX_ATTEMPTS = 5
LOCKOUT_SECS = 300
_failed = {}

def _client_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr or '0.0.0.0').split(',')[0].strip()

def _locked(ip):
    rec = _failed.get(ip)
    if not rec: return False
    count, ts = rec
    if count >= MAX_ATTEMPTS and time.time() - ts < LOCKOUT_SECS: return True
    if time.time() - ts >= LOCKOUT_SECS: _failed.pop(ip, None)
    return False

def _fail(ip):
    rec = _failed.get(ip, [0, time.time()])
    rec[0] += 1
    if rec[0] == 1: rec[1] = time.time()
    _failed[ip] = rec

def require_auth(f):
    @wraps(f)
    def wrap(*a, **kw):
        if not session.get('auth'):
            if request.path.startswith(('/start', '/status', '/download')) or request.is_json:
                return jsonify({'error': 'unauthorized'}), 401
            return redirect(url_for('login_page'))
        return f(*a, **kw)
    return wrap
# ------------------------------------------------------------------------

JOBS = {}
HERE = os.path.dirname(os.path.abspath(__file__))
OUT_ROOT = os.path.join('/tmp' if os.environ.get('RENDER') else HERE, 'newsletters')
os.makedirs(OUT_ROOT, exist_ok=True)


def get_imap_server(domain):
    d = domain.lower()
    if 'gmail.com' in d: return 'imap.gmail.com'
    if 'yahoo' in d: return 'imap.mail.yahoo.com'
    if any(x in d for x in ('outlook', 'hotmail', 'live')): return 'outlook.office365.com'
    if 't-online.de' in d: return 'secureimap.t-online.de'
    if 'aol' in d: return 'imap.aol.com'
    if 'icloud' in d or 'me.com' in d: return 'imap.mail.me.com'
    raise Exception(f"No IMAP server mapping for {domain}")


def log(job_id, msg):
    JOBS[job_id]['log'].append(msg)
    print(f"[{job_id[:6]}] {msg}", flush=True)


def strip_html_text(html):
    soup = BeautifulSoup(html, 'html.parser')
    for a in soup.find_all('a'): a.decompose()
    return " ".join(soup.get_text(separator=' ').split())

def strip_text_keep_html(html):
    return " ".join(re.sub(r'>([^<]+)<', '><', html).split())

def html_one_line(html):
    return " ".join(html.split())

def extract_html(parsed):
    for part in parsed.walk():
        if part.get_content_type() == "text/html":
            try:
                return part.get_payload(decode=True).decode(
                    part.get_content_charset() or 'utf-8', errors='ignore')
            except Exception:
                return None
    return None

def process_content(html, mode):
    if mode == 'text': return strip_html_text(html)
    if mode == 'html_no_text': return strip_text_keep_html(html)
    return html_one_line(html)

def save_batch(job_dir, email_address, newsletters, batch_id):
    if not newsletters: return None
    safe = re.sub(r'[^A-Za-z0-9_.@-]', '_', email_address)
    fname = os.path.join(job_dir, f"{safe}_batch_{batch_id}.txt")
    with open(fname, 'w', encoding='utf-8') as f:
        for n in newsletters:
            f.write(n + "\n\n")
    return fname


def run_job(job_id, params):
    try:
        JOBS[job_id]['status'] = 'running'
        creds = params['credentials']
        mode = params.get('content_mode', 'html')
        filter_type = params.get('filter_type', 'all')
        batch_size = int(params.get('batch_size', 10))
        job_dir = os.path.join(OUT_ROOT, job_id)
        os.makedirs(job_dir, exist_ok=True)
        JOBS[job_id]['dir'] = job_dir

        def worker(cred):
            email_address, password = cred['email'], cred['password']
            try:
                domain = email_address.split('@')[1]
                imap_server = get_imap_server(domain)
                socket.setdefaulttimeout(30)
                mail = imaplib.IMAP4_SSL(imap_server)
                mail.login(email_address, password)
                log(job_id, f"{email_address} logged in")
                mail.select("inbox")

                if filter_type == 'last_days':
                    days = int(params.get('days', 30))
                    since = (datetime.date.today() - datetime.timedelta(days=days)).strftime("%d-%b-%Y")
                    status, messages = mail.search(None, f'SINCE {since}')
                elif filter_type == 'from':
                    sender = params.get('from_address', '').strip()
                    status, messages = mail.search(None, f'FROM "{sender}"')
                else:
                    status, messages = mail.search(None, 'ALL')

                if status != "OK":
                    log(job_id, f"{email_address} search failed")
                    mail.logout(); return

                ids = messages[0].split()
                total = len(ids)
                log(job_id, f"{email_address}: {total} messages matched")
                ids.reverse()

                if filter_type == 'range':
                    start = int(params.get('range_start', 1))
                    end = int(params.get('range_end', total))
                    start = max(1, start); end = min(total, end)
                    ids = ids[start-1:end]

                newsletters = []
                batch_id = 1
                extracted = 0
                for msg_id in ids:
                    try:
                        _, data = mail.fetch(msg_id, "(RFC822)")
                    except Exception as fe:
                        log(job_id, f"{email_address} fetch err: {fe}"); continue
                    for part in data:
                        if isinstance(part, tuple):
                            parsed = email.message_from_bytes(part[1])
                            html = extract_html(parsed)
                            if html:
                                newsletters.append(process_content(html, mode))
                                extracted += 1
                    if len(newsletters) >= batch_size:
                        save_batch(job_dir, email_address, newsletters, batch_id)
                        log(job_id, f"{email_address} saved batch {batch_id} ({len(newsletters)})")
                        newsletters = []; batch_id += 1
                if newsletters:
                    save_batch(job_dir, email_address, newsletters, batch_id)
                    log(job_id, f"{email_address} saved final batch ({len(newsletters)})")
                log(job_id, f"{email_address} done: {extracted} newsletters")
                mail.logout()
            except Exception as e:
                log(job_id, f"ERROR {email_address}: {e}")

        with ThreadPoolExecutor(max_workers=min(20, max(1, len(creds)))) as ex:
            list(ex.map(worker, creds))

        zip_path = os.path.join(job_dir, 'results.zip')
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(job_dir):
                for fn in files:
                    if fn == 'results.zip': continue
                    full = os.path.join(root, fn)
                    zf.write(full, os.path.relpath(full, job_dir))
        JOBS[job_id]['zip'] = zip_path
        JOBS[job_id]['status'] = 'done'
        log(job_id, "JOB COMPLETE")
    except Exception as e:
        JOBS[job_id]['status'] = 'error'
        log(job_id, f"FATAL: {e}")


LOGIN_HTML = """<!doctype html><html><head><meta charset="utf-8"><title>Sign in</title>
<style>body{margin:0;font-family:system-ui,sans-serif;background:#0f1115;color:#e6e9ef;
display:flex;align-items:center;justify-content:center;height:100vh}
.box{background:#1a1d24;border:1px solid #2a2f3a;border-radius:8px;padding:24px;width:320px}
h1{margin:0 0 16px;font-size:18px}label{display:block;font-size:12px;color:#8b93a7;margin:8px 0 4px}
input{width:100%;font:inherit;color:#e6e9ef;background:#0c0e13;border:1px solid #2a2f3a;
border-radius:6px;padding:8px 10px;box-sizing:border-box}
button{width:100%;margin-top:14px;background:#6ea8fe;color:#0c0e13;border:0;
border-radius:6px;padding:10px;font-weight:600;cursor:pointer}
.err{color:#f85149;font-size:12px;margin-top:10px;min-height:16px}</style></head>
<body><div class="box"><h1>🔒 Newsletter Extractor</h1>
<form method="POST"><label>Username</label><input name="u" autofocus autocomplete="username">
<label>Password</label><input name="p" type="password" autocomplete="current-password">
<button>Sign in</button><div class="err">__ERR__</div></form></div></body></html>"""


@app.route('/login', methods=['GET', 'POST'])
def login_page():
    err = ''
    if request.method == 'POST':
        ip = _client_ip()
        if _locked(ip):
            err = 'Too many failed attempts. Try again later.'
        else:
            u = request.form.get('u', '')
            p = request.form.get('p', '')
            if hmac.compare_digest(u, AUTH_USER) and hmac.compare_digest(p, AUTH_PASS):
                session.permanent = True
                session['auth'] = True
                _failed.pop(ip, None)
                return redirect(url_for('index'))
            _fail(ip)
            err = 'Invalid credentials.'
    return LOGIN_HTML.replace('__ERR__', err)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))


@app.route('/')
@require_auth
def index():
    return send_from_directory(HERE, 'index.html')


@app.route('/start', methods=['POST'])
@require_auth
def start():
    params = request.get_json()
    if not params.get('credentials'):
        return jsonify({'error': 'no credentials'}), 400
    job_id = uuid.uuid4().hex
    JOBS[job_id] = {'status': 'queued', 'log': [], 'dir': None, 'zip': None}
    threading.Thread(target=run_job, args=(job_id, params), daemon=True).start()
    return jsonify({'job_id': job_id})


@app.route('/status/<job_id>')
@require_auth
def status(job_id):
    j = JOBS.get(job_id)
    if not j: return jsonify({'error': 'unknown job'}), 404
    return jsonify({'status': j['status'], 'log': j['log'][-200:],
                    'has_zip': bool(j.get('zip'))})


@app.route('/download/<job_id>')
@require_auth
def download(job_id):
    j = JOBS.get(job_id)
    if not j or not j.get('zip'): return 'not ready', 404
    return send_file(j['zip'], as_attachment=True,
                     download_name=f'newsletters_{job_id[:8]}.zip')


@app.route('/healthz')
def healthz():
    return 'ok'


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    if AUTH_PASS == 'changeme':
        print("⚠  Default password in use. Set APP_USER / APP_PASS env vars.")
    print(f"Open http://localhost:{port}  (user: {AUTH_USER})")
    app.run(host='0.0.0.0', port=port, debug=False)
