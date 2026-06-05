"""
Newsletter Extractor - Flask backend (Render-ready, multi-user)
"""
import os, re, imaplib, email, socket, datetime, threading, uuid, secrets, hmac, time, json
import urllib.request, ssl as _ssl
from email.header import decode_header
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
    PERMANENT_SESSION_LIFETIME=86400,
)

# --- USERS --------------------------------------------------------------
def _load_users():
    raw = os.environ.get('APP_USERS', '').strip()
    if raw:
        try:
            d = json.loads(raw)
            if isinstance(d, dict): return {str(k): str(v) for k, v in d.items()}
        except Exception:
            pass
        out = {}
        for pair in raw.split(','):
            if ':' in pair:
                u, p = pair.split(':', 1)
                out[u.strip()] = p.strip()
        if out: return out
    return {os.environ.get('APP_USER', 'admin'): os.environ.get('APP_PASS', 'changeme')}

USERS = _load_users()
ADMINS = set(u.strip() for u in os.environ.get('APP_ADMINS', '').split(',') if u.strip())
if not ADMINS:
    # First user in APP_USERS (or 'admin') is admin by default
    ADMINS = {next(iter(USERS))} if USERS else set()

# --- AUDIT LOG ----------------------------------------------------------
AUDIT_FILE = os.path.join('/tmp' if os.environ.get('RENDER') else HERE, 'audit.log') if False else None
_AUDIT_FILE = os.path.join('/tmp' if os.environ.get('RENDER') else os.path.dirname(os.path.abspath(__file__)), 'audit.log')
_AUDIT_LOCK = threading.Lock()
_AUDIT_MAX = 5000  # keep last N entries in memory

AUDIT = []  # list of {ts, user, ip, event, details}

def audit_bg(event, user, ip='bg', details=None):
    """Audit from background threads (no Flask request context)."""
    entry = {
        'ts': datetime.datetime.utcnow().isoformat(timespec='seconds') + 'Z',
        'user': user or '-',
        'ip': ip,
        'ua': '-',
        'event': event,
        'details': details or '',
    }
    with _AUDIT_LOCK:
        AUDIT.append(entry)
        if len(AUDIT) > _AUDIT_MAX:
            del AUDIT[:len(AUDIT) - _AUDIT_MAX]
        try:
            with open(_AUDIT_FILE, 'a', encoding='utf-8') as f:
                f.write(json.dumps(entry, ensure_ascii=False) + '\n')
        except Exception:
            pass
    print(f"AUDIT {entry['ts']} {entry['user']}@{entry['ip']} {event}: {entry['details']}", flush=True)


def audit(event, user=None, details=None):
    entry = {
        'ts': datetime.datetime.utcnow().isoformat(timespec='seconds') + 'Z',
        'user': user or (session.get('user') if request else None) or '-',
        'ip': _client_ip() if request else '-',
        'ua': (request.headers.get('User-Agent', '-')[:200] if request else '-'),
        'event': event,
        'details': details or '',
    }
    with _AUDIT_LOCK:
        AUDIT.append(entry)
        if len(AUDIT) > _AUDIT_MAX:
            del AUDIT[:len(AUDIT) - _AUDIT_MAX]
        try:
            with open(_AUDIT_FILE, 'a', encoding='utf-8') as f:
                f.write(json.dumps(entry, ensure_ascii=False) + '\n')
        except Exception:
            pass
    print(f"AUDIT {entry['ts']} {entry['user']}@{entry['ip']} {event}: {entry['details']}", flush=True)

def _load_audit_from_disk():
    if not os.path.exists(_AUDIT_FILE): return
    try:
        with open(_AUDIT_FILE, 'r', encoding='utf-8') as f:
            for line in f.readlines()[-_AUDIT_MAX:]:
                try: AUDIT.append(json.loads(line))
                except Exception: pass
    except Exception:
        pass

_load_audit_from_disk()

def require_admin(f):
    @wraps(f)
    def wrap(*a, **kw):
        if session.get('user') not in ADMINS:
            return jsonify({'error': 'forbidden'}), 403
        return f(*a, **kw)
    return wrap
# ------------------------------------------------------------------------

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

def _check(u, p):
    expected = USERS.get(u)
    if expected is None:
        hmac.compare_digest('x', 'y'); return False
    return hmac.compare_digest(p, expected)

def require_auth(f):
    @wraps(f)
    def wrap(*a, **kw):
        if not session.get('user'):
            if request.path.startswith(('/start', '/status', '/download', '/stop', '/me')) or request.is_json:
                return jsonify({'error': 'unauthorized'}), 401
            return redirect(url_for('login_page'))
        return f(*a, **kw)
    return wrap

JOBS = {}
HERE = os.path.dirname(os.path.abspath(__file__))
OUT_ROOT = os.path.join('/tmp' if os.environ.get('RENDER') else HERE, 'newsletters')
os.makedirs(OUT_ROOT, exist_ok=True)


# --- IMAP autodiscovery -------------------------------------------------
_IMAP_CACHE = {}

KNOWN_IMAP = {
    'gmail.com': 'imap.gmail.com', 'googlemail.com': 'imap.gmail.com',
    'yahoo.com': 'imap.mail.yahoo.com', 'yahoo.co.jp': 'imap.mail.yahoo.co.jp',
    'ymail.com': 'imap.mail.yahoo.com', 'rocketmail.com': 'imap.mail.yahoo.com',
    'outlook.com': 'outlook.office365.com', 'hotmail.com': 'outlook.office365.com',
    'live.com': 'outlook.office365.com', 'msn.com': 'outlook.office365.com',
    'office365.com': 'outlook.office365.com',
    'aol.com': 'imap.aol.com',
    'icloud.com': 'imap.mail.me.com', 'me.com': 'imap.mail.me.com', 'mac.com': 'imap.mail.me.com',
    'zoho.com': 'imap.zoho.com', 'zohomail.com': 'imap.zoho.com',
    'gmx.com': 'imap.gmx.com', 'gmx.net': 'imap.gmx.net', 'gmx.de': 'imap.gmx.net',
    'mail.com': 'imap.mail.com',
    'fastmail.com': 'imap.fastmail.com', 'fastmail.fm': 'imap.fastmail.com',
    'yandex.com': 'imap.yandex.com', 'yandex.ru': 'imap.yandex.ru',
    'mail.ru': 'imap.mail.ru', 'inbox.ru': 'imap.mail.ru', 'list.ru': 'imap.mail.ru', 'bk.ru': 'imap.mail.ru',
    'ezweb.ne.jp': 'imap.au.com', 'au.com': 'imap.au.com',
    'docomo.ne.jp': 'imap.spmode.ne.jp', 'spmode.ne.jp': 'imap.spmode.ne.jp',
    'softbank.ne.jp': 'imap.softbank.jp', 'i.softbank.jp': 'imap.softbank.jp',
    'nifty.com': 'imap.nifty.com', 'so-net.ne.jp': 'mail.so-net.ne.jp',
    'biglobe.ne.jp': 'mail.biglobe.ne.jp', 'ocn.ne.jp': 'imap.ocn.ne.jp',
    'plala.or.jp': 'imap.plala.or.jp', 'ybb.ne.jp': 'imap.ybb.ne.jp',
    'excite.co.jp': 'mail.excite.co.jp',
    't-online.de': 'secureimap.t-online.de', 'web.de': 'imap.web.de',
    '1und1.de': 'imap.1und1.de', 'freenet.de': 'mx.freenet.de',
    'mailbox.org': 'imap.mailbox.org', 'posteo.de': 'posteo.de',
    'orange.fr': 'imap.orange.fr', 'wanadoo.fr': 'imap.orange.fr',
    'free.fr': 'imap.free.fr', 'laposte.net': 'imap.laposte.net',
    'libero.it': 'imapmail.libero.it', 'tiscali.it': 'imap.tiscali.it',
    'btinternet.com': 'mail.btinternet.com', 'sky.com': 'imap.tools.sky.com',
    'virginmedia.com': 'imap.virginmedia.com',
    'comcast.net': 'imap.comcast.net', 'verizon.net': 'imap.aol.com',
    'att.net': 'imap.mail.att.net', 'sbcglobal.net': 'imap.mail.att.net',
    'cox.net': 'imap.cox.net', 'charter.net': 'mobile.charter.net',
    'optonline.net': 'mail.optonline.net', 'earthlink.net': 'imap.earthlink.net',
    'rediffmail.com': 'imap.rediffmail.com', 'sina.com': 'imap.sina.com',
    'qq.com': 'imap.qq.com', '163.com': 'imap.163.com', '126.com': 'imap.126.com',
}

def _probe_imap(host, port=993, timeout=4):
    try:
        ctx = _ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                banner = ss.recv(64)
                return b'IMAP' in banner.upper() or b'OK' in banner.upper()
    except Exception:
        return False

def _try_ispdb(domain):
    urls = [
        f"https://autoconfig.thunderbird.net/v1.1/{domain}",
        f"https://autoconfig.{domain}/mail/config-v1.1.xml?emailaddress=user@{domain}",
    ]
    for url in urls:
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                xml = r.read().decode('utf-8', errors='ignore')
            m = re.search(
                r'<incomingServer[^>]*type=["\']imap["\'][^>]*>(.*?)</incomingServer>',
                xml, re.DOTALL | re.IGNORECASE)
            if m:
                h = re.search(r'<hostname>([^<]+)</hostname>', m.group(1))
                if h:
                    return h.group(1).strip().replace('%EMAILDOMAIN%', domain)
        except Exception:
            continue
    return None

def _try_patterns(domain):
    for h in (f'imap.{domain}', f'mail.{domain}', f'imaps.{domain}', f'imap-mail.{domain}', domain):
        if _probe_imap(h):
            return h
    return None

def resolve_imap(domain, provider_hint=None):
    domain = domain.lower().strip()
    if provider_hint:
        hint = provider_hint.lower()
        if hint == 'gmail': return 'imap.gmail.com'
        if hint == 'yahoo': return 'imap.mail.yahoo.com'
        if hint == 'hotmail': return 'outlook.office365.com'
    if domain in _IMAP_CACHE: return _IMAP_CACHE[domain]
    if domain in KNOWN_IMAP:
        host = KNOWN_IMAP[domain]
        if host is None: raise Exception(f"{domain} does not support IMAP")
        _IMAP_CACHE[domain] = host
        return host
    for fn in (_try_ispdb, _try_patterns):
        try:
            host = fn(domain)
            if host:
                _IMAP_CACHE[domain] = host
                return host
        except Exception:
            continue
    raise Exception(f"Could not autodiscover IMAP for {domain}")


# --- Folder mapping -----------------------------------------------------
FOLDER_MAP = {
    'inbox': 'INBOX',
    'all': '[Gmail]/All Mail',
    'archive': 'Archive',
    'drafts': 'Drafts',
    'flagged': 'Flagged',
    'junk': 'Junk',
    'sent': 'Sent',
    'trash': 'Trash',
}

def select_folder(mail, folder_key):
    folder_key = (folder_key or 'inbox').lower()
    if folder_key == 'inbox':
        mail.select('INBOX'); return 'INBOX'
    try:
        status, _ = mail.list()
        if status != 'OK': mail.select('INBOX'); return 'INBOX'
    except Exception:
        mail.select('INBOX'); return 'INBOX'
    candidates = {
        'all':     ['[Gmail]/All Mail', '[Google Mail]/All Mail', 'Archive', 'All Mail'],
        'archive': ['Archive', '[Gmail]/All Mail', 'All Mail'],
        'drafts':  ['Drafts', '[Gmail]/Drafts', 'INBOX.Drafts'],
        'flagged': ['Flagged', '[Gmail]/Starred', 'Starred', 'INBOX.Flagged'],
        'junk':    ['Junk', 'Spam', '[Gmail]/Spam', 'INBOX.Junk', 'INBOX.Spam', 'Junk Email'],
        'sent':    ['Sent', '[Gmail]/Sent Mail', 'Sent Items', 'INBOX.Sent'],
        'trash':   ['Trash', '[Gmail]/Trash', 'Deleted Items', 'INBOX.Trash'],
    }.get(folder_key, ['INBOX'])
    for c in candidates:
        try:
            status, _ = mail.select(f'"{c}"')
            if status == 'OK': return c
        except Exception:
            continue
    mail.select('INBOX'); return 'INBOX'


# --- Email parsing helpers ----------------------------------------------
def decode_str(s):
    if not s: return ''
    try:
        parts = decode_header(s)
        return ''.join(
            (p.decode(enc or 'utf-8', errors='ignore') if isinstance(p, bytes) else p)
            for p, enc in parts)
    except Exception:
        return str(s)

def get_html_body(msg):
    for part in msg.walk():
        if part.get_content_type() == 'text/html':
            try:
                return part.get_payload(decode=True).decode(
                    part.get_content_charset() or 'utf-8', errors='ignore')
            except Exception:
                return ''
    return ''

def get_text_body(msg):
    for part in msg.walk():
        if part.get_content_type() == 'text/plain':
            try:
                return part.get_payload(decode=True).decode(
                    part.get_content_charset() or 'utf-8', errors='ignore')
            except Exception:
                return ''
    html = get_html_body(msg)
    if html:
        soup = BeautifulSoup(html, 'html.parser')
        for a in soup.find_all('a'): a.decompose()
        return soup.get_text(separator=' ')
    return ''

def header_str(msg, key):
    return decode_str(msg.get(key, ''))

def render_email(msg, return_type, sym_sep):
    rt = (return_type or 'fullsource').lower()
    if rt == 'fullsource':
        try: return msg.as_string()
        except Exception: return msg.as_bytes().decode('utf-8', errors='ignore')
    if rt == 'fullheader':
        return '\n'.join(f"{k}: {decode_str(v)}" for k, v in msg.items())
    if rt == 'header':
        keys = ('From', 'To', 'Subject', 'Date', 'Message-ID')
        sep = sym_sep or ' | '
        return sep.join(f"{k}: {header_str(msg, k)}" for k in keys)
    if rt == 'body':
        html = get_html_body(msg)
        return " ".join(html.split()) if html else " ".join(get_text_body(msg).split())
    if rt == 'bodyparameter':
        return " ".join(get_text_body(msg).split())
    # --- original 3 modes ---
    if rt == 'html':
        # Raw HTML (one line)
        html = get_html_body(msg)
        return " ".join(html.split())
    if rt == 'text':
        # Text only (links removed)
        html = get_html_body(msg)
        if not html: return " ".join(get_text_body(msg).split())
        soup = BeautifulSoup(html, 'html.parser')
        for a in soup.find_all('a'): a.decompose()
        return " ".join(soup.get_text(separator=' ').split())
    if rt == 'html_no_text':
        # HTML structure only (text between tags removed)
        html = get_html_body(msg)
        return " ".join(re.sub(r'>([^<]+)<', '><', html).split())
    return msg.as_string()


# --- Filtering ----------------------------------------------------------
def email_matches_filters(msg, filters, operator):
    if not filters: return True
    op = (operator or 'and').lower()

    def one(f):
        param = (f.get('param') or '').strip().lower()
        ftype = (f.get('type') or 'contains').lower()
        val = (f.get('value') or '').strip()
        if not param or not val: return True
        if param == 'body':
            field = (get_html_body(msg) + ' ' + get_text_body(msg)).lower()
        else:
            field = decode_str(msg.get(param, '')).lower()
        v = val.lower()
        if ftype == 'contains':       return v in field
        if ftype == 'equals':         return v == field
        if ftype == 'starts_with':    return field.startswith(v)
        if ftype == 'ends_with':      return field.endswith(v)
        if ftype == 'not_contains':   return v not in field
        if ftype == 'regex':
            try: return re.search(val, field, re.IGNORECASE) is not None
            except re.error: return False
        return v in field

    results = [one(f) for f in filters]
    return all(results) if op == 'and' else any(results)


def log(job_id, msg):
    JOBS[job_id]['log'].append(msg)
    print(f"[{job_id[:6]}] {msg}", flush=True)


def save_mailbox(job_id, job_dir, email_address, items, sep):
    """Save all newsletters for one mailbox to a single .txt with separator between."""
    if not items: return None
    safe_addr = re.sub(r'[^A-Za-z0-9_.@-]', '_', email_address)
    fname = f"{safe_addr}.txt"
    full = os.path.join(job_dir, fname)
    sep = sep or '_SEPARATOR_'
    body = f"\n{sep}\n".join(items)
    with open(full, 'w', encoding='utf-8') as f:
        f.write(body + "\n")
    size = len(body.encode('utf-8'))
    # Replace existing entry if re-saved
    JOBS[job_id]['files'] = [f for f in JOBS[job_id]['files'] if f['name'] != fname]
    JOBS[job_id]['files'].append({
        'name': fname,
        'email': email_address,
        'count': len(items),
        'size': size,
    })
    return fname


def run_job(job_id, params, owner):
    job_start_ts = time.time()
    try:
        JOBS[job_id]['status'] = 'running'
        creds = params['credentials']
        provider = params.get('provider', 'others')
        folder = params.get('folder', 'inbox')
        return_type = params.get('return_type', 'fullsource')
        sym_sep = params.get('symbol_separator', '')
        result_sep = params.get('result_separator', '_SEPARATOR_')
        max_emails = int(params.get('max_emails', 0) or 0)
        order = params.get('order', 'new_to_old')
        filters = params.get('filters', [])
        filter_op = params.get('filter_operator', 'and')

        job_dir = os.path.join(OUT_ROOT, job_id)
        os.makedirs(job_dir, exist_ok=True)
        JOBS[job_id]['dir'] = job_dir

        # how often to flush partial progress to disk
        FLUSH_EVERY = 5

        def worker(cred):
            if JOBS[job_id].get('cancel'): return
            email_address, password = cred['email'], cred['password']
            mb_start = time.time()
            try:
                domain = email_address.split('@')[1]
                imap_server = resolve_imap(domain, provider)
                socket.setdefaulttimeout(30)
                mail = imaplib.IMAP4_SSL(imap_server)
                mail.login(email_address, password)
                log(job_id, f"{email_address} logged in @ {imap_server}")
                audit_bg('mailbox_login_ok', owner,
                         details=f"job={job_id[:8]} mailbox={email_address} imap={imap_server}")
                selected = select_folder(mail, folder)
                log(job_id, f"{email_address} folder={selected}")

                status, messages = mail.search(None, 'ALL')
                if status != 'OK':
                    log(job_id, f"{email_address} search failed")
                    audit_bg('mailbox_search_fail', owner,
                             details=f"job={job_id[:8]} mailbox={email_address}")
                    mail.logout(); return

                ids = messages[0].split()
                total = len(ids)
                log(job_id, f"{email_address}: {total} messages in folder")

                if order == 'new_to_old':
                    ids.reverse()
                if max_emails > 0:
                    ids = ids[:max_emails]

                items = []
                extracted = 0
                kept = 0
                for msg_id in ids:
                    if JOBS[job_id].get('cancel'):
                        log(job_id, f"{email_address} cancelled"); break
                    try:
                        _, data = mail.fetch(msg_id, '(RFC822)')
                    except Exception as fe:
                        log(job_id, f"{email_address} fetch err: {fe}"); continue
                    for part in data:
                        if isinstance(part, tuple):
                            msg = email.message_from_bytes(part[1])
                            extracted += 1
                            if not email_matches_filters(msg, filters, filter_op):
                                continue
                            kept += 1
                            items.append(render_email(msg, return_type, sym_sep))
                    if kept and kept % FLUSH_EVERY == 0:
                        save_mailbox(job_id, job_dir, email_address, items, result_sep)
                # Final save
                if items:
                    save_mailbox(job_id, job_dir, email_address, items, result_sep)
                dur = round(time.time() - mb_start, 1)
                log(job_id, f"{email_address} done: {extracted} scanned, {kept} saved")
                audit_bg('mailbox_done', owner, details=(
                    f"job={job_id[:8]} mailbox={email_address} folder={selected} "
                    f"total={total} scanned={extracted} saved={kept} duration={dur}s"
                ))
                mail.logout()
            except imaplib.IMAP4.error as e:
                log(job_id, f"ERROR {email_address}: {e}")
                audit_bg('mailbox_login_fail', owner,
                         details=f"job={job_id[:8]} mailbox={email_address} err={e}")
            except Exception as e:
                log(job_id, f"ERROR {email_address}: {e}")
                audit_bg('mailbox_error', owner,
                         details=f"job={job_id[:8]} mailbox={email_address} err={e}")

        with ThreadPoolExecutor(max_workers=min(20, max(1, len(creds)))) as ex:
            list(ex.map(worker, creds))

        # Build optional ZIP of all .txt for "download all"
        zip_path = os.path.join(job_dir, 'results.zip')
        try:
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                for f in JOBS[job_id]['files']:
                    full = os.path.join(job_dir, f['name'])
                    if os.path.exists(full):
                        zf.write(full, f['name'])
            JOBS[job_id]['zip'] = zip_path
        except Exception as e:
            log(job_id, f"zip error: {e}")
        if JOBS[job_id].get('cancel'):
            JOBS[job_id]['status'] = 'cancelled'
            log(job_id, "JOB CANCELLED (partial results saved)")
            total_nl = sum(f.get('count', 0) for f in JOBS[job_id]['files'])
            total_sz = sum(f.get('size', 0) for f in JOBS[job_id]['files'])
            audit_bg('job_cancelled', owner, details=(
                f"job={job_id[:8]} mailboxes={len(JOBS[job_id]['files'])} "
                f"newsletters={total_nl} size={total_sz} "
                f"duration={round(time.time()-job_start_ts,1)}s"
            ))
        else:
            JOBS[job_id]['status'] = 'done'
            log(job_id, "JOB COMPLETE")
            total_nl = sum(f.get('count', 0) for f in JOBS[job_id]['files'])
            total_sz = sum(f.get('size', 0) for f in JOBS[job_id]['files'])
            audit_bg('job_done', owner, details=(
                f"job={job_id[:8]} mailboxes={len(JOBS[job_id]['files'])} "
                f"newsletters={total_nl} size={total_sz} "
                f"duration={round(time.time()-job_start_ts,1)}s"
            ))
    except Exception as e:
        JOBS[job_id]['status'] = 'error'
        log(job_id, f"FATAL: {e}")
        audit_bg('job_error', owner,
                 details=f"job={job_id[:8]} err={e} duration={round(time.time()-job_start_ts,1)}s")


LOGIN_HTML = """<!doctype html><html><head><meta charset="utf-8"><title>Sign in</title>
<style>body{margin:0;font-family:system-ui,sans-serif;background:#f4f5f7;color:#1a1a1a;
display:flex;align-items:center;justify-content:center;height:100vh}
.box{background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:24px;width:320px;box-shadow:0 1px 3px rgba(0,0,0,.06)}
h1{margin:0 0 16px;font-size:18px}label{display:block;font-size:12px;color:#666;margin:8px 0 4px}
input{width:100%;font:inherit;border:1px solid #d1d5db;border-radius:6px;padding:8px 10px;box-sizing:border-box}
button{width:100%;margin-top:14px;background:#1ba9c2;color:#fff;border:0;
border-radius:6px;padding:10px;font-weight:600;cursor:pointer}
.err{color:#d4183d;font-size:12px;margin-top:10px;min-height:16px}</style></head>
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
            audit('login_locked', user=request.form.get('u','-'))
        else:
            u = request.form.get('u', '').strip()
            p = request.form.get('p', '')
            if _check(u, p):
                session.permanent = True; session['user'] = u
                _failed.pop(ip, None)
                audit('login_success', user=u)
                return redirect(url_for('index'))
            _fail(ip); err = 'Invalid credentials.'
            audit('login_fail', user=u or '-')
    return LOGIN_HTML.replace('__ERR__', err)


@app.route('/logout')
def logout():
    if session.get('user'):
        audit('logout', user=session.get('user'))
    session.clear()
    return redirect(url_for('login_page'))


@app.route('/me')
@require_auth
def me():
    return jsonify({'user': session.get('user')})


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
    JOBS[job_id] = {'status': 'queued', 'log': [], 'dir': None, 'zip': None,
                    'owner': session.get('user'), 'cancel': False, 'files': []}
    mailboxes = [c.get('email','?') for c in params['credentials']]
    audit('job_start', details=(
        f"job={job_id[:8]} "
        f"provider={params.get('provider','?')} "
        f"folder={params.get('folder','?')} "
        f"type={params.get('return_type','?')} "
        f"max={params.get('max_emails','?')} "
        f"mailboxes={','.join(mailboxes)}"
    ))
    threading.Thread(target=run_job, args=(job_id, params, session.get('user')), daemon=True).start()
    return jsonify({'job_id': job_id})


def _owned(j):
    return j and j.get('owner') == session.get('user')


@app.route('/stop/<job_id>', methods=['POST'])
@require_auth
def stop(job_id):
    j = JOBS.get(job_id)
    if not _owned(j): return jsonify({'error': 'unknown job'}), 404
    if j['status'] in ('done', 'error', 'cancelled'):
        return jsonify({'ok': True, 'status': j['status']})
    j['cancel'] = True; j['status'] = 'cancelling'
    log(job_id, "STOP requested by user")
    audit('job_stop', details=f"job={job_id[:8]}")
    return jsonify({'ok': True, 'status': 'cancelling'})


@app.route('/status/<job_id>')
@require_auth
def status(job_id):
    j = JOBS.get(job_id)
    if not _owned(j): return jsonify({'error': 'unknown job'}), 404
    return jsonify({'status': j['status'], 'log': j['log'][-200:],
                    'has_zip': bool(j.get('zip')),
                    'files': j.get('files', [])})


@app.route('/file/<job_id>/<path:fname>')
@require_auth
def file(job_id, fname):
    j = JOBS.get(job_id)
    if not _owned(j): return 'not found', 404
    allowed = {f['name'] for f in j.get('files', [])}
    if fname not in allowed: return 'not found', 404
    full = os.path.join(j['dir'], fname)
    if not os.path.exists(full): return 'not found', 404
    audit('file_download', details=f"job={job_id[:8]} file={fname} size={os.path.getsize(full)}")
    return send_file(full, as_attachment=True, download_name=fname, mimetype='text/plain')


@app.route('/download/<job_id>')
@require_auth
def download(job_id):
    j = JOBS.get(job_id)
    if not _owned(j) or not j.get('zip'): return 'not ready', 404
    audit('zip_download', details=f"job={job_id[:8]} size={os.path.getsize(j['zip'])}")
    return send_file(j['zip'], as_attachment=True,
                     download_name=f'newsletters_{job_id[:8]}.zip')


@app.route('/healthz')
def healthz():
    return 'ok'


# --- ADMIN AUDIT --------------------------------------------------------
ADMIN_HTML = """<!doctype html><html><head><meta charset="utf-8"><title>Audit Log</title>
<style>body{margin:0;font-family:-apple-system,system-ui,sans-serif;background:#f4f5f7;color:#1f2937;padding:20px}
h1{margin:0 0 16px;font-size:20px;display:flex;justify-content:space-between;align-items:center}
.head a{font-size:12px;color:#6b7280;text-decoration:none;border:1px solid #e5e7eb;padding:6px 10px;border-radius:6px;background:#fff;margin-left:8px}
.bar{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap}
input,select,button{font:inherit;border:1px solid #e5e7eb;border-radius:6px;padding:6px 10px;background:#fff}
button{cursor:pointer;background:#1ba9c2;color:#fff;border:0;font-weight:600}
button.sec{background:#fff;color:#1f2937;border:1px solid #e5e7eb}
.card{background:#fff;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden;margin-bottom:16px}
.card-head{padding:10px 14px;background:#fafafa;border-bottom:1px solid #e5e7eb;font-weight:600;font-size:13px}
table{width:100%;border-collapse:collapse;font-size:12px}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid #f3f4f6;vertical-align:top}
th{background:#fafafa;font-weight:600;position:sticky;top:0}
tr:hover td{background:#f9fafb}
.ev{display:inline-block;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:600;background:#e5e7eb;color:#374151}
.ev.login_success{background:#dcfce7;color:#166534}
.ev.login_fail,.ev.login_locked{background:#fee2e2;color:#991b1b}
.ev.logout{background:#e0e7ff;color:#3730a3}
.ev.job_start{background:#dbeafe;color:#1d4ed8}
.ev.job_done{background:#dcfce7;color:#166534}
.ev.job_stop,.ev.job_cancelled{background:#fef3c7;color:#92400e}
.ev.job_error,.ev.mailbox_login_fail,.ev.mailbox_error{background:#fee2e2;color:#991b1b}
.ev.mailbox_login_ok{background:#ecfdf5;color:#065f46}
.ev.mailbox_done{background:#dbeafe;color:#1e40af}
.ev.file_download,.ev.zip_download{background:#fae8ff;color:#86198f}
.det{font-family:ui-monospace,monospace;font-size:11px;color:#6b7280;word-break:break-all;max-width:550px}
.ua{font-size:10px;color:#9ca3af;max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.muted{color:#9ca3af;font-size:11px}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:8px;padding:12px}
.stat{background:#f9fafb;border-radius:6px;padding:10px}
.stat-user{font-weight:700;font-size:13px;margin-bottom:6px}
.stat-row{display:flex;justify-content:space-between;font-size:11px;color:#6b7280;padding:1px 0}
.stat-row b{color:#1f2937}
</style></head><body>
<h1>🛡️ Audit Log <span><a href="/">← App</a><a href="/logout">Sign out</a></span></h1>

<div class="card">
  <div class="card-head">📊 Per-user activity</div>
  <div class="stats-grid" id="stats"></div>
</div>

<div class="bar">
  <input id="q" placeholder="filter (user / event / details / IP)" style="flex:1;min-width:200px">
  <select id="evf"><option value="">All events</option></select>
  <button class="sec" id="refresh">↻ Refresh</button>
  <a href="/admin/export" download style="text-decoration:none"><button class="sec">⬇ Export .jsonl</button></a>
</div>
<div class="card"><table><thead>
<tr><th>Time (UTC)</th><th>User</th><th>IP</th><th>Event</th><th>Details</th><th>UA</th></tr>
</thead><tbody id="rows"></tbody></table></div>
<div class="muted" id="count" style="margin-top:8px"></div>
<script>
let data = [];
async function load(){
  const r = await fetch('/admin/data');
  if(r.status===403){ document.body.innerHTML='<h1>403 Forbidden</h1>'; return; }
  data = await r.json();
  const evs = [...new Set(data.map(d=>d.event))].sort();
  const sel = document.getElementById('evf');
  const cur = sel.value;
  sel.innerHTML = '<option value="">All events</option>' + evs.map(e=>`<option ${e===cur?'selected':''}>${e}</option>`).join('');
  render();
  loadStats();
}
async function loadStats(){
  const r = await fetch('/admin/stats');
  if(!r.ok) return;
  const s = await r.json();
  document.getElementById('stats').innerHTML = Object.entries(s).filter(([u])=>u!=='-').map(([u,v])=>`
    <div class="stat">
      <div class="stat-user">${u}</div>
      <div class="stat-row"><span>Logins (ok/fail)</span><b>${v.logins} / ${v.fails}</b></div>
      <div class="stat-row"><span>Jobs run</span><b>${v.jobs}</b></div>
      <div class="stat-row"><span>Mailboxes extracted</span><b>${v.mailboxes}</b></div>
      <div class="stat-row"><span>Newsletters saved</span><b>${v.newsletters}</b></div>
      <div class="stat-row"><span>Downloads</span><b>${v.downloads}</b></div>
      <div class="stat-row"><span>Unique IPs</span><b>${v.ip_count}</b></div>
      <div class="stat-row"><span>Last seen</span><b>${v.last_seen||'-'}</b></div>
    </div>`).join('') || '<div class="muted" style="padding:12px">No activity yet</div>';
}
function render(){
  const q = document.getElementById('q').value.toLowerCase();
  const ev = document.getElementById('evf').value;
  const rows = data.filter(d => {
    if(ev && d.event!==ev) return false;
    if(!q) return true;
    return (d.user+' '+d.event+' '+d.details+' '+d.ip).toLowerCase().includes(q);
  }).slice().reverse();
  document.getElementById('rows').innerHTML = rows.map(d=>`
    <tr><td>${d.ts}</td><td><b>${d.user}</b></td><td>${d.ip}</td>
    <td><span class="ev ${d.event}">${d.event}</span></td>
    <td class="det">${(d.details||'').replace(/[<>]/g,'')}</td>
    <td class="ua" title="${(d.ua||'').replace(/"/g,'')}">${(d.ua||'').replace(/[<>]/g,'')}</td></tr>`).join('');
  document.getElementById('count').textContent = `${rows.length} of ${data.length} entries`;
}
document.getElementById('q').addEventListener('input', render);
document.getElementById('evf').addEventListener('change', render);
document.getElementById('refresh').addEventListener('click', load);
load();
setInterval(load, 8000);
</script></body></html>"""


@app.route('/admin')
@require_auth
@require_admin
def admin_page():
    return ADMIN_HTML


@app.route('/admin/data')
@require_auth
@require_admin
def admin_data():
    with _AUDIT_LOCK:
        return jsonify(list(AUDIT))


@app.route('/admin/stats')
@require_auth
@require_admin
def admin_stats():
    stats = {}  # user -> {logins, jobs, mailboxes, newsletters, downloads, last_seen}
    with _AUDIT_LOCK:
        for e in AUDIT:
            u = e['user']
            s = stats.setdefault(u, {'logins':0,'fails':0,'jobs':0,'mailboxes':0,
                                     'newsletters':0,'downloads':0,'last_seen':'',
                                     'ips':set()})
            s['last_seen'] = e['ts']
            if e['ip'] != '-' and e['ip'] != 'bg': s['ips'].add(e['ip'])
            ev = e['event']
            if ev == 'login_success': s['logins'] += 1
            elif ev == 'login_fail':  s['fails'] += 1
            elif ev == 'job_start':   s['jobs'] += 1
            elif ev == 'mailbox_done':
                s['mailboxes'] += 1
                m = re.search(r'saved=(\d+)', e['details'])
                if m: s['newsletters'] += int(m.group(1))
            elif ev in ('file_download', 'zip_download'): s['downloads'] += 1
    # serialize sets
    for u, s in stats.items():
        s['ips'] = sorted(s['ips'])
        s['ip_count'] = len(s['ips'])
    return jsonify(stats)


@app.route('/admin/export')
@require_auth
@require_admin
def admin_export():
    with _AUDIT_LOCK:
        body = '\n'.join(json.dumps(e, ensure_ascii=False) for e in AUDIT)
    from flask import Response
    return Response(body, mimetype='application/x-ndjson',
                    headers={'Content-Disposition': 'attachment; filename=audit.jsonl'})


@app.route('/whoami')
@require_auth
def whoami():
    return jsonify({'user': session.get('user'), 'is_admin': session.get('user') in ADMINS})
# ------------------------------------------------------------------------


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    if 'changeme' in USERS.values():
        print("⚠  Default password 'changeme' is in use. Set APP_USERS env var.")
    print(f"Users: {list(USERS.keys())}")
    print(f"Open http://localhost:{port}")
    app.run(host='0.0.0.0', port=port, debug=False)
