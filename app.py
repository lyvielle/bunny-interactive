import os, re, time, json, hashlib, secrets, mimetypes, base64, threading, zipfile, unicodedata
from urllib.parse import quote, unquote
import requests
from cryptography.fernet import Fernet, InvalidToken
from flask import (Flask, request, session, redirect, flash, get_flashed_messages,
                   render_template_string, Response, stream_with_context)

# ---- config ----
API = os.environ.get("BUNNY_API", "https://cutebunny.io").rstrip("/")
H_REGISTER = "Register-Content"
H_LOGIN = "Login-Content"
H_FILENAME = "File-Name"
H_RENAME = "Rename-Content"
H_PUBLISH = "Publish-Content"
# PublishInfoContent maps its AccessEndTime property to the JSON name "accessStartTime"
END_KEY = "accessStartTime"
HWID_SALT = os.environ.get("HWID_SALT", "change-me")
VERIFY = os.environ.get("VERIFY_TLS", "1") == "1"

def hwid(email):  # 64 alphanumeric chars, stable per email
    return hashlib.sha256((HWID_SALT + email.lower()).encode()).hexdigest().upper()

app = Flask(__name__)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # POST forms (bulk download) must not carry the session cross-site
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
SESS = {}  # sid -> {token, ext}


class AuthError(Exception):
    pass


# The server puts the stored file name into response headers, which Kestrel only allows as ASCII;
# files with other characters (emoji, Cyrillic, ...) can't be downloaded. Keep new names ASCII.
DOWNLOAD_PATH = os.environ.get("DOWNLOAD_PATH", "/download")
DOWNLOAD_ENABLED = os.environ.get("DOWNLOAD_ENABLED", "0") == "1"


def local_dl():
    """Dev feature: only offered when DOWNLOAD_ENABLED=1 and DOWNLOAD_PATH exists and is writable."""
    return DOWNLOAD_ENABLED and os.path.isdir(DOWNLOAD_PATH) and os.access(DOWNLOAD_PATH, os.W_OK)


STRICT_NAMES = os.environ.get("STRICT_NAMES", "1") == "1"
_CYR = dict(zip("абвгдеёжзийклмнопрстуфхцчшщъыьэюя",
                ["a", "b", "v", "g", "d", "e", "yo", "zh", "z", "i", "y", "k", "l", "m", "n", "o", "p", "r", "s", "t",
                 "u", "f", "kh", "ts", "ch", "sh", "shch", "", "y", "", "e", "yu", "ya"]))
_CYR.update({"і": "i", "ї": "yi", "є": "ye", "ґ": "g"})


def safe_name(name):
    out = []
    for ch in name:
        if ch.isascii():
            out.append(ch)
        elif ch.lower() in _CYR:
            t = _CYR[ch.lower()]
            out.append(t.capitalize() if ch != ch.lower() else t)
        else:  # strip accents (é -> e); emoji and other symbols are dropped
            out.append("".join(c for c in unicodedata.normalize("NFKD", ch) if c.isascii()))
    s = re.sub(r"\s+\.", ".", re.sub(r"\s+", " ", "".join(out))).strip()  # no space left before the extension
    return "file" + s if not s or s.startswith(".") else s


def reason(r):
    try:
        try:
            j = r.json()
            if isinstance(j, dict):
                return next((str(v) for k, v in j.items() if k.lower() == "reason"), str(j))
        except ValueError:
            pass
        return r.text or f"HTTP {r.status_code}"
    except Exception:  # truncated body, e.g. the server aborted the response midway
        r.close()
        return f"Server error (HTTP {r.status_code})"


def reason_for(r, name):
    if r.status_code == 500 and not name.isascii():  # server puts the raw name into response headers
        r.close()
        return ("The server could not send this file, probably because of special characters (e.g. emoji) "
                "in its name. Renaming it to plain ASCII should fix it.")
    return reason(r)


def start_session(r):
    try:
        token = r.json().get("session")
    except ValueError:
        token = None
    if not token:
        raise RuntimeError("No session in response: " + r.text[:200])
    sid = secrets.token_hex(16)
    SESS[sid] = {"token": token, "ext": time.time()}
    session["sid"] = sid


def remember(resp, body):  # license + email only; the password stays with the browser's password manager
    for k, v in (("lic", body["license"]), ("em", body["email"])):
        resp.set_cookie(k, v, max_age=365 * 86400, httponly=True, samesite="Lax")
    return resp


# ---- "stay signed in": credentials kept encrypted on the server, looked up via a random cookie token ----
DATA_DIR = os.environ.get("DATA_DIR", "/data")
STAY_DAYS = 90
_store_lock, _login_lock = threading.Lock(), threading.Lock()
_fernet = None
AUTO = {}  # sha256(rt token) -> sid of the session auto-login created (so parallel requests share one login)


def fernet():
    global _fernet
    if _fernet is None:
        key = os.environ.get("REMEMBER_KEY", "").encode()
        if not key:
            os.makedirs(DATA_DIR, exist_ok=True)
            path = os.path.join(DATA_DIR, "remember.key")
            if not os.path.exists(path):
                with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as f:
                    f.write(Fernet.generate_key())
            key = open(path, "rb").read()
        _fernet = Fernet(key)
    return _fernet


def _h(tok):
    return hashlib.sha256(tok.encode()).hexdigest()


def _load():
    try:
        with open(os.path.join(DATA_DIR, "remember.json")) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _save(d):
    os.makedirs(DATA_DIR, exist_ok=True)
    path = os.path.join(DATA_DIR, "remember.json")
    with open(path + ".tmp", "w") as f:
        json.dump(d, f)
    os.replace(path + ".tmp", path)


def stay_save(creds):
    tok, now = secrets.token_urlsafe(32), time.time()
    with _store_lock:
        d = {k: v for k, v in _load().items() if v["exp"] > now}
        d[_h(tok)] = {"exp": now + STAY_DAYS * 86400, "c": fernet().encrypt(json.dumps(creds).encode()).decode()}
        _save(d)
    return tok


def stay_get(tok):
    entry = _load().get(_h(tok)) if tok else None
    if not entry or entry["exp"] < time.time():
        return None
    try:
        return json.loads(fernet().decrypt(entry["c"].encode()))
    except InvalidToken:
        return None


def stay_forget(tok):
    if not tok:
        return
    AUTO.pop(_h(tok), None)
    with _store_lock:
        d = _load()
        if d.pop(_h(tok), None):
            _save(d)


def auto_login(bad_sid=None):
    """Log in again with the stored credentials of this browser's 'rt' cookie; None if not possible."""
    tok = request.cookies.get("rt")
    creds = stay_get(tok)
    if not creds:
        return None
    h = _h(tok)
    with _login_lock:
        sid = AUTO.get(h)
        if sid in SESS and sid != bad_sid:  # another request already refreshed the session
            session["sid"] = sid
            return SESS[sid]
        SESS.pop(bad_sid, None)
        body = {"license": creds["license"], "hwid": hwid(creds["email"]),
                "email": creds["email"], "password": creds["password"]}
        try:
            r = requests.get(f"{API}/api/license/login", headers={H_LOGIN: json.dumps(body)},
                             verify=VERIFY, timeout=30)
            if not r.ok:
                return None
            start_session(r)
        except Exception:
            return None
        AUTO[h] = session["sid"]
        return SESS[session["sid"]]


def drop():
    SESS.pop(session.pop("sid", None), None)


def api(method, path, **kw):
    sid = session.get("sid")
    s = SESS.get(sid) or auto_login(sid)
    if not s:
        raise AuthError
    if time.time() - s["ext"] > 20 * 60:
        e = requests.post(f"{API}/api/license/extend", headers={"Auth-Token": s["token"]}, timeout=30, verify=VERIFY)
        if e.ok:
            s["ext"] = time.time()
        else:
            drop()
            s = auto_login(sid)
            if not s:
                raise AuthError
    headers = kw.pop("headers", {})
    # requests sends str header values as latin-1; send non-ASCII (e.g. Cyrillic) names as UTF-8 bytes
    headers = {k: v.encode("utf-8") if isinstance(v, str) and not v.isascii() else v for k, v in headers.items()}
    timeout = kw.pop("timeout", 30)
    for attempt in (0, 1):
        r = requests.request(method, f"{API}{path}", headers={"Auth-Token": s["token"], **headers},
                             timeout=timeout, verify=VERIFY, **kw)
        if r.status_code not in (401, 403):
            return r
        cur = session.get("sid")
        drop()
        if attempt or "data" in kw:  # a consumed upload body can't be replayed
            raise AuthError
        s = auto_login(cur)
        if not s:
            raise AuthError


def human(n):
    if not isinstance(n, (int, float)):
        return ""
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {u}" if u != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} PB"


KINDS = {
    "video": "mkv mp4 avi mov webm m4v wmv ogv",
    "audio": "mp3 flac wav ogg m4a aac opus",
    "image": "jpg jpeg png gif webp bmp svg avif",
    "archive": "zip rar 7z tar gz zst xz iso",
    "doc": "pdf txt doc docx md odt epub",
    "code": "py cs js ts json html css yaml yml sh xml",
    "app": "exe msi deb rpm appimage",
}
ICONS = {
    "file": '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/>',
    "video": '<rect x="2" y="4" width="20" height="16" rx="2"/><path d="m10 9 5 3-5 3z"/>',
    "audio": '<path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/>',
    "image": '<rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="9" cy="9" r="2"/><path d="m21 15-3.1-3.1a2 2 0 0 0-2.8 0L6 21"/>',
    "archive": '<path d="M21 8v13H3V8"/><path d="M1 3h22v5H1z"/><path d="M10 12h4"/>',
    "doc": '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M16 13H8M16 17H8M10 9H8"/>',
    "code": '<path d="m16 18 6-6-6-6"/><path d="m8 6-6 6 6 6"/>',
    "app": '<rect x="4" y="4" width="16" height="16" rx="2"/><path d="M9 9h6v6H9z"/>',
    "bunny": '<ellipse cx="8.6" cy="6" rx="2.2" ry="4.2"/><ellipse cx="15.4" cy="6" rx="2.2" ry="4.2"/><ellipse cx="12" cy="15" rx="6.5" ry="5.5"/><path d="M9.5 14.5h.01M14.5 14.5h.01"/><path d="M10.8 17.4q1.2 1 2.4 0"/>',
    "trash": '<path d="M3 6h18"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><path d="M10 11v6M14 11v6"/>',
    "pencil": '<path d="M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z"/><path d="m15 5 4 4"/>',
    "eye": '<path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/>',
    "x": '<path d="M18 6 6 18M6 6l12 12"/>',
    "list": '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
    "grid": '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/>',
    "globe": '<circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
    "lock": '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
    "copy": '<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
    "dots": '<circle cx="12" cy="5" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="12" cy="19" r="1"/>',
    "prev": '<path d="m15 18-6-6 6-6"/>',
    "next": '<path d="m9 18 6-6-6-6"/>',
    "select": '<path d="m9 11 3 3L22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>',
    "warn": '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4M12 17h.01"/>',
    "filter": '<path d="M21 4h-7M10 4H3M21 12h-9M8 12H3M21 20h-5M12 20H3M14 2v4M8 10v4M16 18v4"/>',
    "search": '<circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/>',
    "upload": '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m17 8-5-5-5 5M12 3v12"/>',
    "hdd": '<path d="M22 12H2"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/><path d="M6 16h.01M10 16h.01"/>',
    "download": '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m7 10 5 5 5-5M12 15V3"/>',
}


app.jinja_env.globals["logo"] = ICONS["bunny"]


PREVIEW = {"video": "mp4 webm mkv m4v mov ogv", "audio": "mp3 flac wav ogg m4a aac opus",
           "image": "jpg jpeg png gif webp bmp svg avif"}


GALLERY_MAX = 10 * 1024 * 1024  # gallery tiles: viewable images/videos below this size


def preview(name):
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    return next((k for k, v in PREVIEW.items() if ext in v.split()), "")


def kind(name):
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    return next((k for k, v in KINDS.items() if ext in v.split()), "file")


LAYOUT = """<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Bunny Interactive</title><link rel=icon href="/favicon.ico?v={{iv}}" sizes=any><link rel=icon type=image/png sizes=192x192 href="/icon-192.png?v={{iv}}"><link rel=manifest href="/manifest.webmanifest?v={{iv}}"><meta name=theme-color content="#09090b"><link rel=apple-touch-icon href="/apple-touch-icon.png?v={{iv}}"><meta name=apple-mobile-web-app-capable content=yes><style>
:root{--bg:#09090b;--card:#111113;--line:#1f1f23;--text:#e4e4e7;--mute:#71717a;--acc:#8b5cf6}
*{box-sizing:border-box}[hidden]{display:none!important}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 Inter,system-ui,-apple-system,sans-serif}
a{color:var(--text)}svg{width:18px;height:18px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round;flex:none}
.brand{display:flex;align-items:center;gap:10px;font-weight:600;font-size:17px}
.dot{width:30px;height:30px;border-radius:9px;display:grid;place-items:center;color:#fff;background:linear-gradient(135deg,var(--acc),#38bdf8)}.dot svg{width:20px;height:20px;stroke-width:2}
input{background:#0c0c0e;color:var(--text);border:1px solid var(--line);border-radius:10px;padding:11px 14px;font:inherit;outline:0;width:100%;transition:.15s}
input:focus{border-color:var(--acc);box-shadow:0 0 0 3px #8b5cf622}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;background:var(--acc);color:#fff;border:0;border-radius:10px;padding:10px 16px;font:inherit;font-weight:500;cursor:pointer;text-decoration:none;transition:.15s}
.btn:hover{filter:brightness(1.15)}.btn.ghost{background:transparent;color:var(--text);border:1px solid var(--line)}
.btn.ghost:hover{border-color:#3f3f46;background:#18181b;filter:none}.btn.sm{padding:7px 10px}
.chk{display:flex;align-items:center;gap:8px;color:var(--mute);font-size:14px;cursor:pointer}
.chk input{width:auto;padding:0;accent-color:var(--acc)}
.msgs{position:fixed;top:16px;right:16px;display:grid;gap:8px;z-index:50}
.alert{background:#2a1215;border:1px solid #5b1f27;color:#fca5a5;padding:10px 14px;border-radius:10px;max-width:360px}
body.auth{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px;
background:radial-gradient(600px 300px at 50% -10%,#8b5cf633,transparent),var(--bg)}
.card{width:100%;max-width:360px;background:var(--card);border:1px solid var(--line);border-radius:16px;padding:32px}
.card h1{font-size:22px;margin:24px 0 4px}.card .sub{color:var(--mute);margin:0 0 20px}
form{display:grid;gap:12px}.alt{text-align:center;color:var(--mute);margin:20px 0 0}
.bar{display:flex;justify-content:space-between;align-items:center;max-width:880px;margin:0 auto;padding:20px 16px}
main{max-width:880px;margin:0 auto;padding:0 16px 60px}
.tools{display:flex;gap:10px}.search{position:relative;flex:1}.search svg{position:absolute;left:13px;top:50%;margin-top:-9px;color:var(--mute)}
.search input{padding-left:40px}
.info-line{display:flex;align-items:center;gap:12px;color:var(--mute);font-size:13px;margin:14px 2px 8px}
.filters{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}
.sel{display:flex;align-items:center;gap:8px;background:#0c0c0e;border:1px solid var(--line);border-radius:10px;padding:0 10px 0 12px;color:var(--mute);font-size:13px;transition:.15s}
.sel:hover,.sel:focus-within{border-color:#3f3f46}
.sel select{appearance:none;background:transparent;border:0;color:var(--text);font:inherit;font-size:13px;padding:8px 18px 8px 0;outline:0;cursor:pointer;
background:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%2371717a' stroke-width='2.5' stroke-linecap='round'%3E%3Cpath d='m6 9 6 6 6-6'/%3E%3C/svg%3E") no-repeat right center}
.sel option{background:#111113}
.list{border:1px solid var(--line);border-radius:14px;background:var(--card);overflow:hidden}
.row{display:flex;align-items:center;gap:14px;padding:12px 16px;border-bottom:1px solid var(--line);transition:.12s}
.row:last-child{border:0}.row:hover{background:#16161a}
.ico{width:38px;height:38px;border-radius:10px;display:grid;place-items:center;color:var(--c,#a1a1aa);background:color-mix(in srgb,var(--c,#a1a1aa) 14%,transparent)}
.k-video{--c:#f472b6}.k-audio{--c:#34d399}.k-image{--c:#38bdf8}.k-archive{--c:#fbbf24}.k-doc{--c:#a78bfa}.k-code{--c:#fb923c}.k-app{--c:#f87171}
.info{flex:1;min-width:0}.nm{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.sub2{color:var(--mute);font-size:13px}
.btn.outline{background:#0c0c0e;border:1px solid var(--acc);color:#c4b5fd}.btn.outline:hover{background:#8b5cf61f;filter:none}
.ren{padding:6px 10px;min-width:0}#pv,#pb{position:fixed;inset:0;background:#000d;display:grid;place-items:center;z-index:45;padding:16px;backdrop-filter:blur(6px)}
.pvbox{background:var(--card);border:1px solid var(--line);border-radius:14px;max-width:min(94vw,1100px);min-width:min(94vw,360px);overflow:hidden}
.pvbar{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:10px 14px;border-bottom:1px solid var(--line)}
.pvbar span{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
#pvm{display:grid;place-items:center;background:#000;min-height:80px}
#pvm video,#pvm img{display:block;max-width:100%;max-height:calc(100vh - 200px)}#pvm audio{width:min(90vw,480px);margin:24px}
.row.pv .ico,.row.pv .nm{cursor:pointer}.row.pv .nm:hover{text-decoration:underline}
.rt{display:flex;gap:8px;margin-left:auto}
.fbtn{display:none!important}.fbtn #fbadge{background:var(--acc);color:#fff;border-radius:9px;font-size:11px;padding:0 6px;line-height:16px}
.sel.tog{padding:8px 10px 8px 12px;cursor:pointer;user-select:none}
input.sw{appearance:none;-webkit-appearance:none;width:30px;height:18px;padding:0;margin:0;border-radius:9px;background:#27272a;border:1px solid #3f3f46;position:relative;cursor:pointer;transition:.15s;flex:none}
input.sw::after{content:'';position:absolute;top:2px;left:2px;width:12px;height:12px;border-radius:50%;background:#a1a1aa;transition:.15s}
input.sw:checked{background:var(--acc);border-color:var(--acc)}input.sw:checked::after{left:14px;background:#fff}
.seg{display:flex;border:1px solid var(--line);border-radius:10px;overflow:hidden}
.seg button{display:flex;background:transparent;border:0;color:var(--mute);padding:8px 11px;cursor:pointer;transition:.15s}
.seg button:hover{color:var(--text)}.seg button.on{background:#18181b;color:var(--text)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px}
.tile{position:relative;aspect-ratio:1;border-radius:12px;overflow:hidden;background:var(--card);border:1px solid var(--line);cursor:pointer;transition:.15s}
.tile:hover{border-color:#3f3f46}
.tile .ph{position:absolute;inset:0;display:grid;place-items:center;color:var(--c,#52525b)}
.tile .ph svg{width:34px;height:34px;opacity:.45}.tile.bad .ph svg{opacity:.9}
.tile img,.tile video{position:absolute;inset:0;width:100%;height:100%;object-fit:cover;transition:opacity .25s}
.tile .cap{position:absolute;left:0;right:0;bottom:0;padding:22px 10px 8px;font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;background:linear-gradient(transparent,#000c);opacity:0;transition:.15s}
.tile:hover .cap{opacity:1}
.tile[data-pv=video]::after{content:'';position:absolute;right:8px;top:8px;width:24px;height:24px;border-radius:50%;background:#000a url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='white'%3E%3Cpath d='M8 5v14l11-7z'/%3E%3C/svg%3E") center/12px no-repeat}
.act{display:flex;gap:6px}.btn.danger:hover{color:#f87171;border-color:#5b1f27;background:#2a121566}
.empty{text-align:center;color:var(--mute);padding:40px 0}
#prog{position:fixed;top:0;left:0;right:0;height:3px}#bar{display:block;height:100%;width:0;background:linear-gradient(90deg,var(--acc),#38bdf8);transition:width .1s}
#drop{position:fixed;inset:0;background:#000c;display:none;place-items:center;font-size:20px;border:2px dashed var(--acc);z-index:40;pointer-events:none}
body.drag #drop{display:grid}
.pbadge{display:inline-flex;align-items:center;gap:4px;color:#c4b5fd;background:#8b5cf61f;border-radius:6px;padding:2px 6px;cursor:pointer;flex:none}
.pbadge svg{width:13px;height:13px}
.warnb{display:inline-flex;align-items:center;color:#fbbf24;background:#fbbf2420;border-radius:6px;padding:2px 6px;cursor:pointer;flex:none}.warnb svg{width:13px;height:13px}.pbadge .lk{display:none}.pbadge.lock .lk{display:block}
.tile .pbadge{position:absolute;left:8px;top:8px;z-index:2;background:#000a;padding:4px 6px}
.btn.ghost.on{color:#c4b5fd;border-color:#4c2f9e}.btn.ok{color:#34d399;border-color:#14532d}
.nmrow{display:flex;align-items:center;gap:8px;min-width:0}.nmrow .nm{min-width:0}.nmrow .ren{flex:1}
.dlg{width:min(94vw,440px);min-width:0}.pbody{padding:16px;display:grid;gap:14px}
.lbl{font-size:13px;color:var(--mute);margin-bottom:6px}.linkrow{display:flex;gap:8px}.linkrow input{font-size:13px}
.hint{color:var(--mute);font-size:12px;margin-top:6px}.sub{margin:-4px 0 0 26px}
.pvact{display:flex;gap:8px;padding:10px 12px;border-top:1px solid var(--line)}.pvact .btn{flex:1;gap:6px}
.pvbar .ren{flex:1;min-width:0}
@media(max-width:480px){.pvact .btn span{display:none}.pvact .btn{padding:9px 6px}}
.pager{display:flex;align-items:center;justify-content:center;gap:12px;margin:18px 0 4px;flex-wrap:wrap}
.pager .btn:disabled{opacity:.35;cursor:default;filter:none}#pinfo{color:var(--mute);font-size:14px;min-width:90px;text-align:center}
.sall{display:flex;align-items:center;gap:10px}
input.rsel,#sa{display:none;width:18px;height:18px;flex:none;margin:0;padding:0;position:relative;appearance:none;-webkit-appearance:none;
background:#0c0c0e;border:1px solid #3f3f46;border-radius:5px;cursor:pointer;transition:.15s}
input.rsel:hover,#sa:hover{border-color:var(--acc)}
input.rsel:checked,#sa:checked{background:var(--acc);border-color:var(--acc)}
input.rsel:checked::after,#sa:checked::after{content:'';position:absolute;left:5px;top:2px;width:4px;height:8px;
border:solid #fff;border-width:0 2px 2px 0;transform:rotate(45deg)}
#sa:indeterminate{background:var(--acc);border-color:var(--acc)}
#sa:indeterminate::after{content:'';position:absolute;left:4px;top:8px;width:8px;height:2px;background:#fff;border-radius:1px}
input.rsel:focus-visible,#sa:focus-visible{outline:2px solid var(--acc);outline-offset:2px}
body.selmode input.rsel,body.selmode #sa{display:block}
.row:has(.rsel:checked){background:#8b5cf614}
.bulk{position:fixed;left:50%;bottom:calc(16px + env(safe-area-inset-bottom));transform:translateX(-50%);z-index:44;display:flex;align-items:center;gap:14px;background:var(--card);border:1px solid var(--line);border-radius:14px;padding:10px 12px 10px 16px;box-shadow:0 12px 40px #000c;width:max-content;max-width:calc(100vw - 24px)}
.bact{display:flex;gap:8px}body.bulkon main{padding-bottom:96px}
@media(max-width:480px){.bulk{gap:8px;padding-left:12px}.bact .btn span{display:none}}
.sl{display:grid;gap:14px;margin:18px 0}.si{display:grid;gap:6px}.si progress{width:100%;height:6px;accent-color:var(--acc)}
.ss{color:var(--mute);font-size:12px}.sact{display:flex;gap:8px;justify-content:flex-end}
.pbfoot{display:flex;justify-content:flex-end;gap:8px;margin-top:4px}input[type=datetime-local]{color-scheme:dark}
.more{display:none!important}
.menu{position:fixed;z-index:48;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:6px;min-width:190px;box-shadow:0 12px 40px #000c}
.mi{display:flex;align-items:center;gap:10px;width:100%;background:transparent;border:0;color:var(--text);padding:10px 12px;border-radius:8px;font:inherit;cursor:pointer;text-align:left}
.mi:hover{background:#18181b}.mi.danger{color:#f87171}
@media(max-width:640px){
body{font-size:14px}.bar,main{padding-left:12px;padding-right:12px}
.row{padding:10px 12px;gap:10px}.ico{width:34px;height:34px}
.act>[data-act]{display:none!important}.act>.more{display:inline-flex!important}
.sub2{font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.tools{gap:8px}.btn.outline{padding:10px 12px}.btn.outline .lbl{display:none}
.fbtn{display:inline-flex!important;padding:10px 12px;gap:6px}.fbtn.on{color:#c4b5fd;border-color:#4c2f9e}
.filters{display:none;margin-top:8px;padding:10px;background:var(--card);border:1px solid var(--line);border-radius:12px;gap:8px;grid-template-columns:1fr 1fr}
.filters.open{display:grid}.filters .sel{width:100%;justify-content:space-between;min-width:0}.filters .sel select{max-width:62%;text-overflow:ellipsis}
.filters .sel:first-child,.filters .tog{grid-column:1/-1}.filters #rs{grid-column:1/-1;justify-self:end}
.info-line .rt{gap:6px}.rt #selbtn:not(.on) span{display:none}
.grid{grid-template-columns:repeat(auto-fill,minmax(105px,1fr));gap:8px}.tile .cap{opacity:1;padding-top:16px}
.msgs{left:12px;right:12px}.alert{max-width:none}
}
</style>
<body class="{{cls}}"><div class=msgs>{% for m in msgs %}<div class=alert>{{m}}</div>{% endfor %}</div>
{{body|safe}}<script>setTimeout(()=>document.querySelector('.msgs').remove(),7000);if('serviceWorker' in navigator)navigator.serviceWorker.register('/sw.js')</script>"""


def page(tpl, cls="", **ctx):
    return render_template_string(LAYOUT, cls=cls, msgs=get_flashed_messages(),
                                  body=render_template_string(tpl, **ctx))


LOGIN = """<div class=card><div class=brand><span class=dot><svg viewBox="0 0 24 24">{{logo|safe}}</svg></span>Bunny Interactive</div>
<h1>Welcome back</h1><p class=sub>Sign in to your files</p><form method=post>
<input type=hidden name=next value="{{nxt}}">
<input name=license placeholder="License ID" value="{{lic}}" required>
<input name=email type=email placeholder=Email value="{{em}}" autocomplete=username required>
<input name=password type=password placeholder=Password autocomplete=current-password {% if em %}autofocus{% endif %} required>
<label class=chk><input type=checkbox name=stay>Stay signed in</label>
<button class=btn>Sign in</button></form><p class=alt>No account? <a href=/register>Register</a></p></div>"""

REGISTER = """<div class=card><div class=brand><span class=dot><svg viewBox="0 0 24 24">{{logo|safe}}</svg></span>Bunny Interactive</div>
<h1>Create account</h1><p class=sub>Activate your license</p><form method=post>
<input name=license placeholder="License ID" required>
<input name=username placeholder=Username minlength=3 maxlength=15 autocomplete=username required>
<input name=email type=email placeholder=Email autocomplete=email required>
<input name=password type=password placeholder=Password minlength=5 maxlength=120 autocomplete=new-password required>
<button class=btn>Register</button></form><p class=alt>Have an account? <a href=/login>Sign in</a></p></div>"""

FILES = """<div id=prog><i id=bar></i></div>
<header class=bar><div class=brand><span class=dot><svg viewBox="0 0 24 24">{{logo|safe}}</svg></span>Bunny Interactive</div><a class="btn ghost sm" href=/logout>Logout</a></header>
<main>
<div class=tools>
<label class=search><svg viewBox="0 0 24 24">{{icons.search|safe}}</svg><input id=q placeholder="Search files   ( / )" autocomplete=off></label>
<button class="btn ghost fbtn" id=fbtn title=Filters><svg viewBox="0 0 24 24">{{icons.filter|safe}}</svg><span id=fbadge hidden></span></button>
<button class="btn outline" title=Upload onclick="f.click()"><svg viewBox="0 0 24 24">{{icons.upload|safe}}</svg><span class=lbl>Upload</span></button>
<input type=file id=f multiple hidden></div>
<div class=filters id=filters>
<label class=sel><span>Sort</span><select id=so><option value=new>Newest</option><option value=old>Oldest</option><option value=az>Name A–Z</option><option value=za>Name Z–A</option><option value=big>Largest</option><option value=small>Smallest</option></select></label>
<label class=sel><span>Uploaded</span><select id=dt><option value=0>Any time</option><option value=1>Last 24 hours</option><option value=7>Last 7 days</option><option value=30>Last 30 days</option><option value=365>Last year</option></select></label>
<label class=sel><span>Size</span><select id=sz><option value="">Any size</option><option value=0-10485760>&lt; 10 MB</option><option value=10485760-1073741824>10 MB – 1 GB</option><option value=1073741824-10737418240>1 – 10 GB</option><option value=10737418240-1e18>&gt; 10 GB</option></select></label>
<label class="sel tog"><span>Show .bunnyc files</span><input type=checkbox id=hid class=sw></label>
{% if local_dl() %}<label class="sel tog" title="Downloads are saved on the server instead of this device"><span>Download to server</span><input type=checkbox id=ldt class=sw></label>{% endif %}
<button class="btn ghost sm" id=rs hidden>Reset</button></div>
<div class=info-line><span class=sall><input type=checkbox id=sa title="Select all"><span id=cnt>{{files|length}} files</span></span><span id=st></span>
<div class=rt><button class="btn ghost sm" id=selbtn title="Select files"><svg viewBox="0 0 24 24">{{icons.select|safe}}</svg><span id=sbl>Select</span></button>
<div class=seg><button id=vl title=List class=on><svg viewBox="0 0 24 24">{{icons.list|safe}}</svg></button><button id=vg title=Grid><svg viewBox="0 0 24 24">{{icons.grid|safe}}</svg></button></div></div></div>
<div class=list>{% for f in files %}
<div class="row{% if f.pv %} pv{% endif %}" data-i="{{loop.index0}}" data-fn="{{f.name}}" data-pv="{{f.pv}}" data-name="{{f.name|lower}}" data-size="{{f.bytes}}" data-time="{{f.time}}"{% if f.hid %} data-hid=1{% endif %}{% if f.bad %} data-bad=1 data-safe="{{f.safe}}"{% endif %}{% if f.pub %} data-pub='{{f.pub|tojson}}'{% endif %}><input type=checkbox class=rsel onchange="updateBulk()" aria-label="Select file">
<div class="ico k-{{f.kind}}"><svg viewBox="0 0 24 24">{{icons[f.kind]|safe}}</svg></div>
<div class=info><div class=nmrow><div class=nm title="{{f.name}}">{{f.name}}</div><span class="pbadge{% if f.pub and f.pub.pw %} lock{% endif %}"{% if not f.pub %} hidden{% endif %} title="Published - click to manage" onclick="pubOpen(this.closest('.row'))"><svg viewBox="0 0 24 24">{{icons.globe|safe}}</svg><svg class=lk viewBox="0 0 24 24">{{icons.lock|safe}}</svg></span>{% if f.bad %}<span class=warnb title="The server cannot send files whose names contain special characters or emoji, so this file cannot be downloaded or previewed. Click to rename it." onclick="ren(this.closest('.row').querySelector('[data-act=ren]'))"><svg viewBox="0 0 24 24">{{icons.warn|safe}}</svg></span>{% endif %}</div>
<div class=sub2>{{f.size}}{% if f.by %} · {{f.by}}{% endif %}{% if f.when %} · {{f.when}}{% endif %}</div></div>
<div class=act>{% if f.pv %}<button class="btn ghost sm" data-act=pv title=Preview onclick="pvRow(this)"><svg viewBox="0 0 24 24">{{icons.eye|safe}}</svg></button>{% endif %}
<a class="btn ghost sm" data-act=dl title=Download href="/download?name={{f.name|urlencode}}"><svg viewBox="0 0 24 24">{{icons.download|safe}}</svg></a>
<button class="btn ghost sm{% if f.pub %} on{% endif %}" data-act=pub title="{% if f.pub %}Manage publishing{% else %}Publish{% endif %}" onclick="pubOpen(this.closest('.row'))"><svg viewBox="0 0 24 24">{{icons.globe|safe}}</svg></button>
<button class="btn ghost sm" data-act=ren title=Rename data-n="{{f.name}}" onclick="ren(this)"><svg viewBox="0 0 24 24">{{icons.pencil|safe}}</svg></button>
<button class="btn ghost sm danger" data-act=del title=Delete data-n="{{f.name}}" onclick="del(this)"><svg viewBox="0 0 24 24">{{icons.trash|safe}}</svg></button>
<button class="btn ghost sm more" title=More onclick="openMenu(this)"><svg viewBox="0 0 24 24">{{icons.dots|safe}}</svg></button></div></div>{% endfor %}
<p id=empty class=empty {% if files %}hidden{% endif %}>No files</p></div>
<div id=grid class=grid hidden>{% for f in files %}{% if f.gal %}
<div class=tile data-i="{{loop.index0}}" data-fn="{{f.name}}" data-pv="{{f.pv}}" data-time="{{f.time}}"{% if f.bad %} data-bad=1{% endif %} title="{{f.name}}"><span class="pbadge{% if f.pub and f.pub.pw %} lock{% endif %}"{% if not f.pub %} hidden{% endif %} title="Published - click to manage" onclick="pubOpen(rows[this.closest('.tile').dataset.i])"><svg viewBox="0 0 24 24">{{icons.globe|safe}}</svg><svg class=lk viewBox="0 0 24 24">{{icons.lock|safe}}</svg></span><div class="ph k-{{f.kind}}"><svg viewBox="0 0 24 24">{{icons[f.kind]|safe}}</svg></div><div class=cap>{{f.name}}</div></div>{% endif %}{% endfor %}</div>
<p id=gempty class=empty hidden>No viewable files under 10 MB</p>
<div id=pager class=pager hidden><button class="btn ghost sm" id=pp title=Previous><svg viewBox="0 0 24 24">{{icons.prev|safe}}</svg></button><span id=pinfo></span><button class="btn ghost sm" id=pn title=Next><svg viewBox="0 0 24 24">{{icons.next|safe}}</svg></button><label class=sel><span>Per page</span><select id=ps><option>24</option><option>48</option><option>96</option></select></label></div>
</main>
<div id=pv hidden><div class=pvbox><div class=pvbar><span id=pvt></span><button class="btn ghost sm" id=pvx title=Close><svg viewBox="0 0 24 24">{{icons.x|safe}}</svg></button></div><div id=pvm></div>
<div class=pvact>
<a class="btn ghost sm" id=pvdl title=Download><svg viewBox="0 0 24 24">{{icons.download|safe}}</svg><span>Download</span></a>
<button class="btn ghost sm" id=pvpb title=Publish><svg viewBox="0 0 24 24">{{icons.globe|safe}}</svg><span id=pvpbl>Publish</span></button>
<button class="btn ghost sm" id=pvrn title=Rename><svg viewBox="0 0 24 24">{{icons.pencil|safe}}</svg><span>Rename</span></button>
<button class="btn ghost sm danger" id=pvdel title=Delete><svg viewBox="0 0 24 24">{{icons.trash|safe}}</svg><span>Delete</span></button></div>
</div></div>
<div id=pb hidden><div class="pvbox dlg"><div class=pvbar><span id=pbt></span><button class="btn ghost sm" id=pbx title=Close><svg viewBox="0 0 24 24">{{icons.x|safe}}</svg></button></div>
<div class=pbody>
<div id=pblink hidden><div class=lbl>Public link</div><div class=linkrow><input id=pburl readonly><button class="btn ghost" id=pbcp title=Copy onclick="pubCopy()"><svg viewBox="0 0 24 24">{{icons.copy|safe}}</svg></button></div><div class=hint id=pbinfo></div></div>
<label class=chk><input type=checkbox id=pbmime>Show media in a viewer on the public page</label>
<label class=chk><input type=checkbox id=pbname>Serve the original file name</label>
<label class=chk><input type=checkbox id=pbexp onchange=pbSync()>Time limit</label>
<div class=sub id=pbendw hidden><input type=datetime-local id=pbend><div class=hint>Expires at this time, server local time</div></div>
<label class=chk><input type=checkbox id=pbpw onchange=pbSync()>Password protect</label>
<div class=sub id=pbpassw hidden><input type=password id=pbpass autocomplete=new-password></div>
<div class=pbfoot><button class="btn ghost" id=pbun hidden onclick="pubUn()">Unpublish</button><button class=btn id=pbgo onclick="pubSave()">Publish</button></div>
</div></div></div>
<div id=menu class=menu hidden></div>
<div id=bulk class=bulk hidden><span id=bcnt></span><div class=bact>
<button class="btn ghost sm" id=bdl title="Download selected"><svg viewBox="0 0 24 24">{{icons.download|safe}}</svg><span>Download</span></button>
<button class="btn ghost sm danger" id=bdel title="Delete selected"><svg viewBox="0 0 24 24">{{icons.trash|safe}}</svg><span>Delete</span></button>
<button class="btn ghost sm" id=bx title="Clear selection"><svg viewBox="0 0 24 24">{{icons.x|safe}}</svg></button></div></div>

<div id=drop>Drop files to upload</div>
<script>
const q=document.getElementById('q'),rows=[...document.querySelectorAll('.row')],cnt=document.getElementById('cnt'),
emp=document.getElementById('empty'),st=document.getElementById('st'),bar=document.getElementById('bar');
const list=document.querySelector('.list'),so=document.getElementById('so'),dt=document.getElementById('dt'),
sz=document.getElementById('sz'),rs=document.getElementById('rs'),total=rows.length;
const cmp={new:(a,b)=>b.t-a.t,old:(a,b)=>a.t-b.t,
az:(a,b)=>a.n.localeCompare(b.n,undefined,{numeric:true}),za:(a,b)=>b.n.localeCompare(a.n,undefined,{numeric:true}),
big:(a,b)=>b.s-a.s,small:(a,b)=>a.s-b.s};
const grid=document.getElementById('grid'),gemp=document.getElementById('gempty'),tl={},
pager=document.getElementById('pager'),pinfo=document.getElementById('pinfo'),pp=document.getElementById('pp'),pn=document.getElementById('pn'),ps=document.getElementById('ps');
let page=1,pgSize=24;try{const v=+localStorage.getItem('bunny-pgsize');if([24,48,96].includes(v))pgSize=v}catch(e){}ps.value=pgSize;
document.querySelectorAll('.tile').forEach(t=>tl[t.dataset.i]=t);
const totalG=Object.keys(tl).length;let mode='list';
try{if(localStorage.getItem('bunny-view')=='grid')mode='grid'}catch(e){}
const sels=rows.map(r=>r.querySelector('input.rsel')),sa=document.getElementById('sa'),bulk=document.getElementById('bulk'),bcnt=document.getElementById('bcnt'),selbtn=document.getElementById('selbtn');
let selMode=false;
const filters=document.getElementById('filters'),fbtn=document.getElementById('fbtn'),fbadge=document.getElementById('fbadge'),hidT=document.getElementById('hid');
let showHid=false;try{showHid=sessionStorage.getItem('bunny-showhid')=='1'}catch(e){}hidT.checked=showHid;
const meta=rows.map(r=>({r,g:tl[r.dataset.i],h:!!r.dataset.hid,n:r.dataset.name,s:+r.dataset.size,t:Date.parse(r.dataset.time)||0}));
function apply(){const v=q.value.toLowerCase().trim(),days=+dt.value,now=Date.now(),
[lo,hi]=sz.value?sz.value.split('-').map(Number):[0,0];let n=0,ng=0,tot=0,totG=0;const okT=[];
meta.sort(cmp[so.value]).forEach(m=>{
const el=showHid||!m.h,ok=el&&m.n.includes(v)&&(!days||now-m.t<=days*864e5)&&(!sz.value||(m.s>=lo&&m.s<hi));
if(el){tot++;if(m.g)totG++}
m.r.hidden=!ok;if(ok)n++;list.insertBefore(m.r,emp);
if(m.g){m.g.hidden=true;if(ok){ng++;okT.push(m.g)}grid.appendChild(m.g)}});
const pages=Math.max(1,Math.ceil(ng/pgSize));if(page>pages)page=pages;
okT.slice((page-1)*pgSize,page*pgSize).forEach(t=>t.hidden=false);
pager.hidden=mode!='grid'||ng<=24;pinfo.textContent='Page '+page+' of '+pages;pp.disabled=page<=1;pn.disabled=page>=pages;
const g=mode=='grid',c=g?ng:n,tt=g?totG:tot;
cnt.textContent=(c<tt?c+' of '+tt:c)+(g?' item':' file')+(tt==1?'':'s');
emp.hidden=n>0;gemp.hidden=!g||ng>0;rs.hidden=!(v||days||sz.value||so.value!='new'||showHid);
const fa=(days?1:0)+(sz.value?1:0)+(so.value!='new'?1:0)+(showHid?1:0);fbadge.textContent=fa;fbadge.hidden=!fa;
rows.forEach((r,i)=>{if(r.hidden)sels[i].checked=false});updateBulk()}
// gallery: tiles load their media only near the viewport and release it again when scrolled far away
const io=new IntersectionObserver(es=>es.forEach(e=>e.isIntersecting?gl(e.target):gu(e.target)),{rootMargin:'700px 0px'});
function gl(t){if(t.m||t.dataset.bad)return;const k=t.dataset.pv,u='/stream?name='+encodeURIComponent(t.dataset.fn)+'&v='+encodeURIComponent(t.dataset.time);let m;
if(k=='image'){m=new Image();m.decoding='async';m.src=u}
else{m=document.createElement('video');m.muted=true;m.playsInline=true;m.preload='metadata';m.src=u+'#t=0.1'}
m.style.opacity=0;m.onload=m.onloadeddata=()=>{m.style.opacity=1};
m.onerror=()=>{gu(t);t.classList.add('bad')};t.classList.remove('bad');t.prepend(m);t.m=m}
function gu(t){const m=t.m;if(!m)return;m.onerror=m.onload=m.onloadeddata=null;m.removeAttribute('src');if(m.load)m.load();m.remove();t.m=null}
document.querySelectorAll('.tile').forEach(t=>io.observe(t));
grid.addEventListener('click',e=>{const t=e.target.closest('.tile');if(t&&!e.target.closest('.pbadge'))view(t.dataset.fn,t.dataset.pv)});
const vl=document.getElementById('vl'),vg=document.getElementById('vg');
function setView(m){mode=m;if(m=='grid')setSelMode(false);list.hidden=m=='grid';grid.hidden=m!='grid';vl.classList.toggle('on',m=='list');vg.classList.toggle('on',m=='grid');
try{localStorage.setItem('bunny-view',m)}catch(e){}apply()}
vl.onclick=()=>setView('list');vg.onclick=()=>setView('grid');
function go(p){page=p;apply();if(grid.scrollIntoView)grid.scrollIntoView()}
pp.onclick=()=>go(page-1);pn.onclick=()=>go(page+1);
ps.onchange=()=>{pgSize=+ps.value;page=1;try{localStorage.setItem('bunny-pgsize',pgSize)}catch(e){}apply()};
hidT.onchange=()=>{showHid=hidT.checked;try{sessionStorage.setItem('bunny-showhid',showHid?'1':'')}catch(e){}page=1;apply()};
fbtn.onclick=()=>{filters.classList.toggle('open');fbtn.classList.toggle('on',filters.classList.contains('open'))};
[q,so,dt,sz].forEach(e=>e.oninput=()=>{page=1;apply()});
rs.onclick=()=>{q.value='';so.value='new';dt.value='0';sz.value='';showHid=false;hidT.checked=false;try{sessionStorage.removeItem('bunny-showhid')}catch(e){}page=1;apply()};setView(mode);
addEventListener('keydown',e=>{if(e.key=='/'&&!/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName)){e.preventDefault();q.focus()}});
f.onchange=()=>upAll(f.files);
let d=0;addEventListener('dragenter',e=>{e.preventDefault();d++;document.body.classList.add('drag')});
addEventListener('dragleave',()=>{if(--d<=0){d=0;document.body.classList.remove('drag')}});
addEventListener('dragover',e=>e.preventDefault());
addEventListener('drop',e=>{e.preventDefault();d=0;document.body.classList.remove('drag');upAll(e.dataTransfer.files)});
async function doRename(old,nw){const go=n=>fetch('/rename',{method:'POST',headers:{'X-File-Name':encodeURIComponent(old),'X-New-Name':encodeURIComponent(n)}});
let r=await go(nw);
if(r.status==422){const sug=await r.text();
if(!confirm('This server cannot send files whose names contain special characters or emoji, so downloads and previews would fail. Rename to "'+sug+'" instead?'))return null;
nw=sug;r=await go(nw)}
if(r.status==401){location='/files';return null}
if(!r.ok){alert(await r.text()||'Rename failed');return null}
return nw}
function ren(b){const row=b.closest('.row'),nm=row.querySelector('.nm'),old=b.dataset.n,v0=row.dataset.safe||old,
i=document.createElement('input'),dot=v0.lastIndexOf('.');let done=false;
i.value=v0;i.className='ren';nm.replaceWith(i);i.focus();i.setSelectionRange(0,dot>0?dot:v0.length);
const fin=async save=>{if(done)return;done=true;const v=i.value.trim();
if(!save||!v||v==old){i.replaceWith(nm);return}
if(await doRename(old,v))location.reload();else i.replaceWith(nm)};
i.onkeydown=e=>{if(e.key=='Enter')fin(true);if(e.key=='Escape')fin(false)};i.onblur=()=>fin(false)}
const pv=document.getElementById('pv'),pvm=document.getElementById('pvm'),pvt=document.getElementById('pvt');
function view(n,k){const rw=rows.find(r=>r.dataset.fn==n);
if(rw&&rw.dataset.bad){pvt.textContent=n;pvm.innerHTML='<p class=empty>The server cannot send files with special characters in their name. Use Rename to fix it.</p>';pvOpen(n);pv.hidden=false;return}
const u='/stream?name='+encodeURIComponent(n);let e;
if(k=='image'){e=new Image();e.src=u}
else{e=document.createElement(k);e.controls=true;e.autoplay=true;e.preload='metadata';e.src=u}
e.onerror=()=>{pvm.innerHTML='<p class=empty>Cannot preview this file in the browser. Try downloading it.</p>'};
pvt.textContent=n;pvm.replaceChildren(e);pvOpen(n);pv.hidden=false}
function pvRow(b){const r=b.closest('.row');view(r.dataset.fn,r.dataset.pv)}
function closePv(){pv.hidden=true;const e=pvm.firstChild;if(e&&e.pause){e.pause();e.removeAttribute('src');e.load()}pvm.replaceChildren()}
pv.onclick=e=>{if(e.target==pv)closePv()};document.getElementById('pvx').onclick=closePv;
list.addEventListener('click',e=>{if(e.target.closest('.act,.ren,.pbadge,.rsel'))return;const r=e.target.closest('.row');if(!r)return;
if(selMode){const c=r.querySelector('input.rsel');c.checked=!c.checked;updateBulk();return}
if(r.classList.contains('pv'))view(r.dataset.fn,r.dataset.pv)});
const BASE={{base|tojson}},pb=document.getElementById('pb'),mn=document.getElementById('menu'),E=id=>document.getElementById(id);
let pbRow=null;const ts=s=>(s||'').slice(0,16).replace('T',' ');
function pubUrl(p){return BASE+(p.pw?'file/protected/access?id=':'file?id=')+encodeURIComponent(p.id)}
function pubOpen(r){const p=JSON.parse(r.dataset.pub||'null');pbRow=r;
E('pbt').textContent=(p?'Published · ':'Publish · ')+r.dataset.fn;
E('pbmime').checked=!!(p&&p.mime);E('pbname').checked=!!(p&&p.name);
E('pbexp').checked=!!(p&&p.end);E('pbend').value=p&&p.end?p.end.slice(0,16):'';
E('pbpw').checked=!!(p&&p.pw);E('pbpass').value='';E('pbpass').placeholder=p&&p.pw?'Leave blank to keep the current password':'Password';
E('pblink').hidden=!p;E('pbun').hidden=!p;E('pbgo').textContent=p?'Save changes':'Publish';
if(p){E('pburl').value=pubUrl(p);E('pbinfo').textContent=(p.start?'Published '+ts(p.start):'Published')+(p.end?' · expires '+ts(p.end):'')}
pbSync();pb.hidden=false}
function pbSync(){E('pbendw').hidden=!E('pbexp').checked;E('pbpassw').hidden=!E('pbpw').checked}
function setPub(r,d){const p=d&&d.isPublished?{id:d.publicAccessId,pw:!!d.publicIsPasswordProtected,start:d.publicAccessStartTime,end:d.publicAccessEndTime,mime:!!d.serveMimeType,name:!!d.serveFileName}:null;
r.dataset.pub=p?JSON.stringify(p):'';
const b=r.querySelector('[data-act=pub]');b.classList.toggle('on',!!p);b.title=p?'Manage publishing':'Publish';
[r,tl[r.dataset.i]].forEach(e=>{if(!e)return;const x=e.querySelector('.pbadge');x.hidden=!p;x.classList.toggle('lock',!!(p&&p.pw))});syncPv()}
async function pubSave(){const r=pbRow,p=JSON.parse(r.dataset.pub||'null'),pw=E('pbpass').value,prot=E('pbpw').checked,ex=E('pbexp').checked,end=ex?E('pbend').value:'';
if(ex&&!end){alert('Pick an expiry date and time');return}
if(end&&new Date(end)<new Date()&&!confirm('This expiry is in the past, so the link would be expired immediately. Continue?'))return;
if(prot&&!pw&&!(p&&p.pw)){alert('Enter a password');return}
E('pbgo').disabled=true;
const x=await fetch('/publish',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:r.dataset.fn,mime:E('pbmime').checked,fname:E('pbname').checked,end:end,protect:prot,password:pw})});
E('pbgo').disabled=false;
if(x.status==401){location='/files';return}
if(!x.ok){alert(await x.text()||'Publish failed');return}
setPub(r,await x.json());pubOpen(r)}
async function pubUn(){const r=pbRow;if(!confirm('Unpublish this file? The public link will stop working.'))return;
const x=await fetch('/unpublish',{method:'POST',headers:{'X-File-Name':encodeURIComponent(r.dataset.fn)}});
if(x.status==401){location='/files';return}
if(!x.ok){alert(await x.text()||'Unpublish failed');return}
setPub(r,null);pubOpen(r)}
async function pubCopy(){const u=E('pburl');u.select();try{await navigator.clipboard.writeText(u.value)}catch(e){document.execCommand('copy')}
const b=E('pbcp');b.classList.add('ok');setTimeout(()=>b.classList.remove('ok'),1200)}
function openMenu(b){const r=b.closest('.row');mn.replaceChildren();
r.querySelectorAll('.act [data-act]').forEach(a=>{const i=document.createElement('button'),s=document.createElement('span');
i.className='mi'+(a.dataset.act=='del'?' danger':'');i.innerHTML=a.innerHTML;s.textContent=a.title;i.append(s);
i.onclick=()=>{closeMenu();a.click()};mn.append(i)});
const R=b.getBoundingClientRect();mn.hidden=false;
mn.style.right=(innerWidth-R.right)+'px';mn.style.top=Math.max(8,Math.min(R.bottom+4,innerHeight-mn.offsetHeight-8))+'px'}
let toSrv=false;const ldt=E('ldt');if(ldt){try{toSrv=sessionStorage.getItem('bunny-ldl')=='1'}catch(e){}ldt.checked=toSrv;
ldt.onchange=()=>{toSrv=ldt.checked;try{sessionStorage.setItem('bunny-ldl',toSrv?'1':'')}catch(e){}}}
document.addEventListener('click',e=>{const a=toSrv&&e.target.closest('a[href^="/download?name="]');if(!a)return;
e.preventDefault();ldl(decodeURIComponent(a.getAttribute('href').split('name=')[1]),a)},true);
async function ldl(n,b){if(!n||b.dataset.busy)return;b.dataset.busy=1;b.style.opacity=.6;
try{const x=await fetch('/download-local?name='+encodeURIComponent(n),{method:'POST'});
if(x.status==401){location='/files';return}
if(!x.ok){alert(await x.text()||'Local download failed');return}
b.classList.add('ok');setTimeout(()=>b.classList.remove('ok'),1500)}
catch(e){alert('Local download failed')}finally{delete b.dataset.busy;b.style.opacity=''}}
function closeMenu(){mn.hidden=true}
addEventListener('click',e=>{if(!e.target.closest('#menu,.more'))closeMenu()});
addEventListener('scroll',closeMenu,true);addEventListener('resize',closeMenu);
pb.onclick=e=>{if(e.target==pb)pb.hidden=true};E('pbx').onclick=()=>{pb.hidden=true};
let pvCur=null;
function pvOpen(n){pvCur=rows.find(r=>r.dataset.fn==n)||null;E('pvdl').href='/download?name='+encodeURIComponent(n);syncPv()}
function syncPv(){if(!pvCur)return;const on=!!pvCur.dataset.pub;E('pvpb').classList.toggle('on',on);E('pvpbl').textContent=on?'Published':'Publish'}
E('pvpb').onclick=()=>{if(pvCur)pubOpen(pvCur)};
E('pvdel').onclick=()=>{if(pvCur)del(pvCur.querySelector('[data-act=del]'))};
E('pvrn').onclick=()=>{if(!pvCur)return;const old=pvCur.dataset.fn,v0=pvCur.dataset.safe||old,t=E('pvt'),i=document.createElement('input'),dot=v0.lastIndexOf('.');let done=false;
i.value=v0;i.className='ren';t.replaceWith(i);i.focus();i.setSelectionRange(0,dot>0?dot:v0.length);
const fin=async save=>{if(done)return;done=true;const v=i.value.trim();i.replaceWith(t);if(!save||!v||v==old)return;
const n=await doRename(old,v);if(n){try{sessionStorage.setItem('bunny-open',n)}catch(e){}location.reload()}};
i.onkeydown=e=>{if(e.key=='Enter')fin(true);if(e.key=='Escape'){e.stopPropagation();fin(false)}};i.onblur=()=>fin(false)};
// Escape closes only the topmost layer: menu, then publish dialog, then preview
addEventListener('keydown',e=>{if(e.key!='Escape')return;if(!mn.hidden)closeMenu();else if(!pb.hidden)pb.hidden=true;else if(!pv.hidden)closePv();else if(!bulk.hidden)clearSel();else if(selMode)setSelMode(false)});
// after a rename from the preview the page reloads; reopen the preview of the renamed file
try{const o=sessionStorage.getItem('bunny-open');if(o){sessionStorage.removeItem('bunny-open');const r=rows.find(x=>x.dataset.fn==o);if(r&&r.dataset.pv)view(o,r.dataset.pv)}}catch(e){}
// bulk actions (list view): selection = ticked rows that are currently visible
function selRows(){return rows.filter((r,i)=>!r.hidden&&sels[i].checked)}
function updateBulk(){const n=selRows().length,vis=rows.filter(r=>!r.hidden).length;
bulk.hidden=n==0||mode!='list';bcnt.textContent=n+' selected';
sa.hidden=!selMode||mode!='list';sa.checked=n>0&&n==vis;sa.indeterminate=n>0&&n<vis;selbtn.hidden=mode!='list';
document.body.classList.toggle('bulkon',!bulk.hidden);document.body.classList.toggle('selmode',selMode&&mode=='list')}
function setSelMode(on){selMode=on;if(!on)sels.forEach(c=>{c.checked=false});selbtn.classList.toggle('on',on);
document.getElementById('sbl').textContent=on?'Done':'Select';updateBulk()}
selbtn.onclick=()=>setSelMode(!selMode);
sa.onchange=()=>{rows.forEach((r,i)=>{sels[i].checked=sa.checked&&!r.hidden});updateBulk()};
function clearSel(){sels.forEach(c=>{c.checked=false});updateBulk()}
E('bx').onclick=clearSel;E('bdl').onclick=()=>bulkDl();E('bdel').onclick=()=>bulkDel();
function bulkDl(){const sel=selRows();if(!sel.length)return;
if(sel.length==1){location.href='/download?name='+encodeURIComponent(sel[0].dataset.fn);return}
const fm=document.createElement('form'),i=document.createElement('input');fm.method='post';fm.action='/bulk-download';
i.type='hidden';i.name='names';i.value=JSON.stringify(sel.map(r=>r.dataset.fn));fm.append(i);document.body.append(fm);fm.submit();fm.remove()}
let busy=false;
async function bulkDel(){if(busy)return;const sel=selRows();if(!sel.length)return;
if(!confirm('Delete '+sel.length+(sel.length==1?' file':' files')+'? This cannot be undone.'))return;
busy=true;E('bdel').disabled=E('bdl').disabled=true;const fail=[];
for(let i=0;i<sel.length;i++){bcnt.textContent='Deleting '+(i+1)+' of '+sel.length+'...';
const r=await fetch('/delete',{method:'POST',headers:{'X-File-Name':encodeURIComponent(sel[i].dataset.fn)}});
if(r.status==401){location='/files';return}
if(!r.ok)fail.push(sel[i].dataset.fn+': '+(await r.text()||'failed'))}
if(fail.length)alert('Could not delete '+fail.length+' file(s): '+fail.join(' | '));
location.reload()}
async function del(b){const n=b.dataset.n;if(!confirm('Delete "'+n+'"? This cannot be undone.'))return;
const r=await fetch('/delete',{method:'POST',headers:{'X-File-Name':encodeURIComponent(n)}});
if(r.status==401)location='/files';else if(r.ok)location.reload();else alert(await r.text()||'Delete failed')}
const saved=[];
async function upAll(fl){fl=[...fl];let ok=true;
for(let i=0;i<fl.length;i++){st.textContent='Uploading '+fl[i].name+' ('+(i+1)+'/'+fl.length+')';
if(!await up(fl[i]))ok=false}
if(saved.length){alert('These names contain characters the server cannot send, so they were saved as: '+saved.join(', '));saved.length=0}
if(ok)location.reload();else{st.textContent='Some uploads failed';bar.style.width=0}}
function up(file){return new Promise(res=>{const x=new XMLHttpRequest();
x.open('POST','/upload');x.setRequestHeader('X-File-Name',encodeURIComponent(file.name));
x.setRequestHeader('Content-Type','application/octet-stream');
x.upload.onprogress=e=>{bar.style.width=e.loaded/e.total*100+'%'};
x.onload=()=>{if(x.status==401)location='/files';
if(x.status!=200)alert(file.name+': '+(x.responseText||'Upload failed'));
const sv=x.getResponseHeader('X-Saved-As');if(x.status==200&&sv&&sv!=file.name)saved.push(file.name+' -> '+sv);res(x.status==200)};
x.onerror=()=>{alert(file.name+': Upload failed');res(false)};x.send(file)})}
</script>"""


SW_JS = r"""const C = 'bunny-v2-ICONV', OFF = '/offline', SH = 'bunny-share';
self.addEventListener('install', e => { e.waitUntil(caches.open(C).then(c => c.add(OFF))); self.skipWaiting(); });
self.addEventListener('activate', e => e.waitUntil(
  caches.keys().then(k => Promise.all(k.filter(x => x != C && x != SH).map(x => caches.delete(x)))).then(() => clients.claim())));
// files shared to the app (Web Share Target): park them in the cache, the page then uploads them with the normal session
async function handleShare(req) {
  const files = (await req.formData()).getAll('files').filter(f => typeof f != 'string');
  await caches.delete(SH);
  const c = await caches.open(SH);
  for (let i = 0; i < files.length; i++)
    await c.put('/share-file/' + i, new Response(files[i], {headers: {'X-Name': encodeURIComponent(files[i].name), 'Content-Type': files[i].type || 'application/octet-stream'}}));
  return Response.redirect('/share-receive?n=' + files.length, 303);
}
// pages are never cached (file lists and sessions must stay live); only an offline fallback is served
self.addEventListener('fetch', e => {
  const p = new URL(e.request.url).pathname;
  if (e.request.method == 'POST' && p == '/share') { e.respondWith(handleShare(e.request)); return; }
  if (e.request.mode == 'navigate' && !/^\/(download|stream)/.test(p))
    e.respondWith(fetch(e.request).catch(() => caches.match(OFF)));
});
"""

OFFLINE = """<div class=card><div class=brand><span class=dot><svg viewBox="0 0 24 24">{{logo|safe}}</svg></span>Bunny Interactive</div>
<h1>You're offline</h1><p class=sub>Check your connection and try again.</p>
<button class=btn onclick="location.reload()">Retry</button></div>"""


SHARE = """<div class=card style="max-width:460px"><div class=brand><span class=dot><svg viewBox="0 0 24 24">{{logo|safe}}</svg></span>Bunny Interactive</div>
<h1>Shared files</h1><p class=sub id=ssub>Preparing...</p><div class=sl id=sl></div>
<div class=sact id=sact hidden><button class="btn ghost" id=sretry>Retry failed</button><a class=btn href=/files>Open files</a></div></div>
<script>
const n=+new URLSearchParams(location.search).get('n')||0,sl=document.getElementById('sl'),ssub=document.getElementById('ssub'),sact=document.getElementById('sact'),sretry=document.getElementById('sretry'),items=[];
function row(it){const d=document.createElement('div');d.className='si';d.innerHTML='<div class=nm></div><progress value=0 max=100></progress><div class=ss>Waiting</div>';
d.firstChild.textContent=it.name;it.bar=d.children[1];it.st=d.children[2];sl.append(d)}
function send(it){return new Promise(res=>{const x=new XMLHttpRequest();x.open('POST','/upload');
x.setRequestHeader('X-File-Name',encodeURIComponent(it.name));x.setRequestHeader('Content-Type','application/octet-stream');
x.upload.onprogress=e=>{it.bar.value=e.loaded/e.total*100};
x.onload=()=>{if(x.status==200){it.bar.value=100;const sv=x.getResponseHeader('X-Saved-As');it.st.textContent=sv&&sv!=it.name?'Uploaded as '+sv:'Uploaded';it.done=true;res('ok')}
else if(x.status==401)res('auth');else{it.st.textContent=x.responseText||'Upload failed';res('fail')}};
x.onerror=()=>{it.st.textContent='Upload failed';res('fail')};it.st.textContent='Uploading...';x.send(it.blob)})}
async function run(){sact.hidden=true;let fail=0;
for(const it of items){if(it.done)continue;const r=await send(it);
if(r=='auth'){ssub.textContent='Please sign in to continue.';location.href='/login?next='+encodeURIComponent(location.pathname+location.search);return}
if(r=='fail')fail++}
if(!fail){ssub.textContent='All files uploaded.';try{await caches.delete('bunny-share')}catch(e){}sretry.hidden=true}
else{ssub.textContent=fail+(fail==1?' file':' files')+' failed.';sretry.hidden=false}
sact.hidden=false}
sretry.onclick=run;
(async()=>{try{const c=await caches.open('bunny-share');
for(let i=0;i<n;i++){const r=await c.match('/share-file/'+i);if(r){const it={name:decodeURIComponent(r.headers.get('X-Name')),blob:await r.blob()};items.push(it);row(it)}}}catch(e){}
if(!items.length){ssub.textContent='Nothing to upload.';sretry.hidden=true;sact.hidden=false;return}
ssub.textContent=items.length+(items.length==1?' file':' files')+' received';run()})();
</script>"""


@app.route("/share", methods=["GET", "POST"])
def share():  # normally intercepted by the service worker; this is only the fallback
    return redirect("/files", 303)


@app.route("/share-receive")
def share_receive():
    sid = session.get("sid")
    if not (SESS.get(sid) or auto_login(sid)):
        return redirect("/login?next=" + quote(request.full_path.rstrip("?"), safe=""))
    return page(SHARE, "auth")


@app.route("/manifest.webmanifest")
def manifest():
    return Response(json.dumps({
        "name": "Bunny Interactive", "short_name": "Bunny Interactive",
        "start_url": "/files", "scope": "/", "display": "standalone",
        "background_color": "#09090b", "theme_color": "#09090b",
        "share_target": {"action": "/share", "method": "POST", "enctype": "multipart/form-data",
                         "params": {"files": [{"name": "files", "accept": ["image/*", "video/*", "audio/*", "application/*", "text/*"]}]}},
        "id": "/?app=bunny-interactive",
        "icons": [
            {"src": f"/icon-192.png?v={ICON_V}", "sizes": "192x192", "type": "image/png", "purpose": "any"},
            {"src": f"/icon-512.png?v={ICON_V}", "sizes": "512x512", "type": "image/png", "purpose": "any"},
            {"src": f"/icon-maskable-512.png?v={ICON_V}", "sizes": "512x512", "type": "image/png", "purpose": "maskable"}]}),
        headers={"Cache-Control": "no-cache"},
        mimetype="application/manifest+json")


@app.route("/sw.js")
def sw():
    return Response(SW_JS.replace("ICONV", ICON_V), mimetype="text/javascript", headers={"Cache-Control": "no-cache"})


_NOCACHE = {"Cache-Control": "no-cache, max-age=0, must-revalidate"}


@app.route("/icon-<int:size>.png")
def icon(size):
    data = {192: ICON_192, 512: ICON_512}.get(size)
    return Response(data, mimetype="image/png", headers=_NOCACHE) if data else ("", 404)


@app.route("/icon-maskable-512.png")
def icon_maskable():
    return Response(ICON_MASK, mimetype="image/png", headers=_NOCACHE)


@app.route("/apple-touch-icon.png")
def apple_icon():
    return Response(ICON_APPLE, mimetype="image/png", headers=_NOCACHE)


@app.route("/offline")
def offline():  # rendered without flash messages so the service worker's install fetch can't consume any
    return render_template_string(LAYOUT, cls="auth", msgs=[], body=render_template_string(OFFLINE))


@app.route("/favicon.ico")
def favicon():
    return Response(FAVICON_ICO, mimetype="image/x-icon", headers=_NOCACHE)


@app.route("/")
def index():
    return redirect("/files")


@app.route("/login", methods=["GET", "POST"])
def login():
    nxt = request.values.get("next", "")
    if not (nxt.startswith("/") and not nxt.startswith("//") and "\\" not in nxt and len(nxt) < 300):
        nxt = ""
    if request.method == "POST":
        f = request.form
        body = {"license": f["license"].strip(), "hwid": hwid(f["email"]),
                "email": f["email"].strip(), "password": f["password"]}
        try:
            r = requests.get(f"{API}/api/license/login", headers={H_LOGIN: json.dumps(body)},
                             verify=VERIFY, timeout=30)
            if r.ok:
                start_session(r)
                resp = remember(redirect(nxt or "/files"), body)
                stay_forget(request.cookies.get("rt"))
                if f.get("stay"):
                    tok = stay_save({"license": body["license"], "email": body["email"], "password": body["password"]})
                    AUTO[_h(tok)] = session["sid"]
                    resp.set_cookie("rt", tok, max_age=STAY_DAYS * 86400, httponly=True, samesite="Lax")
                else:
                    resp.delete_cookie("rt")
                return resp
            flash(reason(r))
        except Exception as e:
            flash(str(e))
    return page(LOGIN, "auth", lic=request.form.get("license") or request.cookies.get("lic", ""),
                em=request.form.get("email") or request.cookies.get("em", ""), nxt=nxt)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        f = request.form
        body = {"license": f["license"].strip(), "hwid": hwid(f["email"]),
                "email": f["email"].strip(), "username": f["username"].strip(),
                "password": f["password"]}
        try:
            r = requests.get(f"{API}/api/license/register", headers={H_REGISTER: json.dumps(body)},
                             verify=VERIFY, timeout=30)
            if r.ok:
                start_session(r)
                return remember(redirect("/files"), body)
            flash(reason(r))
        except Exception as e:
            flash(str(e))
    return page(REGISTER, "auth")


@app.route("/logout")
def logout():
    drop()
    stay_forget(request.cookies.get("rt"))
    resp = redirect("/login")
    resp.delete_cookie("rt")
    return resp


@app.route("/files")
def files():
    try:
        r = api("GET", "/api/read")
    except AuthError:
        return redirect("/login")
    items = []
    if r.ok:
        for d in r.json():
            low = {k.lower(): v for k, v in d.items()}
            pv = preview(str(low.get("filename", "")))
            size = low["filesize"] if isinstance(low.get("filesize"), int) else -1
            pub = None
            if low.get("ispublished"):
                pub = {"id": low.get("publicaccessid"), "pw": bool(low.get("publicispasswordprotected")),
                       "start": low.get("publicaccessstarttime"), "end": low.get("publicaccessendtime"),
                       "mime": bool(low.get("servemimetype")), "name": bool(low.get("servefilename"))}
            items.append({"name": low.get("filename", "?"), "size": human(low.get("filesize")),
                          "by": low.get("uploadername", ""), "kind": kind(str(low.get("filename", ""))),
                          "when": str(low.get("uploadtime", ""))[:16].replace("T", " "),
                          "time": str(low.get("uploadtime", "")),
                          "bytes": size,
                          "pv": pv, "gal": pv in ("image", "video") and 0 <= size < GALLERY_MAX, "pub": pub,
                          "bad": STRICT_NAMES and not str(low.get("filename", "")).isascii(),
                          "safe": safe_name(str(low.get("filename", ""))),
                          "hid": str(low.get("filename", "")).lower().startswith(".bunnyc")})
    else:
        flash(reason(r))
    return page(FILES, files=items, icons=ICONS, base=API + "/")


@app.route("/download")
def download():
    name = request.args["name"]
    try:
        r = api("GET", "/api/download", headers={H_FILENAME: name}, stream=True, timeout=(30, None))
    except AuthError:
        return redirect("/login")
    if not r.ok:
        flash(reason_for(r, name))
        return redirect("/files")
    h = {"Content-Disposition": f"attachment; filename*=UTF-8''{quote(name)}"}
    if "Content-Length" in r.headers:
        h["Content-Length"] = r.headers["Content-Length"]
    return Response(stream_with_context(r.iter_content(65536)),
                    content_type="application/octet-stream", headers=h)


@app.route("/download-local", methods=["POST"])
def download_local():
    if not local_dl():
        return "Local download is not enabled", 404
    name = request.args["name"]
    dest = os.path.join(DOWNLOAD_PATH, os.path.basename(name.replace("\\", "/")))
    if os.path.basename(dest) in ("", ".", ".."):
        return "Invalid file name", 400
    try:
        r = api("GET", "/api/download", headers={H_FILENAME: name}, stream=True, timeout=(30, None))
    except AuthError:
        return "", 401
    if not r.ok:
        return reason_for(r, name), 502
    tmp = dest + ".part"
    try:
        with open(tmp, "wb") as fh:
            for chunk in r.iter_content(65536):
                fh.write(chunk)
        os.replace(tmp, dest)
    except Exception as e:
        try:
            os.remove(tmp)
        except OSError:
            pass
        return f"Save failed: {e}", 500
    return {"saved": dest, "size": os.path.getsize(dest)}


@app.route("/stream")
def stream():
    name = request.args.get("name", "")
    try:
        r = api("GET", "/api/download", headers={H_FILENAME: name}, stream=True, timeout=(30, None))
    except AuthError:
        return "", 401
    if not r.ok:
        return reason_for(r, name), 400
    total = int(r.headers.get("Content-Length") or 0)
    start, end, status = 0, total - 1, 200
    m = re.match(r"bytes=(\d*)-(\d*)$", request.headers.get("Range", "")) if total else None
    if m and (m[1] or m[2]):
        if m[1]:
            start = int(m[1])
            if m[2]:
                end = min(int(m[2]), end)
        else:
            start = max(total - int(m[2]), 0)
        if start > end:
            r.close()
            return "", 416, {"Content-Range": f"bytes */{total}"}
        status = 206

    def gen():  # upstream has no range support: skip bytes up to `start`, stop after `end`
        skip, left = start, (end - start + 1) if total else float("inf")
        try:
            for chunk in r.iter_content(262144):
                if skip:
                    if len(chunk) <= skip:
                        skip -= len(chunk)
                        continue
                    chunk, skip = chunk[skip:], 0
                if len(chunk) >= left:
                    yield chunk[:int(left)]
                    return
                left -= len(chunk)
                yield chunk
        finally:
            r.close()

    h = {"Accept-Ranges": "bytes", "Content-Disposition": "inline",
         "X-Content-Type-Options": "nosniff", "Content-Security-Policy": "sandbox"}
    if total:
        h["Content-Length"] = str(end - start + 1)
    if request.args.get("v"):  # versioned URL (gallery): let the browser cache it
        h["Cache-Control"] = "private, max-age=86400"
    if status == 206:
        h["Content-Range"] = f"bytes {start}-{end}/{total}"
    return Response(stream_with_context(gen()), status=status, headers=h,
                    content_type=mimetypes.guess_type(name)[0] or "application/octet-stream")


@app.route("/rename", methods=["POST"])
def rename():
    old = unquote(request.headers.get("X-File-Name", ""))
    new = unquote(request.headers.get("X-New-Name", ""))
    if not old or not new:
        return "Missing file name", 400
    if STRICT_NAMES and not new.isascii():
        return safe_name(new), 422
    try:
        r = api("GET", "/api/rename",
                headers={H_RENAME: json.dumps({"fileNameOld": old, "fileNameNew": new})})
    except AuthError:
        return "", 401
    return ("", 200) if r.ok else (reason(r), 400)


@app.route("/publish", methods=["POST"])
def publish():
    j = request.get_json(silent=True) or {}
    name = j.get("name", "")
    if not name:
        return "Missing file name", 400
    body = {"fileName": name, "serveMimeType": bool(j.get("mime")), "serveFileName": bool(j.get("fname")),
            "isPasswordProtected": bool(j.get("protect")), "passwordHash": ""}
    end = j.get("end") or ""
    if end:
        if not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d(:\d\d)?", end):
            return "Invalid expiry time", 400
        body[END_KEY] = end if len(end) > 16 else end + ":00"
    if body["isPasswordProtected"] and j.get("password"):  # blank = keep the current password
        body["passwordHash"] = hashlib.sha256(j["password"].encode()).hexdigest()
    try:
        r = api("GET", "/api/publish", headers={H_PUBLISH: json.dumps(body)})
    except AuthError:
        return "", 401
    return Response(r.text, mimetype="application/json") if r.ok else (reason(r), 400)


@app.route("/unpublish", methods=["POST"])
def unpublish():
    name = unquote(request.headers.get("X-File-Name", ""))
    if not name:
        return "Missing file name", 400
    try:
        r = api("GET", "/api/unpublish", headers={H_FILENAME: name})
    except AuthError:
        return "", 401
    return Response(r.text, mimetype="application/json") if r.ok else (reason(r), 400)


class _Sink:  # unseekable write target for streaming zipfile output
    def __init__(self):
        self.parts = []

    def write(self, b):
        self.parts.append(bytes(b))
        return len(b)

    def flush(self):
        pass

    def take(self):
        data, self.parts = b"".join(self.parts), []
        return data


@app.route("/bulk-download", methods=["POST"])
def bulk_download():
    try:
        names = json.loads(request.form.get("names", "[]"))
    except ValueError:
        names = []
    names = [n for n in names if isinstance(n, str) and n] if isinstance(names, list) else []
    if not names:
        return "No files selected", 400
    skipped, opened, it = [], None, iter(names)
    for name in it:  # open the first available file now, so auth/server errors can still redirect
        try:
            r = api("GET", "/api/download", headers={H_FILENAME: name}, stream=True, timeout=(30, None))
        except AuthError:
            return redirect("/login")
        if r.ok:
            opened = (name, r)
            break
        r.close()
        skipped.append(name)
    if not opened:
        flash("None of the selected files could be downloaded")
        return redirect("/files")

    def gen():
        sink, current = _Sink(), opened
        z = zipfile.ZipFile(sink, "w", zipfile.ZIP_STORED, allowZip64=True)
        pending = it
        while current:
            name, r = current
            try:
                safe = name.replace("\\", "_").replace("/", "_")
                info = zipfile.ZipInfo(safe if safe.strip(".") else "_" + safe, time.localtime()[:6])
                info.compress_type = zipfile.ZIP_STORED
                with z.open(info, "w", force_zip64=True) as dest:
                    for chunk in r.iter_content(262144):
                        dest.write(chunk)
                        data = sink.take()
                        if data:
                            yield data
            finally:
                r.close()
            current = None
            for nxt in pending:
                try:
                    r2 = api("GET", "/api/download", headers={H_FILENAME: nxt}, stream=True, timeout=(30, None))
                except AuthError:
                    skipped.append(nxt)
                    skipped.extend(pending)
                    break
                if r2.ok:
                    current = (nxt, r2)
                    break
                r2.close()
                skipped.append(nxt)
        if skipped:
            z.writestr("_skipped.txt", "These files could not be downloaded:\r\n" + "\r\n".join(skipped) + "\r\n")
        z.close()
        data = sink.take()
        if data:
            yield data

    fname = f"bunny-{time.strftime('%Y%m%d-%H%M')}.zip"
    return Response(stream_with_context(gen()), mimetype="application/zip",
                    headers={"Content-Disposition": f"attachment; filename=\"{fname}\"", "X-Accel-Buffering": "no"})


@app.route("/delete", methods=["POST"])
def delete():
    name = unquote(request.headers.get("X-File-Name", ""))
    if not name:
        return "Missing file name", 400
    try:
        r = api("GET", "/api/delete", headers={H_FILENAME: name})
    except AuthError:
        return "", 401
    return ("", 200) if r.ok else (reason(r), 400)


@app.route("/upload", methods=["POST"])
def upload():
    name = unquote(request.headers.get("X-File-Name", ""))
    if not name:
        return "Missing file name", 400
    if STRICT_NAMES and not name.isascii():
        name = safe_name(name)
    boundary = secrets.token_hex(16)
    ascii_name = name.encode("ascii", "replace").decode().replace('"', "_")
    head = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{ascii_name}"; '
            f"filename*=UTF-8''{quote(name)}\r\nContent-Type: application/octet-stream\r\n\r\n").encode()
    tail = f"\r\n--{boundary}--\r\n".encode()

    def body():
        yield head
        while chunk := request.stream.read(65536):
            yield chunk
        yield tail

    try:
        r = api("POST", "/api/upload", data=body(), timeout=(30, None), headers={
            "File-Size": str(request.content_length or 0),
            "Content-Type": f"multipart/form-data; boundary={boundary}"})
    except AuthError:
        return "", 401
    return ("", 200, {"X-Saved-As": name}) if r.ok else (reason(r), 400)


# --- icons (PNG/ICO, base64): rounded 'any' icons, full-bleed maskable + Apple touch icon, multi-size favicon ---
ICON_192 = base64.b64decode("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")
ICON_512 = base64.b64decode("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")
ICON_MASK = base64.b64decode("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")
ICON_APPLE = base64.b64decode("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")
FAVICON_ICO = base64.b64decode("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")
ICON_V = hashlib.sha1(ICON_192 + ICON_512 + ICON_MASK + ICON_APPLE + FAVICON_ICO).hexdigest()[:8]  # changes whenever an icon changes
app.jinja_env.globals["iv"] = ICON_V
app.jinja_env.globals["local_dl"] = local_dl
