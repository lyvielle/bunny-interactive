Disclaimer: Due to ongoing health issues I am no longer able to concentrate on developing software by myself. This project is therefore vibe-coded: written together with an AI assistant (Claude) and directed, tested and run by me. It is not a demo or proof of concept. It exists because I need it: it fixes a real problem in my day-to-day life and is in daily use. Read the code and the security notes below with that in mind.

# Bunny Interactive

A small web client (Flask, one Python file, Docker) for a private ASP.NET file server called Bunny. It replaces the original Windows WPF client, which can no longer be maintained or run here. It is a thin proxy and UI: it holds no files of its own and talks to the Bunny server's HTTP API on behalf of the logged-in browser.

Features: register / login, file list with search, filters and sort, upload (drag and drop and PWA share target), download, rename, delete, media preview, paged gallery grid, bulk select with streamed ZIP download and bulk delete, publish / unpublish public links (optional password), optional "stay signed in", installable PWA.

## Architecture

```
Browser / PWA  <--HTTPS-->  [reverse proxy]  <-->  Bunny Interactive (Flask, :8000)  <--HTTPS-->  Bunny server (BUNNY_API)
                                                        |
                                                        +-- /data volume (stay-signed-in store, key)
                                                        +-- optional $DOWNLOAD_PATH volume
```

- **Single file**: `app.py` holds the routes, the HTML/CSS/JS templates (Jinja strings rendered with `render_template_string`), the service worker and the PWA icons (embedded as base64).
- **No database**. Server-side state is an in-memory dict (`SESS`) plus the optional stay-signed-in files in `/data`.
- **Upstream API** (all with an `Auth-Token` header, parameters in headers): `/api/license/login`, `/api/license/register`, `/api/license/extend`, `/api/read`, `/api/download`, `/api/upload` (multipart POST), `/api/rename`, `/api/delete`, `/api/publish`, `/api/unpublish`. The Bunny server uses GET for most mutating calls; this client mirrors that.
- **Streaming**: downloads, preview (`/stream`), uploads and the bulk ZIP are streamed in chunks (64 KB to 256 KB), so memory use does not grow with file size. The ZIP is built on the fly with `ZIP_STORED` (no compression, Zip64 enabled).
- **Preview / range requests**: the upstream server has no range support, so `/stream` emulates `Range` by reading and discarding bytes up to the requested offset. Seeking in large videos therefore costs a re-read from the start.
- **Gallery**: shows images and videos under 10 MB (`GALLERY_MAX`), lazy-loaded with an `IntersectionObserver` and paged. Files whose name starts with `.bunnyc` are hidden in list and gallery unless a toggle is switched on (filtering happens in the browser).
- **Service worker** (`/sw.js`): never caches pages (file lists and sessions stay live); it only serves an offline fallback page and handles the Web Share Target. Shared files are parked in Cache Storage (`bunny-share`), then `/share-receive` uploads them with the normal session.

## Authentication and encryption

- **No client-side file encryption.** Whatever encryption the Bunny server applies to stored files, `/api/download` returns the file bytes and this client passes them through. File keys never reach this app.
- **Login**: the browser posts license key, email and password to this app. The app sends them to the Bunny server (`Login-Content` header, JSON) and receives a session token. The token is kept only in server memory (`SESS`, keyed by a random `sid`); the browser holds a Flask signed session cookie containing the `sid` (signed with `SECRET_KEY`).
- **Token lifetime**: before a call, if the last extension was more than 20 minutes ago, the app calls `/api/license/extend`. On a 401/403 from upstream it drops the session and, if "stay signed in" is active, logs in again once and retries (not for uploads, whose body is already consumed).
- **HWID**: the Bunny server requires a 64-character alphanumeric hardware ID bound at registration. Here it is `SHA-256(HWID_SALT + lowercase email)` in upper-case hex, so it is stable per account. **Do not change `HWID_SALT` after registering accounts**, or logins will present a different HWID.
- **Remembered form fields**: license key and email are stored in plain HttpOnly cookies (`lic`, `em`, one year) to prefill the login form. The password is never stored in a cookie.
- **Stay signed in** (opt-in checkbox): license, email and password are encrypted with Fernet (`cryptography`) and stored in `/data/remember.json`, indexed by the SHA-256 of a random token held in an HttpOnly `rt` cookie (90 days). The Fernet key comes from `REMEMBER_KEY`, or is generated once as `/data/remember.key` (mode 0600). Logout deletes the entry and cookie.
- **Public links** are created by the Bunny server. For password-protected links this app sends the SHA-256 hex of the password; what the server does with it is outside this repo.

## Deployment

```bash
git clone https://github.com/lyvielle/bunny-interactive && cd bunny-interactive
# edit docker-compose.yml: set BUNNY_API, HWID_SALT, SECRET_KEY (and optionally REMEMBER_KEY)
docker compose up -d --build
```

The app listens on port 8000 over plain HTTP. Put a TLS-terminating reverse proxy in front of it (see security notes). For large uploads and downloads, disable proxy request and response buffering and body-size limits (for nginx: `client_max_body_size 0; proxy_request_buffering off; proxy_buffering off;`; the bulk ZIP response already sends `X-Accel-Buffering: no`).

The image is `python:3.12-slim`, started with `gunicorn -w 1 -k gthread --threads 32 -t 0`. **Keep one worker**: sessions live in process memory. `-t 0` disables the worker timeout so long transfers are not killed.

Generate a Fernet key (optional): `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`.

### Optional: "Download to server"

For development use. If the folder `DOWNLOAD_PATH` exists and is writable (i.e. a volume is mounted), a "Download to server" switch appears in the filters. While it is on, the normal Download buttons save the file into that folder on the server instead of downloading to the browser. Enable it by uncommenting the `./download:/download` line in `docker-compose.yml`. Without the mount the switch is not shown and the endpoint returns 404.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `BUNNY_API` | `https://cutebunny.io` | Base URL of the Bunny server. Change this to your own server. |
| `HWID_SALT` | `change-me` | Salt for the derived hardware ID. Set once, never change. |
| `SECRET_KEY` | random per start | Signs the Flask session cookie. If unset, everyone is logged out on every restart (and `docker-compose.yml` ships a `change-me-too` placeholder you must replace). |
| `REMEMBER_KEY` | generated in `DATA_DIR` | Fernet key for "stay signed in". |
| `DATA_DIR` | `/data` | Where `remember.json` and `remember.key` are stored. |
| `DOWNLOAD_PATH` | `/download` | Target folder for "Download to server" (feature appears only if it exists and is writable). |
| `STRICT_NAMES` | `1` | Force ASCII file names on upload and rename (`0` disables). |
| `VERIFY_TLS` | `1` | Verify the Bunny server's TLS certificate (`0` disables; avoid). |

## Repository layout

| Path | Contents |
|---|---|
| `app.py` | The whole application: routes, templates, JS, service worker, embedded icons |
| `Dockerfile` | Image build and gunicorn start command |
| `docker-compose.yml` | Service definition, environment placeholders, `/data` volume |
| `requirements.txt` | `flask`, `requests`, `gunicorn`, `cryptography` (unpinned) |
| `.gitignore` | Keeps keys, `.env`, data folders, databases and caches out of git |

## Routes (summary)

Public: `/login`, `/register`, `/manifest.webmanifest`, `/sw.js`, `/offline`, icons, `/favicon.ico`, and the redirect-only `/` and `/share`. Everything else needs a session: `/files`, `/download`, `/download-local` (POST), `/stream`, `/upload`, `/rename`, `/delete`, `/publish`, `/unpublish`, `/bulk-download` (POST), `/share-receive`, `/logout`. Icon, favicon and manifest URLs carry a `?v=` hash of the icon bytes and are served with `no-cache`, so an icon change is never masked by a cache.

## Security notes

- **TLS is not handled here.** The session and `rt` cookies are not marked `Secure`. Run it only behind HTTPS (or on a private network such as a VPN) so cookies and credentials are not sent in clear text.
- **Default secrets are placeholders.** Replace `HWID_SALT` and `SECRET_KEY` before use; do not commit real values.
- **"Stay signed in" stores the account password** (encrypted). With the default setup the Fernet key and the ciphertext both live in the same `/data` volume, so anyone who can read the volume can decrypt it. Supplying `REMEMBER_KEY` from outside the volume improves this. Leave the checkbox off if that is not acceptable.
- **Plain cookies** `lic` and `em` (license key and email) persist for a year.
- **No CSRF tokens.** `/logout` is a plain GET, so a cross-site link can log a user out. Protection for the rest relies on `SameSite=Lax` cookies and on state-changing endpoints being POST requests, most of them requiring custom headers (`X-File-Name` and similar). There is no rate limiting or lockout on login.
- **Previews** are served by `/stream` with `X-Content-Type-Options: nosniff` and `Content-Security-Policy: sandbox`. Templates are rendered with Jinja autoescaping.
- **Open redirect guard**: the `next` parameter after login only accepts same-site paths.
- **"Download to server"** writes with the container user's permissions, reduces the name to its base file name (no path traversal), and overwrites an existing file of the same name. Any logged-in user can trigger it, so mount the folder only on a trusted single-user deployment.
- Uploads have no size limit in this app.

## Limitations

- Single worker, sessions in memory: a restart ends all sessions (stay-signed-in users are logged in again automatically). Entries in `SESS` are only removed on logout or a failed refresh, so they accumulate slowly.
- File names with non-ASCII characters (emoji, Cyrillic) cannot be downloaded from the upstream server (Kestrel rejects non-ASCII response headers). The client therefore sanitizes new names, shows a warning badge on existing ones and suggests a rename. This is a workaround for a server bug, not a fix.
- The publish "end time" does not work upstream (the server's model uses the JSON key `accessStartTime`; the client sends that key). Treated as a dead feature.
- No folders; the Bunny server has a flat file list.
- No automated tests are included. Dependencies are not pinned.
- Seeking in videos re-reads the file from the start (no upstream range support).
