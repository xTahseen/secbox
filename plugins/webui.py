"""
SecureBox WebUI — compatible with the File Storage Bot schema.

DB schema (bot):
  folders: { _id, user_id, name }
  files:   { _id, user_id, folder_id, folder_name, file_name,
              telegram_file_id, file_type }
  settings:{ user_id, default_folder_id, webui_password_hash }

WebUI account is managed via /webui in the Telegram bot.
"""
import hashlib, hmac, json, logging, os, secrets, time, urllib.parse
from datetime import datetime
from functools import wraps
from aiohttp import web
from bson import ObjectId

logger = logging.getLogger(__name__)

CHUNK_SIZE = 1024 * 1024  # 1 MiB


# ── Streaming helper ──────────────────────────────────────────────────────────

async def _get_file_size(client, tg_file_id):
    """Probe Telegram for the real file size when it's missing from the DB."""
    try:
        tg_file = await client.get_file(tg_file_id)
        return getattr(tg_file, "file_size", None)
    except Exception:
        return None


async def _pyro_stream_response(request, client, tg_file_id, file_size, file_name,
                                content_type, disposition="inline"):
    """Stream a Telegram file via Pyrogram MTProto (supports Range requests)."""

    # If file_size is missing, ask Telegram — this is required for proper
    # HTTP Range support so browsers can seek/buffer without a full download.
    if not file_size:
        file_size = await _get_file_size(client, tg_file_id)

    range_header = request.headers.get("Range")
    start, end = 0, (file_size - 1) if file_size else None

    if range_header and file_size:
        try:
            units, rng = range_header.split("=")
            s, e = rng.split("-")
            start = int(s) if s else 0
            end   = int(e) if e else file_size - 1
        except Exception:
            start, end = 0, file_size - 1
        end = min(end, file_size - 1)

    status  = 206 if range_header and file_size else 200
    headers = {
        "Content-Disposition": f'{disposition}; filename="{urllib.parse.quote(file_name)}"',
        "Content-Type": content_type,
        "Accept-Ranges": "bytes",
    }
    if file_size:
        headers["Content-Length"] = str(end - start + 1)
        if status == 206:
            headers["Content-Range"] = f"bytes {start}-{end}/{file_size}"

    resp = web.StreamResponse(status=status, headers=headers)
    await resp.prepare(request)

    if not file_size:
        # Last resort: stream without range support
        async for chunk in client.stream_media(tg_file_id):
            await resp.write(chunk)
        await resp.write_eof()
        return resp

    first_chunk_idx  = start // CHUNK_SIZE
    last_chunk_idx   = end   // CHUNK_SIZE
    offset_in_first  = start % CHUNK_SIZE
    bytes_remaining  = end - start + 1
    chunk_idx        = first_chunk_idx

    async for chunk in client.stream_media(tg_file_id, offset=first_chunk_idx,
                                            limit=last_chunk_idx - first_chunk_idx + 1):
        data = chunk
        if chunk_idx == first_chunk_idx:
            data = data[offset_in_first:]
        if len(data) > bytes_remaining:
            data = data[:bytes_remaining]
        if data:
            await resp.write(data)
            bytes_remaining -= len(data)
        chunk_idx += 1
        if bytes_remaining <= 0:
            break

    await resp.write_eof()
    return resp


# ── Auth ──────────────────────────────────────────────────────────────────────

def _secret():
    return os.getenv("WEBUI_SECRET_KEY", "securebox-secret-change-me")

def _sign(payload):
    import base64
    d = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    s = hmac.new(_secret().encode(), d.encode(), hashlib.sha256).hexdigest()
    return f"{d}.{s}"

def _verify(token):
    try:
        import base64
        d, s = token.rsplit(".", 1)
        if not hmac.compare_digest(s, hmac.new(_secret().encode(), d.encode(), hashlib.sha256).hexdigest()):
            return None
        p = json.loads(base64.urlsafe_b64decode(d).decode())
        return None if p.get("exp", 0) < time.time() else p
    except Exception:
        return None

SESSION_TTL = 6 * 3600  # 6 hours — both the cookie's max_age and the signed exp claim

def _make_token(uid, ver=0):
    return _sign({"uid": uid, "ver": ver, "exp": time.time() + SESSION_TTL})

def _hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def _fmt_size(b):
    if not b: return "0 B"
    b = int(b)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if b < 1024: return f"{b} {u}" if u == "B" else f"{b:.1f} {u}"
        b /= 1024
    return f"{b:.2f} TB"

# ── Public share links ───────────────────────────────────────────────────────
# shares collection schema:
#   { _id, user_id, resource_type: "file"|"folder", resource_id (str),
#     token (str, unique, url-safe), password_hash (str|None), created_at }
#
# A resource (file or folder) has at most one active share document. Sharing
# again while one exists rotates/updates that same document instead of
# creating duplicates, so a given file/folder always maps to one stable token.

def _gen_share_token():
    return secrets.token_urlsafe(16)

def _share_base_url():
    # Reuse the WEBUI_BASE_URL convention used elsewhere in the bot (e.g.
    # plugins/callbacks.py), but strip any path it might already carry (it's
    # normally set to something like "https://host/drive?folder=").
    raw = os.getenv("WEBUI_BASE_URL", "")
    if raw:
        for cut in ("/drive", "/files"):
            idx = raw.find(cut)
            if idx != -1:
                raw = raw[:idx]
                break
        return raw.rstrip("/")
    return ""

def _share_sign_pw(token):
    """Token proving a visitor supplied the correct password for this share,
    stored in a short-lived cookie scoped to that one share token."""
    import base64
    payload = {"tok": token, "exp": time.time() + 86400}
    d = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    s = hmac.new(_secret().encode(), d.encode(), hashlib.sha256).hexdigest()
    return f"{d}.{s}"

def _share_verify_pw_cookie(token, cookie_val):
    if not cookie_val:
        return False
    try:
        import base64
        d, s = cookie_val.rsplit(".", 1)
        if not hmac.compare_digest(s, hmac.new(_secret().encode(), d.encode(), hashlib.sha256).hexdigest()):
            return False
        p = json.loads(base64.urlsafe_b64decode(d).decode())
        return p.get("tok") == token and p.get("exp", 0) >= time.time()
    except Exception:
        return False

async def _find_share(shares_col, resource_type, resource_id, uid):
    return await shares_col.find_one({
        "resource_type": resource_type, "resource_id": resource_id, "user_id": uid,
    })

async def _shares_index_map(shares_col, uid, file_ids, folder_ids):
    """Bulk-fetch share docs for a set of file/folder ids, keyed for quick
    lookup so list views can show a share badge without N+1 queries."""
    if not file_ids and not folder_ids:
        return {}
    cursor = shares_col.find({
        "user_id": uid,
        "$or": [
            {"resource_type": "file", "resource_id": {"$in": list(file_ids)}},
            {"resource_type": "folder", "resource_id": {"$in": list(folder_ids)}},
        ],
    })
    out = {}
    async for d in cursor:
        out[(d["resource_type"], d["resource_id"])] = d
    return out


def require_auth(handler):
    @wraps(handler)
    async def wrapper(request):
        tok = request.cookies.get("session")
        p   = _verify(tok) if tok else None
        if p:
            # A signature+exp check alone isn't enough to catch "this account's
            # credentials were changed/cleared since this cookie was issued" —
            # that requires a live DB check against session_version, which
            # account.py bumps on password change and on account clear.
            settings_col = request.app["settings_col"]
            doc = await settings_col.find_one({"user_id": p["uid"]})
            current_ver = (doc or {}).get("session_version", 0)
            if p.get("ver", 0) != current_ver:
                p = None
        if not p:
            if request.path.startswith("/api/"):
                raise web.HTTPUnauthorized()
            raise web.HTTPFound("/?next=" + str(request.rel_url))
        request["uid"] = p["uid"]
        return await handler(request)
    return wrapper


# ── SVG Icons ─────────────────────────────────────────────────────────────────

def _icon(name, size=20, cls="", bg=None):
    ca = f' class="{cls}"' if cls else ""
    M = {
        "folder":      '<path d="M2.25 12.75V12A2.25 2.25 0 014.5 9.75h15A2.25 2.25 0 0121.75 12v.75m-8.69-6.44l-2.12-2.12a1.5 1.5 0 00-1.061-.44H4.5A2.25 2.25 0 002.25 6v12a2.25 2.25 0 002.25 2.25h15A2.25 2.25 0 0021.75 18V9a2.25 2.25 0 00-2.25-2.25h-5.379a1.5 1.5 0 01-1.06-.44z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
        "file":        '<path d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m2.25 0H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
        "image":       '<path d="M2.25 15.75l5.159-5.159a2.25 2.25 0 013.182 0l5.159 5.159m-1.5-1.5l1.409-1.409a2.25 2.25 0 013.182 0l2.909 2.909m-18 3.75h16.5a1.5 1.5 0 001.5-1.5V6a1.5 1.5 0 00-1.5-1.5H3.75A1.5 1.5 0 002.25 6v12a1.5 1.5 0 001.5 1.5zm10.5-11.25h.008v.008h-.008V8.25zm.375 0a.375.375 0 11-.75 0 .375.375 0 01.75 0z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
        "video":       '<path d="M15.75 10.5l4.72-4.72a.75.75 0 011.28.53v11.38a.75.75 0 01-1.28.53l-4.72-4.72M4.5 18.75h9a2.25 2.25 0 002.25-2.25v-9a2.25 2.25 0 00-2.25-2.25h-9A2.25 2.25 0 002.25 7.5v9a2.25 2.25 0 002.25 2.25z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
        "audio":       '<path d="M9 9l10.5-3m0 6.553v3.75a2.25 2.25 0 01-1.632 2.163l-1.32.377a1.803 1.803 0 11-.99-3.467l2.31-.66a2.25 2.25 0 001.632-2.163zm0 0V2.25L9 5.25v10.303m0 0v3.75a2.25 2.25 0 01-1.632 2.163l-1.32.377a1.803 1.803 0 01-.99-3.467l2.31-.66A2.25 2.25 0 009 15.553z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
        "home":        '<path d="M2.25 12l8.954-8.955a1.126 1.126 0 011.591 0L21.75 12M4.5 9.75v10.125c0 .621.504 1.125 1.125 1.125H9.75v-4.875c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125V21h4.125c.621 0 1.125-.504 1.125-1.125V9.75M8.25 21h8.25" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "search":      '<path d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 15.803 7.5 7.5 0 0015.803 15.803z" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "back":        '<path d="M10.5 19.5L3 12m0 0l7.5-7.5M3 12h18" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "plus":        '<path d="M12 4.5v15m7.5-7.5h-15" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "close":       '<path d="M6 18L18 6M6 6l12 12" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "upload":      '<path d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "download":    '<path d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "delete":      '<path d="M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 01-2.244 2.077H8.084a2.25 2.25 0 01-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 00-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 013.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 00-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 00-7.5 0" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "rename":      '<path d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L6.832 19.82a4.5 4.5 0 01-1.897 1.13l-2.685.8.8-2.685a4.5 4.5 0 011.13-1.897L16.863 4.487zm0 0L19.5 7.125" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "move":        '<path d="M7.5 21L3 16.5m0 0L7.5 12M3 16.5h13.5m0-13.5L21 7.5m0 0L16.5 12M21 7.5H7.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "copy":        '<path d="M15.75 17.25v3.375c0 .621-.504 1.125-1.125 1.125h-9.75a1.125 1.125 0 01-1.125-1.125V7.875c0-.621.504-1.125 1.125-1.125H6.75a9.06 9.06 0 011.5.124m7.5 10.376h3.375c.621 0 1.125-.504 1.125-1.125V11.25c0-4.46-3.243-8.161-7.5-8.876a9.06 9.06 0 00-1.5-.124H9.375c-.621 0-1.125.504-1.125 1.125v3.5m7.5 10.376H9.375a1.125 1.125 0 01-1.125-1.126v-9.25m12 6.625v-1.875a3.375 3.375 0 00-3.375-3.375h-1.5a1.125 1.125 0 01-1.125-1.125v-1.5a3.375 3.375 0 00-3.375-3.375H9.75" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "chart":       '<path d="M3 13.125C3 12.504 3.504 12 4.125 12h2.25c.621 0 1.125.504 1.125 1.125v6.75C7.5 20.496 6.996 21 6.375 21h-2.25A1.125 1.125 0 013 19.875v-6.75zM9.75 8.625c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125v11.25c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V8.625zM16.5 4.125c0-.621.504-1.125 1.125-1.125h2.25C20.496 3 21 3.504 21 4.125v15.75c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V4.125z" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "newfolder":   '<path d="M12 10.5v6m3-3H9m4.06-7.19l-2.12-2.12a1.5 1.5 0 00-1.061-.44H4.5A2.25 2.25 0 002.25 6v12a2.25 2.25 0 002.25 2.25h15A2.25 2.25 0 0021.75 18V9a2.25 2.25 0 00-2.25-2.25h-5.379a1.5 1.5 0 01-1.06-.44z" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "signout":     '<path d="M15.75 9V5.25A2.25 2.25 0 0013.5 3h-6a2.25 2.25 0 00-2.25 2.25v13.5A2.25 2.25 0 007.5 21h6a2.25 2.25 0 002.25-2.25V15M12 9l-3 3m0 0l3 3m-3-3h12.75" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "alert":       '<path d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "login_arrow": '<path d="M15.75 9V5.25A2.25 2.25 0 0013.5 3h-6a2.25 2.25 0 00-2.25 2.25v13.5A2.25 2.25 0 007.5 21h6a2.25 2.25 0 002.25-2.25V15m3 0l3-3m0 0l-3-3m3 3H9" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "lock":        '<path d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "refresh":     '<path d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0l3.181 3.183a8.25 8.25 0 0013.803-3.7M4.031 9.865a8.25 8.25 0 0113.803-3.7l3.181 3.182m0-4.991v4.99" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "share":       '<path d="M7.217 10.907a2.25 2.25 0 100 2.186m0-2.186c.18.324.283.696.283 1.093s-.103.77-.283 1.093m0-2.186l9.566-5.314m-9.566 7.5l9.566 5.314m0 0a2.25 2.25 0 103.935 2.186 2.25 2.25 0 00-3.935-2.186zm0-12.814a2.25 2.25 0 103.933-2.185 2.25 2.25 0 00-3.933 2.185z" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "link":        '<path d="M13.19 8.688a4.5 4.5 0 011.242 7.244l-4.5 4.5a4.5 4.5 0 01-6.364-6.364l1.757-1.757m13.35-.622l1.757-1.757a4.5 4.5 0 00-6.364-6.364l-4.5 4.5a4.5 4.5 0 001.242 7.244" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
        "globe":       '<path d="M12 21a9 9 0 100-18 9 9 0 000 18zM3.6 9h16.8M3.6 15h16.8M12 3a14.91 14.91 0 013.76 9 14.91 14.91 0 01-3.76 9 14.91 14.91 0 01-3.76-9A14.91 14.91 0 0112 3z" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
    }
    path = M.get(name, M["file"])
    svg  = f'<svg{ca} width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">{path}</svg>'
    if bg:
        return f'<div class="icon-bg" style="background-color:{bg}">{svg}</div>'
    return svg

def _file_icon(ft, size=20, file_name=""):
    # Resolve the effective type: documents with video/audio/image extensions
    # should show the matching icon, consistent with the webui file manager.
    if ft == "document" and file_name:
        resolved = _get_share_preview_kind(ft, file_name)
        if resolved in ("video", "audio", "photo"):
            ft = resolved
    m = {"photo": "#a78bfa", "video": "#f87171", "audio": "#e55835", "document": "#607d8b"}
    i = {"photo": "image", "video": "video", "audio": "audio"}
    return _icon(i.get(ft, "file"), size, "", m.get(ft, "#607d8b"))


_PLAY_TRIANGLE_SVG = (
    '<svg viewBox="0 0 24 24" fill="white"><path d="M8 5v14l11-7z"/></svg>'
)

def _share_thumb_html(token, fid, ft, file_name, has_thumb):
    """Server-rendered equivalent of the WebUI's thumbHTML() — used for the
    public share folder browser, which is plain HTML (no client JS file
    list). Falls back to the generic colored icon if there's no captured
    thumbnail, or via onerror if the thumb request fails at render time."""
    resolved = ft
    if ft == "document" and file_name:
        r = _get_share_preview_kind(ft, file_name)
        if r in ("video", "audio", "photo"):
            resolved = r
    if not has_thumb or resolved not in ("photo", "video", "audio"):
        return _file_icon(ft, 28, file_name)
    fallback_icon = _file_icon(ft, 28, file_name).replace('"', "&quot;")
    play_overlay = f'<span class="sri-thumb-play">{_PLAY_TRIANGLE_SVG}</span>' if resolved in ("video", "audio") else ""
    return (
        f'<span class="sri-thumb-wrap">'
        f'<img class="sri-thumb" loading="lazy" src="/s/{token}/thumb?fid={fid}" '
        f'onerror="this.parentElement.outerHTML=\'{fallback_icon}\'">'
        f'{play_overlay}'
        f'</span>'
    )


_PREVIEW_VID_EXTS = {"mp4","webm","ogv","mov","mkv","avi","m4v","3gp","flv"}
_PREVIEW_AUD_EXTS = {"mp3","m4a","ogg","oga","opus","wav","flac","aac","weba","wma","amr"}
_PREVIEW_IMG_EXTS = {"jpg","jpeg","png","gif","webp","bmp"}
_PREVIEW_TXT_EXTS = {"txt","md","py","js","ts","json","yaml","yml","toml","ini","cfg","csv","html","htm","xml","sh","bat","log","css","c","cpp","h","java","go","rs","rb","php","swift","kt"}

def _get_share_preview_kind(ft, file_name):
    """Return 'photo'|'video'|'audio'|'text'|None for a file, to decide if preview is possible."""
    if ft == "photo":
        return "photo"
    if ft == "video":
        return "video"
    if ft == "audio":
        return "audio"
    ext = file_name.rsplit(".", 1)[-1].lower() if "." in file_name else ""
    if ft == "document":
        if ext in _PREVIEW_VID_EXTS:
            return "video"
        if ext in _PREVIEW_AUD_EXTS:
            return "audio"
        if ext in _PREVIEW_IMG_EXTS:
            return "photo"
        if ext in _PREVIEW_TXT_EXTS:
            return "text"
        # plain text fallback — browser will try to render it
        if "." not in file_name or ext in {"pdf"}:
            return None
        return "text"  # attempt text viewer for unknown docs
    return None


# ── CSS ───────────────────────────────────────────────────────────────────────

_CSS = """
:root{--bg:#000000;--header:#171717;--surface:#1a1a1a;--surface2:#222222;--surface3:#2a2a2a;--border:#2c2c2c;--border2:#3a3a3a;--accent:#0483c3;--accent2:#0369a1;--accent-dim:rgba(4,131,195,.13);--green:#22c55e;--red:#ef4444;--yellow:#f59e0b;--fab:#ffb200;--fab2:#e6a000;--text:#f0f0f0;--text2:#a0a0a0;--text3:#555;--folder:#0483c3;--r4:4px;--r8:8px;--r12:12px;--r16:16px;--sans:'Google Sans','Roboto','Segoe UI',system-ui,-apple-system,sans-serif;--shadow:0 8px 32px rgba(0,0,0,.6)}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{height:100%;-webkit-text-size-adjust:100%}
body{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:15px;height:100%;-webkit-font-smoothing:antialiased;overflow-x:hidden}
a{color:var(--accent);text-decoration:none}
::-webkit-scrollbar{width:4px;height:4px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:var(--border2);border-radius:2px}
#bar{position:fixed;top:0;left:0;right:0;height:3px;background:var(--accent);transform:scaleX(0);transform-origin:left;transition:transform .4s;z-index:9999;opacity:0}
#bar.on{transform:scaleX(.7);opacity:1}#bar.done{transform:scaleX(1);opacity:0;transition:transform .3s,opacity .4s .2s}
#toast{position:fixed;bottom:90px;left:50%;transform:translateX(-50%) translateY(20px);background:var(--surface2);border:1px solid var(--border2);color:var(--text);border-radius:24px;padding:12px 22px;font-size:14px;z-index:9999;opacity:0;pointer-events:none;transition:all .22s ease;white-space:nowrap;box-shadow:var(--shadow)}
#toast.show{transform:translateX(-50%) translateY(0);opacity:1}#toast.ok{border-color:var(--green);color:var(--green)}#toast.err{border-color:var(--red);color:var(--red)}#toast.warn{border-color:var(--yellow);color:var(--yellow)}
.btn{display:inline-flex;align-items:center;gap:8px;border:none;border-radius:var(--r8);cursor:pointer;font-size:14px;font-weight:500;font-family:var(--sans);transition:all .15s;white-space:nowrap;padding:0 16px;height:40px}
.btn:active{transform:scale(.97)}.btn-primary{background:var(--accent);color:#fff}.btn-primary:hover{background:var(--accent2)}.btn-ghost{background:transparent;color:var(--text2);border:1px solid var(--border2)}.btn-ghost:hover{background:var(--surface3);color:var(--text)}.btn-danger{background:rgba(239,68,68,.15);color:var(--red);border:1px solid rgba(239,68,68,.3)}.btn-danger:hover{background:rgba(239,68,68,.25)}.btn-icon{width:40px;height:40px;padding:0;border-radius:var(--r8);background:transparent;color:var(--text2);border:none;justify-content:center;display:inline-flex;align-items:center}.btn-icon:hover{background:var(--surface3);color:var(--text)}.btn-sm{height:34px;padding:0 13px;font-size:13px}.btn-wide{width:100%;justify-content:center}
input,select{background:var(--surface3);color:var(--text);border:1px solid var(--border);border-radius:var(--r8);padding:11px 14px;font-size:15px;font-family:var(--sans);width:100%;outline:none;transition:border-color .15s,box-shadow .15s}
input:focus,select:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-dim)}input::placeholder{color:var(--text3)}
nav{background:#171717;padding:0 14px;display:flex;align-items:center;gap:10px;height:58px;position:sticky;top:0;z-index:200}
.nav-logo{display:flex;align-items:center;gap:10px;text-decoration:none;flex-shrink:0}.nav-logo img{width:32px;height:32px;object-fit:contain}.nav-logo-wordmark{font-size:18px;font-weight:800;color:var(--text)}.nav-logo-wordmark span{color:var(--accent)}.nav-logo-icon{color:var(--accent)}.nav-avatar{position:relative;flex-shrink:0}.nav-av-btn{width:36px;height:36px;border-radius:50%;border:2px solid var(--border2);background:var(--surface2);cursor:pointer;display:flex;align-items:center;justify-content:center;overflow:hidden;transition:border-color .18s}.nav-av-btn:hover{border-color:var(--accent)}.nav-av-btn img{width:100%;height:100%;object-fit:cover}.nav-av-initials{font-size:14px;font-weight:700;color:var(--accent)}
#av-popup{display:none;position:fixed;top:62px;right:12px;z-index:1200;background:rgba(26,26,26,.82);backdrop-filter:blur(24px) saturate(160%);-webkit-backdrop-filter:blur(24px) saturate(160%);border:1px solid rgba(255,255,255,.09);border-radius:var(--r16);padding:20px;width:290px;max-width:calc(100vw - 24px);box-shadow:0 12px 48px rgba(0,0,0,.7);animation:mIn .18s ease}
#av-popup.open{display:block}
.avp-head{display:flex;align-items:center;gap:14px;margin-bottom:16px}
.avp-avatar{width:52px;height:52px;border-radius:50%;overflow:hidden;flex-shrink:0;background:var(--accent);display:flex;align-items:center;justify-content:center;font-size:20px;font-weight:700;color:#fff;position:relative}
.avp-avatar img{width:100%;height:100%;object-fit:cover;position:absolute;inset:0;display:none}
.avp-name{font-size:14px;font-weight:700;color:var(--text);word-break:break-word}
.avp-uid{font-size:12px;color:var(--text3);margin-top:2px}
.avp-section{margin-top:14px;border-top:1px solid var(--border);padding-top:14px}
.avp-section-label{font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--text3);margin-bottom:10px}
.avp-stat-card{display:flex;align-items:center;gap:12px}
.avp-stat-icon{width:38px;height:38px;border-radius:var(--r12);background:var(--accent-dim);color:var(--accent);display:flex;align-items:center;justify-content:center;flex-shrink:0}
.avp-stat-num{font-size:18px;font-weight:700;color:var(--text);line-height:1.2}
.avp-stat-label{font-size:12px;color:var(--text3)}
.avp-sk{height:14px;width:60%;border-radius:var(--r4);background:linear-gradient(90deg,var(--surface2) 25%,var(--surface3) 50%,var(--surface2) 75%);background-size:200% 100%;animation:sk 1.4s infinite}
.ac-sw{width:28px;height:28px;border-radius:50%;cursor:pointer;transition:all .15s;flex-shrink:0;outline:none}

.nav-center{flex:1;display:flex;justify-content:center;padding:0 8px}
.nav-search-wrap{display:flex;align-items:center;gap:8px;background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.1);border-radius:24px;padding:0 14px;height:38px;width:100%;max-width:420px;transition:background .18s,border-color .18s,box-shadow .18s}
.nav-search-wrap:focus-within{background:rgba(255,255,255,.11);border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-dim)}.nav-search-wrap svg{color:var(--text3);flex-shrink:0}
#nav-search-input{background:transparent;border:none;outline:none;color:var(--text);font-size:14px;font-family:var(--sans);width:100%;padding:0;box-shadow:none}#nav-search-input::placeholder{color:var(--text3)}
.toolbar{display:flex;align-items:center;gap:8px;padding:10px 14px;background:#171717;flex-shrink:0;min-height:52px}
.breadcrumb{display:flex;align-items:center;gap:2px;flex:1;min-width:0;overflow-x:auto;overflow-y:hidden;scroll-behavior:smooth;scrollbar-width:none;-ms-overflow-style:none}.breadcrumb::-webkit-scrollbar{display:none}
.bc-crumb{color:var(--text2);cursor:pointer;padding:5px 8px;border-radius:var(--r4);font-size:15px;text-transform:uppercase;white-space:nowrap;transition:all .1s;flex-shrink:0}.bc-crumb:hover{background:var(--surface2);color:var(--text)}.bc-crumb.last{color:var(--accent);cursor:default;font-weight:600}.bc-crumb.last:hover{background:transparent}.bc-sep{color:var(--text3);flex-shrink:0;font-size:25px}
.layout{display:flex;height:calc(100vh - 58px);overflow:hidden}
.sidebar{width:230px;flex-shrink:0;background:var(--header);border-right:1px solid var(--border);padding:12px 8px;display:flex;flex-direction:column;gap:2px;overflow-y:auto}
.sb-item{display:flex;align-items:center;gap:10px;padding:11px 12px;border-radius:var(--r8);cursor:pointer;font-size:15px;font-weight:500;color:var(--text2);transition:all .12s;border:1px solid transparent}.sb-item:hover{background:var(--surface2);color:var(--text)}.sb-item.active{background:var(--accent-dim);color:var(--accent);border-color:rgba(4,131,195,.2)}.sb-item svg{flex-shrink:0}
.sb-divider{height:1px;background:var(--border);margin:8px 4px}.sb-label{font-size:11px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--text3);padding:8px 12px 3px}
.drive-tab{display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:var(--r8);cursor:pointer;font-size:13px;color:var(--text2);transition:all .12s;border:1px solid transparent}.drive-tab:hover{background:var(--surface2);color:var(--text)}.drive-tab.active{background:var(--accent-dim);color:var(--accent)}
.main{flex:1;display:flex;flex-direction:column;overflow:hidden;min-width:0}.file-area{flex:1;overflow-y:auto;padding-bottom:100px}
.file-item{display:flex;align-items:center;gap:16px;padding:10px 12px;border-bottom:.9px solid rgba(44,44,44,.6);cursor:pointer;transition:background .08s;position:relative;user-select:none;-webkit-user-select:none}.file-item:active{background:var(--surface2)}.file-item.sel{background:rgba(4,131,195,.1)}.file-item.sel .fi-cb{display:flex}
.fi-cb{display:none;width:20px;height:20px;flex-shrink:0;align-items:center;justify-content:center}body.select-mode .fi-cb{display:flex}
.custom-cb{width:20px;height:20px;border-radius:50%;border:2px solid var(--border2);background:transparent;display:flex;align-items:center;justify-content:center;cursor:pointer;transition:all .18s ease;flex-shrink:0;position:relative}
.custom-cb::after{content:'';width:0;height:0;border-radius:50%;background:var(--accent);transition:all .15s ease;position:absolute}
.custom-cb.checked{background:var(--accent);border-color:var(--accent);box-shadow:0 2px 8px rgba(4,131,195,.4)}
.custom-cb.checked::after{content:'';width:7px;height:4px;background:transparent;border-radius:0;border-left:2px solid #fff;border-bottom:2px solid #fff;transform:rotate(-45deg) translateY(-1px);position:static}
.custom-cb:not(.checked):hover{border-color:var(--accent);background:var(--accent-dim)}
.fi-icon{flex-shrink:0;display:flex;align-items:center;justify-content:center;width:46px;height:46px}
.fi-thumb-wrap,.sri-thumb-wrap{position:relative;flex-shrink:0;display:block;width:46px;height:46px;border-radius:50%;box-shadow:0 2px 8px rgba(0,0,0,.3)}
.fi-thumb,.sri-thumb{width:46px;height:46px;border-radius:50%;object-fit:cover;display:block;background:var(--bg2,#1a1a1a)}
.fi-thumb-play,.sri-thumb-play{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);display:flex;align-items:center;justify-content:center;pointer-events:none;filter:drop-shadow(0 1px 3px rgba(0,0,0,.65))}
.fi-thumb-play svg,.sri-thumb-play svg{width:18px;height:18px}
.icon-bg{display:flex;align-items:center;justify-content:center;width:46px;height:46px;border-radius:50%;flex-shrink:0;box-shadow:0 2px 8px rgba(0,0,0,.3)}.icon-bg svg{width:24px;height:24px;color:white;stroke:white}
.fi-info{flex:1;min-width:0;overflow:hidden}
.fi-name{font-size:16px;font-weight:400;color:var(--text);white-space:normal;overflow-wrap:break-word;word-break:break-word;line-height:1.3}.fi-name.fol{font-weight:400}
.fi-meta{display:flex;justify-content:space-between;align-items:center;margin-top:3px;width:100%}.fi-size{font-size:12px;color:var(--text3)}.fi-date{font-size:12px;color:var(--text3);margin-left:auto;padding-left:8px;white-space:nowrap}
.fi-act{position:absolute;right:10px;top:50%;transform:translateY(-50%);opacity:0;transition:opacity .15s;pointer-events:none}
@media(hover:hover){.file-item:hover .fi-act{opacity:1;pointer-events:auto}}
.empty{display:flex;flex-direction:column;align-items:center;justify-content:center;padding:80px 24px;gap:16px;color:var(--text3)}.empty-icon{opacity:.35}.empty h3{font-size:20px;font-weight:600;color:var(--text2)}.empty p{font-size:14px}
.sk{background:linear-gradient(90deg,var(--surface) 25%,var(--surface3) 50%,var(--surface) 75%);background-size:200% 100%;animation:sk 1.4s infinite;border-radius:var(--r4)}
@keyframes sk{0%{background-position:200% 0}100%{background-position:-200% 0}}.sk-n{height:15px;width:55%}.sk-s{height:12px;width:30%}.sk-i{height:28px;width:28px;border-radius:var(--r4);flex-shrink:0}
#fab{position:fixed;bottom:24px;right:20px;z-index:400;display:flex;flex-direction:column;align-items:flex-end;gap:12px;transition:bottom .3s ease}body.select-mode #fab{bottom:96px}
#fab-share{display:none}
body.select-mode.share-eligible #fab-share{display:flex}
.fab-main{width:58px;height:58px;border-radius:50%;background:var(--fab);color:#fff;border:none;display:flex;align-items:center;justify-content:center;cursor:pointer;box-shadow:0 4px 20px rgba(255,178,0,.4);transition:all .2s;flex-shrink:0}
.fab-main:hover{background:var(--fab2);transform:scale(1.06)}.fab-main:active{transform:scale(.96)}.fab-main.open{transform:rotate(45deg)}.fab-main.open:hover{transform:rotate(45deg) scale(1.06)}
.fab-options{display:flex;flex-direction:column;align-items:flex-end;gap:10px;transform-origin:bottom right;animation:fabIn .18s ease}
@keyframes fabIn{from{opacity:0;transform:scale(.85) translateY(10px)}}
.fab-opt{display:flex;align-items:center;gap:10px;background:var(--surface2);border:1px solid var(--border2);border-radius:28px;padding:10px 18px 10px 14px;cursor:pointer;font-size:14px;font-weight:600;color:var(--text);box-shadow:0 4px 16px rgba(0,0,0,.5);transition:all .15s;white-space:nowrap}.fab-opt:hover{background:var(--surface3);border-color:var(--accent);color:var(--accent)}.fab-opt svg{flex-shrink:0}
#selbar{position:fixed;bottom:20px;left:50%;transform:translateX(-50%) translateY(100px);background:var(--surface2);border:1px solid var(--border2);border-radius:36px;padding:10px 14px;display:flex;align-items:center;gap:6px;box-shadow:0 8px 40px rgba(0,0,0,.7);z-index:1100;opacity:0;pointer-events:none;transition:transform .28s cubic-bezier(.34,1.56,.64,1),opacity .18s;max-width:calc(100vw - 32px)}
#selbar.show{transform:translateX(-50%) translateY(0);opacity:1;pointer-events:auto}#selcnt{font-size:13px;color:var(--text2);padding:0 4px;white-space:nowrap}
.selbar-sep{width:1px;height:22px;background:var(--border2);margin:0 2px;flex-shrink:0}
.sel-btn{display:flex;flex-direction:column;align-items:center;gap:2px;background:transparent;border:none;cursor:pointer;padding:6px 8px;border-radius:var(--r8);color:var(--text2);transition:all .12s;flex-shrink:0}.sel-btn:hover{background:var(--surface3);color:var(--text)}.sel-btn.danger{color:var(--red)}.sel-btn.danger:hover{background:rgba(239,68,68,.15)}.sel-btn span{font-size:10px;font-weight:600;white-space:nowrap}
.sel-close{width:30px;height:30px;border-radius:50%;background:var(--surface3);border:none;cursor:pointer;display:flex;align-items:center;justify-content:center;color:var(--text3);flex-shrink:0;margin-left:2px}.sel-close:hover{color:var(--text);background:var(--border2)}
.moverlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);backdrop-filter:blur(6px);z-index:1000;align-items:center;justify-content:center;padding:16px}.moverlay.open{display:flex}
.modal{background:var(--surface);border:1px solid var(--border2);border-radius:var(--r16);padding:22px 20px;width:100%;max-width:420px;box-shadow:var(--shadow);animation:mIn .2s ease;max-height:88vh;overflow-y:auto}
@keyframes mIn{from{transform:scale(.95) translateY(-8px);opacity:0}}.modal-title{font-size:16px;font-weight:700;margin-bottom:16px;display:flex;align-items:center;gap:9px;color:var(--text)}.fg{margin-bottom:14px}.fg label{display:block;font-size:11px;color:var(--text3);margin-bottom:5px;text-transform:uppercase;letter-spacing:.05em;font-weight:600}.macts{display:flex;gap:8px;justify-content:flex-end;margin-top:18px}
#preview-overlay{display:none;position:fixed;inset:0;z-index:2000;background:#000;flex-direction:column}#preview-overlay.open{display:flex}
#preview-bar{display:flex;align-items:center;gap:10px;padding:10px 14px;background:rgba(0,0,0,.85);backdrop-filter:blur(12px);border-bottom:1px solid rgba(255,255,255,.07);flex-shrink:0;min-height:52px;position:relative;z-index:10}
#preview-title{flex:1;min-width:0;font-size:14px;font-weight:500;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
#preview-dl-btn{width:36px;height:36px;border-radius:50%;border:none;cursor:pointer;background:rgba(255,255,255,.1);color:var(--text);display:flex;align-items:center;justify-content:center;flex-shrink:0;transition:background .15s}#preview-dl-btn:hover{background:var(--accent);color:#fff}#preview-copy-btn{width:36px;height:36px;border-radius:50%;border:none;cursor:pointer;background:rgba(255,255,255,.1);color:var(--text);display:none;align-items:center;justify-content:center;flex-shrink:0;transition:background .15s}#preview-copy-btn:hover{background:var(--accent);color:#fff}
#preview-close-btn{width:36px;height:36px;border-radius:50%;border:none;cursor:pointer;background:rgba(255,255,255,.08);color:var(--text2);display:flex;align-items:center;justify-content:center;flex-shrink:0;transition:background .15s,color .15s}#preview-close-btn:hover{background:rgba(239,68,68,.25);color:#ef4444}
#preview-body{flex:1;overflow:auto;display:flex;align-items:center;justify-content:center;padding:0;position:relative;background:#000}#img-viewer{position:relative;width:100%;height:100%;display:flex;align-items:center;justify-content:center;overflow:hidden}#img-viewer img{max-width:100%;max-height:100%;object-fit:contain;user-select:none;-webkit-user-select:none;transition:opacity .25s}.img-nav-btn{position:absolute;top:50%;transform:translateY(-50%);width:48px;height:48px;border-radius:50%;border:1px solid rgba(255,255,255,0.12);cursor:pointer;background:rgba(0,0,0,0.55);backdrop-filter:blur(8px);color:#fff;display:flex;align-items:center;justify-content:center;z-index:10;transition:all .18s;opacity:0}#img-viewer:hover .img-nav-btn{opacity:1}.img-nav-btn:hover{background:rgba(4,131,195,0.7);border-color:var(--accent);transform:translateY(-50%) scale(1.1)}.img-nav-btn.prev{left:14px}.img-nav-btn.next{right:14px}.img-nav-btn:disabled{opacity:0!important;pointer-events:none}.img-counter{position:absolute;bottom:16px;left:50%;transform:translateX(-50%);background:rgba(0,0,0,0.6);backdrop-filter:blur(8px);border:1px solid rgba(255,255,255,0.1);color:var(--text2);font-size:12px;font-weight:500;padding:5px 14px;border-radius:20px;pointer-events:none;white-space:nowrap}#video-player-wrap{position:relative;width:100%;height:100%;display:flex;flex-direction:column;background:#000;overflow:hidden}#video-player-wrap video{flex:1;width:100%;min-height:0;display:block}#vid-play-flash{width:72px;height:72px;border-radius:50%;background:rgba(0,0,0,.55);display:flex;align-items:center;justify-content:center;opacity:0;pointer-events:none;position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);z-index:3}#vid-play-flash.flash{animation:vidFlashAnim 0.45s ease forwards}@keyframes vidFlashAnim{0%{opacity:1;transform:translate(-50%,-50%) scale(1)}60%{opacity:1;transform:translate(-50%,-50%) scale(1.15)}100%{opacity:0;transform:translate(-50%,-50%) scale(1.25)}}#vid-overlay-center{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);z-index:4;pointer-events:auto;display:flex;align-items:center;justify-content:center;gap:18px;transition:opacity .3s}.vid-overlay-btn{border:none;background:rgba(0,0,0,0.52);backdrop-filter:blur(4px);border-radius:50%;display:flex;align-items:center;justify-content:center;color:#fff;cursor:pointer;opacity:0;transition:opacity .18s,transform .15s;border:1px solid rgba(255,255,255,0.18);flex-shrink:0}.vid-overlay-btn:active{transform:scale(.92)}.vid-overlay-btn.sm{width:48px;height:48px}.vid-overlay-btn.lg{width:64px;height:64px}#video-player-wrap:hover .vid-overlay-btn{opacity:1}#video-player-wrap.controls-hidden #vid-overlay-center{opacity:0;pointer-events:none}.vid-overlay-btn.dimmed{cursor:not-allowed;pointer-events:none}.vid-overlay-btn.dimmed svg{opacity:0.25}.vid-seek-ripple{position:absolute;top:50%;transform:translateY(-50%);pointer-events:none;z-index:6;display:flex;flex-direction:column;align-items:center;gap:4px}.vid-seek-ripple.left{left:24px}.vid-seek-ripple.right{right:24px}.vid-seek-ripple-icon{width:56px;height:56px;border-radius:50%;background:rgba(255,255,255,0.18);display:flex;align-items:center;justify-content:center;animation:seekRipple .5s ease forwards}.vid-seek-ripple-label{font-size:11px;font-weight:700;color:#fff;text-shadow:0 1px 4px rgba(0,0,0,.7);animation:seekRipple .5s ease forwards}@keyframes seekRipple{0%{opacity:1;transform:scale(1)}80%{opacity:1;transform:scale(1.1)}100%{opacity:0;transform:scale(1.15)}}#video-player-wrap::after{content:"";position:absolute;bottom:0;left:0;right:0;height:120px;background:linear-gradient(transparent,rgba(0,0,0,0.7));pointer-events:none;z-index:4;transition:opacity .3s}#video-player-wrap.controls-hidden::after{opacity:0}#vid-controls{position:absolute;bottom:0;left:0;right:0;z-index:5;padding:0 16px 14px;transition:opacity .3s,transform .3s}#video-player-wrap.controls-hidden #vid-controls{opacity:0;pointer-events:none;transform:translateY(8px)}#vid-progress-wrap{height:18px;display:flex;align-items:center;cursor:pointer;margin-bottom:8px;position:relative}#vid-progress-track{width:100%;height:4px;background:rgba(255,255,255,0.25);border-radius:4px;overflow:hidden;transition:height .18s;position:relative}#vid-progress-wrap:hover #vid-progress-track{height:6px}#vid-progress-buf{position:absolute;left:0;top:0;height:100%;background:rgba(255,255,255,0.25);border-radius:4px;pointer-events:none}#vid-progress-fill{position:absolute;left:0;top:0;height:100%;background:var(--accent);border-radius:4px;pointer-events:none}#vid-thumb{position:absolute;top:50%;width:14px;height:14px;border-radius:50%;background:#fff;transform:translate(-50%,-50%);pointer-events:none;box-shadow:0 1px 6px rgba(0,0,0,.5);opacity:0;transition:opacity .18s}#vid-progress-wrap:hover #vid-thumb{opacity:1}#vid-controls-row{display:flex;align-items:center;gap:10px}.vid-btn{width:36px;height:36px;border:none;background:transparent;color:#fff;cursor:pointer;display:flex;align-items:center;justify-content:center;border-radius:50%;flex-shrink:0;transition:background .15s}.vid-btn:hover{background:rgba(255,255,255,0.15)}#vid-time{font-size:13px;color:rgba(255,255,255,.9);font-weight:500;white-space:nowrap;flex-shrink:0;min-width:90px}#vid-title-bar{flex:1;min-width:0;font-size:13px;color:rgba(255,255,255,.7);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}#vid-vol-wrap{display:flex;align-items:center;gap:6px}.vid-counter-badge{font-size:11px;color:rgba(255,255,255,.55);padding:3px 8px;background:rgba(255,255,255,0.08);border-radius:12px;white-space:nowrap}#audio-player-wrap{width:100%;height:100%;display:flex;flex-direction:column;background:linear-gradient(160deg,#0d1117 0%,#111 60%,#0d1821 100%);overflow:hidden}#audio-now-playing{display:flex;flex-direction:column;align-items:center;justify-content:center;padding:28px 24px 20px;flex-shrink:0;gap:16px}#audio-art{width:120px;height:120px;border-radius:50%;background:linear-gradient(135deg,var(--accent),#1a3a5c);display:flex;align-items:center;justify-content:center;box-shadow:0 8px 40px rgba(4,131,195,.35);animation:audioSpin 8s linear infinite paused}#audio-art.playing{animation-play-state:running}@keyframes audioSpin{to{transform:rotate(360deg)}}#audio-now-title{font-size:16px;font-weight:700;color:var(--text);text-align:center;max-width:300px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}#audio-now-sub{font-size:12px;color:var(--text3)}#audio-scrubber-wrap{padding:0 24px;flex-shrink:0}#audio-progress-wrap{height:20px;display:flex;align-items:center;cursor:pointer;position:relative}#audio-progress-track{width:100%;height:3px;background:rgba(255,255,255,0.15);border-radius:3px;overflow:visible;position:relative;transition:height .18s}#audio-progress-wrap:hover #audio-progress-track{height:5px}#audio-progress-fill{position:absolute;left:0;top:0;height:100%;background:var(--accent);border-radius:3px;pointer-events:none}#audio-thumb{position:absolute;top:50%;width:12px;height:12px;border-radius:50%;background:#fff;transform:translate(-50%,-50%);opacity:0;pointer-events:none;transition:opacity .18s}#audio-progress-wrap:hover #audio-thumb{opacity:1}#audio-times{display:flex;justify-content:space-between;font-size:11px;color:var(--text3);margin-top:6px;padding:0 2px}#audio-controls{display:flex;align-items:center;justify-content:center;gap:6px;padding:12px 24px 8px;flex-shrink:0}.aud-btn{width:40px;height:40px;border:none;background:transparent;color:var(--text2);cursor:pointer;display:flex;align-items:center;justify-content:center;border-radius:50%;transition:all .15s}.aud-btn:hover{color:var(--text);background:rgba(255,255,255,.08)}#aud-play-btn{width:54px;height:54px;border-radius:50%;background:var(--accent);color:#fff;border:none;cursor:pointer;display:flex;align-items:center;justify-content:center;box-shadow:0 4px 20px rgba(4,131,195,.45);transition:all .18s}#aud-play-btn:hover{filter:brightness(1.15);transform:scale(1.05)}#audio-playlist-wrap{flex:1;min-height:0;display:flex;flex-direction:column;border-top:1px solid rgba(255,255,255,0.07)}#audio-playlist-header{display:flex;align-items:center;justify-content:space-between;padding:10px 20px 8px;flex-shrink:0;font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--text3)}#audio-playlist{flex:1;overflow-y:auto;padding:0 8px 16px}.apl-item{display:flex;align-items:center;gap:12px;padding:9px 12px;border-radius:var(--r8);cursor:pointer;transition:background .1s}.apl-item:hover{background:rgba(255,255,255,0.05)}.apl-item.active{background:rgba(4,131,195,0.15)}.apl-item.active .apl-name{color:var(--accent)}.apl-idx{font-size:12px;color:var(--text3);width:22px;text-align:center;flex-shrink:0}.apl-name{flex:1;min-width:0;font-size:13px;color:var(--text2);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}#text-viewer-wrap{width:100%;height:100%;display:flex;flex-direction:column;background:var(--bg)}#text-viewer-pre{flex:1;overflow:auto;margin:0;padding:20px 24px;font-family:var(--sans);font-size:13px;line-height:1.7;color:var(--text);white-space:pre-wrap;word-break:break-word;background:var(--bg)}
#preview-spinner{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;background:#000;z-index:5}#preview-spinner svg{animation:spin 1s linear infinite;color:var(--accent)}@keyframes spin{to{transform:rotate(360deg)}}
#preview-unsupported{display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:48px 32px;gap:0;min-height:320px}
.pu-icon-wrap{width:96px;height:96px;border-radius:50%;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);display:flex;align-items:center;justify-content:center;margin-bottom:24px;opacity:.75}
#preview-unsupported h3{font-size:20px;font-weight:700;color:var(--text);margin-bottom:10px}#preview-unsupported p{font-size:14px;color:var(--text3);margin-bottom:28px;max-width:340px;line-height:1.6}
.pu-dl-btn{display:inline-flex;align-items:center;gap:10px;padding:13px 28px;border-radius:50px;border:none;cursor:pointer;background:var(--accent);color:#fff;font-size:15px;font-weight:600;font-family:var(--sans);transition:all .2s;box-shadow:0 4px 20px rgba(4,131,195,.4)}.pu-dl-btn:hover{filter:brightness(1.12);transform:translateY(-1px)}
.dropzone{border:2px dashed var(--border2);border-radius:var(--r12);padding:24px 16px;text-align:center;color:var(--text3);cursor:pointer;transition:all .18s;position:relative}.dropzone:hover,.dropzone.dragover{border-color:var(--accent);color:var(--accent);background:var(--accent-dim)}.dropzone input[type=file]{position:absolute;inset:0;opacity:0;cursor:pointer;font-size:0}
.dz-icon{margin:0 auto 8px}.dz-txt{font-size:15px;font-weight:600;margin-top:2px}.dz-hint{font-size:12px;margin-top:4px;opacity:.7}
.ulist{margin-top:10px;max-height:160px;overflow-y:auto;display:flex;flex-direction:column;gap:6px}.uitem{padding:9px 11px;background:var(--surface2);border-radius:var(--r8);font-size:13px}.uitem-top{display:flex;align-items:center;gap:10px}.uname{flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.ust{color:var(--text3);white-space:nowrap}.ubar{height:3px;background:var(--border);border-radius:99px;overflow:hidden;margin-top:7px}.ufill{height:100%;background:var(--accent);border-radius:99px;transition:width .25s;width:0}
.ftree{max-height:220px;overflow-y:auto;border:1px solid var(--border);border-radius:var(--r8)}.fti{display:flex;align-items:center;gap:10px;padding:12px 14px;cursor:pointer;font-size:14px;border-bottom:1px solid rgba(44,44,44,.4);transition:background .09s}.fti:last-child{border-bottom:none}.fti:hover{background:var(--surface2)}.fti.sel{background:var(--accent-dim);color:var(--accent)}
.sri{display:flex;align-items:center;gap:14px;padding:10px 12px;cursor:pointer;border-bottom:.9px solid rgba(44,44,44,.6);transition:background .08s}.sri:last-child{border-bottom:none}.sri:active{background:var(--surface2)}.sri-icon{flex-shrink:0;display:flex;align-items:center;justify-content:center;width:46px;height:46px}.sri-info{flex:1;min-width:0;overflow:hidden}.sri-name{font-size:15px;font-weight:400;color:var(--text);white-space:normal;overflow-wrap:break-word;word-break:break-word}.sri-meta{display:flex;justify-content:space-between;align-items:center;margin-top:3px}.sri-size{font-size:12px;color:var(--text3)}.sri-date{font-size:12px;color:var(--text3);margin-left:auto;padding-left:8px;white-space:nowrap}.sri-dl-btn{flex-shrink:0;width:36px;height:36px;border-radius:50%;display:flex;align-items:center;justify-content:center;color:var(--text3);text-decoration:none;transition:background .15s,color .15s}.sri-dl-btn:hover{background:var(--accent-dim);color:var(--accent)}
.lp{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}.lcard{background:var(--header);border:1px solid var(--border2);border-radius:var(--r16);padding:40px 32px;width:100%;max-width:380px;box-shadow:var(--shadow)}.llogo{text-align:center;margin-bottom:32px}.llogo-img{width:64px;height:64px;object-fit:contain;margin:0 auto 16px;display:block}.llogo h1{font-size:26px;font-weight:800}.llogo p{color:var(--text2);font-size:14px;margin-top:6px}
.lerr{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);border-radius:var(--r8);padding:12px 14px;color:var(--red);font-size:14px;margin-bottom:16px;display:flex;align-items:center;gap:8px}.lhint{font-size:12px;color:var(--text3);text-align:center;margin-top:20px;line-height:1.6}
@media(max-width:640px){.sidebar{display:none}nav{padding:0 10px;gap:6px}.nav-search-wrap{max-width:100%}.toolbar{padding:8px 12px}.fab-main{width:54px;height:54px}#selbar{padding:8px 10px;gap:2px}.sel-btn span{display:none}.moverlay{padding:12px}}
.fi-shared-badge{display:inline-flex;align-items:center;justify-content:center;width:15px;height:15px;color:var(--accent);flex-shrink:0;margin-left:6px}.fi-shared-badge svg{width:13px;height:13px}
.fi-name-row{display:flex;align-items:flex-start;min-width:0}.fi-name-row .fi-name{flex:1;min-width:0}.fi-name-row .fi-shared-badge{margin-top:3px}
.share-status{display:flex;align-items:center;gap:12px;padding:12px 14px;border-radius:var(--r12);background:var(--surface2);border:1px solid var(--border);margin-bottom:16px}
.share-status-icon{width:38px;height:38px;border-radius:50%;background:var(--accent-dim);color:var(--accent);display:flex;align-items:center;justify-content:center;flex-shrink:0}
.share-status.off .share-status-icon{background:var(--surface3);color:var(--text3)}
.share-status-text{flex:1;min-width:0}.share-status-title{font-size:14px;font-weight:600;color:var(--text)}.share-status-sub{font-size:12px;color:var(--text3);margin-top:1px}
.switch{position:relative;width:42px;height:24px;flex-shrink:0}.switch input{opacity:0;width:0;height:0;position:absolute}
.switch-track{position:absolute;inset:0;background:var(--surface3);border:1px solid var(--border2);border-radius:99px;cursor:pointer;transition:all .18s}
.switch-track::after{content:'';position:absolute;width:18px;height:18px;border-radius:50%;background:#fff;top:2px;left:2px;transition:all .18s;box-shadow:0 1px 3px rgba(0,0,0,.4)}
.switch input:checked+.switch-track{background:var(--accent)}.switch input:checked+.switch-track::after{transform:translateX(18px)}
.share-link-row{display:flex;gap:8px;margin-bottom:14px}.share-link-row input{flex:1;font-size:13px;color:var(--text2);background:var(--surface3)}
.share-pw-row{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:14px}
.share-pw-row .lbl{display:flex;align-items:center;gap:8px;font-size:13px;color:var(--text2)}
#share-pw-field{margin-top:10px;display:none}
.share-spub-page{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;background:var(--bg)}
.spub-card{background:var(--header);border:1px solid var(--border2);border-radius:var(--r16);padding:36px 30px;width:100%;max-width:400px;box-shadow:var(--shadow);text-align:center}
.spub-icon{width:60px;height:60px;border-radius:50%;background:var(--accent-dim);color:var(--accent);display:flex;align-items:center;justify-content:center;margin:0 auto 18px}
.spub-name{font-size:17px;font-weight:700;color:var(--text);word-break:break-word;margin-bottom:6px}
.spub-meta{font-size:13px;color:var(--text3);margin-bottom:22px}
.spub-browse{max-width:640px;margin:0 auto;padding:20px}
"""


# ── Shared JS ─────────────────────────────────────────────────────────────────

_JS_BASE = """
function toast(msg,type){var t=document.getElementById('toast');t.textContent=msg;t.className='show '+(type||'');clearTimeout(t._t);t._t=setTimeout(function(){t.className=''},3500);}
function bar(on){var b=document.getElementById('bar');b.className=on?'on':'done';if(!on)setTimeout(function(){b.className=''},800);}
function openModal(id){document.getElementById('m-'+id).classList.add('open');}
function closeModal(id){document.getElementById('m-'+id).classList.remove('open');}
document.addEventListener('DOMContentLoaded',function(){
  document.querySelectorAll('.moverlay').forEach(function(el){
    el.addEventListener('click',function(e){if(e.target===el)el.classList.remove('open');});
  });
  /* Read URL params to restore folder/file state on page load or share link */
  var params=new URLSearchParams(window.location.search);
  var urlFolder=params.get('folder');
  var urlFile=params.get('file');
  if(urlFolder){
    folder=urlFolder; folderName=''; stack=[{id:urlFolder,name:''}];
    /* Load folder first, then open file if present */
    renderBC();
    load(function(){
      if(urlFile){
        var f=files.find(function(x){return x._id===urlFile;});
        if(f) openPreview(f._id,f.file_type,f.file_name);
      }
    });
  } else {
    navRoot();
    if(urlFile){
      /* file at root */
      load(function(){
        var f=files.find(function(x){return x._id===urlFile;});
        if(f) openPreview(f._id,f.file_type,f.file_name);
      });
    }
  }
});
window.addEventListener('popstate',function(e){
  var ov=document.getElementById('preview-overlay');
  if(ov&&ov.classList.contains('open')){
    var body=document.getElementById('preview-body');var sp=document.getElementById('preview-spinner');
    _clearPreviewBody(body,sp);sp.style.display='none';ov.classList.remove('open');_pvId=null;
  }
  var st=e.state;
  if(st){
    folder=st.folder||'root'; folderName=st.folderName||'My Drive'; stack=st.stack||[];
    document.querySelectorAll('.drive-tab').forEach(function(el){el.classList.toggle('active',el.dataset.folder===folder);});
    document.getElementById('sb-home').classList.toggle('active',folder==='root');
    renderBC(); load();
    if(st.file){
      load(function(){
        var f=files.find(function(x){return x._id===st.file;});
        if(f) openPreview(f._id,f.file_type,f.file_name);
      });
    }
  } else {
    navRoot();
  }
});
"""

def _og_meta_tags(title, description, url_path="", image_path="/logo.png"):
    """Build Open Graph / Twitter Card meta tags so links unfurl nicely when
    shared on Telegram, WhatsApp, Discord, X, etc. Uses absolute URLs where
    possible (via WEBUI_BASE_URL) since most crawlers ignore relative ones."""
    import html as _html
    base = _share_base_url()
    image_url = f"{base}{image_path}" if base else image_path
    page_url  = f"{base}{url_path}" if base else url_path
    t = _html.escape(title, quote=True)
    d = _html.escape(description, quote=True)
    tags = (
        f"<meta property='og:title' content='{t}'>"
        f"<meta property='og:description' content='{d}'>"
        f"<meta property='og:image' content='{image_url}'>"
        "<meta property='og:type' content='website'>"
        "<meta name='twitter:card' content='summary'>"
        f"<meta name='twitter:title' content='{t}'>"
        f"<meta name='twitter:description' content='{d}'>"
        f"<meta name='twitter:image' content='{image_url}'>"
    )
    if page_url:
        tags += f"<meta property='og:url' content='{page_url}'>"
    return tags


def _page(body, title="SecureBox"):
    og = _og_meta_tags(
        f"{title} — SecureBox" if title != "SecureBox" else "SecureBox",
        "Your personal file storage, powered by Telegram.",
    )
    return web.Response(content_type="text/html", text=(
        "<!DOCTYPE html><html lang='en'><head>"
        "<meta charset='UTF-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1,maximum-scale=1'>"
        f"<title>{title} — SecureBox</title>"
        "<link rel='icon' type='image/png' href='/favicon.ico'>"
        f"{og}"
        "<link rel='preconnect' href='https://fonts.googleapis.com'>"
        "<link rel='preconnect' href='https://fonts.gstatic.com' crossorigin>"
        "<link href='https://fonts.googleapis.com/css2?family=Google+Sans:wght@400;500;700&family=Roboto:wght@400;500;700&display=swap' rel='stylesheet'>"
        f"<style>{_CSS}</style>"
        f"</head><body><div id='bar'></div><div id='toast'></div>{body}"
        f"<script>{_JS_BASE}</script></body></html>"
    ))


# ── Login ──────────────────────────────────────────────────────────────────────

async def handle_login(request):
    try:
        tok = request.cookies.get("session")
        p = _verify(tok) if tok else None
        if p:
            settings_col = request.app["settings_col"]
            doc = await settings_col.find_one({"user_id": p["uid"]})
            if (doc or {}).get("session_version", 0) != p.get("ver", 0):
                p = None
        if p:
            next_url = request.rel_url.query.get("next", "/drive")
            if not next_url.startswith("/"):
                next_url = "/drive"
            raise web.HTTPFound(next_url)
        error = ""
        if request.method == "POST":
            data         = await request.post()
            username_in  = (data.get("username", "") or "").strip().lower().lstrip("@")
            pw           = data.get("password", "")
            settings_col = request.app["settings_col"]

            if not username_in:
                error = "Please enter your username."
            else:
                # Look up by webui_username first (new accounts), then fall back
                # to matching against Telegram @username stored in user records.
                doc = await settings_col.find_one({
                    "webui_username": username_in,
                    "webui_password_hash": {"$exists": True},
                })
                # Fallback: account set password before username field was added —
                # try matching the raw username field if present.
                if not doc:
                    doc = await settings_col.find_one({
                        "webui_password_hash": {"$exists": True},
                        "$or": [
                            {"webui_username": username_in},
                            {"telegram_username": username_in},
                        ]
                    })
                if not doc or not doc.get("webui_password_hash"):
                    error = "No account found with that username. Use /webui in the Telegram bot."
                elif _hash_pw(pw) == doc["webui_password_hash"]:
                    uid  = doc.get("user_id", 0)
                    next_url = request.rel_url.query.get("next", "/drive")
                    if not next_url.startswith("/"):
                        next_url = "/drive"
                    resp = web.HTTPFound(next_url)
                    resp.set_cookie("session", _make_token(uid, doc.get("session_version", 0)),
                                     max_age=SESSION_TTL, httponly=True, samesite="Lax")
                    raise resp
                else:
                    error = "Incorrect password."
    except web.HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}", exc_info=True)
        error = "Server error. Please try again."
    err = (f'<div class="lerr">{_icon("alert",16)} {error}</div>') if error else ""
    _next = request.rel_url.query.get('next', '/drive')
    if not _next.startswith('/'):
        _next = '/drive'
    return _page(
        f'<div class="lp"><div class="lcard">'
        '<div class="llogo"><img class="llogo-img" src="/logo.png" alt="SecureBox">'
        f'<h1>SecureBox</h1><p>Sign in to access your files</p></div>'
        f'{err}'
        f'<form method="POST" action="/?next={_next}">'
        f'<div class="fg"><label>Username</label>'\
        f'<input name="username" type="text" placeholder="Your username" autofocus autocomplete="username" spellcheck="false"></div>'\
        f'<div class="fg"><label>Password</label>'\
        f'<input name="password" type="password" placeholder="Enter your password" autocomplete="current-password"></div>'\
        f'<button type="submit" class="btn btn-primary btn-wide" style="height:46px;margin-top:8px;font-size:16px">'\
        f'{_icon("login_arrow",18)} Sign In</button></form>'\
        f'<p class="lhint">Set credentials via Telegram @SecureBoxbot using the "/webui" command.</p>'\
        f'</div></div>',
        "Sign In"
    )

async def handle_logout(request):
    r = web.HTTPFound("/")
    r.del_cookie("session")
    raise r


# ── Avatar (Telegram profile photo) ─────────────────────────────────────────────

_AVATAR_CACHE_TTL = 3600  # seconds

@require_auth
async def handle_avatar(request):
    """Streams the logged-in user's Telegram profile photo for use as their
    WebUI avatar. Falls back to a 404 (handled client-side via onerror) if the
    bot can't reach Telegram or the user has no profile photo set."""
    uid = request["uid"]
    bot = request.app.get("bot_instance")
    if not bot:
        raise web.HTTPNotFound()

    cache = request.app["_avatar_cache"]
    now   = time.time()
    cached = cache.get(uid)
    if cached and (now - cached["ts"]) < _AVATAR_CACHE_TTL:
        if cached["data"] is None:
            raise web.HTTPNotFound()
        return web.Response(body=cached["data"], content_type="image/jpeg",
                             headers={"Cache-Control": "private, max-age=3600"})

    data = None
    try:
        me    = await bot.get_users(uid)
        photo = getattr(me, "photo", None) if me else None
        if photo and getattr(photo, "small_file_id", None):
            f = await bot.download_media(photo.small_file_id, in_memory=True)
            if f:
                data = bytes(f.getbuffer())
    except Exception as e:
        logger.error(f"Avatar fetch error for uid={uid}: {e}", exc_info=True)
        data = None

    cache[uid] = {"ts": now, "data": data}
    if not data:
        raise web.HTTPNotFound()
    return web.Response(body=data, content_type="image/jpeg",
                         headers={"Cache-Control": "private, max-age=3600"})


# ── File thumbnails (photo / video / audio) ─────────────────────────────────────

_THUMB_CACHE_TTL = 86400  # seconds — thumbnails never change for a given file
_THUMB_CACHE_MAX = 2000   # cap in-memory entries so this can't grow unbounded

@require_auth
async def api_thumb(request):
    """Streams a small preview image for photo/video/audio files so the WebUI
    grid can show real thumbnails instead of generic icons.

    Telegram already generates a low-res JPEG thumbnail for videos, documents,
    and audio (album art) and stores it server-side — we just need to ask for
    it via `thumb_file_id`, which `save_file()` captures at upload time. For
    photos we fall back to the photo's own (already small) file_id. Results
    are cached in-memory since a thumbnail's bytes never change."""
    uid       = request["uid"]
    fid       = request.match_info["fid"]
    files_col = request.app["files_col"]
    bot       = request.app.get("bot_instance")
    if not bot:
        raise web.HTTPNotFound()

    cache = request.app["_thumb_cache"]
    cached = cache.get(fid)
    if cached is not None:
        if cached is False:
            raise web.HTTPNotFound()
        return web.Response(body=cached, content_type="image/jpeg",
                             headers={"Cache-Control": "private, max-age=86400, immutable"})

    try:
        doc = await files_col.find_one({"_id": ObjectId(fid), "user_id": uid})
    except Exception:
        doc = None
    if not doc:
        raise web.HTTPNotFound()

    thumb_fid = doc.get("thumb_file_id")
    if not thumb_fid:
        cache[fid] = False
        raise web.HTTPNotFound()

    data = None
    try:
        f = await bot.download_media(thumb_fid, in_memory=True)
        if f:
            data = bytes(f.getbuffer())
    except Exception as e:
        logger.error(f"Thumb fetch error for fid={fid}: {e}", exc_info=True)
        data = None

    if len(cache) >= _THUMB_CACHE_MAX:
        cache.pop(next(iter(cache)))  # evict oldest-inserted entry
    cache[fid] = data if data else False

    if not data:
        raise web.HTTPNotFound()
    return web.Response(body=data, content_type="image/jpeg",
                         headers={"Cache-Control": "private, max-age=86400, immutable"})


# ── Drive browser ──────────────────────────────────────────────────────────────

@require_auth
async def handle_drive(request):
    uid         = request["uid"]
    folders_col = request.app["folders_col"]
    settings_col = request.app["settings_col"]
    bot          = request.app["bot_instance"]

    # Fetch user display info
    user_name   = "User"
    user_initials = "U"
    try:
        doc = await settings_col.find_one({"user_id": uid})
        if doc and doc.get("display_name"):
            user_name = doc["display_name"]
        elif bot:
            me = await bot.get_users(uid)
            if me:
                user_name = (me.first_name or "") + (" " + me.last_name if me.last_name else "")
                user_name = user_name.strip() or me.username or "User"
    except Exception:
        pass
    user_initials = "".join(w[0].upper() for w in user_name.split()[:2]) or "U"

    # Build sidebar — top-level folders only (subfolders are reached by navigating in)
    docs = await folders_col.find({
        "user_id": uid,
        "$or": [{"parent_id": None}, {"parent_id": {"$exists": False}}],
    }).sort("name", 1).to_list(500)

    ico_tab = _icon("folder", 14)
    sb_parts = []
    for d in docs:
        fid = str(d["_id"])
        fn  = d.get("name", "")
        if not fn:
            continue
        fn_safe = fn.replace("'", "&#39;").replace('"', "&quot;")
        sb_parts.append(
            '<div class="drive-tab" data-folder="' + fid + '" onclick="navFolder(\'' + fid + '\',\'' + fn_safe + '\')">'
            + ico_tab + ' <span style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis">' + fn + '</span></div>'
        )
    sb = "".join(sb_parts)

    skel = "".join(
        '<div class="file-item">'
        '<div class="fi-cb"><div class="custom-cb"></div></div>'
        '<div class="sk sk-i"></div>'
        '<div class="fi-info">'
        '<div class="sk sk-n" style="margin-bottom:6px"></div>'
        '<div class="sk sk-s"></div></div></div>'
        for _ in range(10)
    )

    ico_close = _icon("close", 14)

    def _js_str(s):
        return s.replace("\\", "\\\\").replace("`", "\\`")

    ic_folder  = _js_str(_icon("folder", 32, "", "#0386c3"))
    ic_file    = _js_str(_icon("file",   32, "", "#607d8b"))
    ic_image   = _js_str(_icon("image",  32, "", "#a78bfa"))
    ic_video   = _js_str(_icon("video",  32, "", "#f87171"))
    ic_audio   = _js_str(_icon("audio",  32, "", "#e55835"))
    ic_dl      = _js_str(_icon("download", 20))
    ic_rename  = _js_str(_icon("rename",  20))
    ic_del     = _js_str(_icon("delete",  20))
    ic_newfol  = _js_str(_icon("newfolder", 22))
    ic_upload  = _js_str(_icon("upload",  22))
    ic_close   = _js_str(_icon("close",   14))
    ic_search  = _js_str(_icon("search",  16))
    ic_move    = _js_str(_icon("move",    20))
    ic_copy    = _js_str(_icon("copy",    20))
    ic_chart   = _js_str(_icon("chart",   20))
    ic_folout  = _js_str(_icon("folder",  16))
    ic_back2   = _js_str(_icon("back",    16))
    ic_share   = _js_str(_icon("share",   18))
    ic_link    = _js_str(_icon("link",    13))
    ic_globe   = _js_str(_icon("globe",   16))
    ic_lock    = _js_str(_icon("lock",    16))

    ic_js_init = (
        "var IC={" +
        f"folder:`{ic_folder}`," +
        f"file:`{ic_file}`," +
        f"image:`{ic_image}`," +
        f"video:`{ic_video}`," +
        f"audio:`{ic_audio}`," +
        f"dl:`{ic_dl}`," +
        f"rename:`{ic_rename}`," +
        f"del:`{ic_del}`," +
        f"newfol:`{ic_newfol}`," +
        f"upload:`{ic_upload}`," +
        f"close:`{ic_close}`," +
        f"search:`{ic_search}`," +
        f"move:`{ic_move}`," +
        f"copy:`{ic_copy}`," +
        f"chart:`{ic_chart}`," +
        f"folout:`{ic_folout}`," +
        f"back2:`{ic_back2}`," +
        f"share:`{ic_share}`," +
        f"link:`{ic_link}`," +
        f"globe:`{ic_globe}`," +
        f"lock:`{ic_lock}`" +
        "};"
    )

    js = ic_js_init + r"""
function getIco(ft,name){
  if(!ft) return IC.file;
  if(ft==='photo') return IC.image;
  if(ft==='video') return IC.video;
  if(ft==='audio') return IC.audio;
  if(ft==='folder') return IC.folder;
  if(ft==='document'&&name){
    var _e=name.includes('.')?name.split('.').pop().toLowerCase():'';
    if({mp4:1,webm:1,ogv:1,mov:1,mkv:1,avi:1,m4v:1,'3gp':1,flv:1}[_e]) return IC.video;
    if({mp3:1,m4a:1,ogg:1,oga:1,opus:1,wav:1,flac:1,aac:1,weba:1,wma:1,amr:1}[_e]) return IC.audio;
  }
  return IC.file;
}
var PLAY_TRI='<svg viewBox="0 0 24 24" fill="white"><path d="M8 5v14l11-7z"/></svg>';
function thumbHTML(f){
  // Photos/videos/audio with a captured Telegram thumbnail get a real
  // preview image; everything else (and any image that fails to load)
  // falls back to the generic type icon. Video/audio thumbs get a small
  // play-triangle badge so they read as "playable" rather than a generic photo.
  if(f.thumb_file_id && (f.file_type==='photo'||f.file_type==='video'||f.file_type==='audio')){
    var ico=getIco(f.file_type,f.file_name).replace(/"/g,'&quot;');
    var playBadge=(f.file_type==='video'||f.file_type==='audio')?'<span class="fi-thumb-play">'+PLAY_TRI+'</span>':'';
    return '<span class="fi-thumb-wrap">'
      +'<img class="fi-thumb" loading="lazy" src="/api/thumb/'+f._id+'"'
      +' onerror="this.parentElement.outerHTML=\'<div class=&quot;fi-icon&quot;>'+ico+'</div>\'">'
      +playBadge+'</span>';
  }
  return '<div class="fi-icon">'+getIco(f.file_type,f.file_name)+'</div>';
}

var folder='root', folderName='My Drive', stack=[], files=[], sel=new Set(),
    renameId=null, delIds=[], fabOpen=false, longPressTimer=null, _pvId=null,
    _vidEl=null, _vidList=[], _vidIdx=0, _vidHideTimer=null, _vidDragging=false,
    _audEl=null, _audList=[], _audIdx=0, _audDragging=false,
    _imgList=[], _imgIdx=0;

function sz(b){if(!b||isNaN(b))return'—';b=+b;if(b<1024)return b+' B';if(b<1048576)return(b/1024).toFixed(1)+' KB';if(b<1073741824)return(b/1048576).toFixed(1)+' MB';return(b/1073741824).toFixed(2)+' GB';}
function dt(s){if(!s&&s!==0)return'—';var d=new Date(typeof s==='number'?s:s),now=new Date(),diff=now-d;if(isNaN(d.getTime()))return'—';if(diff<86400000)return d.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});if(diff<604800000)return d.toLocaleDateString([],{weekday:'short',month:'short',day:'numeric'});return d.toLocaleDateString([],{year:'numeric',month:'short',day:'numeric'});}
function fmtSize(b){if(b===undefined||b===null||isNaN(b))return'—';b=Number(b);if(b<1024)return b+' B';var u=['KB','MB','GB','TB'],i=-1;do{b/=1024;i++;}while(b>=1024&&i<u.length-1);return b.toFixed(b<10?1:0)+' '+u[i];}

function _pushUrl(){
  var url='/drive';
  var params=[];
  if(folder&&folder!=='root') params.push('folder='+encodeURIComponent(folder));
  if(params.length) url+='?'+params.join('&');
  history.pushState({folder:folder,folderName:folderName,stack:JSON.parse(JSON.stringify(stack))},'',url);
}
function navRoot(){
  folder='root'; folderName='My Drive'; stack=[];
  document.querySelectorAll('.drive-tab').forEach(function(e){e.classList.remove('active');});
  document.getElementById('sb-home').classList.add('active');
  renderBC(); _pushUrl(); load();
}
function navFolder(id,name){
  folder=id; folderName=name;
  var i=stack.findIndex(function(x){return x.id===id;});
  if(i>=0) stack=stack.slice(0,i+1); else stack.push({id:id,name:name});
  document.querySelectorAll('.drive-tab').forEach(function(e){
    e.classList.toggle('active', e.dataset.folder===id);
  });
  document.getElementById('sb-home').classList.remove('active');
  renderBC(); _pushUrl(); load();
}
function goBack(){
  stack.pop();
  if(!stack.length){navRoot();return;}
  var top=stack[stack.length-1];
  folder=top.id; folderName=top.name;
  renderBC(); _pushUrl(); load();
}
function renderBC(){
  var h='<span class="bc-crumb" onclick="navRoot()">My Drive</span>';
  stack.forEach(function(f,i){
    var last=i===stack.length-1;
    h+='<span class="bc-sep">\u203a</span><span class="bc-crumb'+(last?' last':'')+'" onclick="navFolder(\''+f.id+'\',\''+f.name.replace(/'/g,"\\'")+'\')">'+f.name+'</span>';
  });
  var bc=document.getElementById('bc'); bc.innerHTML=h;
  setTimeout(function(){bc.scrollLeft=bc.scrollWidth;},0);
  document.getElementById('back-btn').style.display=stack.length?'':'none';
}

async function load(cb){
  sel.clear(); clearSel(); closeFab();
  var fl=document.getElementById('fl');
  var skel='';
  for(var i=0;i<8;i++) skel+='<div class="file-item"><div class="fi-cb"><div class="custom-cb"></div></div><div class="sk sk-i"></div><div class="fi-info"><div class="sk sk-n" style="margin-bottom:6px"></div><div class="sk sk-s"></div></div></div>';
  fl.innerHTML=skel;
  bar(true);
  try{
    var r=await fetch('/api/files?folder='+encodeURIComponent(folder));
    if(!r.ok) throw new Error('HTTP '+r.status);
    var d=await r.json();
    files=d.files||[];
    /* Update folder name from API if we don't have it (e.g. direct URL load) */
    if(d.folder_name && folder !== 'root'){
      folderName=d.folder_name;
      /* Fix stack entry name if it was empty (loaded from URL) */
      if(stack.length>0 && stack[stack.length-1].id===folder){
        stack[stack.length-1].name=d.folder_name;
      } else if(!stack.find(function(x){return x.id===folder;})){
        stack=[{id:folder,name:d.folder_name}];
      }
      renderBC();
    }
    render(d.folders||[]);
    if(typeof cb==='function') cb();
  }catch(e){
    fl.innerHTML='<div class="empty"><div class="empty-icon">'+IC.folder+'</div><h3>Failed to load</h3><p>'+e.message+'</p></div>';
  }
  bar(false);
}

function _fHTML(f){
  var fn=f.name.replace(/"/g,'&quot;').replace(/'/g,'&#39;');
  var badge=f.shared?'<span class="fi-shared-badge" title="Public link active">'+IC.link+'</span>':'';
  return '<div class="file-item" data-fol="true" data-folid="'+f._id+'"'
    +' onclick="folItemClick(event,\''+f._id+'\',\''+fn+'\')"'
    +' oncontextmenu="event.preventDefault();longPressFol(\''+f._id+'\')"'
    +' ontouchstart="startLongFol(event,\''+f._id+'\')" ontouchend="endLong()" ontouchmove="endLong()">'
    +'<div class="fi-cb" onclick="event.stopPropagation();toggleSelFol(\''+f._id+'\',this.querySelector(\'.custom-cb\'))"><div class="custom-cb"></div></div>'
    +'<div class="fi-icon">'+IC.folder+'</div>'
    +'<div class="fi-info"><div class="fi-name-row"><div class="fi-name fol">'+f.name+'</div>'+badge+'</div>'
    +'<div class="fi-meta"><span class="fi-size">Directory</span></div></div></div>';
}
function _fiHTML(f){
  var nm=f.file_name.replace(/"/g,'&quot;').replace(/'/g,'&#39;');
  var badge=f.shared?'<span class="fi-shared-badge" title="Public link active">'+IC.link+'</span>':'';
  return '<div class="file-item" data-id="'+f._id+'" data-name="'+nm+'"'
    +' onclick="itemClick(event,\''+f._id+'\')"'
    +' oncontextmenu="event.preventDefault();longPress(\''+f._id+'\')"'
    +' ontouchstart="startLong(event,\''+f._id+'\')" ontouchend="endLong()" ontouchmove="endLong()">'
    +'<div class="fi-cb" onclick="event.stopPropagation();toggleSelCustom(\''+f._id+'\',this.querySelector(\'.custom-cb\'))"><div class="custom-cb"></div></div>'
    +thumbHTML(f)
    +'<div class="fi-info"><div class="fi-name-row"><div class="fi-name">'+f.file_name+'</div>'+badge+'</div>'
    +'<div class="fi-meta"><span class="fi-size">'+fmtSize(f.file_size)+'</span>'
    +'<span class="fi-date">'+dt(f.created_at)+'</span></div></div>'
    +'<button class="btn-icon fi-act" title="Download" onclick="event.stopPropagation();dlFile(\''+f._id+'\')">'+IC.dl+'</button>'
    +'</div>';
}
function render(fols){
  var fl=document.getElementById('fl');
  if(!fols.length&&!files.length){
    fl.innerHTML='<div class="empty"><div class="empty-icon">'+IC.folder+'</div><h3>This folder is empty</h3><p>Upload files via Telegram or use the + button below</p></div>';
    return;
  }
  var h='';
  fols.forEach(function(f){h+=_fHTML(f);});
  files.forEach(function(f){h+=_fiHTML(f);});
  fl.innerHTML=h;
}

function itemClick(e,id){
  if(e.target.classList.contains('custom-cb')) return;
  if(document.body.classList.contains('select-mode')){
    var cb=e.currentTarget.querySelector('.custom-cb');
    if(cb) toggleSelCustom(id,cb); return;
  }
  var f=files.find(function(x){return x._id===id;});
  if(f) openPreview(id,f.file_type,f.file_name);
}
function startLong(e,id){longPressTimer=setTimeout(function(){longPress(id);},500);}
function endLong(){clearTimeout(longPressTimer);}
function startLongFol(e,fid){longPressTimer=setTimeout(function(){longPressFol(fid);},500);}
function longPressFol(fid){
  if(!document.body.classList.contains('select-mode')) document.body.classList.add('select-mode');
  var els=document.querySelectorAll('[data-folid]');
  for(var i=0;i<els.length;i++){if(els[i].dataset.folid===fid){var cb=els[i].querySelector('.custom-cb');if(cb&&!cb.classList.contains('checked'))toggleSelFol(fid,cb);break;}}
}
function folItemClick(e,fid,fname){
  if(document.body.classList.contains('select-mode')){
    var els=document.querySelectorAll('[data-folid]');
    for(var i=0;i<els.length;i++){if(els[i].dataset.folid===fid){var cb=els[i].querySelector('.custom-cb');if(cb)toggleSelFol(fid,cb);break;}}
    return;
  }
  navFolder(fid,fname);
}
function toggleSelFol(fid,cb){
  var id='fol:'+fid;
  var els=document.querySelectorAll('[data-folid]');
  var el=null;
  for(var i=0;i<els.length;i++){if(els[i].dataset.folid===fid){el=els[i];break;}}
  if(!el) return;
  if(sel.has(id)){sel.delete(id);el.classList.remove('sel');if(cb)cb.classList.remove('checked');}
  else{sel.add(id);el.classList.add('sel');if(cb)cb.classList.add('checked');}
  if(!sel.size) document.body.classList.remove('select-mode');
  updSelBar();
}
function longPress(id){
  if(!document.body.classList.contains('select-mode')) document.body.classList.add('select-mode');
  if(!sel.has(id)) toggleSelCustom(id);
}
function toggleSelCustom(id){
  var willCheck=!sel.has(id);
  if(willCheck){sel.add(id);} else {sel.delete(id);}
  document.querySelectorAll('.file-item[data-id="'+id+'"]').forEach(function(row){
    row.classList.toggle('sel',willCheck);
    var cb=row.querySelector('.custom-cb');
    if(cb) cb.classList.toggle('checked',willCheck);
  });
  if(!document.body.classList.contains('select-mode')) document.body.classList.add('select-mode');
  updSelBar();
}
function updSelBar(){
  document.getElementById('selcnt').textContent=sel.size+' selected';
  document.getElementById('selbar').classList.toggle('show',sel.size>0);
  var hasFolder=false;
  sel.forEach(function(id){ if(id.startsWith('fol:')) hasFolder=true; });
  document.body.classList.toggle('share-eligible',sel.size===1);
  var dlBtn=document.getElementById('sel-btn-dl');
  if(dlBtn) dlBtn.style.display=hasFolder?'none':'flex';
  if(!sel.size) document.body.classList.remove('select-mode');
}
function selShare(){
  if(sel.size!==1) return;
  var id=[...sel][0];
  if(id.startsWith('fol:')) openShareModal('folder',id.slice(4));
  else openShareModal('file',id);
}
function clearSel(){
  sel.clear();
  document.querySelectorAll('.file-item .custom-cb').forEach(function(c){c.classList.remove('checked');});
  document.querySelectorAll('.file-item.sel').forEach(function(r){r.classList.remove('sel');});
  document.body.classList.remove('select-mode');
  document.getElementById('selbar').classList.remove('show');
  updSelBar();
}
function dlFile(id){window.open('/api/download/'+id,'_blank');}
function selDl(){sel.forEach(function(id){if(!id.startsWith('fol:'))window.open('/api/download/'+id,'_blank');});}
function selRename(){
  if(sel.size!==1){toast('Select exactly one item to rename','warn');return;}
  var id=[...sel][0];
  if(id.startsWith('fol:')){
    var fid=id.slice(4);
    var el=document.querySelector('[data-folid="'+fid+'"]');
    var name=el?el.querySelector('.fi-name').textContent:'';
    openRename('fol:'+fid,name);
  } else {
    var row=document.querySelector('[data-id="'+id+'"]');
    openRename(id,row?row.dataset.name:'');
  }
}
function selDel(){
  if(!sel.size) return;
  delIds=[...sel];
  var count=delIds.length;
  var msg=count===1?'Delete this item?':'Delete '+count+' items?';
  document.getElementById('del-msg').textContent=msg;
  openModal('delete');
}
var _mvMode='move', _mvFolder='root', _mvStack=[];
function selMove(){ if(!sel.size) return; openMoveCopy('move'); }
function selCopy(){ if(!sel.size) return; openMoveCopy('copy'); }
function openMoveCopy(mode){
  _mvMode=mode; _mvFolder='root'; _mvStack=[];
  document.getElementById('mv-title').innerHTML=(mode==='move'?IC.move:IC.copy)+' '+(mode==='move'?'Move to\u2026':'Copy to\u2026');
  document.getElementById('mv-confirm').textContent=mode==='move'?'Move Here':'Copy Here';
  openModal('movecopy');
  _mvLoad();
}
async function _mvLoad(){
  var listEl=document.getElementById('mv-list');
  listEl.innerHTML='<div style="padding:16px;text-align:center;color:var(--text3);font-size:13px">Loading\u2026</div>';
  var here=_mvStack.length?_mvStack[_mvStack.length-1].name:'My Drive';
  try{
    var r=await fetch('/api/files?folder='+encodeURIComponent(_mvFolder));
    var d=await r.json();
    var h='<div style="padding:10px 12px;font-size:12px;color:var(--text3);border-bottom:1px solid var(--border)">Current: '+here+'</div>';
    if(_mvStack.length){
      h+='<div class="drive-tab" onclick="_mvUp()">'+IC.back2+' <span>.. Back</span></div>';
    }
    if(!d.folders||!d.folders.length){
      h+='<div style="padding:14px;text-align:center;color:var(--text3);font-size:13px">No subfolders</div>';
    } else {
      d.folders.forEach(function(f){
        var fn=f.name.replace(/"/g,'&quot;').replace(/'/g,'&#39;');
        h+='<div class="drive-tab" onclick="_mvEnter(\''+f._id+'\',\''+fn+'\')">'+IC.folout+' <span>'+f.name+'</span></div>';
      });
    }
    listEl.innerHTML=h;
  }catch(e){
    listEl.innerHTML='<div style="padding:14px;text-align:center;color:var(--text3);font-size:13px">Could not load folders</div>';
  }
}
function _mvEnter(id,name){ _mvStack.push({id:id,name:name}); _mvFolder=id; _mvLoad(); }
function _mvUp(){ _mvStack.pop(); _mvFolder=_mvStack.length?_mvStack[_mvStack.length-1].id:'root'; _mvLoad(); }
async function confirmMoveCopy(){
  var dest=_mvFolder, mode=_mvMode, ids=[...sel];
  closeModal('movecopy'); bar(true);
  var failed=0;
  await Promise.all(ids.map(function(id){
    var isFol=id.startsWith('fol:');
    var realId=isFol?id.slice(4):id;
    var url=mode==='move'
      ? (isFol?'/api/move-folder/'+realId:'/api/move/'+realId)
      : (isFol?'/api/copy-folder/'+realId:'/api/copy/'+realId);
    return fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({dest:dest})})
      .then(function(r){ if(!r.ok) failed++; })
      .catch(function(){ failed++; });
  }));
  bar(false);
  if(failed) toast(failed+' item(s) failed to '+mode,'err');
  else toast(mode==='move'?'Moved':'Copied','ok');
  clearSel();
  var sm=document.getElementById('m-search');
  if(sm&&sm.classList.contains('open')) doSearch();
  load();
}
function openRename(id,name){
  renameId=id;
  document.getElementById('i-rename').value=name;
  openModal('rename');
  setTimeout(function(){document.getElementById('i-rename').select();},60);
}
async function doRename(){
  var name=document.getElementById('i-rename').value.trim();
  if(!name) return;
  closeModal('rename'); bar(true);
  var url=renameId.startsWith('fol:')?'/api/rename-folder/'+renameId.slice(4):'/api/rename/'+renameId;
  var r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:name})});
  bar(false); r.ok?toast('Renamed','ok'):toast('Failed','err'); load();
}
async function doDelete(){
  closeModal('delete'); bar(true);
  await Promise.all(delIds.map(function(id){
    if(id.startsWith('fol:')){
      return fetch('/api/delete-folder/'+id.slice(4),{method:'POST'});
    } else {
      return fetch('/api/delete/'+id,{method:'POST'});
    }
  }));
  bar(false); toast('Deleted','ok'); clearSel();
  var sm=document.getElementById('m-search');
  if(sm&&sm.classList.contains('open')) doSearch();
  load();
}
function openMkdir(){
  document.getElementById('i-mkdir').value='';
  openModal('mkdir');
  setTimeout(function(){document.getElementById('i-mkdir').focus();},60);
}
async function doMkdir(){
  var name=document.getElementById('i-mkdir').value.trim();
  if(!name) return;
  var wasRoot=(folder==='root');
  closeModal('mkdir'); bar(true);
  var r=await fetch('/api/mkdir',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:name,parent:folder})});
  bar(false); r.ok?toast('Folder created','ok'):toast('Failed','err');
  if(wasRoot && r.ok){ location.reload(); } else { load(); }
}

/* ── Share / Public link ── */
var _shareType=null, _shareId=null, _shareData=null;
function openShareModal(type,id){
  _shareType=type; _shareId=id; _shareData=null;
  var row = type==='folder'
    ? document.querySelector('[data-folid="'+id+'"] .fi-name')
    : document.querySelector('.file-item[data-id="'+id+'"] .fi-name');
  document.getElementById('share-item-name').textContent = row ? row.textContent : '';
  var itemIcon = document.getElementById('share-item-icon');
  itemIcon.style.background = type==='folder' ? 'rgba(3,134,195,0.15)' : 'var(--surface2)';
  itemIcon.style.color = type==='folder' ? '#0386c3' : 'var(--text3)';
  itemIcon.innerHTML = type==='folder' ? IC.folder.replace(/width="\d+" height="\d+"/, 'width="18" height="18"') : IC.file.replace(/width="\d+" height="\d+"/, 'width="18" height="18"');
  document.getElementById('share-pw-input').value='';
  document.getElementById('share-pw-input').placeholder='Enter a password';
  document.getElementById('share-pw-input').dataset.hasSaved='';
  document.getElementById('share-pw-field').style.display='none';
  document.getElementById('share-pw-toggle').checked=false;
  _updateSharePwBtn(false);
  _renderShareStatus(null,true);
  openModal('share');
  _loadShareStatus();
}
function _renderShareStatus(d,loading){
  var box=document.getElementById('share-status-box');
  var linkRow=document.getElementById('share-link-row');
  var enableRow=document.getElementById('share-enable-row');
  if(loading){
    box.className='share-status off';
    box.innerHTML='<div class="share-status-icon">'+IC.globe+'</div><div class="share-status-text"><div class="share-status-title">Checking\u2026</div></div>';
    linkRow.style.display='none';
    return;
  }
  var active = d && d.active;
  document.getElementById('share-enable-toggle').checked=!!active;
  document.getElementById('share-pw-toggle').checked=!!(d&&d.has_password);
  document.getElementById('share-pw-field').style.display=(d&&d.has_password)?'block':'none';
  if(d&&d.has_password){
    var inp=document.getElementById('share-pw-input');
    inp.value='';
    inp.placeholder='••••';
    inp.dataset.hasSaved='1';
    _updateSharePwBtn(true);
  } else {
    var inp=document.getElementById('share-pw-input');
    inp.placeholder='Enter a password';
    inp.dataset.hasSaved='';
    _updateSharePwBtn(false);
  }
  if(active){
    box.className='share-status on';
    box.innerHTML='<div class="share-status-icon">'+IC.globe+'</div><div class="share-status-text">'
      +'<div class="share-status-title">Public link active</div>'
      +'<div class="share-status-sub">'+(d.has_password?'Password protected':'Anyone with the link can access')+'</div></div>';
    document.getElementById('share-link-input').value=d.url||'';
    linkRow.style.display='flex';
    document.getElementById('share-clear-btn').style.display='inline-flex';
  } else {
    box.className='share-status off';
    box.innerHTML='<div class="share-status-icon">'+IC.globe+'</div><div class="share-status-text">'
      +'<div class="share-status-title">Not shared</div>'
      +'<div class="share-status-sub">Turn on to generate a public link</div></div>';
    linkRow.style.display='none';
    document.getElementById('share-clear-btn').style.display='none';
  }
}
async function _loadShareStatus(){
  try{
    var r=await fetch('/api/share/'+_shareType+'/'+_shareId);
    if(!r.ok) throw new Error('HTTP '+r.status);
    _shareData=await r.json();
    _renderShareStatus(_shareData,false);
  }catch(e){
    _renderShareStatus(null,false);
  }
}
async function shareTogglePublic(checked){
  bar(true);
  try{
    var pwField=document.getElementById('share-pw-toggle');
    var body={enabled:checked};
    if(checked && pwField.checked){
      var pw=document.getElementById('share-pw-input').value;
      if(pw) body.password=pw;
    }
    var r=await fetch('/api/share/'+_shareType+'/'+_shareId,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    if(!r.ok) throw new Error('HTTP '+r.status);
    _shareData=await r.json();
    _renderShareStatus(_shareData,false);
    toast(checked?'Public link created':'Link disabled','ok');
    load();
  }catch(e){
    toast('Failed to update share','err');
    document.getElementById('share-enable-toggle').checked=!checked;
  }
  bar(false);
}
function _updateSharePwBtn(saved){
  var btn=document.getElementById('share-pw-save-btn');
  if(!btn)return;
  if(saved){
    btn.textContent='Saved';
    btn.disabled=true;
    btn.classList.remove('btn-primary');
    btn.classList.add('btn-ghost');
  } else {
    btn.textContent='Save';
    btn.disabled=false;
    btn.classList.add('btn-primary');
    btn.classList.remove('btn-ghost');
  }
}
function sharePwInputChanged(){
  var inp=document.getElementById('share-pw-input');
  if(inp.dataset.hasSaved==='1' && inp.value===''){
    _updateSharePwBtn(true);
  } else {
    _updateSharePwBtn(false);
  }
}
function sharePwToggleChanged(checked){
  document.getElementById('share-pw-field').style.display=checked?'block':'none';
  if(!checked) shareSavePassword('');
}
async function shareSavePassword(){
  if(!document.getElementById('share-enable-toggle').checked) return;
  var usePw=document.getElementById('share-pw-toggle').checked;
  var pw=usePw?document.getElementById('share-pw-input').value:'';
  if(usePw && !pw){
    /* Empty field with existing password = no change needed */
    var inp=document.getElementById('share-pw-input');
    if(inp.dataset.hasSaved==='1') return;
    return;
  }
  bar(true);
  try{
    var r=await fetch('/api/share/'+_shareType+'/'+_shareId,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:true,password:pw})});
    if(!r.ok) throw new Error('HTTP '+r.status);
    _shareData=await r.json();
    _renderShareStatus(_shareData,false);
    toast(usePw?'Password set':'Password removed','ok');
    load();
  }catch(e){ toast('Failed to update password','err'); }
  bar(false);
}
function shareCopyLink(){
  var input=document.getElementById('share-link-input');
  if(!input.value) return;
  navigator.clipboard.writeText(input.value).then(function(){
    toast('Link copied','ok');
  }).catch(function(){
    input.select(); document.execCommand('copy'); toast('Link copied','ok');
  });
}
async function shareClearLink(){
  bar(true);
  try{
    var r=await fetch('/api/share/'+_shareType+'/'+_shareId,{method:'DELETE'});
    if(!r.ok) throw new Error('HTTP '+r.status);
    _shareData={active:false};
    _renderShareStatus(_shareData,false);
    toast('Link removed','ok');
    load();
  }catch(e){ toast('Failed to remove link','err'); }
  bar(false);
}

function toggleFab(){
  fabOpen=!fabOpen;
  var btn=document.getElementById('fab-btn');
  var opts=document.getElementById('fab-opts');
  if(fabOpen){
    btn.classList.add('open'); opts.style.display='flex';
    opts.innerHTML=
      '<div class="fab-opt" onclick="closeFab();openMkdir()">'+IC.newfol+' <span>New Folder</span></div>'
      +'<div class="fab-opt" onclick="closeFab();openModal(\'upload\')">'+IC.upload+' <span>Upload File</span></div>';
  } else { closeFab(); }
}
function closeFab(){
  fabOpen=false;
  document.getElementById('fab-btn').classList.remove('open');
  document.getElementById('fab-opts').style.display='none';
}
document.addEventListener('click',function(e){
  if(fabOpen&&!document.getElementById('fab').contains(e.target)) closeFab();
});
var dz=document.getElementById('dz');
if(dz){
  dz.addEventListener('dragover',function(e){e.preventDefault();dz.classList.add('dragover');});
  dz.addEventListener('dragleave',function(){dz.classList.remove('dragover');});
  dz.addEventListener('drop',function(e){e.preventDefault();dz.classList.remove('dragover');addFiles(e.dataTransfer.files);});
}
var uploadQ=[];
function addFiles(flist){
  Array.from(flist).forEach(function(f){
    var id='u'+Date.now()+Math.random().toString(36).slice(2);
    uploadQ.push({id:id,file:f,status:'pending'});
    var el=document.createElement('div'); el.className='uitem'; el.id=id;
    el.innerHTML='<div class="uitem-top"><span class="uname">'+f.name+'</span><span class="ust" id="'+id+'-st">Pending</span></div>'
      +'<div class="ubar"><div class="ufill" id="'+id+'-f"></div></div>';
    document.getElementById('ulist').appendChild(el);
  });
  document.getElementById('fi').value='';
}
async function startUpload(){
  if(!uploadQ.length){toast('No files selected','warn');return;}
  document.getElementById('ubtn').disabled=true;
  for(var i=0;i<uploadQ.length;i++){
    var item=uploadQ[i];
    if(item.status!=='pending') continue;
    var st=document.getElementById(item.id+'-st');
    var fill=document.getElementById(item.id+'-f');
    st.textContent='Uploading...'; st.style.color='var(--accent)';
    try{
      await new Promise(function(res,rej){
        var xhr=new XMLHttpRequest(); xhr.open('POST','/api/upload');
        xhr.upload.onprogress=function(e){if(e.lengthComputable){var p=Math.round(e.loaded/e.total*100);fill.style.width=p+'%';st.textContent=p+'%';}};
        xhr.onload=function(){if(xhr.status<300){fill.style.width='100%';fill.style.background='var(--green)';st.textContent='Done';st.style.color='var(--green)';item.status='done';res();}else{st.textContent='Error';st.style.color='var(--red)';item.status='err';rej();}};
        xhr.onerror=function(){st.textContent='Error';st.style.color='var(--red)';rej();};
        var fd=new FormData(); fd.append('file',item.file); fd.append('folder',folder);
        xhr.send(fd);
      });
    }catch(e){item.status='err';}
  }
  document.getElementById('ubtn').disabled=false;
  var done=uploadQ.filter(function(x){return x.status==='done';}).length;
  if(done) toast('Uploaded '+done+' file'+(done>1?'s':''),'ok');
  closeModal('upload'); uploadQ=[]; document.getElementById('ulist').innerHTML=''; load();
}
function doNavSearch(){
  var q=document.getElementById('nav-search-input').value.trim();
  if(!q) return;
  document.getElementById('i-search').value=q;
  document.getElementById('search-res').innerHTML='';
  openModal('search'); doSearch();
}
function openSearchModal(){
  document.getElementById('i-search').value='';
  document.getElementById('search-res').innerHTML='';
  openModal('search');
  setTimeout(function(){document.getElementById('i-search').focus();},60);
}
async function doSearch(){
  var q=document.getElementById('i-search').value.trim();
  if(!q) return;
  var el=document.getElementById('search-res');
  el.innerHTML='<div style="padding:16px;text-align:center;color:var(--text3);font-size:14px">Searching...</div>';
  var r=await fetch('/api/search?q='+encodeURIComponent(q));
  var d=await r.json();
  if(!d.files||!d.files.length){
    el.innerHTML='<div style="padding:20px;text-align:center;color:var(--text3);font-size:14px">No results for "'+q+'"</div>';
    return;
  }
  var h='';
  d.files.forEach(function(f){ h+=_searchItemHTML(f); });
  el.innerHTML=h;
}
function _searchItemHTML(f){
  var nm=f.file_name.replace(/"/g,'&quot;').replace(/'/g,'&#39;');
  var badge=f.shared?'<span class="fi-shared-badge" title="Public link active">'+IC.link+'</span>':'';
  return '<div class="file-item" data-id="'+f._id+'" data-name="'+nm+'"'
    +' onclick="searchItemClick(event,\''+f._id+'\',\''+f.file_type+'\',\''+nm+'\')"'
    +' oncontextmenu="event.preventDefault();longPress(\''+f._id+'\')"'
    +' ontouchstart="startLong(event,\''+f._id+'\')" ontouchend="endLong()" ontouchmove="endLong()">'
    +'<div class="fi-cb" onclick="event.stopPropagation();toggleSelCustom(\''+f._id+'\')"><div class="custom-cb"></div></div>'
    +thumbHTML(f)
    +'<div class="fi-info"><div class="fi-name-row"><div class="fi-name">'+f.file_name+'</div>'+badge+'</div>'
    +'<div class="fi-meta"><span class="fi-size">'+fmtSize(f.file_size)+'</span>'
    +'<span class="fi-date">'+dt(f.created_at)+'</span></div></div>'
    +'<button class="btn-icon fi-act" title="Download" onclick="event.stopPropagation();dlFile(\''+f._id+'\')">'+IC.dl+'</button>'
    +'</div>';
}
function searchItemClick(e,id,ft,name){
  if(e.target.classList.contains('custom-cb')) return;
  if(document.body.classList.contains('select-mode')){
    toggleSelCustom(id);
    return;
  }
  closeModal('search');
  openPreview(id,ft,name);
}
function openPreview(id,ft,name){
  _pvId=id;
  /* Push file URL so it's shareable / copyable from address bar */
  var fileUrl='/drive?'+(folder&&folder!=='root'?'folder='+encodeURIComponent(folder)+'&':'')+'file='+encodeURIComponent(id);
  history.pushState({folder:folder,folderName:folderName,stack:JSON.parse(JSON.stringify(stack)),file:id,fileName:name,fileType:ft},'',fileUrl);
  var ov=document.getElementById('preview-overlay');
  document.getElementById('preview-title').textContent=name||'Preview';
  var body=document.getElementById('preview-body');
  var sp=document.getElementById('preview-spinner');
  _clearPreviewBody(body,sp);
  sp.style.display='flex'; ov.classList.add('open');
  var src='/api/preview/'+id;
  var hide=function(){sp.style.display='none';};
  if(ft==='photo'){
    var siblings=_getSiblingFiles('photo');
    _imgList=siblings.length?siblings:[{_id:id,file_name:name,file_type:'photo'}];
    _imgIdx=_imgList.findIndex(function(f){return f._id===id;});
    if(_imgIdx<0)_imgIdx=0;
    _buildImageViewer(body,hide);
  } else if(ft==='video'){
    var siblings=_getSiblingFiles('video');
    _vidList=siblings.length?siblings:[{_id:id,file_name:name,file_type:'video'}];
    _vidIdx=_vidList.findIndex(function(f){return f._id===id;});
    if(_vidIdx<0)_vidIdx=0;
    _buildVideoPlayer(body,hide);
  } else if(ft==='audio'){
    var siblings=_getSiblingFiles('audio');
    _audList=siblings.length?siblings:[{_id:id,file_name:name,file_type:'audio'}];
    _audIdx=_audList.findIndex(function(f){return f._id===id;});
    if(_audIdx<0)_audIdx=0;
    _buildAudioPlayer(body,hide);
  } else if(ft==='document'){
    /* Detect audio/video files stored as "document" type by their extension */
    var _ext=name.includes('.')?name.split('.').pop().toLowerCase():'';
    var _vidExts={'mp4':1,'webm':1,'ogv':1,'mov':1,'mkv':1,'avi':1,'m4v':1,'3gp':1,'flv':1};
    var _audExts={'mp3':1,'m4a':1,'ogg':1,'oga':1,'opus':1,'wav':1,'flac':1,'aac':1,'weba':1,'wma':1,'amr':1};
    if(_vidExts[_ext]){
      var siblings=_getSiblingFiles('video').concat(_getSiblingFiles('document').filter(function(f){var e=f.file_name.includes('.')?f.file_name.split('.').pop().toLowerCase():'';return _vidExts[e];}));
      _vidList=siblings.length?siblings:[{_id:id,file_name:name,file_type:'video'}];
      _vidIdx=_vidList.findIndex(function(f){return f._id===id;});
      if(_vidIdx<0){_vidIdx=0;_vidList=[{_id:id,file_name:name,file_type:'video'}];}
      _buildVideoPlayer(body,hide);
    } else if(_audExts[_ext]){
      var siblings=_getSiblingFiles('audio').concat(_getSiblingFiles('document').filter(function(f){var e=f.file_name.includes('.')?f.file_name.split('.').pop().toLowerCase():'';return _audExts[e];}));
      _audList=siblings.length?siblings:[{_id:id,file_name:name,file_type:'audio'}];
      _audIdx=_audList.findIndex(function(f){return f._id===id;});
      if(_audIdx<0){_audIdx=0;_audList=[{_id:id,file_name:name,file_type:'audio'}];}
      _buildAudioPlayer(body,hide);
    } else {
      fetch(src).then(function(r){if(!r.ok)throw new Error(r.status);return r.text();}).then(function(txt){
        hide();
        _buildTextViewer(body,txt,name);
      }).catch(function(){hide();showUnsupported(name);});
    }
  } else { hide(); showUnsupported(name); }
}

function _getSiblingFiles(ft){
  if(typeof files==='undefined')return[];
  return files.filter(function(f){return f.file_type===ft;});
}

/* ── Image Viewer ── */
function _buildImageViewer(body,onReady){
  var wrap=document.createElement('div');wrap.id='img-viewer';
  var img=document.createElement('img');img.style.opacity='0';img.style.transition='opacity .22s';
  var btnPrev=document.createElement('button');
  btnPrev.className='img-nav-btn prev';
  btnPrev.innerHTML='<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>';
  btnPrev.onclick=function(){_imgNavigate(-1);};
  var btnNext=document.createElement('button');
  btnNext.className='img-nav-btn next';
  btnNext.innerHTML='<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>';
  btnNext.onclick=function(){_imgNavigate(1);};
  var counter=document.createElement('div');counter.className='img-counter';
  wrap.appendChild(btnPrev);wrap.appendChild(img);wrap.appendChild(btnNext);wrap.appendChild(counter);
  body.appendChild(wrap);
  _imgLoadCurrent(img,counter,btnPrev,btnNext,onReady);
  /* Pinch-to-zoom & swipe */
  var _z=1,_zx=0,_zy=0,_px=0,_py=0,_pinchDist0=0,_pinchZ0=1,_swipeStartX=0,_swipeStartY=0,_swipeActive=false;
  function _dist(t){return Math.hypot(t[0].clientX-t[1].clientX,t[0].clientY-t[1].clientY);}
  function _applyTransform(){img.style.transform='translate('+_zx+'px,'+_zy+'px) scale('+_z+')';img.style.transition='none';}
  function _resetZoom(){_z=1;_zx=0;_zy=0;_applyTransform();img.style.transition='opacity .22s';}
  wrap.addEventListener('touchstart',function(e){
    if(e.touches.length===2){e.preventDefault();_swipeActive=false;_pinchDist0=_dist(e.touches);_pinchZ0=_z;}
    else if(e.touches.length===1){_swipeStartX=e.touches[0].clientX;_swipeStartY=e.touches[0].clientY;_swipeActive=true;if(_z>1){_px=e.touches[0].clientX;_py=e.touches[0].clientY;}}
  },{passive:false});
  wrap.addEventListener('touchmove',function(e){
    if(e.touches.length===2){e.preventDefault();_swipeActive=false;var d=_dist(e.touches);_z=Math.min(5,Math.max(1,_pinchZ0*(d/_pinchDist0)));if(_z<=1){_zx=0;_zy=0;}_applyTransform();}
    else if(e.touches.length===1&&_z>1){e.preventDefault();var dx=e.touches[0].clientX-_px;var dy=e.touches[0].clientY-_py;_px=e.touches[0].clientX;_py=e.touches[0].clientY;_zx+=dx;_zy+=dy;_applyTransform();}
  },{passive:false});
  wrap.addEventListener('touchend',function(e){
    if(e.touches.length<2&&_z>1)return;
    if(_z<=1.05)_resetZoom();
    if(_swipeActive&&e.changedTouches.length===1&&_z<=1.05){
      var dx=e.changedTouches[0].clientX-_swipeStartX;var dy=e.changedTouches[0].clientY-_swipeStartY;
      if(Math.abs(dx)>50&&Math.abs(dx)>Math.abs(dy)*1.5){if(dx<0)_imgNavigate(1);else _imgNavigate(-1);}
      _swipeActive=false;
    }
  },{passive:true});
  var _dtTap=0;
  wrap.addEventListener('touchend',function(e){var now=Date.now();if(now-_dtTap<300&&e.changedTouches.length===1){if(_z>1)_resetZoom();}_dtTap=now;},{passive:true});
}
function _imgLoadCurrent(img,counter,btnPrev,btnNext,onReady){
  var f=_imgList[_imgIdx];if(!f)return;
  _pvId=f._id;
  document.getElementById('preview-title').textContent=f.file_name||'Image';
  img.style.opacity='0';
  img.onload=function(){if(onReady){onReady();onReady=null;}img.style.opacity='1';};
  img.onerror=function(){if(onReady){onReady();onReady=null;}showUnsupported(f.file_name);};
  img.src='/api/preview/'+f._id;
  counter.textContent=(_imgIdx+1)+' / '+_imgList.length;
  btnPrev.disabled=_imgIdx===0;btnNext.disabled=_imgIdx===_imgList.length-1;
  if(_imgList.length<=1){btnPrev.style.display='none';btnNext.style.display='none';counter.style.display='none';}
  else{btnPrev.style.display='';btnNext.style.display='';counter.style.display='';}
}
function _imgNavigate(dir){
  var ni=_imgIdx+dir;if(ni<0||ni>=_imgList.length)return;
  _imgIdx=ni;
  var wrap=document.getElementById('img-viewer');if(!wrap)return;
  var img=wrap.querySelector('img');img.style.transform='';
  var counter=wrap.querySelector('.img-counter');
  var btnPrev=wrap.querySelector('.img-nav-btn.prev');
  var btnNext=wrap.querySelector('.img-nav-btn.next');
  _imgLoadCurrent(img,counter,btnPrev,btnNext,null);
}

/* ── Video Player ── */
function _buildVideoPlayer(body,onReady){
  var f=_vidList[_vidIdx];if(!f)return;
  var wrap=document.createElement('div');wrap.id='video-player-wrap';
  var vid=document.createElement('video');vid.playsInline=true;vid.preload='auto';_vidEl=vid;
  wrap.innerHTML='<div id="vid-play-flash"></div>'
    +'<div id="vid-overlay-center">'
    +'<button class="vid-overlay-btn sm" id="vid-ol-prev" onclick="vidNavigate(-1)" title="Previous"><svg width="22" height="22" viewBox="0 0 24 24" fill="currentColor"><path d="M6 6h2v12H6zm3.5 6 8.5 6V6z"/></svg></button>'
    +'<button class="vid-overlay-btn lg" id="vid-ol-play" onclick="vidTogglePlay()" title="Play/Pause"><svg id="vid-overlay-play-ico" width="34" height="34" viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7z"/></svg></button>'
    +'<button class="vid-overlay-btn sm" id="vid-ol-next" onclick="vidNavigate(1)" title="Next"><svg width="22" height="22" viewBox="0 0 24 24" fill="currentColor"><path d="M6 18l8.5-6L6 6v12z"/><rect x="16" y="6" width="2" height="12"/></svg></button>'
    +'</div>'
    +'<div id="vid-controls">'
    +'<div id="vid-progress-wrap"><div id="vid-progress-track"><div id="vid-progress-buf"></div><div id="vid-progress-fill"></div><div id="vid-thumb"></div></div></div>'
    +'<div id="vid-controls-row">'
    +'<button class="vid-btn" id="vid-play-btn" title="Play/Pause" onclick="vidTogglePlay()"><svg id="vid-play-ico" width="26" height="26" viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7z"/></svg></button>'
    +'<span id="vid-time">0:00 / 0:00</span>'
    +'<span id="vid-title-bar"></span>'
    +'<div id="vid-vol-wrap"><button class="vid-btn" id="vid-mute-btn" onclick="vidToggleMute()"><svg id="vid-vol-ico" width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M3 9v6h4l5 5V4L7 9H3zm13.5 3c0-1.77-1.02-3.29-2.5-4.03v8.05c1.48-.73 2.5-2.25 2.5-4.02zM14 3.23v2.06c2.89.86 5 3.54 5 6.71s-2.11 5.85-5 6.71v2.06c4.01-.91 7-4.49 7-8.77s-2.99-7.86-7-8.77z"/></svg></button></div>'
    +'<button class="vid-btn" id="vid-full-btn" onclick="vidToggleFullscreen()" title="Fullscreen"><svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M7 14H5v5h5v-2H7v-3zm-2-4h2V7h3V5H5v5zm12 7h-3v2h5v-5h-2v3zM14 5v2h3v3h2V5h-5z"/></svg></button>'
    +'</div></div>';
  wrap.insertBefore(vid,wrap.firstChild);
  body.appendChild(wrap);
  vid.src='/api/preview/'+f._id;
  document.getElementById('vid-title-bar').textContent=f.file_name||'';
  _vidUpdateNavBtns();
  vid.oncanplay=function(){if(onReady){onReady();onReady=null;}vid.play().then(function(){_vidUpdatePlayBtn();}).catch(function(){});};
  vid.onerror=function(){if(onReady){onReady();onReady=null;}showUnsupported(f.file_name);};
  vid.addEventListener('timeupdate',_vidSyncProgress);
  vid.addEventListener('progress',_vidSyncBuffer);
  vid.addEventListener('ended',function(){if(_vidIdx<_vidList.length-1)vidNavigate(1);});
  /* Double-tap seek */
  var _tapTimer=null,_tapCount=0,_tapX=0;
  vid.addEventListener('click',function(e){
    _tapCount++;_tapX=e.clientX;
    if(_tapTimer)clearTimeout(_tapTimer);
    _tapTimer=setTimeout(function(){
      if(_tapCount>=2){var rect=vid.getBoundingClientRect();var pct=(_tapX-rect.left)/rect.width;var secs=10;
        if(pct<0.5){vid.currentTime=Math.max(0,vid.currentTime-secs);_vidShowSeekRipple('left',-secs);}
        else{vid.currentTime=Math.min(vid.duration||0,vid.currentTime+secs);_vidShowSeekRipple('right',secs);}
      }
      _tapCount=0;_tapTimer=null;
    },280);
  });
  wrap.addEventListener('mousemove',_vidShowControls);
  wrap.addEventListener('touchstart',_vidShowControls,{passive:true});
  var pw=document.getElementById('vid-progress-wrap');
  pw.addEventListener('mousedown',function(e){_vidDragging=true;_vidSeekTo(e,pw);});
  document.addEventListener('mousemove',function(e){if(_vidDragging)_vidSeekTo(e,pw);});
  document.addEventListener('mouseup',function(){_vidDragging=false;});
  pw.addEventListener('touchstart',function(e){_vidDragging=true;_vidSeekTouch(e,pw);},{passive:true});
  document.addEventListener('touchmove',function(e){if(_vidDragging)_vidSeekTouch(e,pw);},{passive:true});
  document.addEventListener('touchend',function(){_vidDragging=false;});
}
function _vidShowControls(){
  var w=document.getElementById('video-player-wrap');if(w)w.classList.remove('controls-hidden');
  clearTimeout(_vidHideTimer);
  if(_vidEl&&!_vidEl.paused){_vidHideTimer=setTimeout(function(){var w2=document.getElementById('video-player-wrap');if(w2)w2.classList.add('controls-hidden');},3000);}
}
function _vidSyncProgress(){
  var vid=_vidEl;if(!vid)return;
  var pct=vid.duration?vid.currentTime/vid.duration*100:0;
  var fill=document.getElementById('vid-progress-fill');var thumb=document.getElementById('vid-thumb');
  if(fill)fill.style.width=pct+'%';if(thumb)thumb.style.left=pct+'%';
  var t=document.getElementById('vid-time');if(t)t.textContent=_fmtTime(vid.currentTime)+' / '+_fmtTime(vid.duration);
}
function _vidSyncBuffer(){
  var vid=_vidEl;if(!vid||!vid.duration)return;
  var buf=0;for(var i=0;i<vid.buffered.length;i++){if(vid.buffered.start(i)<=vid.currentTime&&vid.currentTime<=vid.buffered.end(i)){buf=vid.buffered.end(i)/vid.duration*100;break;}}
  var b=document.getElementById('vid-progress-buf');if(b)b.style.width=buf+'%';
}
function _vidSeekTo(e,pw){var vid=_vidEl;if(!vid||!vid.duration)return;var r=pw.getBoundingClientRect();var pct=Math.max(0,Math.min(1,(e.clientX-r.left)/r.width));vid.currentTime=pct*vid.duration;_vidSyncProgress();}
function _vidSeekTouch(e,pw){if(!e.touches.length)return;_vidSeekTo(e.touches[0],pw);}
function _fmtTime(s){if(isNaN(s)||!isFinite(s))return'0:00';var m=Math.floor(s/60),sc=Math.floor(s%60);return m+':'+(sc<10?'0':'')+sc;}
function vidTogglePlay(){var vid=_vidEl;if(!vid)return;if(vid.paused){vid.play();_vidFlash(true);}else{vid.pause();_vidFlash(false);}_vidUpdatePlayBtn();_vidShowControls();}
function _vidFlash(playing){
  var fl=document.getElementById('vid-play-flash');if(!fl)return;
  fl.innerHTML=playing?'<svg width="36" height="36" viewBox="0 0 24 24" fill="#fff"><path d="M8 5v14l11-7z"/></svg>':'<svg width="36" height="36" viewBox="0 0 24 24" fill="#fff"><path d="M6 19h4V5H6v14zm8-14v14h4V5h-4z"/></svg>';
  fl.classList.remove('flash');void fl.offsetWidth;fl.classList.add('flash');
}
function _vidShowSeekRipple(side,secs){
  var wrap=document.getElementById('video-player-wrap');if(!wrap)return;
  wrap.querySelectorAll('.vid-seek-ripple.'+side).forEach(function(r){r.remove();});
  var r=document.createElement('div');r.className='vid-seek-ripple '+side;
  var arrow=secs>0?'&#9654;&#9654;':'&#9664;&#9664;';
  var iconPath=secs>0?'<path d="M5.59 7.41L10.18 12l-4.59 4.59L7 18l6-6-6-6-1.41 1.41zm9 0L19.18 12l-4.59 4.59L16 18l6-6-6-6-1.41 1.41z"/>':'<path d="M18.41 7.41L13.83 12l4.58 4.59L17 18l-6-6 6-6 1.41 1.41zm-9 0L4.83 12l4.58 4.59L8 18 2 12l6-6 1.41 1.41z"/>';
  r.innerHTML='<div class="vid-seek-ripple-icon"><svg width="28" height="28" viewBox="0 0 24 24" fill="#fff">'+iconPath+'</svg></div><span class="vid-seek-ripple-label">'+Math.abs(secs)+' sec</span>';
  wrap.appendChild(r);setTimeout(function(){r.remove();},600);
}
function _vidUpdatePlayBtn(){
  var paused=_vidEl?_vidEl.paused:true;
  var path=paused?'<path d="M8 5v14l11-7z"/>':'<path d="M6 19h4V5H6v14zm8-14v14h4V5h-4z"/>';
  var ico=document.getElementById('vid-play-ico');if(ico)ico.innerHTML=path;
  var oico=document.getElementById('vid-overlay-play-ico');if(oico)oico.innerHTML=path;
}
function vidToggleMute(){
  var vid=_vidEl;if(!vid)return;vid.muted=!vid.muted;
  var ico=document.getElementById('vid-vol-ico');if(!ico)return;
  ico.innerHTML=vid.muted?'<path d="M16.5 12c0-1.77-1.02-3.29-2.5-4.03v2.21l2.45 2.45c.03-.2.05-.41.05-.63zm2.5 0c0 .94-.2 1.82-.54 2.64l1.51 1.51C20.63 14.91 21 13.5 21 12c0-4.28-2.99-7.86-7-8.77v2.06c2.89.86 5 3.54 5 6.71zM4.27 3L3 4.27 7.73 9H3v6h4l5 5v-6.73l4.25 4.25c-.67.52-1.42.93-2.25 1.18v2.06c1.38-.31 2.63-.95 3.69-1.81L19.73 21 21 19.73l-9-9L4.27 3zM12 4L9.91 6.09 12 8.18V4z"/>':'<path d="M3 9v6h4l5 5V4L7 9H3zm13.5 3c0-1.77-1.02-3.29-2.5-4.03v8.05c1.48-.73 2.5-2.25 2.5-4.02zM14 3.23v2.06c2.89.86 5 3.54 5 6.71s-2.11 5.85-5 6.71v2.06c4.01-.91 7-4.49 7-8.77s-2.99-7.86-7-8.77z"/>';
}
function vidToggleFullscreen(){
  var w=document.getElementById('video-player-wrap');if(!w)return;
  if(!document.fullscreenElement){
    var p=w.requestFullscreen||w.webkitRequestFullscreen||w.mozRequestFullScreen||w.msRequestFullscreen;
    if(p){p.call(w).then(function(){try{var scr=screen.orientation||screen.msOrientation;if(scr&&scr.lock){scr.lock('landscape').catch(function(){});}else if(screen.lockOrientation){screen.lockOrientation('landscape');}}catch(e){}}).catch(function(){});}
  } else {
    var exit=document.exitFullscreen||document.webkitExitFullscreen||document.mozCancelFullScreen||document.msExitFullscreen;
    if(exit)exit.call(document).catch(function(){});
    try{var scr=screen.orientation||screen.msOrientation;if(scr&&scr.unlock)scr.unlock();else if(screen.unlockOrientation)screen.unlockOrientation();}catch(e){}
  }
  document.addEventListener('fullscreenchange',_vidUpdateFullBtn,{once:true});
  document.addEventListener('webkitfullscreenchange',_vidUpdateFullBtn,{once:true});
}
function _vidUpdateFullBtn(){
  var btn=document.getElementById('vid-full-btn');if(!btn)return;
  var isFs=!!document.fullscreenElement||!!document.webkitFullscreenElement;
  btn.innerHTML=isFs?'<svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M5 16h3v3h2v-5H5v2zm3-8H5v2h5V5H8v3zm6 11h2v-3h3v-2h-5v5zm2-11V5h-2v5h5V8h-3z"/></svg>':'<svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M7 14H5v5h5v-2H7v-3zm-2-4h2V7h3V5H5v5zm12 7h-3v2h5v-5h-2v3zM14 5v2h3v3h2V5h-5z"/></svg>';
}
function _vidUpdateNavBtns(){
  var pb=document.getElementById('vid-ol-prev');var nb=document.getElementById('vid-ol-next');
  if(pb){pb.classList.toggle('dimmed',_vidIdx===0);}
  if(nb){nb.classList.toggle('dimmed',_vidIdx===_vidList.length-1);}
}
function vidNavigate(dir){
  var ni=_vidIdx+dir;if(ni<0||ni>=_vidList.length)return;
  _vidIdx=ni;var f=_vidList[_vidIdx];_pvId=f._id;
  document.getElementById('preview-title').textContent=f.file_name||'Video';
  var tb=document.getElementById('vid-title-bar');if(tb)tb.textContent=f.file_name||'';
  if(_vidEl){_vidEl.src='/api/preview/'+f._id;_vidEl.load();_vidEl.oncanplay=function(){_vidEl.play().then(function(){_vidUpdatePlayBtn();}).catch(function(){});};}
  _vidUpdateNavBtns();
}

/* ── Audio Player ── */
function _buildAudioPlayer(body,onReady){
  var f=_audList[_audIdx];if(!f)return;
  var wrap=document.createElement('div');wrap.id='audio-player-wrap';
  var playlistItems=_audList.map(function(af,i){
    return '<div class="apl-item'+(i===_audIdx?' active':'')+'" onclick="audPlayIdx('+i+')" id="apl-'+af._id+'">'
      +'<span class="apl-idx">'+(i+1)+'</span>'
      +'<svg class="apl-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M9 9l10.5-3m0 6.553v3.75a2.25 2.25 0 01-1.632 2.163l-1.32.377a1.803 1.803 0 11-.99-3.467l2.31-.66a2.25 2.25 0 001.632-2.163zm0 0V2.25L9 5.25v10.303m0 0v3.75a2.25 2.25 0 01-1.632 2.163l-1.32.377a1.803 1.803 0 01-.99-3.467l2.31-.66A2.25 2.25 0 009 15.553z"/></svg>'
      +'<span class="apl-name">'+af.file_name+'</span>'
      +'</div>';
  }).join('');
  wrap.innerHTML='<audio id="audio-el" preload="auto"></audio>'
    +'<div id="audio-now-playing">'
    +'<div id="audio-art"><svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="rgba(255,255,255,0.6)" stroke-width="1.5" stroke-linecap="round"><path d="M9 9l10.5-3m0 6.553v3.75a2.25 2.25 0 01-1.632 2.163l-1.32.377a1.803 1.803 0 11-.99-3.467l2.31-.66a2.25 2.25 0 001.632-2.163zm0 0V2.25L9 5.25v10.303m0 0v3.75a2.25 2.25 0 01-1.632 2.163l-1.32.377a1.803 1.803 0 01-.99-3.467l2.31-.66A2.25 2.25 0 009 15.553z"/></svg></div>'
    +'<div id="audio-now-title">'+f.file_name+'</div>'
    +'<div id="audio-now-sub">'+(_audIdx+1)+' of '+_audList.length+'</div>'
    +'</div>'
    +'<div id="audio-scrubber-wrap"><div id="audio-progress-wrap"><div id="audio-progress-track"><div id="audio-progress-buf" style="position:absolute;left:0;top:0;height:100%;background:rgba(255,255,255,0.15);border-radius:3px;pointer-events:none"></div><div id="audio-progress-fill"></div><div id="audio-thumb"></div></div></div>'
    +'<div id="audio-times"><span id="aud-cur">0:00</span><span id="aud-dur">0:00</span></div></div>'
    +'<div id="audio-controls">'
    +'<button class="aud-btn" onclick="audNavigate(-1)" id="aud-prev-btn" title="Previous"><svg width="22" height="22" viewBox="0 0 24 24" fill="currentColor"><path d="M6 6h2v12H6zm3.5 6 8.5 6V6z"/></svg></button>'
    +'<button id="aud-play-btn" onclick="audTogglePlay()" title="Play/Pause"><svg id="aud-play-ico" width="26" height="26" viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7z"/></svg></button>'
    +'<button class="aud-btn" onclick="audNavigate(1)" id="aud-next-btn" title="Next"><svg width="22" height="22" viewBox="0 0 24 24" fill="currentColor"><path d="M6 18l8.5-6L6 6v12z"/><rect x="16" y="6" width="2" height="12"/></svg></button>'
    +'</div>'
    +'<div id="audio-playlist-wrap"><div id="audio-playlist-header"><span>Playlist</span><span style="font-weight:400">'+_audList.length+' tracks</span></div>'
    +'<div id="audio-playlist">'+playlistItems+'</div></div>';
  body.appendChild(wrap);
  _audEl=wrap.querySelector('#audio-el');
  _audLoadTrack(onReady);
  _audEl.addEventListener('timeupdate',_audSyncProgress);
  _audEl.addEventListener('ended',function(){if(_audIdx<_audList.length-1)audNavigate(1);});
  var pw=document.getElementById('audio-progress-wrap');
  pw.addEventListener('mousedown',function(e){_audDragging=true;_audSeekTo(e,pw);});
  document.addEventListener('mousemove',function(e){if(_audDragging)_audSeekTo(e,pw);});
  document.addEventListener('mouseup',function(){_audDragging=false;});
  pw.addEventListener('touchstart',function(e){_audDragging=true;_audSeekTouch(e,pw);},{passive:true});
  document.addEventListener('touchmove',function(e){if(_audDragging)_audSeekTouch(e,pw);},{passive:true});
  document.addEventListener('touchend',function(){_audDragging=false;});
}
function _audLoadTrack(onReady){
  var f=_audList[_audIdx];if(!f||!_audEl)return;
  _pvId=f._id;
  document.getElementById('preview-title').textContent=f.file_name||'Audio';
  var title=document.getElementById('audio-now-title');if(title)title.textContent=f.file_name||'Audio';
  var sub=document.getElementById('audio-now-sub');if(sub)sub.textContent=(_audIdx+1)+' of '+_audList.length;
  _audEl.src='/api/preview/'+f._id;
  _audEl.onloadedmetadata=function(){if(onReady){onReady();onReady=null;}};
  _audEl.oncanplay=function(){_audEl.play().then(function(){_audUpdatePlayBtn();_audUpdateArt(true);}).catch(function(){});};
  _audEl.onerror=function(){if(onReady){onReady();onReady=null;}};
  _audEl.addEventListener('progress',_audSyncBuffer);
  document.querySelectorAll('.apl-item').forEach(function(el,i){el.classList.toggle('active',i===_audIdx);});
  var activeEl=document.getElementById('apl-'+f._id);if(activeEl)activeEl.scrollIntoView({block:'nearest',behavior:'smooth'});
  _audUpdateBtns();_audUpdateArt(false);
}
function _audSyncProgress(){
  var a=_audEl;if(!a)return;
  var pct=a.duration?a.currentTime/a.duration*100:0;
  var fill=document.getElementById('audio-progress-fill');var thumb=document.getElementById('audio-thumb');
  if(fill)fill.style.width=pct+'%';if(thumb)thumb.style.left=pct+'%';
  var cur=document.getElementById('aud-cur');if(cur)cur.textContent=_fmtTime(a.currentTime);
  var dur=document.getElementById('aud-dur');if(dur)dur.textContent=_fmtTime(a.duration);
}
function _audSyncBuffer(){
  var a=_audEl;if(!a||!a.duration)return;
  var buf=0;for(var i=0;i<a.buffered.length;i++){if(a.buffered.start(i)<=a.currentTime&&a.currentTime<=a.buffered.end(i)){buf=a.buffered.end(i)/a.duration*100;break;}}
  var b=document.getElementById('audio-progress-buf');if(b)b.style.width=buf+'%';
}
function _audSeekTo(e,pw){var a=_audEl;if(!a||!a.duration)return;var r=pw.getBoundingClientRect();var pct=Math.max(0,Math.min(1,(e.clientX-r.left)/r.width));a.currentTime=pct*a.duration;_audSyncProgress();}
function _audSeekTouch(e,pw){if(!e.touches.length)return;_audSeekTo(e.touches[0],pw);}
function audTogglePlay(){var a=_audEl;if(!a)return;if(a.paused){a.play();_audUpdateArt(true);}else{a.pause();_audUpdateArt(false);}_audUpdatePlayBtn();}
function _audUpdatePlayBtn(){var ico=document.getElementById('aud-play-ico');if(!ico||!_audEl)return;ico.innerHTML=_audEl.paused?'<path d="M8 5v14l11-7z"/>':'<path d="M6 19h4V5H6v14zm8-14v14h4V5h-4z"/>';}
function _audUpdateArt(playing){var art=document.getElementById('audio-art');if(art)art.classList.toggle('playing',playing);}
function _audUpdateBtns(){var pb=document.getElementById('aud-prev-btn');var nb=document.getElementById('aud-next-btn');if(pb)pb.disabled=_audIdx===0;if(nb)nb.disabled=_audIdx===_audList.length-1;}
function audPlayIdx(idx){if(idx<0||idx>=_audList.length)return;var wasPlaying=_audEl&&!_audEl.paused;_audIdx=idx;_audLoadTrack(null);if(wasPlaying)setTimeout(function(){if(_audEl){_audEl.play();_audUpdateArt(true);_audUpdatePlayBtn();}},120);}
function audNavigate(dir){audPlayIdx(_audIdx+dir);}

/* ── Text/Code Viewer ── */
function _buildTextViewer(body,txt,name){
  var wrap=document.createElement('div');wrap.id='text-viewer-wrap';
  var pre=document.createElement('pre');pre.id='text-viewer-pre';pre.textContent=txt;
  wrap.appendChild(pre);
  body.appendChild(wrap);
  /* Show copy icon in the preview bar (same circle style as download btn) */
  var copyBtn=document.getElementById('preview-copy-btn');
  if(copyBtn){copyBtn.style.display='flex';}
}
function _textViewerCopy(){
  var pre=document.getElementById('text-viewer-pre');if(!pre)return;
  navigator.clipboard.writeText(pre.textContent).then(function(){
    var btn=document.getElementById('preview-copy-btn');if(!btn)return;
    var orig=btn.innerHTML;
    btn.innerHTML='<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>';
    btn.style.background='var(--green)';btn.style.color='#fff';
    setTimeout(function(){btn.innerHTML=orig;btn.style.background='';btn.style.color='';},1800);
  }).catch(function(){});
}

function showUnsupported(name){
  var body=document.getElementById('preview-body');
  var d=document.createElement('div');d.id='preview-unsupported';
  d.innerHTML='<div class="pu-icon-wrap">'+IC.file+'</div><h3>Can\'t preview this file</h3><p>Download it to open locally.</p><button class="pu-dl-btn" onclick="previewDownload()">'+IC.dl+' Download</button>';
  body.appendChild(d);
}
function _clearPreviewBody(body,sp){
  if(_vidEl){try{_vidEl.pause();_vidEl.src='';}catch(e){}}_vidEl=null;
  if(_audEl){try{_audEl.pause();_audEl.src='';}catch(e){}}_audEl=null;
  clearTimeout(_vidHideTimer);
  var cb=document.getElementById('preview-copy-btn');if(cb)cb.style.display='none';
  Array.from(body.children).forEach(function(c){if(c!==sp)c.remove();});
  sp.style.display='flex';
}
function closePreview(){
  var ov=document.getElementById('preview-overlay');ov.classList.remove('open');
  var body=document.getElementById('preview-body');var sp=document.getElementById('preview-spinner');
  _clearPreviewBody(body,sp);sp.style.display='none';_pvId=null;
  /* Restore folder URL when closing preview */
  var url='/drive';
  if(folder&&folder!=='root') url+='?folder='+encodeURIComponent(folder);
  history.pushState({folder:folder,folderName:folderName,stack:JSON.parse(JSON.stringify(stack))},'',url);
}
function previewDownload(){if(_pvId) dlFile(_pvId);}

let _avpStatsLoaded=false;
function toggleAvPopup(){
  var p=document.getElementById('av-popup');
  var open=p.classList.toggle('open');
  if(open&&!_avpStatsLoaded)loadAvpStats();
}
async function loadAvpStats(){
  try{
    var r=await fetch('/api/stats');
    if(!r.ok)throw new Error('HTTP '+r.status);
    var d=await r.json();
    _avpStatsLoaded=true;
    document.getElementById('avp-stats').innerHTML=
      '<div class="avp-stat-card"><div class="avp-stat-icon">'+IC.chart+'</div>'
      +'<div><div class="avp-stat-num">'+d.total_files+'</div><div class="avp-stat-label">Total Files'
      +(d.total_folders?' \u00b7 '+d.total_folders+' Folders':'')+'</div></div></div>';
  }catch(e){
    document.getElementById('avp-stats').innerHTML='<div style="font-size:12px;color:var(--text3)">Could not load stats</div>';
  }
}
document.addEventListener('click',function(e){
  var p=document.getElementById('av-popup');
  var av=document.getElementById('nav-av');
  if(p&&p.classList.contains('open')&&!p.contains(e.target)&&av&&!av.contains(e.target)){
    p.classList.remove('open');
  }
});

var ACCENT_COLORS=[
  {name:'Blue',hex:'#0483c3',hex2:'#0369a1'},
  {name:'Indigo',hex:'#6366f1',hex2:'#4f46e5'},
  {name:'Purple',hex:'#a855f7',hex2:'#9333ea'},
  {name:'Pink',hex:'#ec4899',hex2:'#db2777'},
  {name:'Rose',hex:'#f43f5e',hex2:'#e11d48'},
  {name:'Orange',hex:'#f97316',hex2:'#ea6c0a'},
  {name:'Amber',hex:'#f59e0b',hex2:'#d97706'},
  {name:'Green',hex:'#22c55e',hex2:'#16a34a'},
  {name:'Teal',hex:'#14b8a6',hex2:'#0d9488'},
  {name:'Cyan',hex:'#06b6d4',hex2:'#0891b2'}
];
function _hexToRgba(hex,a){
  var r=parseInt(hex.slice(1,3),16),g=parseInt(hex.slice(3,5),16),b=parseInt(hex.slice(5,7),16);
  return 'rgba('+r+','+g+','+b+','+a+')';
}
function applyAccent(hex,hex2,save){
  var r=document.documentElement.style;
  r.setProperty('--accent',hex);
  r.setProperty('--accent2',hex2);
  r.setProperty('--accent-dim',_hexToRgba(hex,.13));
  r.setProperty('--folder',hex);
  document.querySelectorAll('.ac-sw').forEach(function(s){
    var on=s.dataset.hex===hex;
    s.style.border='2px solid '+(on?'#fff':'transparent');
    s.style.boxShadow=on?'0 0 0 2px '+hex:'none';
  });
  if(save)localStorage.setItem('securebox_accent',JSON.stringify({hex:hex,hex2:hex2}));
}
function initAccentSwatches(){
  var el=document.getElementById('accent-swatches');
  if(!el)return;
  var saved=JSON.parse(localStorage.getItem('securebox_accent')||'null');
  var activeHex=(saved&&saved.hex)||'#0483c3';
  el.innerHTML=ACCENT_COLORS.map(function(c){
    return '<button class="ac-sw" data-hex="'+c.hex+'" data-hex2="'+c.hex2+'" title="'+c.name+'" '
      +'onclick="applyAccent(\''+c.hex+'\',\''+c.hex2+'\',true)" '
      +'style="background:'+c.hex+';border:2px solid '+(c.hex===activeHex?'#fff':'transparent')+';box-shadow:'+(c.hex===activeHex?'0 0 0 2px '+c.hex:'none')+'"></button>';
  }).join('');
  if(saved)applyAccent(saved.hex,saved.hex2,false);
}
initAccentSwatches();
document.addEventListener('keydown',function(e){
  if(e.key==='ArrowLeft'||e.key==='ArrowRight'){
    var ov2=document.getElementById('preview-overlay');
    if(ov2&&ov2.classList.contains('open')){
      if(document.getElementById('img-viewer'))_imgNavigate(e.key==='ArrowLeft'?-1:1);
      else if(document.getElementById('video-player-wrap'))vidNavigate(e.key==='ArrowLeft'?-1:1);
      return;
    }
  }
  if(e.key==='Escape'){
    var ov=document.getElementById('preview-overlay');
    if(ov&&ov.classList.contains('open')){closePreview();return;}
    document.querySelectorAll('.moverlay.open').forEach(function(m){m.classList.remove('open');});
    clearSel(); closeFab();
  }
  if(e.key==='Enter'){
    if(document.getElementById('m-rename').classList.contains('open')) doRename();
    else if(document.getElementById('m-mkdir').classList.contains('open')) doMkdir();
    else if(document.getElementById('m-search').classList.contains('open')) doSearch();
  }
});
"""

    body = (
        "<nav>"
        '<a href="/drive" class="nav-logo"><img src="/logo.png" alt="SecureBox" style="width:36px;height:36px;object-fit:contain"></a>'
        '<div class="nav-center"><div class="nav-search-wrap">'
        f'{_icon("search",16)}'
        '<input id="nav-search-input" type="text" placeholder="Search files and folders\u2026" onkeydown="if(event.key===\'Enter\')doNavSearch()"></div></div>'
        f'<div class="nav-avatar"><button class="nav-av-btn" id="nav-av" onclick="toggleAvPopup()" title="Account">'
        f'<img src="/avatar.png" alt="" style="display:none" '
        f'onload="this.style.display=\'block\';this.nextElementSibling.style.display=\'none\'" '
        f'onerror="this.style.display=\'none\'">'
        f'<span class="nav-av-initials">{user_initials}</span></button></div>'
        "</nav>"
        '<div id="av-popup">'
        '<div class="avp-head">'
        '<div class="avp-avatar" id="avp-av">'
        '<img src="/avatar.png" alt="" '
        'onload="this.style.display=\'block\';this.nextElementSibling.style.display=\'none\'" '
        'onerror="this.style.display=\'none\'">'
        f'<span>{user_initials}</span></div>'
        f'<div><div class="avp-name">{user_name}</div><div class="avp-uid">ID: {uid}</div></div>'
        '</div>'
        '<div class="avp-section">'
        '<div class="avp-section-label">Library</div>'
        '<div id="avp-stats"><div class="avp-sk"></div></div>'
        '</div>'
        '<div class="avp-section">'
        '<div class="avp-section-label">Accent Color</div>'
        '<div id="accent-swatches" style="display:flex;flex-wrap:wrap;gap:8px;align-items:center"></div>'
        '</div>'
        '<div class="avp-section">'
        f'<a href="/logout" class="btn btn-ghost btn-wide" style="color:var(--red);border-color:rgba(239,68,68,.3);justify-content:center;gap:8px">{_icon("signout",16)} Sign out</a>'
        '</div>'
        '</div>'
        '<div class="layout">'
        '<aside class="sidebar">'
        f'<div class="sb-item active" id="sb-home" onclick="navRoot()">{_icon("home",18)} My Drive</div>'
        f'<div class="sb-item" onclick="openSearchModal()">{_icon("search",18)} Search</div>'
        '<div class="sb-divider"></div>'
        '<div class="sb-label">Folders</div>'
        f'{sb}'
        '<div class="sb-divider"></div>'
        f'<a href="/logout" class="sb-item" style="color:var(--red)">{_icon("signout",18)} Sign out</a>'
        "</aside>"
        '<div class="main">'
        '<div class="toolbar">'
        f'<button class="btn btn-icon" id="back-btn" onclick="goBack()" style="display:none" title="Back">{_icon("back",20)}</button>'
        '<div class="breadcrumb" id="bc"><span class="bc-crumb last">My Drive</span></div>'
        "</div>"
        f'<div class="file-area" id="file-area"><div id="fl">{skel}</div></div>'
        "</div></div>"
        '<div id="fab">'
        '<div id="fab-opts" class="fab-options" style="display:none"></div>'
        f'<button class="fab-main" id="fab-share" onclick="selShare()" title="Share">{_icon("share",24)}</button>'
        f'<button class="fab-main" id="fab-btn" onclick="toggleFab()" title="New">{_icon("plus",26)}</button>'
        "</div>"
        '<div id="selbar">'
        f'<button class="sel-close" onclick="clearSel()">{ico_close}</button>'
        '<span id="selcnt">0 selected</span><div class="selbar-sep"></div>'
        f'<button class="sel-btn" id="sel-btn-dl" onclick="selDl()">{_icon("download",20)}<span>Download</span></button>'
        f'<button class="sel-btn" onclick="selCopy()">{_icon("copy",20)}<span>Copy</span></button>'
        f'<button class="sel-btn" onclick="selMove()">{_icon("move",20)}<span>Move</span></button>'
        f'<button class="sel-btn" onclick="selRename()">{_icon("rename",20)}<span>Rename</span></button>'
        f'<button class="sel-btn danger" onclick="selDel()">{_icon("delete",20)}<span>Delete</span></button>'
        "</div>"
        # Modals
        '<div class="moverlay" id="m-rename"><div class="modal">'
        f'<div class="modal-title">{_icon("rename",18)} Rename</div>'
        '<div class="fg"><label>New name</label><input id="i-rename" type="text"></div>'
        '<div class="macts"><button class="btn btn-ghost btn-sm" onclick="closeModal(\'rename\')">Cancel</button>'
        '<button class="btn btn-primary btn-sm" onclick="doRename()">Rename</button></div>'
        "</div></div>"
        '<div class="moverlay" id="m-mkdir"><div class="modal">'
        f'<div class="modal-title">{_icon("newfolder",18)} New folder</div>'
        '<div class="fg"><label>Folder name</label><input id="i-mkdir" type="text" placeholder="Untitled folder"></div>'
        '<div class="macts"><button class="btn btn-ghost btn-sm" onclick="closeModal(\'mkdir\')">Cancel</button>'
        '<button class="btn btn-primary btn-sm" onclick="doMkdir()">Create</button></div>'
        "</div></div>"
        '<div class="moverlay" id="m-share"><div class="modal">'
        f'<div class="modal-title">{_icon("share",18)} Share'
        '<span id="share-item-icon" style="margin-left:auto;display:flex;align-items:center;justify-content:center;width:34px;height:34px;border-radius:50%;background:var(--surface2);flex-shrink:0"></span></div>'
        '<div style="font-size:13px;color:var(--text2);margin:-10px 0 14px;word-break:break-word" id="share-item-name"></div>'
        '<div class="share-status off" id="share-status-box"></div>'
        '<div class="share-pw-row" id="share-enable-row">'
        f'<span class="lbl">{_icon("globe",16)} Anyone with the link</span>'
        '<label class="switch"><input type="checkbox" id="share-enable-toggle" onchange="shareTogglePublic(this.checked)"><span class="switch-track"></span></label>'
        "</div>"
        '<div class="share-pw-row">'
        f'<span class="lbl">{_icon("lock",16)} Require password</span>'
        '<label class="switch"><input type="checkbox" id="share-pw-toggle" onchange="sharePwToggleChanged(this.checked)"><span class="switch-track"></span></label>'
        "</div>"
        '<div class="fg" id="share-pw-field">'
        '<label>Password</label>'
        '<div style="display:flex;gap:8px">'
        '<input id="share-pw-input" type="text" placeholder="Enter a password" autocomplete="off" oninput="sharePwInputChanged()">'
        '<button id="share-pw-save-btn" class="btn btn-primary btn-sm" style="flex-shrink:0" onclick="shareSavePassword()">Save</button>'
        "</div></div>"
        '<div class="share-link-row" id="share-link-row">'
        '<input id="share-link-input" type="text" readonly>'
        f'<button class="btn btn-ghost btn-sm" style="flex-shrink:0" onclick="shareCopyLink()">{_icon("copy",16)} Copy</button>'
        "</div>"
        '<div class="macts">'
        '<button class="btn btn-danger btn-sm" id="share-clear-btn" style="margin-right:auto;display:none" onclick="shareClearLink()">'
        f'{_icon("delete",15)} Clear link</button>'
        '<button class="btn btn-ghost btn-sm" onclick="closeModal(\'share\')">Done</button>'
        "</div></div></div>"
        '<div class="moverlay" id="m-delete"><div class="modal">'
        f'<div class="modal-title">{_icon("delete",18)} Delete</div>'
        '<p id="del-msg" style="color:var(--text2);font-size:14px;margin-bottom:6px"></p>'
        '<p style="font-size:12px;color:var(--text3)">This action cannot be undone.</p>'
        '<div class="macts"><button class="btn btn-ghost btn-sm" onclick="closeModal(\'delete\')">Cancel</button>'
        '<button class="btn btn-danger btn-sm" onclick="doDelete()">Delete</button></div>'
        "</div></div>"
        '<div class="moverlay" id="m-movecopy"><div class="modal">'
        '<div class="modal-title" id="mv-title"></div>'
        '<div id="mv-list" style="max-height:320px;overflow-y:auto;border:1px solid var(--border);border-radius:var(--r8);margin-bottom:14px"></div>'
        '<div class="macts"><button class="btn btn-ghost btn-sm" onclick="closeModal(\'movecopy\')">Cancel</button>'
        '<button class="btn btn-primary btn-sm" id="mv-confirm" onclick="confirmMoveCopy()">Move Here</button></div>'
        "</div></div>"
        '<div class="moverlay" id="m-upload"><div class="modal">'
        f'<div class="modal-title">{_icon("upload",18)} Upload files</div>'
        '<div class="dropzone" id="dz"><input type="file" id="fi" multiple onchange="addFiles(this.files)">'
        f'<div class="dz-icon">{_icon("upload",34)}</div>'
        '<div class="dz-txt">Drop files here or tap to browse</div>'
        '<div class="dz-hint">Files will be saved to Telegram</div></div>'
        '<div class="ulist" id="ulist"></div>'
        '<div class="macts" style="margin-top:14px">'
        "<button class=\"btn btn-ghost btn-sm\" onclick=\"closeModal('upload');uploadQ=[];document.getElementById('ulist').innerHTML='';document.getElementById('fi').value=''\">Cancel</button>"
        f'<button class="btn btn-primary btn-sm" id="ubtn" onclick="startUpload()">{_icon("upload",15)} Upload</button>'
        "</div></div></div>"
        '<div class="moverlay" id="m-search"><div class="modal" style="max-width:480px">'
        f'<div class="modal-title">{_icon("search",18)} Search</div>'
        '<div class="fg" style="display:flex;gap:8px;margin-bottom:0">'
        '<input id="i-search" type="text" placeholder="Search files..." style="flex:1">'
        f'<button class="btn btn-primary" onclick="doSearch()" style="flex-shrink:0">{_icon("search",16)}</button></div>'
        '<div id="search-res" style="max-height:340px;overflow-y:auto;margin-top:12px;border:1px solid var(--border);border-radius:var(--r8)"></div>'
        "<div class=\"macts\"><button class=\"btn btn-ghost btn-sm\" onclick=\"clearSel();closeModal('search')\">Close</button></div>"
        "</div></div>"
        # Preview overlay
        '<div id="preview-overlay">'
        '<div id="preview-bar">'
        '<button id="preview-close-btn" onclick="closePreview()">'
        '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round">'
        '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>'
        '<span id="preview-title"></span>'
        '<button id="preview-copy-btn" onclick="_textViewerCopy()" title="Copy">'
        '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        '<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg></button>'
        '<button id="preview-dl-btn" onclick="previewDownload()">'
        '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        '<path d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3"/></svg></button>'
        "</div>"
        '<div id="preview-body">'
        '<div id="preview-spinner" style="display:none">'
        '<svg width="42" height="42" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">'
        '<path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg>'
        "</div></div></div>"
        f"<script>{js}</script>"
    )
    return _page(body, "My Drive")


# ── API — compatible with bot's DB schema ─────────────────────────────────────

@require_auth
async def api_files(request):
    """
    List subfolders and files for the current view.
    folder query param is either "root" or a folder _id (ObjectId hex string).
    Returns subfolders of that folder plus files stored directly in it.
    """
    uid         = request["uid"]
    files_col   = request.app["files_col"]
    folders_col = request.app["folders_col"]
    shares_col  = request.app["shares_col"]
    folder_param = request.rel_url.query.get("folder") or "root"

    if folder_param == "root":
        parent_id = None
    else:
        parent_id = folder_param

    # Subfolders directly under this folder (root = parent_id None, including
    # legacy folders saved without a parent_id field at all).
    if parent_id is None:
        folder_query = {"user_id": uid, "$or": [{"parent_id": None}, {"parent_id": {"$exists": False}}]}
    else:
        folder_query = {"user_id": uid, "parent_id": parent_id}

    docs = await folders_col.find(folder_query).sort("name", 1).to_list(500)
    sub_folders = [{"name": d.get("name", ""), "_id": str(d["_id"])} for d in docs if d.get("name")]

    # Files stored directly in this folder. Root files have folder_id == "" (or missing).
    if parent_id is None:
        file_query = {"user_id": uid, "$or": [{"folder_id": ""}, {"folder_id": {"$exists": False}}, {"folder_id": None}]}
    else:
        file_query = {"user_id": uid, "folder_id": parent_id}

    cursor = files_col.find(file_query).sort("_id", -1).limit(500)
    raw    = await cursor.to_list(500)

    def ser(f):
        oid             = f["_id"]
        # ObjectId first 4 bytes = Unix timestamp in seconds
        ts_ms           = oid.generation_time.timestamp() * 1000
        f["_id"]        = str(oid)
        f["file_name"]  = f.get("file_name", "file")
        f["file_type"]  = f.get("file_type", "document")
        f["created_at"] = ts_ms          # milliseconds — JS new Date(ms) works correctly
        return f

    files_ser = [ser(f) for f in raw]

    # Attach a "shared" badge flag to folders & files in one bulk query.
    share_map = await _shares_index_map(
        shares_col, uid,
        file_ids=[f["_id"] for f in files_ser],
        folder_ids=[f["_id"] for f in sub_folders],
    )
    for f in sub_folders:
        f["shared"] = ("folder", f["_id"]) in share_map
    for f in files_ser:
        f["shared"] = ("file", f["_id"]) in share_map

    # Resolve the current folder's name so the client can build breadcrumbs
    current_folder_name = "My Drive"
    if parent_id is not None:
        from bson import ObjectId as _OID
        try:
            cf = await folders_col.find_one({"_id": _OID(parent_id), "user_id": uid})
            if cf:
                current_folder_name = cf.get("name", "Folder")
        except Exception:
            pass

    return web.json_response({
        "folders": sub_folders,
        "files": files_ser,
        "folder_name": current_folder_name,
        "folder_id": folder_param,
    })


@require_auth
async def api_mkdir(request):
    """Create a new folder (or subfolder) under the given parent."""
    uid         = request["uid"]
    folders_col = request.app["folders_col"]
    body        = await request.json()
    name        = body.get("name", "").strip()
    parent_param = (body.get("parent") or "root").strip()
    parent_id   = None if parent_param == "root" else parent_param
    if not name:
        raise web.HTTPBadRequest(reason="Name required")
    existing = await folders_col.find_one({"user_id": uid, "parent_id": parent_id, "name": name})
    if existing:
        return web.json_response({"ok": True, "existed": True, "id": str(existing["_id"])})
    result = await folders_col.insert_one({"user_id": uid, "name": name, "parent_id": parent_id})
    return web.json_response({"ok": True, "id": str(result.inserted_id)})


@require_auth
async def api_rename(request):
    """Rename a file."""
    uid       = request["uid"]
    fid       = request.match_info["fid"]
    files_col = request.app["files_col"]
    body      = await request.json()
    name      = body.get("name", "").strip()
    if not name:
        raise web.HTTPBadRequest(reason="Name required")
    await files_col.update_one(
        {"_id": ObjectId(fid), "user_id": uid},
        {"$set": {"file_name": name}}
    )
    return web.json_response({"ok": True})


@require_auth
async def api_delete(request):
    """Delete a file from MongoDB (does not delete from Telegram)."""
    uid       = request["uid"]
    fid       = request.match_info["fid"]
    files_col = request.app["files_col"]
    shares_col = request.app["shares_col"]
    await files_col.delete_one({"_id": ObjectId(fid), "user_id": uid})
    if shares_col is not None:
        await shares_col.delete_one({"resource_type": "file", "resource_id": fid, "user_id": uid})
    return web.json_response({"ok": True})


@require_auth
async def api_rename_folder(request):
    """Rename a folder."""
    uid         = request["uid"]
    fid         = request.match_info["fid"]
    folders_col = request.app["folders_col"]
    files_col   = request.app["files_col"]
    body        = await request.json()
    name        = body.get("name", "").strip()
    if not name:
        raise web.HTTPBadRequest(reason="Name required")
    await folders_col.update_one(
        {"_id": ObjectId(fid), "user_id": uid},
        {"$set": {"name": name}}
    )
    # Keep folder_name in files in sync
    await files_col.update_many({"folder_id": fid, "user_id": uid}, {"$set": {"folder_name": name}})
    return web.json_response({"ok": True})


@require_auth
async def api_delete_folder(request):
    """Recursively delete a folder and all its contents."""
    uid         = request["uid"]
    fid         = request.match_info["fid"]
    folders_col = request.app["folders_col"]
    files_col   = request.app["files_col"]
    settings_col = request.app["settings_col"]
    shares_col  = request.app["shares_col"]

    # Verify ownership
    folder = await folders_col.find_one({"_id": ObjectId(fid), "user_id": uid})
    if not folder:
        raise web.HTTPNotFound()

    async def _delete_recursive(folder_id: str):
        children = await folders_col.find({"parent_id": folder_id, "user_id": uid}).to_list(1000)
        for child in children:
            await _delete_recursive(str(child["_id"]))
        if shares_col is not None:
            file_ids = [str(d["_id"]) for d in await files_col.find(
                {"folder_id": folder_id, "user_id": uid}, {"_id": 1}
            ).to_list(1000)]
            if file_ids:
                await shares_col.delete_many({"resource_type": "file", "resource_id": {"$in": file_ids}, "user_id": uid})
            await shares_col.delete_one({"resource_type": "folder", "resource_id": folder_id, "user_id": uid})
        await files_col.delete_many({"folder_id": folder_id, "user_id": uid})
        await folders_col.delete_one({"_id": ObjectId(folder_id)})
        await settings_col.update_many(
            {"default_folder_id": folder_id},
            {"$unset": {"default_folder_id": ""}}
        )

    await _delete_recursive(fid)
    return web.json_response({"ok": True})


async def _is_descendant(folders_col, uid, candidate_id, ancestor_id):
    """True if candidate_id is ancestor_id itself, or nested somewhere under it."""
    cur = candidate_id
    seen = set()
    while cur and cur not in seen:
        if cur == ancestor_id:
            return True
        seen.add(cur)
        doc = await folders_col.find_one({"_id": ObjectId(cur), "user_id": uid})
        cur = doc.get("parent_id") if doc else None
    return False


@require_auth
async def api_stats(request):
    """Quick stats for the avatar popup: total files & folders for this user."""
    uid         = request["uid"]
    files_col   = request.app["files_col"]
    folders_col = request.app["folders_col"]
    total_files   = await files_col.count_documents({"user_id": uid})
    total_folders = await folders_col.count_documents({"user_id": uid})
    return web.json_response({"total_files": total_files, "total_folders": total_folders})


@require_auth
async def api_move(request):
    """Move a single file into a different folder (or root)."""
    uid         = request["uid"]
    fid         = request.match_info["fid"]
    files_col   = request.app["files_col"]
    folders_col = request.app["folders_col"]
    body        = await request.json()
    dest        = (body.get("dest") or "root").strip()
    dest_id     = None if dest == "root" else dest

    dest_name = ""
    if dest_id is not None:
        d = await folders_col.find_one({"_id": ObjectId(dest_id), "user_id": uid})
        if not d:
            raise web.HTTPBadRequest(reason="Destination folder not found")
        dest_name = d.get("name", "")

    res = await files_col.update_one(
        {"_id": ObjectId(fid), "user_id": uid},
        {"$set": {"folder_id": dest_id or "", "folder_name": dest_name}}
    )
    if res.matched_count == 0:
        raise web.HTTPNotFound()
    return web.json_response({"ok": True})


@require_auth
async def api_move_folder(request):
    """Move a folder (and, implicitly, its contents) into a different parent folder."""
    uid         = request["uid"]
    fid         = request.match_info["fid"]
    folders_col = request.app["folders_col"]
    body        = await request.json()
    dest        = (body.get("dest") or "root").strip()
    dest_id     = None if dest == "root" else dest

    if dest_id == fid:
        raise web.HTTPBadRequest(reason="Cannot move a folder into itself")
    if dest_id is not None and await _is_descendant(folders_col, uid, dest_id, fid):
        raise web.HTTPBadRequest(reason="Cannot move a folder into its own subfolder")

    res = await folders_col.update_one(
        {"_id": ObjectId(fid), "user_id": uid},
        {"$set": {"parent_id": dest_id}}
    )
    if res.matched_count == 0:
        raise web.HTTPNotFound()
    return web.json_response({"ok": True})


@require_auth
async def api_copy(request):
    """Duplicate a file into a different folder (or root). Re-uses the same
    Telegram file_id, so this is an instant, storage-free copy."""
    uid         = request["uid"]
    fid         = request.match_info["fid"]
    files_col   = request.app["files_col"]
    folders_col = request.app["folders_col"]
    body        = await request.json()
    dest        = (body.get("dest") or "root").strip()
    dest_id     = None if dest == "root" else dest

    doc = await files_col.find_one({"_id": ObjectId(fid), "user_id": uid})
    if not doc:
        raise web.HTTPNotFound()

    dest_name = ""
    if dest_id is not None:
        d = await folders_col.find_one({"_id": ObjectId(dest_id), "user_id": uid})
        if not d:
            raise web.HTTPBadRequest(reason="Destination folder not found")
        dest_name = d.get("name", "")

    new_doc = dict(doc)
    new_doc.pop("_id", None)
    new_doc["folder_id"]   = dest_id or ""
    new_doc["folder_name"] = dest_name
    result = await files_col.insert_one(new_doc)
    return web.json_response({"ok": True, "id": str(result.inserted_id)})


@require_auth
async def api_copy_folder(request):
    """Recursively duplicate a folder (and its subfolders/files) into a different
    parent folder (or root)."""
    uid         = request["uid"]
    fid         = request.match_info["fid"]
    folders_col = request.app["folders_col"]
    files_col   = request.app["files_col"]
    body        = await request.json()
    dest        = (body.get("dest") or "root").strip()
    dest_id     = None if dest == "root" else dest

    if dest_id == fid:
        raise web.HTTPBadRequest(reason="Cannot copy a folder into itself")
    if dest_id is not None and await _is_descendant(folders_col, uid, dest_id, fid):
        raise web.HTTPBadRequest(reason="Cannot copy a folder into its own subfolder")

    src = await folders_col.find_one({"_id": ObjectId(fid), "user_id": uid})
    if not src:
        raise web.HTTPNotFound()

    async def _copy_recursive(folder_id, new_parent_id):
        folder = await folders_col.find_one({"_id": ObjectId(folder_id), "user_id": uid})
        if not folder:
            return
        new_name = folder.get("name", "Folder")
        new_res  = await folders_col.insert_one({
            "user_id": uid, "name": new_name, "parent_id": new_parent_id
        })
        new_folder_id = str(new_res.inserted_id)

        files_here = await files_col.find({"folder_id": folder_id, "user_id": uid}).to_list(2000)
        for f in files_here:
            nf = dict(f)
            nf.pop("_id", None)
            nf["folder_id"]   = new_folder_id
            nf["folder_name"] = new_name
            await files_col.insert_one(nf)

        children = await folders_col.find({"parent_id": folder_id, "user_id": uid}).to_list(1000)
        for child in children:
            await _copy_recursive(str(child["_id"]), new_folder_id)

    await _copy_recursive(fid, dest_id)
    return web.json_response({"ok": True})


@require_auth
async def api_search(request):
    """Search files by name."""
    uid       = request["uid"]
    q         = request.rel_url.query.get("q", "").strip()
    files_col = request.app["files_col"]
    shares_col = request.app["shares_col"]
    if not q:
        return web.json_response({"files": []})
    cursor = files_col.find({
        "user_id": uid,
        "file_name": {"$regex": q, "$options": "i"}
    }).sort("_id", -1).limit(50)
    raw = await cursor.to_list(50)
    def ser(f):
        oid             = f["_id"]
        ts_ms           = oid.generation_time.timestamp() * 1000
        f["_id"]        = str(oid)
        f["file_name"]  = f.get("file_name", "file")
        f["file_type"]  = f.get("file_type", "document")
        f["created_at"] = ts_ms
        return f
    files_ser = [ser(f) for f in raw]
    share_map = await _shares_index_map(shares_col, uid, file_ids=[f["_id"] for f in files_ser], folder_ids=[])
    for f in files_ser:
        f["shared"] = ("file", f["_id"]) in share_map
    return web.json_response({"files": files_ser})


# ── Share management API (auth'd owner side) ──────────────────────────────────

async def _resource_exists(request, resource_type, resource_id, uid):
    try:
        oid = ObjectId(resource_id)
    except Exception:
        return False
    if resource_type == "file":
        doc = await request.app["files_col"].find_one({"_id": oid, "user_id": uid})
    elif resource_type == "folder":
        doc = await request.app["folders_col"].find_one({"_id": oid, "user_id": uid})
    else:
        return False
    return doc is not None

def _share_public_url(token):
    base = _share_base_url()
    return f"{base}/s/{token}" if base else f"/s/{token}"

@require_auth
async def api_share_get(request):
    """Return the current public-share status for a file or folder."""
    uid           = request["uid"]
    resource_type = request.match_info["rtype"]
    resource_id   = request.match_info["rid"]
    shares_col    = request.app["shares_col"]
    if resource_type not in ("file", "folder"):
        raise web.HTTPBadRequest(reason="Invalid resource type")
    doc = await _find_share(shares_col, resource_type, resource_id, uid)
    if not doc:
        return web.json_response({"active": False})
    return web.json_response({
        "active": True,
        "url": _share_public_url(doc["token"]),
        "has_password": bool(doc.get("password_hash")),
    })

@require_auth
async def api_share_set(request):
    """Create, update, or toggle a public share link for a file or folder."""
    uid           = request["uid"]
    resource_type = request.match_info["rtype"]
    resource_id   = request.match_info["rid"]
    shares_col    = request.app["shares_col"]
    if resource_type not in ("file", "folder"):
        raise web.HTTPBadRequest(reason="Invalid resource type")
    if not await _resource_exists(request, resource_type, resource_id, uid):
        raise web.HTTPNotFound()

    body     = await request.json()
    enabled  = bool(body.get("enabled", True))
    password = body.get("password", None)  # None = leave unchanged; "" = remove; str = set

    existing = await _find_share(shares_col, resource_type, resource_id, uid)

    if not enabled:
        if existing:
            await shares_col.delete_one({"_id": existing["_id"]})
        return web.json_response({"active": False})

    update = {}
    if password is not None:
        update["password_hash"] = _hash_pw(password) if password else None

    if existing:
        if update:
            await shares_col.update_one({"_id": existing["_id"]}, {"$set": update})
        token = existing["token"]
    else:
        token = _gen_share_token()
        doc = {
            "user_id": uid,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "token": token,
            "password_hash": (_hash_pw(password) if password else None),
            "created_at": time.time(),
        }
        await shares_col.insert_one(doc)

    fresh = await shares_col.find_one({"token": token})
    return web.json_response({
        "active": True,
        "url": _share_public_url(token),
        "has_password": bool(fresh.get("password_hash")),
    })

@require_auth
async def api_share_clear(request):
    """Remove a public share link entirely."""
    uid           = request["uid"]
    resource_type = request.match_info["rtype"]
    resource_id   = request.match_info["rid"]
    shares_col    = request.app["shares_col"]
    await shares_col.delete_one({
        "resource_type": resource_type, "resource_id": resource_id, "user_id": uid,
    })
    return web.json_response({"active": False})


@require_auth
async def api_download(request):
    """Stream a file from Telegram for download using bot's telegram_file_id field."""
    uid       = request["uid"]
    fid       = request.match_info["fid"]
    files_col = request.app["files_col"]
    bot_inst  = request.app.get("bot_instance")
    try:
        doc = await files_col.find_one({"_id": ObjectId(fid), "user_id": uid})
        if not doc:
            raise web.HTTPNotFound()
        tg_fid    = doc.get("telegram_file_id")
        file_name = doc.get("file_name", "file")
        file_size = doc.get("file_size")
        if not tg_fid:
            raise web.HTTPNotFound(reason="No file_id stored")
        if not bot_inst:
            raise web.HTTPServiceUnavailable(reason="Bot not connected")
        return await _pyro_stream_response(
            request, bot_inst, tg_fid, file_size, file_name,
            content_type="application/octet-stream", disposition="attachment",
        )
    except web.HTTPException:
        raise
    except Exception as e:
        logger.error(f"api_download: {e}", exc_info=True)
        raise web.HTTPInternalServerError(reason=str(e))


@require_auth
async def api_preview(request):
    """Stream a file inline for preview."""
    uid       = request["uid"]
    fid       = request.match_info["fid"]
    files_col = request.app["files_col"]
    bot_inst  = request.app.get("bot_instance")
    try:
        doc = await files_col.find_one({"_id": ObjectId(fid), "user_id": uid})
        if not doc:
            raise web.HTTPNotFound()
        tg_fid    = doc.get("telegram_file_id")
        file_name = doc.get("file_name", "file")
        file_size = doc.get("file_size")
        ft        = doc.get("file_type", "document")
        if not tg_fid:
            raise web.HTTPNotFound(reason="No file_id stored")
        # Map file_type → default MIME
        mime_map = {
            "photo": "image/jpeg", "video": "video/mp4",
            "audio": "audio/mpeg",
        }
        ct = mime_map.get(ft, "application/octet-stream")
        # Extension overrides take priority — critical for non-mp4 video files
        # stored as "document" type (mkv, webm, avi…) or non-mp3 audio.
        ext_map = {
            # images
            "jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png",
            "gif": "image/gif",  "webp": "image/webp", "bmp": "image/bmp",
            # video — all formats browsers can play natively
            "mp4":  "video/mp4",  "m4v": "video/mp4",
            "webm": "video/webm", "ogv": "video/ogg",
            "mov":  "video/quicktime",
            "mkv":  "video/x-matroska",
            "avi":  "video/x-msvideo",
            "3gp":  "video/3gpp",
            "flv":  "video/x-flv",
            # audio
            "mp3":  "audio/mpeg",  "m4a": "audio/mp4",
            "ogg":  "audio/ogg",   "oga": "audio/ogg",
            "opus": "audio/opus",  "wav": "audio/wav",
            "flac": "audio/flac",  "aac": "audio/aac",
            "weba": "audio/webm",
            # docs
            "pdf": "application/pdf",
        }
        ext = file_name.rsplit(".", 1)[-1].lower() if "." in file_name else ""
        if ext in ext_map:
            ct = ext_map[ext]
        # If Telegram stored a mime_type (e.g. for documents), use it as the
        # most authoritative source — but only for streamable media types.
        db_mime = doc.get("mime_type", "")
        if db_mime and not db_mime.startswith("application/"):
            ct = db_mime
        if not bot_inst:
            raise web.HTTPServiceUnavailable(reason="Bot not connected")
        return await _pyro_stream_response(
            request, bot_inst, tg_fid, file_size, file_name,
            content_type=ct, disposition="inline",
        )
    except web.HTTPException:
        raise
    except Exception as e:
        logger.error(f"api_preview: {e}", exc_info=True)
        raise web.HTTPInternalServerError(reason=str(e))


@require_auth
async def api_upload(request):
    """
    Upload a file via WebUI. Sends to the user's Saved Messages via the bot.
    Uses the correct Telegram send method per file type so files appear
    natively (photos as photos, videos as videos, etc.).
    """
    import tempfile, mimetypes
    uid         = request["uid"]
    bot_inst    = request.app.get("bot_instance")
    files_col   = request.app["files_col"]
    folders_col = request.app["folders_col"]

    if not bot_inst:
        raise web.HTTPServiceUnavailable(reason="Bot not connected")

    tmp_path = None
    try:
        reader          = await request.multipart()
        folder_id_param = None
        file_name       = "upload"

        async for part in reader:
            if part.name == "folder":
                v = (await part.read_chunk()).decode().strip()
                folder_id_param = None if not v or v == "root" else v
            elif part.name == "file":
                file_name = part.filename or "upload"
                fd, tmp_path = tempfile.mkstemp(suffix="_" + file_name)
                with os.fdopen(fd, "wb") as f:
                    while True:
                        chunk = await part.read_chunk(1024 * 1024)
                        if not chunk:
                            break
                        f.write(chunk)

        if tmp_path is None:
            raise web.HTTPBadRequest(reason="No file received")

        # Classify by extension
        ext = file_name.rsplit(".", 1)[-1].lower() if "." in file_name else ""
        photo_exts = {"jpg", "jpeg", "png", "webp", "gif", "bmp", "tiff", "heic", "heif"}
        video_exts = {"mp4", "mov", "avi", "mkv", "webm", "m4v", "flv", "wmv", "3gp"}
        audio_exts = {"mp3", "ogg", "flac", "wav", "aac", "m4a", "opus", "wma", "amr"}

        if ext in photo_exts:
            ft = "photo"
        elif ext in video_exts:
            ft = "video"
        elif ext in audio_exts:
            ft = "audio"
        else:
            ft = "document"

        # Detect MIME type — critical for text/code files (.py, .md, etc.)
        # Without this Telegram rejects or mishandles them.
        mime, _ = mimetypes.guess_type(file_name)
        if not mime:
            # Fallback: treat unknown types as binary stream
            mime = "application/octet-stream"

        # Send using the right Telegram method — no caption needed
        if ft == "photo":
            sent = await bot_inst.send_photo(uid, tmp_path)
        elif ft == "video":
            sent = await bot_inst.send_video(uid, tmp_path)
        elif ft == "audio":
            sent = await bot_inst.send_audio(uid, tmp_path)
        else:
            # force_document=True ensures Telegram never auto-converts the file.
            # file_name preserves the original name (including extension) so that
            # text/code files like .py, .json, .md, .txt are stored correctly.
            sent = await bot_inst.send_document(
                uid,
                tmp_path,
                file_name=file_name,
                force_document=True,
            )

        os.unlink(tmp_path)
        tmp_path = None

        # Resolve folder
        folder_id_str = ""
        folder_name   = ""
        if folder_id_param:
            folder_doc = await folders_col.find_one({"_id": ObjectId(folder_id_param), "user_id": uid})
            if folder_doc:
                folder_id_str = str(folder_doc["_id"])
                folder_name   = folder_doc.get("name", "")

        # Extract file_id and file_size from the sent message
        if ft == "photo" and sent.photo:
            file_id   = sent.photo.file_id
            file_size = sent.photo.file_size
        elif ft == "video" and sent.video:
            file_id   = sent.video.file_id
            file_size = sent.video.file_size
        elif ft == "audio" and sent.audio:
            file_id   = sent.audio.file_id
            file_size = sent.audio.file_size
        elif sent.document:
            file_id   = sent.document.file_id
            file_size = sent.document.file_size
            ft = "document"
        else:
            raise web.HTTPInternalServerError(reason="Telegram returned no media object")

        doc = {
            "user_id":          uid,
            "folder_id":        folder_id_str or "",
            "folder_name":      folder_name or "",
            "file_name":        file_name,
            "telegram_file_id": file_id,
            "file_type":        ft,
            "file_size":        file_size,
        }
        res = await files_col.insert_one(doc)
        return web.json_response({"ok": True, "id": str(res.inserted_id)})

    except web.HTTPException:
        raise
    except Exception as e:
        logger.error(f"api_upload: {e}", exc_info=True)
        raise web.HTTPInternalServerError(reason=str(e))
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except Exception:
                pass


# ── Public share pages (no auth — gated by token + optional password) ─────────

_PW_COOKIE_PREFIX = "spw_"


def _build_share_player_page(token, title, files, auto_fid, dl_url, back_url=None):
    """Build a standalone HTML page that uses our existing video/audio/image/text players.
    files: list of dicts with _id, file_name, file_type (for folder views with multiple files).
    auto_fid: the file _id to open immediately on load.
    dl_url: the download href for the currently previewed file.
    back_url: optional href for a "back to folder" button in the overlay bar.
    """
    import json as _json

    def _js_str(s):
        return s.replace("\\", "\\\\").replace("`", "\\`")

    ic_folder = _js_str(_icon("folder", 32, "", "#0386c3"))
    ic_file   = _js_str(_icon("file",   32, "", "#607d8b"))
    ic_image  = _js_str(_icon("image",  32, "", "#a78bfa"))
    ic_video  = _js_str(_icon("video",  32, "", "#f87171"))
    ic_audio  = _js_str(_icon("audio",  32, "", "#e55835"))
    ic_dl     = _js_str(_icon("download", 20))

    ic_js_init = (
        "var IC={"
        f"folder:`{ic_folder}`,"
        f"file:`{ic_file}`,"
        f"image:`{ic_image}`,"
        f"video:`{ic_video}`,"
        f"audio:`{ic_audio}`,"
        f"dl:`{ic_dl}`"
        "};"
    )

    # Serialize file list for JS
    files_js = _json.dumps([{"_id": str(f["_id"]), "file_name": f.get("file_name",""), "file_type": f.get("file_type","document")} for f in files])

    back_btn_html = ""
    if back_url:
        back_btn_html = (
            f'<a href="{back_url}" id="preview-back-btn" style="width:36px;height:36px;border-radius:50%;border:none;cursor:pointer;background:rgba(255,255,255,.08);color:var(--text2);display:flex;align-items:center;justify-content:center;flex-shrink:0;text-decoration:none;transition:background .15s" title="Back to folder">'
            '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg></a>'
        )

    overlay_html = (
        '<div id="preview-overlay" class="open">'
        '<div id="preview-bar">'
        f'{back_btn_html}'
        '<span id="preview-title"></span>'
        '<button id="preview-copy-btn" onclick="_textViewerCopy()" title="Copy" style="display:none">'
        '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        '<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg></button>'
        f'<a id="preview-dl-btn" href="{dl_url}" download style="width:36px;height:36px;border-radius:50%;border:none;cursor:pointer;background:rgba(255,255,255,.1);color:var(--text);display:flex;align-items:center;justify-content:center;flex-shrink:0;text-decoration:none;transition:background .15s">'
        '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        '<path d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3"/></svg></a>'
        '</div>'
        '<div id="preview-body">'
        '<div id="preview-spinner">'
        '<svg width="42" height="42" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">'
        '<path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg>'
        '</div></div></div>'
    )

    # JS: player functions with preview URL adapted to share endpoint
    # We replace /api/preview/{id} with /s/{token}/preview?fid={id}
    # and previewDownload uses the per-file download URL
    js = f"""
{ic_js_init}
var _pvId=null, _pvFiles={files_js}, _pvToken='{token}';
var _vidEl=null, _vidList=[], _vidIdx=0, _vidHideTimer=null, _vidDragging=false;
var _audEl=null, _audList=[], _audIdx=0, _audDragging=false;
var _imgList=[], _imgIdx=0;

function _previewUrl(fid){{return '/s/'+_pvToken+'/preview?fid='+fid;}}
function _dlUrl(fid){{return '/s/'+_pvToken+'/download?fid='+fid;}}

function _updateDlBtn(fid){{
  var btn=document.getElementById('preview-dl-btn');
  if(btn){{btn.href=_dlUrl(fid);}}
}}

function _fmtTime(s){{if(isNaN(s)||!isFinite(s))return'0:00';var m=Math.floor(s/60),sc=Math.floor(s%60);return m+':'+(sc<10?'0':'')+sc;}}

function openSharePreview(fid, ft, name){{
  _pvId=fid;
  document.getElementById('preview-title').textContent=name||'Preview';
  _updateDlBtn(fid);
  var body=document.getElementById('preview-body');
  var sp=document.getElementById('preview-spinner');
  _clearPreviewBody(body,sp);
  sp.style.display='flex';
  var _ext=name&&name.includes('.')?name.split('.').pop().toLowerCase():'';
  var _vidExts={{mp4:1,webm:1,ogv:1,mov:1,mkv:1,avi:1,m4v:1,'3gp':1,flv:1}};
  var _audExts={{mp3:1,m4a:1,ogg:1,oga:1,opus:1,wav:1,flac:1,aac:1,weba:1,wma:1,amr:1}};
  var hide=function(){{sp.style.display='none';}};
  if(ft==='photo'||ft==='image'){{
    _imgList=[{{_id:fid,file_name:name,file_type:ft}}];_imgIdx=0;
    _buildImageViewer(body,hide);
  }} else if(ft==='video'||_vidExts[_ext]){{
    _vidList=[{{_id:fid,file_name:name,file_type:ft}}];_vidIdx=0;
    _buildVideoPlayer(body,hide);
  }} else if(ft==='audio'||_audExts[_ext]){{
    _audList=[{{_id:fid,file_name:name,file_type:ft}}];_audIdx=0;
    _buildAudioPlayer(body,hide);
  }} else {{
    fetch(_previewUrl(fid)).then(function(r){{if(!r.ok)throw new Error(r.status);return r.text();}}).then(function(txt){{
      hide();_buildTextViewer(body,txt,name);
    }}).catch(function(){{hide();showUnsupported(name);}});
  }}
}}

function _buildImageViewer(body,onReady){{
  var f=_imgList[_imgIdx];if(!f)return;
  var wrap=document.createElement('div');wrap.id='img-viewer';
  var img=document.createElement('img');img.style.opacity='0';img.style.transition='opacity .22s';
  var counter=document.createElement('div');counter.className='img-counter';
  wrap.appendChild(img);wrap.appendChild(counter);
  body.appendChild(wrap);
  img.onload=function(){{if(onReady){{onReady();onReady=null;}}img.style.opacity='1';}};
  img.onerror=function(){{if(onReady){{onReady();onReady=null;}}showUnsupported(f.file_name);}};
  img.src=_previewUrl(f._id);
  document.getElementById('preview-title').textContent=f.file_name||'Image';
  counter.style.display='none';
}}

function _buildVideoPlayer(body,onReady){{
  var f=_vidList[_vidIdx];if(!f)return;
  var wrap=document.createElement('div');wrap.id='video-player-wrap';
  var vid=document.createElement('video');vid.playsInline=true;vid.preload='auto';_vidEl=vid;
  wrap.innerHTML='<div id="vid-play-flash"></div>'
    +'<div id="vid-overlay-center">'
    +'<button class="vid-overlay-btn lg" id="vid-ol-play" onclick="vidTogglePlay()" title="Play/Pause"><svg id="vid-overlay-play-ico" width="34" height="34" viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7z"/></svg></button>'
    +'</div>'
    +'<div id="vid-controls">'
    +'<div id="vid-progress-wrap"><div id="vid-progress-track"><div id="vid-progress-buf"></div><div id="vid-progress-fill"></div><div id="vid-thumb"></div></div></div>'
    +'<div id="vid-controls-row">'
    +'<button class="vid-btn" id="vid-play-btn" title="Play/Pause" onclick="vidTogglePlay()"><svg id="vid-play-ico" width="26" height="26" viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7z"/></svg></button>'
    +'<span id="vid-time">0:00 / 0:00</span>'
    +'<span id="vid-title-bar"></span>'
    +'<div id="vid-vol-wrap"><button class="vid-btn" id="vid-mute-btn" onclick="vidToggleMute()"><svg id="vid-vol-ico" width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M3 9v6h4l5 5V4L7 9H3zm13.5 3c0-1.77-1.02-3.29-2.5-4.03v8.05c1.48-.73 2.5-2.25 2.5-4.02zM14 3.23v2.06c2.89.86 5 3.54 5 6.71s-2.11 5.85-5 6.71v2.06c4.01-.91 7-4.49 7-8.77s-2.99-7.86-7-8.77z"/></svg></button></div>'
    +'<button class="vid-btn" id="vid-full-btn" onclick="vidToggleFullscreen()" title="Fullscreen"><svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M7 14H5v5h5v-2H7v-3zm-2-4h2V7h3V5H5v5zm12 7h-3v2h5v-5h-2v3zM14 5v2h3v3h2V5h-5z"/></svg></button>'
    +'</div></div>';
  wrap.insertBefore(vid,wrap.firstChild);
  body.appendChild(wrap);
  vid.src=_previewUrl(f._id);
  _updateDlBtn(f._id);
  var tb=document.getElementById('vid-title-bar');if(tb)tb.textContent=f.file_name||'';
  vid.oncanplay=function(){{if(onReady){{onReady();onReady=null;}}vid.play().then(function(){{_vidUpdatePlayBtn();}}).catch(function(){{}});}};
  vid.onerror=function(){{if(onReady){{onReady();onReady=null;}}showUnsupported(f.file_name);}};
  vid.addEventListener('timeupdate',_vidSyncProgress);
  vid.addEventListener('progress',_vidSyncBuffer);
  var _tapTimer=null,_tapCount=0,_tapX=0;
  vid.addEventListener('click',function(e){{
    _tapCount++;_tapX=e.clientX;
    if(_tapTimer)clearTimeout(_tapTimer);
    _tapTimer=setTimeout(function(){{
      if(_tapCount>=2){{var rect=vid.getBoundingClientRect();var pct=(_tapX-rect.left)/rect.width;var secs=10;
        if(pct<0.5){{vid.currentTime=Math.max(0,vid.currentTime-secs);}}
        else{{vid.currentTime=Math.min(vid.duration||0,vid.currentTime+secs);}}
      }}
      _tapCount=0;_tapTimer=null;
    }},280);
  }});
  wrap.addEventListener('mousemove',_vidShowControls);
  wrap.addEventListener('touchstart',_vidShowControls,{{passive:true}});
  var pw=document.getElementById('vid-progress-wrap');
  pw.addEventListener('mousedown',function(e){{_vidDragging=true;_vidSeekTo(e,pw);}});
  document.addEventListener('mousemove',function(e){{if(_vidDragging)_vidSeekTo(e,pw);}});
  document.addEventListener('mouseup',function(){{_vidDragging=false;}});
  pw.addEventListener('touchstart',function(e){{_vidDragging=true;_vidSeekTouch(e,pw);}},{{passive:true}});
  document.addEventListener('touchmove',function(e){{if(_vidDragging)_vidSeekTouch(e,pw);}},{{passive:true}});
  document.addEventListener('touchend',function(){{_vidDragging=false;}});
}}
function _vidShowControls(){{var w=document.getElementById('video-player-wrap');if(w)w.classList.remove('controls-hidden');clearTimeout(_vidHideTimer);if(_vidEl&&!_vidEl.paused){{_vidHideTimer=setTimeout(function(){{var w2=document.getElementById('video-player-wrap');if(w2)w2.classList.add('controls-hidden');}},3000);}}}}
function _vidSyncProgress(){{var vid=_vidEl;if(!vid)return;var pct=vid.duration?vid.currentTime/vid.duration*100:0;var fill=document.getElementById('vid-progress-fill');var thumb=document.getElementById('vid-thumb');if(fill)fill.style.width=pct+'%';if(thumb)thumb.style.left=pct+'%';var t=document.getElementById('vid-time');if(t)t.textContent=_fmtTime(vid.currentTime)+' / '+_fmtTime(vid.duration);}}
function _vidSyncBuffer(){{var vid=_vidEl;if(!vid||!vid.duration)return;var buf=0;for(var i=0;i<vid.buffered.length;i++){{if(vid.buffered.start(i)<=vid.currentTime&&vid.currentTime<=vid.buffered.end(i)){{buf=vid.buffered.end(i)/vid.duration*100;break;}}}}var b=document.getElementById('vid-progress-buf');if(b)b.style.width=buf+'%';}}
function _vidSeekTo(e,pw){{var vid=_vidEl;if(!vid||!vid.duration)return;var r=pw.getBoundingClientRect();var pct=Math.max(0,Math.min(1,(e.clientX-r.left)/r.width));vid.currentTime=pct*vid.duration;_vidSyncProgress();}}
function _vidSeekTouch(e,pw){{if(!e.touches.length)return;_vidSeekTo(e.touches[0],pw);}}
function vidTogglePlay(){{var vid=_vidEl;if(!vid)return;if(vid.paused){{vid.play();}}else{{vid.pause();}}_vidUpdatePlayBtn();_vidShowControls();}}
function _vidUpdatePlayBtn(){{var paused=_vidEl?_vidEl.paused:true;var path=paused?'<path d="M8 5v14l11-7z"/>':'<path d="M6 19h4V5H6v14zm8-14v14h4V5h-4z"/>';var ico=document.getElementById('vid-play-ico');if(ico)ico.innerHTML=path;var oico=document.getElementById('vid-overlay-play-ico');if(oico)oico.innerHTML=path;}}
function vidToggleMute(){{var vid=_vidEl;if(!vid)return;vid.muted=!vid.muted;var ico=document.getElementById('vid-vol-ico');if(!ico)return;ico.innerHTML=vid.muted?'<path d="M16.5 12c0-1.77-1.02-3.29-2.5-4.03v2.21l2.45 2.45c.03-.2.05-.41.05-.63zm2.5 0c0 .94-.2 1.82-.54 2.64l1.51 1.51C20.63 14.91 21 13.5 21 12c0-4.28-2.99-7.86-7-8.77v2.06c2.89.86 5 3.54 5 6.71zM4.27 3L3 4.27 7.73 9H3v6h4l5 5v-6.73l4.25 4.25c-.67.52-1.42.93-2.25 1.18v2.06c1.38-.31 2.63-.95 3.69-1.81L19.73 21 21 19.73l-9-9L4.27 3zM12 4L9.91 6.09 12 8.18V4z"/>':'<path d="M3 9v6h4l5 5V4L7 9H3zm13.5 3c0-1.77-1.02-3.29-2.5-4.03v8.05c1.48-.73 2.5-2.25 2.5-4.02zM14 3.23v2.06c2.89.86 5 3.54 5 6.71s-2.11 5.85-5 6.71v2.06c4.01-.91 7-4.49 7-8.77s-2.99-7.86-7-8.77z"/>';}}
function vidToggleFullscreen(){{var w=document.getElementById('video-player-wrap');if(!w)return;if(!document.fullscreenElement){{var p=w.requestFullscreen||w.webkitRequestFullscreen||w.mozRequestFullScreen||w.msRequestFullscreen;if(p)p.call(w).catch(function(){{}});}}else{{var exit=document.exitFullscreen||document.webkitExitFullscreen;if(exit)exit.call(document).catch(function(){{}});}}}}

function _buildAudioPlayer(body,onReady){{
  var f=_audList[_audIdx];if(!f)return;
  var wrap=document.createElement('div');wrap.id='audio-player-wrap';
  var playlistItems=_audList.map(function(af,i){{
    return '<div class="apl-item'+(i===_audIdx?' active':'')+'" onclick="audPlayIdx('+i+')" id="apl-'+af._id+'">'
      +'<span class="apl-idx">'+(i+1)+'</span>'
      +'<svg class="apl-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M9 9l10.5-3m0 6.553v3.75a2.25 2.25 0 01-1.632 2.163l-1.32.377a1.803 1.803 0 11-.99-3.467l2.31-.66a2.25 2.25 0 001.632-2.163zm0 0V2.25L9 5.25v10.303m0 0v3.75a2.25 2.25 0 01-1.632 2.163l-1.32.377a1.803 1.803 0 01-.99-3.467l2.31-.66A2.25 2.25 0 009 15.553z"/></svg>'
      +'<span class="apl-name">'+af.file_name+'</span>'
      +'</div>';
  }}).join('');
  wrap.innerHTML='<audio id="audio-el" preload="auto"></audio>'
    +'<div id="audio-now-playing">'
    +'<div id="audio-art"><svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="rgba(255,255,255,0.6)" stroke-width="1.5" stroke-linecap="round"><path d="M9 9l10.5-3m0 6.553v3.75a2.25 2.25 0 01-1.632 2.163l-1.32.377a1.803 1.803 0 11-.99-3.467l2.31-.66a2.25 2.25 0 001.632-2.163zm0 0V2.25L9 5.25v10.303m0 0v3.75a2.25 2.25 0 01-1.632 2.163l-1.32.377a1.803 1.803 0 01-.99-3.467l2.31-.66A2.25 2.25 0 009 15.553z"/></svg></div>'
    +'<div id="audio-now-title">'+f.file_name+'</div>'
    +'<div id="audio-now-sub">'+(_audIdx+1)+' of '+_audList.length+'</div>'
    +'</div>'
    +'<div id="audio-scrubber-wrap"><div id="audio-progress-wrap"><div id="audio-progress-track"><div id="audio-progress-buf" style="position:absolute;left:0;top:0;height:100%;background:rgba(255,255,255,0.15);border-radius:3px;pointer-events:none"></div><div id="audio-progress-fill"></div><div id="audio-thumb"></div></div></div>'
    +'<div id="audio-times"><span id="aud-cur">0:00</span><span id="aud-dur">0:00</span></div></div>'
    +'<div id="audio-controls">'
    +'<button class="aud-btn" onclick="audNavigate(-1)" id="aud-prev-btn" title="Previous"><svg width="22" height="22" viewBox="0 0 24 24" fill="currentColor"><path d="M6 6h2v12H6zm3.5 6 8.5 6V6z"/></svg></button>'
    +'<button id="aud-play-btn" onclick="audTogglePlay()" title="Play/Pause"><svg id="aud-play-ico" width="26" height="26" viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7z"/></svg></button>'
    +'<button class="aud-btn" onclick="audNavigate(1)" id="aud-next-btn" title="Next"><svg width="22" height="22" viewBox="0 0 24 24" fill="currentColor"><path d="M6 18l8.5-6L6 6v12z"/><rect x="16" y="6" width="2" height="12"/></svg></button>'
    +'</div>'
    +'<div id="audio-playlist-wrap"><div id="audio-playlist-header"><span>Playlist</span><span style="font-weight:400">'+_audList.length+' tracks</span></div>'
    +'<div id="audio-playlist">'+playlistItems+'</div></div>';
  body.appendChild(wrap);
  _audEl=wrap.querySelector('#audio-el');
  _audLoadTrack(onReady);
  _audEl.addEventListener('timeupdate',_audSyncProgress);
  _audEl.addEventListener('ended',function(){{if(_audIdx<_audList.length-1)audNavigate(1);}});
  var pw=document.getElementById('audio-progress-wrap');
  pw.addEventListener('mousedown',function(e){{_audDragging=true;_audSeekTo(e,pw);}});
  document.addEventListener('mousemove',function(e){{if(_audDragging)_audSeekTo(e,pw);}});
  document.addEventListener('mouseup',function(){{_audDragging=false;}});
  pw.addEventListener('touchstart',function(e){{_audDragging=true;_audSeekTouch(e,pw);}},{{passive:true}});
  document.addEventListener('touchmove',function(e){{if(_audDragging)_audSeekTouch(e,pw);}},{{passive:true}});
  document.addEventListener('touchend',function(){{_audDragging=false;}});
}}
function _audLoadTrack(onReady){{
  var f=_audList[_audIdx];if(!f||!_audEl)return;
  _pvId=f._id;_updateDlBtn(f._id);
  document.getElementById('preview-title').textContent=f.file_name||'Audio';
  var title=document.getElementById('audio-now-title');if(title)title.textContent=f.file_name||'Audio';
  var sub=document.getElementById('audio-now-sub');if(sub)sub.textContent=(_audIdx+1)+' of '+_audList.length;
  _audEl.src=_previewUrl(f._id);
  _audEl.onloadedmetadata=function(){{if(onReady){{onReady();onReady=null;}}}};
  _audEl.oncanplay=function(){{_audEl.play().then(function(){{_audUpdatePlayBtn();_audUpdateArt(true);}}).catch(function(){{}});}};
  _audEl.onerror=function(){{if(onReady){{onReady();onReady=null;}}}};
  _audEl.addEventListener('progress',_audSyncBuffer);
  document.querySelectorAll('.apl-item').forEach(function(el,i){{el.classList.toggle('active',i===_audIdx);}});
  var activeEl=document.getElementById('apl-'+f._id);if(activeEl)activeEl.scrollIntoView({{block:'nearest',behavior:'smooth'}});
  _audUpdateBtns();_audUpdateArt(false);
}}
function _audSyncProgress(){{var a=_audEl;if(!a)return;var pct=a.duration?a.currentTime/a.duration*100:0;var fill=document.getElementById('audio-progress-fill');var thumb=document.getElementById('audio-thumb');if(fill)fill.style.width=pct+'%';if(thumb)thumb.style.left=pct+'%';var cur=document.getElementById('aud-cur');if(cur)cur.textContent=_fmtTime(a.currentTime);var dur=document.getElementById('aud-dur');if(dur)dur.textContent=_fmtTime(a.duration);}}
function _audSyncBuffer(){{var a=_audEl;if(!a||!a.duration)return;var buf=0;for(var i=0;i<a.buffered.length;i++){{if(a.buffered.start(i)<=a.currentTime&&a.currentTime<=a.buffered.end(i)){{buf=a.buffered.end(i)/a.duration*100;break;}}}}var b=document.getElementById('audio-progress-buf');if(b)b.style.width=buf+'%';}}
function _audSeekTo(e,pw){{var a=_audEl;if(!a||!a.duration)return;var r=pw.getBoundingClientRect();var pct=Math.max(0,Math.min(1,(e.clientX-r.left)/r.width));a.currentTime=pct*a.duration;_audSyncProgress();}}
function _audSeekTouch(e,pw){{if(!e.touches.length)return;_audSeekTo(e.touches[0],pw);}}
function audTogglePlay(){{var a=_audEl;if(!a)return;if(a.paused){{a.play();_audUpdateArt(true);}}else{{a.pause();_audUpdateArt(false);}}_audUpdatePlayBtn();}}
function _audUpdatePlayBtn(){{var ico=document.getElementById('aud-play-ico');if(!ico||!_audEl)return;ico.innerHTML=_audEl.paused?'<path d="M8 5v14l11-7z"/>':'<path d="M6 19h4V5H6v14zm8-14v14h4V5h-4z"/>';}}
function _audUpdateArt(playing){{var art=document.getElementById('audio-art');if(art)art.classList.toggle('playing',playing);}}
function _audUpdateBtns(){{var pb=document.getElementById('aud-prev-btn');var nb=document.getElementById('aud-next-btn');if(pb)pb.disabled=_audIdx===0;if(nb)nb.disabled=_audIdx===_audList.length-1;}}
function audPlayIdx(idx){{if(idx<0||idx>=_audList.length)return;var wasPlaying=_audEl&&!_audEl.paused;_audIdx=idx;_audLoadTrack(null);if(wasPlaying)setTimeout(function(){{if(_audEl){{_audEl.play();_audUpdateArt(true);_audUpdatePlayBtn();}}}},120);}}
function audNavigate(dir){{audPlayIdx(_audIdx+dir);}}

function _buildTextViewer(body,txt,name){{
  var wrap=document.createElement('div');wrap.id='text-viewer-wrap';
  var pre=document.createElement('pre');pre.id='text-viewer-pre';pre.textContent=txt;
  wrap.appendChild(pre);body.appendChild(wrap);
  var copyBtn=document.getElementById('preview-copy-btn');if(copyBtn)copyBtn.style.display='flex';
}}
function _textViewerCopy(){{
  var pre=document.getElementById('text-viewer-pre');if(!pre)return;
  navigator.clipboard.writeText(pre.textContent).then(function(){{
    var btn=document.getElementById('preview-copy-btn');if(!btn)return;
    var orig=btn.innerHTML;
    btn.innerHTML='<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>';
    btn.style.background='var(--green)';btn.style.color='#fff';
    setTimeout(function(){{btn.innerHTML=orig;btn.style.background='';btn.style.color='';}},1800);
  }}).catch(function(){{}});
}}

function showUnsupported(name){{
  var body=document.getElementById('preview-body');
  var d=document.createElement('div');d.id='preview-unsupported';
  d.innerHTML='<div class="pu-icon-wrap">'+IC.file+'</div><h3>Can\\'t preview this file</h3><p>Download it to open locally.</p>';
  body.appendChild(d);
}}
function _clearPreviewBody(body,sp){{
  if(_vidEl){{try{{_vidEl.pause();_vidEl.src='';}}catch(e){{}}}}_vidEl=null;
  if(_audEl){{try{{_audEl.pause();_audEl.src='';}}catch(e){{}}}}_audEl=null;
  clearTimeout(_vidHideTimer);
  var cb=document.getElementById('preview-copy-btn');if(cb)cb.style.display='none';
  Array.from(body.children).forEach(function(c){{if(c!==sp)c.remove();}});
  sp.style.display='flex';
}}

/* Auto-open the preview on page load */
document.addEventListener('DOMContentLoaded',function(){{
  var autoFid='{auto_fid}';
  var f=_pvFiles.find(function(x){{return x._id===autoFid;}});
  if(f)openSharePreview(f._id,f.file_type,f.file_name);
}});
"""

    og = _og_meta_tags(
        title,
        "Shared via SecureBox \u00b7 tap to preview.",
        url_path=f"/s/{token}",
    )
    html = (
        "<!DOCTYPE html><html lang='en'><head>"
        "<meta charset='UTF-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1,maximum-scale=1'>"
        f"<title>{title} — SecureBox</title>"
        "<link rel='icon' type='image/png' href='/favicon.ico'>"
        f"{og}"
        "<link rel='preconnect' href='https://fonts.googleapis.com'>"
        "<link rel='preconnect' href='https://fonts.gstatic.com' crossorigin>"
        "<link href='https://fonts.googleapis.com/css2?family=Google+Sans:wght@400;500;700&family=Roboto:wght@400;500;700&display=swap' rel='stylesheet'>"
        f"<style>{_CSS}</style>"
        f"</head><body>"
        f"{overlay_html}"
        f"<script>{js}</script>"
        "</body></html>"
    )
    return web.Response(content_type="text/html", text=html)


_SHARE_JS_BASE = """
function toast(msg,type){var t=document.getElementById('toast');if(!t)return;t.textContent=msg;t.className='show '+(type||'');clearTimeout(t._t);t._t=setTimeout(function(){t.className=''},3500);}
function bar(on){var b=document.getElementById('bar');if(!b)return;b.className=on?'on':'done';if(!on)setTimeout(function(){b.className=''},800);}
"""

def _share_page(body, title="Shared", description=None, og_url="", extra_js=""):
    desc = description or f"{title} was shared with you via SecureBox."
    og = _og_meta_tags(title, desc, url_path=og_url)
    return web.Response(content_type="text/html", text=(
        "<!DOCTYPE html><html lang='en'><head>"
        "<meta charset='UTF-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1,maximum-scale=1'>"
        f"<title>{title} — SecureBox</title>"
        "<link rel='icon' type='image/png' href='/favicon.ico'>"
        f"{og}"
        "<link rel='preconnect' href='https://fonts.googleapis.com'>"
        "<link rel='preconnect' href='https://fonts.gstatic.com' crossorigin>"
        "<link href='https://fonts.googleapis.com/css2?family=Google+Sans:wght@400;500;700&family=Roboto:wght@400;500;700&display=swap' rel='stylesheet'>"
        f"<style>{_CSS}</style>"
        f"</head><body><div id='bar'></div><div id='toast'></div>{body}"
        f"<script>{_SHARE_JS_BASE}{extra_js}</script></body></html>"
    ))

async def _load_share_or_404(request):
    token      = request.match_info["token"]
    shares_col = request.app["shares_col"]
    doc = await shares_col.find_one({"token": token})
    if not doc:
        raise web.HTTPNotFound()
    return doc

def _share_password_ok(request, doc):
    if not doc.get("password_hash"):
        return True
    cookie = request.cookies.get(_PW_COOKIE_PREFIX + doc["token"])
    return _share_verify_pw_cookie(doc["token"], cookie)

async def _resolve_share_resource(request, doc):
    uid = doc["user_id"]
    if doc["resource_type"] == "file":
        col = request.app["files_col"]
        return await col.find_one({"_id": ObjectId(doc["resource_id"]), "user_id": uid})
    else:
        col = request.app["folders_col"]
        return await col.find_one({"_id": ObjectId(doc["resource_id"]), "user_id": uid})

def _share_password_form(token, error=None):
    err = f'<div class="lerr">{_icon("alert",16)} {error}</div>' if error else ""
    return (
        '<div class="share-spub-page"><div class="spub-card">'
        f'<div class="spub-icon">{_icon("lock",26)}</div>'
        '<div class="spub-name">Password required</div>'
        '<div class="spub-meta">This link is protected. Enter the password to continue.</div>'
        f'{err}'
        f'<form method="POST" action="/s/{token}">'
        '<div class="fg" style="text-align:left"><input name="password" type="password" placeholder="Password" autofocus></div>'
        '<button type="submit" class="btn btn-primary btn-wide" style="height:46px">Unlock</button>'
        "</form></div></div>"
    )

async def handle_share_view(request):
    """GET /s/{token} — landing page. Files show a download/preview card;
    folders show a simple public browser. Prompts for a password if set."""
    doc = await _load_share_or_404(request)
    if not _share_password_ok(request, doc):
        return _share_page(
            _share_password_form(doc["token"]), "Protected link",
            description="This link is password-protected \u00b7 SecureBox",
            og_url=f"/s/{doc['token']}",
        )

    resource = await _resolve_share_resource(request, doc)
    if not resource:
        raise web.HTTPNotFound()

    if doc["resource_type"] == "file":
        name = resource.get("file_name", "file")
        size = _fmt_size(resource.get("file_size"))
        ft   = resource.get("file_type", "document")
        token = doc["token"]
        fid  = str(resource["_id"])
        preview_kind = _get_share_preview_kind(ft, name)
        if preview_kind:
            return _build_share_player_page(
                token=token,
                title=name,
                files=[{"_id": fid, "file_name": name, "file_type": ft}],
                auto_fid=fid,
                dl_url=f"/s/{token}/download",
                back_url=None,
            )
        else:
            body = (
                '<div class="share-spub-page"><div class="spub-card">'
                f'<div class="spub-icon">{_file_icon(ft, 28, name)}</div>'
                f'<div class="spub-name">{name}</div>'
                f'<div class="spub-meta">{size}</div>'
                f'<a class="btn btn-primary btn-wide" style="height:46px" href="/s/{token}/download">'
                f'{_icon("download",16)} Download</a>'
                "</div></div>"
            )
            return _share_page(
                body, name,
                description=f"{size} \u00b7 Shared via SecureBox" if size else "Shared via SecureBox",
                og_url=f"/s/{token}",
            )

    # Folder — render a simple recursive listing with download links
    return await _render_share_folder(request, doc, resource)

async def handle_share_unlock(request):
    """POST /s/{token} — verify password, set a short-lived cookie, redirect back."""
    doc = await _load_share_or_404(request)
    body = await request.post()
    pw   = (body.get("password") or "").strip()
    if not doc.get("password_hash") or _hash_pw(pw) != doc["password_hash"]:
        return _share_page(
            _share_password_form(doc["token"], "Incorrect password."), "Protected link",
            description="This link is password-protected \u00b7 SecureBox",
            og_url=f"/s/{doc['token']}",
        )
    resp = web.HTTPFound(f"/s/{doc['token']}")
    resp.set_cookie(_PW_COOKIE_PREFIX + doc["token"], _share_sign_pw(doc["token"]),
                     max_age=86400, httponly=True, samesite="Lax")
    raise resp

async def _share_resolve_current(request, doc, root_folder):
    """Resolve the folder the request is currently pointed at (root or a
    ?sub= descendant), validating that it really lives under the share."""
    folders_col = request.app["folders_col"]
    uid         = doc["user_id"]
    sub_param   = request.rel_url.query.get("sub", "")
    current_id, current_name = root_folder["_id"], root_folder.get("name", "Shared folder")
    if sub_param:
        try:
            sub_oid = ObjectId(sub_param)
        except Exception:
            raise web.HTTPNotFound()
        if not await _is_descendant(folders_col, uid, sub_param, doc["resource_id"]):
            raise web.HTTPNotFound()
        sub_doc = await folders_col.find_one({"_id": sub_oid, "user_id": uid})
        if not sub_doc:
            raise web.HTTPNotFound()
        current_id, current_name = sub_oid, sub_doc.get("name", "Folder")
    return sub_param, current_id, current_name


async def _share_crumbs(folders_col, uid, root_id, root_name, current_id):
    """Breadcrumb trail from the shared root down to the current folder."""
    crumbs = []
    cur = str(current_id)
    root_str = str(root_id)
    seen = set()
    while cur and cur != root_str and cur not in seen:
        seen.add(cur)
        d = await folders_col.find_one({"_id": ObjectId(cur), "user_id": uid})
        if not d:
            break
        crumbs.append({"id": cur, "name": d.get("name", "Folder")})
        cur = d.get("parent_id")
    crumbs.append({"id": root_str, "name": root_name})
    crumbs.reverse()
    return crumbs


async def _share_list_items(request, doc, current_id):
    folders_col = request.app["folders_col"]
    files_col   = request.app["files_col"]
    uid         = doc["user_id"]
    sub_folders = await folders_col.find({"user_id": uid, "parent_id": str(current_id)}).sort("name", 1).to_list(500)
    sub_files   = await files_col.find({"user_id": uid, "folder_id": str(current_id)}).sort("file_name", 1).to_list(500)
    items = []
    for f in sub_folders:
        items.append({"type": "folder", "id": str(f["_id"]), "name": f.get("name", "")})
    for f in sub_files:
        fn = f.get("file_name", "file")
        ft = f.get("file_type", "document")
        items.append({
            "type": "file",
            "id": str(f["_id"]),
            "name": fn,
            "file_type": ft,
            "size": f.get("file_size"),
            "preview": bool(_get_share_preview_kind(ft, fn)),
            "has_thumb": bool(f.get("thumb_file_id")),
        })
    return items


def _share_esc(s):
    return (s or "").replace("&", "&amp;").replace('"', "&quot;").replace("'", "&#39;").replace("<", "&lt;").replace(">", "&gt;")


def _share_rows_html(token, sub_param, items):
    rows = ""
    for it in items:
        if it["type"] == "folder":
            fn = _share_esc(it["name"])
            rows += (
                f'<a class="sri" href="/s/{token}?sub={it["id"]}" data-nav-folder="{it["id"]}" data-nav-name="{fn}" style="text-decoration:none">'
                f'<div class="sri-icon">{_icon("folder",28,"","#0483c3")}</div>'
                f'<div class="sri-info"><div class="sri-name">{fn}</div>'
                '<div class="sri-meta"><span class="sri-size">Folder</span></div></div></a>'
            )
        else:
            fn, ft = _share_esc(it["name"]), it["file_type"]
            sz = _fmt_size(it.get("size"))
            dl_href = f'/s/{token}/download?fid={it["id"]}'
            icon_html = _share_thumb_html(token, it["id"], ft, fn, it.get("has_thumb"))
            if it.get("preview"):
                sub_qs = f'&sub={sub_param}' if sub_param else ''
                view_href = f'/s/{token}/view?fid={it["id"]}{sub_qs}'
                rows += (
                    f'<div class="sri" style="cursor:pointer;position:relative" onclick="bar(true);location.href=\'{view_href}\'">'
                    f'<div class="sri-icon">{icon_html}</div>'
                    f'<div class="sri-info"><div class="sri-name">{fn}</div>'
                    f'<div class="sri-meta"><span class="sri-size">{sz}</span></div></div>'
                    f'<a href="{dl_href}" class="sri-dl-btn" onclick="event.stopPropagation()" title="Download">'
                    f'{_icon("download",18)}</a>'
                    f'</div>'
                )
            else:
                rows += (
                    f'<a class="sri" href="{dl_href}" style="text-decoration:none">'
                    f'<div class="sri-icon">{icon_html}</div>'
                    f'<div class="sri-info"><div class="sri-name">{fn}</div>'
                    f'<div class="sri-meta"><span class="sri-size">{sz}</span></div></div>'
                    f'<span class="btn-icon sri-dl-btn" style="pointer-events:none">{_icon("download",18)}</span></a>'
                )
    if not rows:
        rows = '<div class="empty"><div class="empty-icon">' + _icon("folder", 40) + '</div><h3>Empty folder</h3></div>'
    return rows


def _share_crumbs_html(token, crumbs):
    if len(crumbs) <= 1:
        return ""
    parts = []
    for i, c in enumerate(crumbs):
        last = i == len(crumbs) - 1
        cls = "bc-crumb last" if last else "bc-crumb"
        cname = _share_esc(c["name"])
        cid   = c["id"]
        if last:
            parts.append(f'<span class="{cls}">{cname}</span>')
        else:
            href_qs = f'?sub={cid}' if i > 0 else ''
            nav_fid = cid if i > 0 else ''
            parts.append(
                f'<a class="{cls}" href="/s/{token}{href_qs}"'
                f' data-nav-folder="{nav_fid}" data-nav-name="{cname}"'
                f' style="text-decoration:none">{cname}</a>'
            )
        if not last:
            parts.append('<span class="bc-sep">\u203a</span>')
    return "".join(parts)


async def handle_share_api_list(request):
    """GET /s/{token}/api/list?sub= — JSON listing used for AJAX navigation
    inside a shared folder (powers the loading bar + smooth in-page nav)."""
    doc = await _load_share_or_404(request)
    if doc["resource_type"] != "folder":
        raise web.HTTPNotFound()
    if not _share_password_ok(request, doc):
        return web.json_response({"error": "password_required"}, status=403)

    folders_col = request.app["folders_col"]
    uid  = doc["user_id"]
    root = await folders_col.find_one({"_id": ObjectId(doc["resource_id"]), "user_id": uid})
    if not root:
        raise web.HTTPNotFound()

    sub_param, current_id, current_name = await _share_resolve_current(request, doc, root)
    items  = await _share_list_items(request, doc, current_id)
    crumbs = await _share_crumbs(folders_col, uid, root["_id"], root.get("name", "Shared folder"), current_id)
    rows_html = _share_rows_html(doc["token"], sub_param, items)
    bc_html   = _share_crumbs_html(doc["token"], crumbs)
    return web.json_response({
        "name": current_name, "sub": sub_param,
        "rows_html": rows_html, "breadcrumb_html": bc_html,
        "item_count": len(items),
    })


_SHARE_FOLDER_JS = r"""
function _shNavBind(){
  document.querySelectorAll('[data-nav-folder]').forEach(function(el){
    el.onclick=function(e){
      e.preventDefault();
      var fid=el.getAttribute('data-nav-folder');
      _shLoad(fid,true);
    };
  });
}
async function _shLoad(fid,push){
  bar(true);
  try{
    var url='/s/'+SH_TOKEN+'/api/list'+(fid?('?sub='+encodeURIComponent(fid)):'');
    var r=await fetch(url);
    if(!r.ok) throw new Error('HTTP '+r.status);
    var d=await r.json();
    document.getElementById('s-rows').innerHTML=d.rows_html;
    document.getElementById('s-bc').innerHTML=d.breadcrumb_html;
    document.getElementById('s-bc').style.display=d.breadcrumb_html?'flex':'none';
    document.getElementById('s-title').textContent=d.name;
    if(push){
      var pageUrl='/s/'+SH_TOKEN+(fid?('?sub='+fid):'');
      history.pushState({fid:fid||''},'',pageUrl);
    }
    _shNavBind();
  }catch(e){
    document.getElementById('s-rows').innerHTML='<div class="empty"><div class="empty-icon">'+IC_FOLDER+'</div><h3>Failed to load</h3><p>'+e.message+'</p></div>';
  }
  bar(false);
}
window.addEventListener('popstate',function(e){
  var params=new URLSearchParams(window.location.search);
  _shLoad(params.get('sub')||'',false);
});
document.addEventListener('DOMContentLoaded',_shNavBind);
"""


async def _render_share_folder(request, doc, folder):
    folders_col = request.app["folders_col"]
    uid         = doc["user_id"]

    sub_param, current_id, current_name = await _share_resolve_current(request, doc, folder)
    items  = await _share_list_items(request, doc, current_id)
    crumbs = await _share_crumbs(folders_col, uid, folder["_id"], folder.get("name", "Shared folder"), current_id)
    rows      = _share_rows_html(doc["token"], sub_param, items)
    bc_html   = _share_crumbs_html(doc["token"], crumbs)

    def _js_str(s):
        return s.replace("\\", "\\\\").replace("`", "\\`").replace("</script>", "<\\/script>")

    body = (
        '<div class="spub-browse">'
        f'<div style="display:flex;align-items:center;gap:10px;margin-bottom:14px">'
        f'<div class="fi-icon">{_icon("folder",28,"","#0483c3")}</div>'
        f'<div><div id="s-title" style="font-size:18px;font-weight:700">{_share_esc(current_name)}</div>'
        f'<div style="font-size:12px;color:var(--text3)">Shared folder \u00b7 view only</div></div></div>'
        f'<div id="s-bc" class="bc" style="display:{"flex" if bc_html else "none"};align-items:center;gap:6px;overflow-x:auto;margin-bottom:10px;font-size:13px;color:var(--text2)">{bc_html}</div>'
        f'<div id="s-rows" style="border:1px solid var(--border);border-radius:var(--r12);overflow:hidden">{rows}</div>'
        "</div>"
    )
    extra_js = (
        f"var SH_TOKEN=`{_js_str(doc['token'])}`;"
        f"var IC_FOLDER=`{_js_str(_icon('folder', 40))}`;"
        + _SHARE_FOLDER_JS
    )
    n_items = len(items)
    item_desc = f"{n_items} item{'s' if n_items != 1 else ''} \u00b7 Shared folder via SecureBox"
    return _share_page(
        body, current_name,
        description=item_desc,
        og_url=f"/s/{doc['token']}" + (f"?sub={sub_param}" if sub_param else ""),
        extra_js=extra_js,
    )

async def handle_share_file_view(request):
    """GET /s/{token}/view?fid= — open a specific file from a folder share in our player.
    Shows the built-in video/audio/image/text player with a back button to the folder."""
    doc = await _load_share_or_404(request)
    if not _share_password_ok(request, doc):
        raise web.HTTPForbidden(reason="Password required")

    files_col   = request.app["files_col"]
    folders_col = request.app["folders_col"]
    uid         = doc["user_id"]
    token       = doc["token"]

    fid = request.rel_url.query.get("fid", "")
    if not fid:
        raise web.HTTPNotFound()
    sub_param = request.rel_url.query.get("sub", "")

    try:
        file_doc = await files_col.find_one({"_id": ObjectId(fid), "user_id": uid})
    except Exception:
        raise web.HTTPNotFound()

    # Verify the file lives inside the shared folder (or a subfolder of it)
    if doc["resource_type"] != "folder":
        raise web.HTTPNotFound()
    if not file_doc or not await _is_descendant(
        folders_col, uid, file_doc.get("folder_id", ""), doc["resource_id"]
    ):
        raise web.HTTPNotFound()

    name = file_doc.get("file_name", "file")
    ft   = file_doc.get("file_type", "document")
    # back URL: go to folder listing (with sub param if we came from a subfolder)
    back_url = f"/s/{token}" + (f"?sub={sub_param}" if sub_param else "")

    return _build_share_player_page(
        token=token,
        title=name,
        files=[{"_id": fid, "file_name": name, "file_type": ft}],
        auto_fid=fid,
        dl_url=f"/s/{token}/download?fid={fid}",
        back_url=back_url,
    )


async def handle_share_download(request):
    """GET /s/{token}/download — stream the shared file (or, for a shared
    folder, the file identified by ?fid=, which must live under that folder)."""
    doc = await _load_share_or_404(request)
    if not _share_password_ok(request, doc):
        raise web.HTTPForbidden(reason="Password required")

    files_col   = request.app["files_col"]
    folders_col = request.app["folders_col"]
    bot_inst    = request.app.get("bot_instance")
    uid         = doc["user_id"]

    if doc["resource_type"] == "file":
        file_doc = await files_col.find_one({"_id": ObjectId(doc["resource_id"]), "user_id": uid})
    else:
        fid = request.rel_url.query.get("fid", "")
        if not fid:
            raise web.HTTPNotFound()
        try:
            file_doc = await files_col.find_one({"_id": ObjectId(fid), "user_id": uid})
        except Exception:
            raise web.HTTPNotFound()
        # Make sure the requested file actually lives inside the shared
        # folder (or one of its subfolders) — never trust the fid alone.
        if not file_doc or not await _is_descendant(
            folders_col, uid, file_doc.get("folder_id", ""), doc["resource_id"]
        ):
            raise web.HTTPNotFound()

    if not file_doc:
        raise web.HTTPNotFound()
    if not bot_inst:
        raise web.HTTPServiceUnavailable(reason="Bot not connected")

    tg_fid    = file_doc.get("telegram_file_id")
    file_name = file_doc.get("file_name", "file")
    file_size = file_doc.get("file_size")
    if not tg_fid:
        raise web.HTTPNotFound(reason="No file_id stored")

    return await _pyro_stream_response(
        request, bot_inst, tg_fid, file_size, file_name,
        content_type="application/octet-stream", disposition="attachment",
    )


async def handle_share_preview(request):
    """GET /s/{token}/preview — stream a shared file inline for preview.
    For folder shares, ?fid= selects a file within the folder."""
    doc = await _load_share_or_404(request)
    if not _share_password_ok(request, doc):
        raise web.HTTPForbidden(reason="Password required")

    files_col   = request.app["files_col"]
    folders_col = request.app["folders_col"]
    bot_inst    = request.app.get("bot_instance")
    uid         = doc["user_id"]

    if doc["resource_type"] == "file":
        file_doc = await files_col.find_one({"_id": ObjectId(doc["resource_id"]), "user_id": uid})
    else:
        fid = request.rel_url.query.get("fid", "")
        if not fid:
            raise web.HTTPNotFound()
        try:
            file_doc = await files_col.find_one({"_id": ObjectId(fid), "user_id": uid})
        except Exception:
            raise web.HTTPNotFound()
        if not file_doc or not await _is_descendant(
            folders_col, uid, file_doc.get("folder_id", ""), doc["resource_id"]
        ):
            raise web.HTTPNotFound()

    if not file_doc:
        raise web.HTTPNotFound()
    if not bot_inst:
        raise web.HTTPServiceUnavailable(reason="Bot not connected")

    tg_fid    = file_doc.get("telegram_file_id")
    file_name = file_doc.get("file_name", "file")
    file_size = file_doc.get("file_size")
    ft        = file_doc.get("file_type", "document")
    if not tg_fid:
        raise web.HTTPNotFound(reason="No file_id stored")

    # Determine content-type for inline display
    mime_map = {"photo": "image/jpeg", "video": "video/mp4", "audio": "audio/mpeg"}
    ct = mime_map.get(ft, "text/plain")
    ext_map = {
        "jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png",
        "gif": "image/gif",  "webp": "image/webp", "bmp": "image/bmp",
        "mp4": "video/mp4",  "m4v": "video/mp4",
        "webm": "video/webm", "ogv": "video/ogg",
        "mov": "video/quicktime", "mkv": "video/x-matroska",
        "avi": "video/x-msvideo", "3gp": "video/3gpp", "flv": "video/x-flv",
        "mp3": "audio/mpeg",  "m4a": "audio/mp4",
        "ogg": "audio/ogg",   "oga": "audio/ogg",
        "opus": "audio/opus", "wav": "audio/wav",
        "flac": "audio/flac", "aac": "audio/aac", "weba": "audio/webm",
        "pdf": "application/pdf",
        "txt": "text/plain",  "md": "text/plain",
    }
    ext = file_name.rsplit(".", 1)[-1].lower() if "." in file_name else ""
    if ext in ext_map:
        ct = ext_map[ext]
    db_mime = file_doc.get("mime_type", "")
    if db_mime and not db_mime.startswith("application/octet"):
        ct = db_mime

    return await _pyro_stream_response(
        request, bot_inst, tg_fid, file_size, file_name,
        content_type=ct, disposition="inline",
    )


async def handle_share_thumb(request):
    """GET /s/{token}/thumb?fid= — small preview image for a file inside a
    public share (folder rows, or a single shared file). Same ownership/path
    checks as download & preview, just serving `thumb_file_id` instead of the
    full file. Token-scoped so it works without a login cookie."""
    doc = await _load_share_or_404(request)
    if not _share_password_ok(request, doc):
        raise web.HTTPNotFound()  # don't leak existence of a thumb behind a password wall

    files_col   = request.app["files_col"]
    folders_col = request.app["folders_col"]
    bot         = request.app.get("bot_instance")
    uid         = doc["user_id"]

    if doc["resource_type"] == "file":
        file_doc = await files_col.find_one({"_id": ObjectId(doc["resource_id"]), "user_id": uid})
    else:
        fid = request.rel_url.query.get("fid", "")
        if not fid:
            raise web.HTTPNotFound()
        try:
            file_doc = await files_col.find_one({"_id": ObjectId(fid), "user_id": uid})
        except Exception:
            raise web.HTTPNotFound()
        if not file_doc or not await _is_descendant(
            folders_col, uid, file_doc.get("folder_id", ""), doc["resource_id"]
        ):
            raise web.HTTPNotFound()

    if not file_doc or not bot:
        raise web.HTTPNotFound()

    thumb_fid = file_doc.get("thumb_file_id")
    if not thumb_fid:
        raise web.HTTPNotFound()

    cache_key = f"share:{file_doc['_id']}"
    cache = request.app["_thumb_cache"]
    cached = cache.get(cache_key)
    if cached is not None:
        if cached is False:
            raise web.HTTPNotFound()
        return web.Response(body=cached, content_type="image/jpeg",
                             headers={"Cache-Control": "public, max-age=86400, immutable"})

    data = None
    try:
        f = await bot.download_media(thumb_fid, in_memory=True)
        if f:
            data = bytes(f.getbuffer())
    except Exception as e:
        logger.error(f"Share thumb fetch error for fid={file_doc['_id']}: {e}", exc_info=True)
        data = None

    if len(cache) >= _THUMB_CACHE_MAX:
        cache.pop(next(iter(cache)))
    cache[cache_key] = data if data else False

    if not data:
        raise web.HTTPNotFound()
    return web.Response(body=data, content_type="image/jpeg",
                         headers={"Cache-Control": "public, max-age=86400, immutable"})


async def handle_logo(request):
    import os
    logo_path = os.path.join(os.path.dirname(__file__), '..', 'logo.png')
    logo_path = os.path.abspath(logo_path)
    if not os.path.exists(logo_path):
        raise web.HTTPNotFound()
    with open(logo_path, 'rb') as f:
        data = f.read()
    return web.Response(body=data, content_type='image/png',
                        headers={'Cache-Control': 'public, max-age=86400'})


async def handle_favicon(request):
    import os
    logo_path = os.path.join(os.path.dirname(__file__), '..', 'logo.png')
    logo_path = os.path.abspath(logo_path)
    if not os.path.exists(logo_path):
        raise web.HTTPNotFound()
    with open(logo_path, 'rb') as f:
        data = f.read()
    return web.Response(body=data, content_type='image/png',
                        headers={'Cache-Control': 'public, max-age=86400'})


def create_app(files_col, folders_col, settings_col, bot_instance=None, shares_col=None):
    app = web.Application(client_max_size=2 * 1024 * 1024 * 1024)  # 2 GB
    app["files_col"]    = files_col
    app["folders_col"]  = folders_col
    app["settings_col"] = settings_col
    app["shares_col"]   = shares_col
    app["bot_instance"] = bot_instance
    app["_avatar_cache"] = {}
    app["_thumb_cache"] = {}

    app.router.add_route("GET",  "/",               handle_login)
    app.router.add_route("POST", "/",               handle_login)
    app.router.add_get("/logo.png",                 handle_logo)
    app.router.add_get("/favicon.ico",               handle_favicon)
    app.router.add_get("/avatar.png",                handle_avatar)
    app.router.add_get("/api/thumb/{fid}",           api_thumb)
    app.router.add_get("/logout",                   handle_logout)
    app.router.add_get("/drive",                    handle_drive)
    app.router.add_get("/files",                    handle_drive)
    app.router.add_get("/api/files",                api_files)
    app.router.add_get("/api/stats",                 api_stats)
    app.router.add_post("/api/mkdir",               api_mkdir)
    app.router.add_post("/api/rename/{fid}",        api_rename)
    app.router.add_post("/api/delete/{fid}",        api_delete)
    app.router.add_post("/api/rename-folder/{fid}", api_rename_folder)
    app.router.add_post("/api/delete-folder/{fid}", api_delete_folder)
    app.router.add_post("/api/move/{fid}",          api_move)
    app.router.add_post("/api/move-folder/{fid}",   api_move_folder)
    app.router.add_post("/api/copy/{fid}",          api_copy)
    app.router.add_post("/api/copy-folder/{fid}",   api_copy_folder)
    app.router.add_get("/api/search",               api_search)
    app.router.add_get("/api/download/{fid}",       api_download)
    app.router.add_get("/api/preview/{fid}",        api_preview)
    app.router.add_post("/api/upload",              api_upload)

    # Share management (owner, authenticated)
    app.router.add_get("/api/share/{rtype}/{rid}",    api_share_get)
    app.router.add_post("/api/share/{rtype}/{rid}",   api_share_set)
    app.router.add_delete("/api/share/{rtype}/{rid}", api_share_clear)

    # Public share pages (no auth — token + optional password gated)
    app.router.add_get("/s/{token}",            handle_share_view)
    app.router.add_post("/s/{token}",           handle_share_unlock)
    app.router.add_get("/s/{token}/download",   handle_share_download)
    app.router.add_get("/s/{token}/preview",    handle_share_preview)
    app.router.add_get("/s/{token}/thumb",       handle_share_thumb)
    app.router.add_get("/s/{token}/view",       handle_share_file_view)
    app.router.add_get("/s/{token}/api/list",   handle_share_api_list)

    async def _ensure_indexes(app):
        # Indexes for every collection (files/folders/settings/shares/etc.)
        # are created centrally in database/mongo.ensure_indexes(), which
        # bot.py already calls on startup. This stays here too so create_app()
        # also works correctly if the WebUI is ever run standalone.
        try:
            from database.mongo import ensure_indexes
            await ensure_indexes()
        except Exception:
            logger.warning("Could not ensure indexes via database.mongo", exc_info=True)
    app.on_startup.append(_ensure_indexes)

    return app
