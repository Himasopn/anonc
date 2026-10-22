import os
import sys
import json
import math
import mimetypes
import shutil
import tempfile
import sqlite3
import asyncio
import time
import uuid
import re
import secrets
import hashlib
import urllib.parse
import io
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, Request, Response, HTTPException, UploadFile, File, Form, Query, Header, Depends
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from telethon import TelegramClient, utils
from telethon.sessions import StringSession
from telethon.tl.functions.channels import CreateChannelRequest
from telethon.errors import (
    SessionPasswordNeededError,
    PhoneCodeInvalidError,
    PhoneCodeExpiredError,
    PasswordHashInvalidError,
    FloodWaitError,
)

try:
    from api.fast_uploader import fast_pipelined_upload
except ImportError:
    from fast_uploader import fast_pipelined_upload

# Master Telegram API Credentials
API_ID = int(os.environ.get("TELEGRAM_API_ID", "38648695"))
API_HASH = os.environ.get("TELEGRAM_API_HASH", "9ea926414705c631aa6a908991cac059")
ENV_SESSION = os.environ.get("TELEGRAM_SESSION", "")

IS_VERCEL = bool(os.environ.get("VERCEL"))

if IS_VERCEL:
    DATA_DIR = os.path.join(tempfile.gettempdir(), "anonc_data")
else:
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    DATA_DIR = os.path.join(BASE_DIR, "data")

os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "drive.db")
SESSION_FILE = os.path.join(DATA_DIR, "tg_session")
STRING_SESSION_FILE = os.path.join(DATA_DIR, "session_string.txt")

# In-memory store for active upload tasks
upload_tasks: Dict[str, Dict[str, Any]] = {}
db_channel_entity = None

# SQLite Database Initialization
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                display_name TEXT DEFAULT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                avatar_color TEXT DEFAULT '#0A84FF',
                avatar_msg_id INTEGER DEFAULT NULL,
                settings_json TEXT DEFAULT '{}',
                message_id INTEGER DEFAULT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        # Schema migration for existing users table
        user_cols = [c[1] for c in conn.execute("PRAGMA table_info(users)").fetchall()]
        if "display_name" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN display_name TEXT DEFAULT NULL;")
        if "avatar_color" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN avatar_color TEXT DEFAULT '#0A84FF';")
        if "avatar_msg_id" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN avatar_msg_id INTEGER DEFAULT NULL;")
        if "settings_json" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN settings_json TEXT DEFAULT '{}';")
        if "message_id" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN message_id INTEGER DEFAULT NULL;")
        if "updated_at" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN updated_at TIMESTAMP DEFAULT NULL;")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS user_tokens (
                token TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS folders (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                name TEXT NOT NULL,
                parent_id TEXT DEFAULT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                message_id INTEGER NOT NULL,
                folder_id TEXT DEFAULT NULL,
                name TEXT NOT NULL,
                size INTEGER NOT NULL,
                mime_type TEXT NOT NULL,
                media_type TEXT NOT NULL,
                date TEXT NOT NULL,
                duration INTEGER DEFAULT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE CASCADE
            );
        """)
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_files_msg_id ON files(message_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_files_user_id ON files(user_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_folders_user_id ON folders(user_id);")
        conn.commit()

init_db()

app = FastAPI(title="anonc by ascloud")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

client: Optional[TelegramClient] = None

def get_saved_session_string() -> str:
    if ENV_SESSION:
        return ENV_SESSION
    if os.path.exists(STRING_SESSION_FILE):
        try:
            with open(STRING_SESSION_FILE, "r", encoding="utf-8") as f:
                return f.read().strip()
        except Exception:
            pass
    return ""

def get_client() -> TelegramClient:
    global client
    if client is None:
        saved_str = get_saved_session_string()
        if saved_str:
            client = TelegramClient(StringSession(saved_str), API_ID, API_HASH)
        elif os.path.exists(os.path.join(DATA_DIR, "telegram_web_drive.session")):
            client = TelegramClient(os.path.join(DATA_DIR, "telegram_web_drive"), API_ID, API_HASH)
        else:
            client = TelegramClient(SESSION_FILE, API_ID, API_HASH)
    return client

async def get_database_channel(c: TelegramClient):
    global db_channel_entity
    if db_channel_entity is not None:
        return db_channel_entity
    
    # Try finding existing 'userdatabase' channel
    async for d in c.iter_dialogs(limit=50):
        if d.is_channel and 'userdatabase' in d.name.lower():
            db_channel_entity = d.entity
            return db_channel_entity
            
    # Create channel if not existing
    try:
        res = await c(CreateChannelRequest(
            title='userdatabase',
            about='anonc cloud database for user logins and media storage',
            megagroup=False
        ))
        db_channel_entity = res.chats[0]
        return db_channel_entity
    except Exception as e:
        print("Error getting/creating userdatabase channel:", e)
        return "me"

# Sync user accounts and files from cloud channel into local SQLite
async def sync_channel_database(c: TelegramClient):
    try:
        channel = await get_database_channel(c)
        with get_db() as conn:
            async for msg in c.iter_messages(channel, limit=1000):
                text = msg.text or ""
                if text.startswith("#USER_RECORD ") or text.startswith("#USER_REGISTER "):
                    parts = dict(re.findall(r'(\w+)=([^\s]+)', text.split("\n")[0]))
                    u_id = parts.get("id")
                    u_name = parts.get("username")
                    pwd_hash = parts.get("hash")
                    salt = parts.get("salt")
                    if u_id and u_name and pwd_hash and salt:
                        d_name = urllib.parse.unquote(parts.get("display", "")) or u_name
                        color = urllib.parse.unquote(parts.get("color", "#0A84FF"))
                        avatar_val = parts.get("avatar")
                        avatar_msg = int(avatar_val) if (avatar_val and avatar_val not in ("None", "null", "")) else None
                        settings_str = urllib.parse.unquote(parts.get("settings", "{}"))
                        conn.execute("""
                            INSERT INTO users (id, username, display_name, password_hash, salt, avatar_color, avatar_msg_id, settings_json, message_id)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                            ON CONFLICT(id) DO UPDATE SET
                                username = excluded.username,
                                display_name = COALESCE(excluded.display_name, users.display_name),
                                password_hash = excluded.password_hash,
                                salt = excluded.salt,
                                avatar_color = excluded.avatar_color,
                                avatar_msg_id = COALESCE(excluded.avatar_msg_id, users.avatar_msg_id),
                                settings_json = excluded.settings_json,
                                message_id = excluded.message_id
                        """, (u_id, u_name, d_name, pwd_hash, salt, color, avatar_msg, settings_str, msg.id))
                elif text.startswith("#USER_AVATAR "):
                    parts = dict(re.findall(r'(\w+)=([^\s]+)', text.split("\n")[0]))
                    u_id = parts.get("user_id")
                    if u_id and msg.media:
                        conn.execute("UPDATE users SET avatar_msg_id = COALESCE(avatar_msg_id, ?) WHERE id = ?", (msg.id, u_id))
                elif text.startswith("#USER_FOLDER "):
                    parts = dict(re.findall(r'(\w+)=([^\s]+)', text))
                    if "id" in parts and "user_id" in parts and "name" in parts:
                        parent_id = parts.get("parent_id")
                        if parent_id == "None":
                            parent_id = None
                        conn.execute("""
                            INSERT OR IGNORE INTO folders (id, user_id, name, parent_id, created_at)
                            VALUES (?, ?, ?, ?, datetime('now'))
                        """, (parts["id"], parts["user_id"], parts["name"], parent_id))
                elif text.startswith("#USER_FILE "):
                    parts = dict(re.findall(r'(\w+)=([^\s]+)', text.split("\n")[0]))
                    if "user_id" in parts and msg.media:
                        u_id = parts["user_id"]
                        f_id = parts.get("folder_id")
                        if f_id in ("root", "None"):
                            f_id = None
                        f_mime = (msg.file.mime_type if msg.file else None) or "application/octet-stream"
                        m_type = "document"
                        if f_mime.startswith("video/"):
                            m_type = "video"
                        elif f_mime.startswith("audio/"):
                            m_type = "audio"
                        elif f_mime.startswith("image/"):
                            m_type = "image"
                        f_name = (msg.file.name if msg.file else None) or (text.split("\n", 1)[1] if "\n" in text else "file")
                        f_size = msg.file.size if msg.file else 0
                        date_str = str(msg.date)
                        conn.execute("""
                            INSERT OR IGNORE INTO files (user_id, message_id, folder_id, name, size, mime_type, media_type, date)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """, (u_id, msg.id, f_id, f_name, f_size, f_mime, m_type, date_str))
            conn.commit()
        print("Synced users, folders, and files from Telegram channel database.")
    except Exception as e:
        print("Sync channel database error:", e)

@app.on_event("startup")
async def startup_event():
    init_db()
    c = get_client()
    try:
        await c.connect()
        if await c.is_user_authorized():
            await sync_channel_database(c)
        print("anonc Cloud by ascloud: Connected to Telegram.")
    except Exception as e:
        print("Startup connection notice:", e)

@app.on_event("shutdown")
async def shutdown_event():
    global client
    if client and client.is_connected():
        await client.disconnect()

def format_size(size_bytes: int) -> str:
    if not size_bytes or size_bytes <= 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {units[i]}"

# Password Hashing with PBKDF2-HMAC-SHA256
def hash_password(password: str, salt: Optional[str] = None) -> tuple[str, str]:
    if not salt:
        salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000
    )
    return key.hex(), salt

def verify_password(password: str, salt: str, expected_hash: str) -> bool:
    key, _ = hash_password(password, salt)
    return secrets.compare_digest(key, expected_hash)

# Authentication Dependency: Returns current user or raises 401
async def get_current_user(
    authorization: Optional[str] = Header(None),
    x_auth_token: Optional[str] = Header(None)
):
    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split("Bearer ")[1].strip()
    elif x_auth_token:
        token = x_auth_token.strip()

    if not token:
        raise HTTPException(status_code=401, detail="Authentication required")

    with get_db() as conn:
        row = conn.execute("""
            SELECT u.id, u.username, u.display_name, u.avatar_color, u.avatar_msg_id, u.created_at, u.message_id
            FROM user_tokens t
            JOIN users u ON t.user_id = u.id
            WHERE t.token = ?
        """, (token,)).fetchone()

        if not row:
            raise HTTPException(status_code=401, detail="Invalid or expired session")
        return dict(row)

# Request Models
class UserRegisterRequest(BaseModel):
    username: str
    password: str

class UserLoginRequest(BaseModel):
    username: str
    password: str

class UpdateSettingsRequest(BaseModel):
    display_name: Optional[str] = None
    username: Optional[str] = None
    avatar_color: Optional[str] = None
    current_password: Optional[str] = None
    new_password: Optional[str] = None
    settings: Optional[Dict[str, Any]] = None

class CreateFolderRequest(BaseModel):
    name: str
    parent_id: Optional[str] = None

# User Registration Endpoint
@app.post("/api/user/register")
async def register_user(req: UserRegisterRequest):
    username = req.username.strip().lower()
    password = req.password.strip()

    if not re.match(r'^[a-zA-Z0-9_]{3,30}$', username):
        raise HTTPException(status_code=400, detail="Username must be 3-30 letters/numbers.")
    if len(password) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters.")

    with get_db() as conn:
        existing = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if existing:
            raise HTTPException(status_code=400, detail="Username is already taken.")

        user_id = f"u_{uuid.uuid4().hex[:12]}"
        pwd_hash, salt = hash_password(password)
        display_name = username
        avatar_color = "#0A84FF"
        settings_json = json.dumps({"auto_preview": True, "fast_seek": True})

        conn.execute("""
            INSERT INTO users (id, username, display_name, password_hash, salt, avatar_color, settings_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (user_id, username, display_name, pwd_hash, salt, avatar_color, settings_json))

        token = secrets.token_hex(32)
        conn.execute("INSERT INTO user_tokens (token, user_id) VALUES (?, ?)", (token, user_id))
        conn.commit()

    # Log user record to cloud database channel
    c = get_client()
    if c.is_connected() and await c.is_user_authorized():
        try:
            channel = await get_database_channel(c)
            record_text = (
                f"#USER_RECORD id={user_id} "
                f"username={username} "
                f"display={urllib.parse.quote(display_name)} "
                f"color={urllib.parse.quote(avatar_color)} "
                f"salt={salt} "
                f"hash={pwd_hash} "
                f"settings={urllib.parse.quote(settings_json)}"
            )
            sent_msg = await c.send_message(channel, record_text)
            with get_db() as conn:
                conn.execute("UPDATE users SET message_id = ? WHERE id = ?", (sent_msg.id, user_id))
                conn.commit()
        except Exception as e:
            print("Error recording user to cloud database channel:", e)

    return {
        "status": "ok",
        "token": token,
        "user": {
            "id": user_id,
            "username": username,
            "display_name": display_name,
            "avatar_color": avatar_color,
            "avatar_url": None,
            "avatar_msg_id": None,
            "settings": {"auto_preview": True, "fast_seek": True}
        }
    }

# User Login Endpoint
@app.post("/api/user/login")
async def login_user(req: UserLoginRequest):
    username = req.username.strip().lower()
    password = req.password.strip()

    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if not user:
            raise HTTPException(status_code=400, detail="Invalid username or password.")

        if not verify_password(password, user["salt"], user["password_hash"]):
            raise HTTPException(status_code=400, detail="Invalid username or password.")

        token = secrets.token_hex(32)
        conn.execute("INSERT INTO user_tokens (token, user_id) VALUES (?, ?)", (token, user["id"]))
        conn.commit()

        settings_dict = {"auto_preview": True, "fast_seek": True}
        if user["settings_json"]:
            try:
                settings_dict.update(json.loads(user["settings_json"]))
            except Exception:
                pass

    avatar_msg = user["avatar_msg_id"] if "avatar_msg_id" in user.keys() else None
    return {
        "status": "ok",
        "token": token,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "display_name": user["display_name"] or user["username"],
            "avatar_color": user["avatar_color"] or "#0A84FF",
            "avatar_url": f"/api/user/avatar/{user['id']}?v={avatar_msg}" if avatar_msg else None,
            "avatar_msg_id": avatar_msg,
            "settings": settings_dict
        }
    }

# Current User Profile & Stats Endpoint
@app.get("/api/user/me")
async def get_user_me(user: dict = Depends(get_current_user)):
    with get_db() as conn:
        stats = conn.execute("""
            SELECT COUNT(*) as count, COALESCE(SUM(size), 0) as total_size
            FROM files WHERE user_id = ?
        """, (user["id"],)).fetchone()
        folders_count = conn.execute("SELECT COUNT(*) FROM folders WHERE user_id = ?", (user["id"],)).fetchone()[0]
        user_row = conn.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()

    settings_dict = {"auto_preview": True, "fast_seek": True}
    if user_row and user_row["settings_json"]:
        try:
            settings_dict.update(json.loads(user_row["settings_json"]))
        except Exception:
            pass

    avatar_msg = user_row["avatar_msg_id"] if user_row and "avatar_msg_id" in user_row.keys() else None
    return {
        "user": {
            "id": user["id"],
            "username": user_row["username"] if user_row else user["username"],
            "display_name": (user_row["display_name"] if user_row else None) or user["username"],
            "avatar_color": (user_row["avatar_color"] if user_row else None) or "#0A84FF",
            "avatar_url": f"/api/user/avatar/{user['id']}?v={avatar_msg}" if avatar_msg else None,
            "avatar_msg_id": avatar_msg,
            "settings": settings_dict,
            "created_at": user_row["created_at"] if user_row else ""
        },
        "stats": {
            "total_files": stats["count"] if stats else 0,
            "total_folders": folders_count,
            "total_bytes": stats["total_size"] if stats else 0,
            "total_formatted": format_size(stats["total_size"] if stats else 0)
        }
    }

# Update User Settings & Sync with Cloud Database Channel
@app.post("/api/user/settings")
async def update_user_settings(req: UpdateSettingsRequest, user: dict = Depends(get_current_user)):
    user_id = user["id"]
    with get_db() as conn:
        user_row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user_row:
            raise HTTPException(status_code=404, detail="User not found")

        curr_username = user_row["username"]
        curr_display = user_row["display_name"] or curr_username
        curr_color = user_row["avatar_color"] or "#0A84FF"
        curr_avatar_msg = user_row["avatar_msg_id"] if "avatar_msg_id" in user_row.keys() else None
        curr_hash = user_row["password_hash"]
        curr_salt = user_row["salt"]
        curr_msg_id = user_row["message_id"]

        curr_settings = {"auto_preview": True, "fast_seek": True}
        if user_row["settings_json"]:
            try:
                curr_settings.update(json.loads(user_row["settings_json"]))
            except Exception:
                pass

        # Update username if requested
        new_username = curr_username
        if req.username and req.username.strip().lower() != curr_username:
            new_u = req.username.strip().lower()
            if not re.match(r'^[a-zA-Z0-9_]{3,30}$', new_u):
                raise HTTPException(status_code=400, detail="Username must be 3-30 letters/numbers.")
            taken = conn.execute("SELECT id FROM users WHERE username = ? AND id != ?", (new_u, user_id)).fetchone()
            if taken:
                raise HTTPException(status_code=400, detail="Username is already taken.")
            new_username = new_u

        # Update display name
        new_display = curr_display
        if req.display_name is not None:
            new_display = req.display_name.strip()[:50] or new_username

        # Update avatar color
        new_color = curr_color
        if req.avatar_color:
            new_color = req.avatar_color.strip()

        # Update password if requested
        new_hash = curr_hash
        new_salt = curr_salt
        if req.new_password:
            if not req.current_password:
                raise HTTPException(status_code=400, detail="Current password is required to change password.")
            if not verify_password(req.current_password.strip(), curr_salt, curr_hash):
                raise HTTPException(status_code=400, detail="Incorrect current password.")
            if len(req.new_password.strip()) < 4:
                raise HTTPException(status_code=400, detail="New password must be at least 4 characters.")
            new_hash, new_salt = hash_password(req.new_password.strip())

        # Update preferences
        if req.settings is not None:
            curr_settings.update(req.settings)

        settings_json = json.dumps(curr_settings)

        conn.execute("""
            UPDATE users 
            SET username = ?, display_name = ?, avatar_color = ?, password_hash = ?, salt = ?, settings_json = ?, updated_at = datetime('now')
            WHERE id = ?
        """, (new_username, new_display, new_color, new_hash, new_salt, settings_json, user_id))
        conn.commit()

    # Edit user record on cloud database channel
    c = get_client()
    if c.is_connected() and await c.is_user_authorized():
        try:
            channel = await get_database_channel(c)
            record_text = (
                f"#USER_RECORD id={user_id} "
                f"username={new_username} "
                f"display={urllib.parse.quote(new_display)} "
                f"color={urllib.parse.quote(new_color)} "
                f"avatar={curr_avatar_msg} "
                f"salt={new_salt} "
                f"hash={new_hash} "
                f"settings={urllib.parse.quote(settings_json)} "
                f"updated={int(time.time())}"
            )

            msg_to_edit = curr_msg_id
            if not msg_to_edit:
                async for m in c.iter_messages(channel, limit=1000):
                    t = m.text or ""
                    if t.startswith("#USER_") and f"id={user_id}" in t:
                        msg_to_edit = m.id
                        break

            if msg_to_edit:
                try:
                    await c.edit_message(channel, msg_to_edit, record_text)
                    print(f"Edited user {user_id} cloud record in database channel (msg {msg_to_edit}).")
                except Exception as edit_err:
                    print("Error editing channel message, sending update:", edit_err)
                    sent = await c.send_message(channel, record_text)
                    msg_to_edit = sent.id
            else:
                sent = await c.send_message(channel, record_text)
                msg_to_edit = sent.id

            with get_db() as conn:
                conn.execute("UPDATE users SET message_id = ? WHERE id = ?", (msg_to_edit, user_id))
                conn.commit()

        except Exception as e:
            print("Error updating user record on cloud channel:", e)

    return {
        "status": "ok",
        "message": "User settings updated and synchronized to cloud.",
        "user": {
            "id": user_id,
            "username": new_username,
            "display_name": new_display,
            "avatar_color": new_color,
            "avatar_url": f"/api/user/avatar/{user_id}?v={curr_avatar_msg}" if curr_avatar_msg else None,
            "avatar_msg_id": curr_avatar_msg,
            "settings": curr_settings
        }
    }

# User Logout Endpoint
@app.post("/api/user/logout")
async def logout_user(
    authorization: Optional[str] = Header(None),
    x_auth_token: Optional[str] = Header(None)
):
    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split("Bearer ")[1].strip()
    elif x_auth_token:
        token = x_auth_token.strip()

    if token:
        with get_db() as conn:
            conn.execute("DELETE FROM user_tokens WHERE token = ?", (token,))
            conn.commit()
    return {"status": "ok"}

# Helper to generate SVG avatar fallback
def generate_svg_avatar(letter: str, bg_color: str = "#0A84FF") -> bytes:
    clean_letter = (letter or "U")[0].upper()
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="128" height="128">
  <defs>
    <linearGradient id="avatarGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="{bg_color}"/>
      <stop offset="100%" stop-color="#4F46E5"/>
    </linearGradient>
  </defs>
  <rect width="128" height="128" rx="64" fill="url(#avatarGrad)"/>
  <text x="50%" y="54%" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif" font-weight="700" font-size="56" fill="#ffffff" text-anchor="middle" dominant-baseline="middle">{clean_letter}</text>
</svg>"""
    return svg.encode("utf-8")

# Endpoint: Serve User Avatar from Cloud Database Channel
@app.get("/api/user/avatar/{user_id}")
async def get_user_avatar(user_id: str):
    with get_db() as conn:
        row = conn.execute("SELECT id, username, display_name, avatar_color, avatar_msg_id FROM users WHERE id = ?", (user_id,)).fetchone()

    fallback_letter = "U"
    fallback_color = "#0A84FF"
    if row:
        name = row["display_name"] or row["username"] or "U"
        fallback_letter = name[0].upper()
        fallback_color = row["avatar_color"] or "#0A84FF"

    if not row or not row["avatar_msg_id"]:
        return Response(
            content=generate_svg_avatar(fallback_letter, fallback_color),
            media_type="image/svg+xml",
            headers={"Cache-Control": "public, max-age=86400"}
        )

    c = get_client()
    if not c.is_connected():
        await c.connect()

    try:
        channel = await get_database_channel(c)
        msg = await c.get_messages(channel, ids=row["avatar_msg_id"])
        if not msg or not msg.media:
            return Response(
                content=generate_svg_avatar(fallback_letter, fallback_color),
                media_type="image/svg+xml",
                headers={"Cache-Control": "public, max-age=3600"}
            )

        media_bytes = await c.download_media(msg, file=bytes)
        if not media_bytes:
            return Response(
                content=generate_svg_avatar(fallback_letter, fallback_color),
                media_type="image/svg+xml",
                headers={"Cache-Control": "public, max-age=3600"}
            )

        mime_type = "image/jpeg"
        if msg.file and msg.file.mime_type:
            mime_type = msg.file.mime_type

        return Response(
            content=media_bytes,
            media_type=mime_type,
            headers={
                "Cache-Control": "public, max-age=604800, immutable",
                "Content-Disposition": f'inline; filename="avatar_{user_id}"'
            }
        )
    except Exception as e:
        print(f"Error streaming avatar for {user_id}:", e)
        return Response(
            content=generate_svg_avatar(fallback_letter, fallback_color),
            media_type="image/svg+xml",
            headers={"Cache-Control": "no-cache"}
        )

# Endpoint: Upload new Profile Picture (PFP) directly to Cloud Database Channel
@app.post("/api/user/avatar")
async def upload_user_avatar(
    avatar: UploadFile = File(...),
    user: dict = Depends(get_current_user)
):
    user_id = user["id"]
    content_type = avatar.content_type or ""
    img_bytes = await avatar.read()
    if len(img_bytes) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    if len(img_bytes) > 5 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Avatar image size must be under 5MB.")

    ext = ".jpg"
    if "png" in content_type:
        ext = ".png"
    elif "webp" in content_type:
        ext = ".webp"
    elif "gif" in content_type:
        ext = ".gif"

    c = get_client()
    if not c.is_connected():
        await c.connect()

    channel = await get_database_channel(c)
    file_obj = io.BytesIO(img_bytes)
    file_obj.name = f"avatar_{user_id}{ext}"

    sent_msg = await c.send_file(
        channel,
        file=file_obj,
        caption=f"#USER_AVATAR user_id={user_id}",
        force_document=True
    )

    avatar_msg_id = sent_msg.id

    with get_db() as conn:
        conn.execute("UPDATE users SET avatar_msg_id = ?, updated_at = datetime('now') WHERE id = ?", (avatar_msg_id, user_id))
        user_row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        conn.commit()

    # Sync #USER_RECORD in cloud channel
    try:
        record_msg_id = user_row["message_id"]
        record_text = (
            f"#USER_RECORD id={user_id} "
            f"username={user_row['username']} "
            f"display={urllib.parse.quote(user_row['display_name'] or user_row['username'])} "
            f"color={urllib.parse.quote(user_row['avatar_color'] or '#0A84FF')} "
            f"avatar={avatar_msg_id} "
            f"salt={user_row['salt']} "
            f"hash={user_row['password_hash']} "
            f"settings={urllib.parse.quote(user_row['settings_json'] or '{}')} "
            f"updated={int(time.time())}"
        )
        if record_msg_id:
            try:
                await c.edit_message(channel, record_msg_id, record_text)
            except Exception:
                await c.send_message(channel, record_text)
    except Exception as e:
        print("Error syncing user record with avatar update:", e)

    return {
        "status": "ok",
        "avatar_url": f"/api/user/avatar/{user_id}?v={avatar_msg_id}",
        "avatar_msg_id": avatar_msg_id,
        "message": "Profile photo uploaded and synchronized to cloud."
    }

# Endpoint: Remove Profile Picture (reverts to default avatar)
@app.delete("/api/user/avatar")
async def delete_user_avatar(user: dict = Depends(get_current_user)):
    user_id = user["id"]
    with get_db() as conn:
        conn.execute("UPDATE users SET avatar_msg_id = NULL, updated_at = datetime('now') WHERE id = ?", (user_id,))
        user_row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        conn.commit()

    c = get_client()
    if c.is_connected() and await c.is_user_authorized():
        try:
            channel = await get_database_channel(c)
            record_msg_id = user_row["message_id"]
            record_text = (
                f"#USER_RECORD id={user_id} "
                f"username={user_row['username']} "
                f"display={urllib.parse.quote(user_row['display_name'] or user_row['username'])} "
                f"color={urllib.parse.quote(user_row['avatar_color'] or '#0A84FF')} "
                f"avatar=None "
                f"salt={user_row['salt']} "
                f"hash={user_row['password_hash']} "
                f"settings={urllib.parse.quote(user_row['settings_json'] or '{}')} "
                f"updated={int(time.time())}"
            )
            if record_msg_id:
                try:
                    await c.edit_message(channel, record_msg_id, record_text)
                except Exception:
                    await c.send_message(channel, record_text)
        except Exception as e:
            print("Error syncing user record with avatar removal:", e)

    return {
        "status": "ok",
        "avatar_url": None,
        "avatar_msg_id": None,
        "message": "Profile photo removed."
    }

# Per-User Folders API
@app.get("/api/folders")
async def list_folders(parent_id: Optional[str] = None, user: dict = Depends(get_current_user)):
    user_id = user["id"]
    with get_db() as conn:
        if parent_id and parent_id != "root":
            cur = conn.execute("SELECT * FROM folders WHERE user_id = ? AND parent_id = ? ORDER BY name ASC", (user_id, parent_id))
        else:
            cur = conn.execute("SELECT * FROM folders WHERE user_id = ? AND (parent_id IS NULL OR parent_id = 'root') ORDER BY name ASC", (user_id,))
        folders = [dict(r) for r in cur.fetchall()]

        for f in folders:
            subfolders_count = conn.execute("SELECT COUNT(*) FROM folders WHERE user_id = ? AND parent_id = ?", (user_id, f["id"])).fetchone()[0]
            files_count = conn.execute("SELECT COUNT(*) FROM files WHERE user_id = ? AND folder_id = ?", (user_id, f["id"])).fetchone()[0]
            f["item_count"] = subfolders_count + files_count

        breadcrumbs = []
        curr = parent_id
        while curr and curr != "root":
            f_row = conn.execute("SELECT id, name, parent_id FROM folders WHERE user_id = ? AND id = ?", (user_id, curr)).fetchone()
            if f_row:
                breadcrumbs.insert(0, {"id": f_row["id"], "name": f_row["name"]})
                curr = f_row["parent_id"]
            else:
                break

    return {"folders": folders, "breadcrumbs": breadcrumbs}

@app.post("/api/folders")
async def create_folder(req: CreateFolderRequest, user: dict = Depends(get_current_user)):
    folder_name = req.name.strip()
    if not folder_name:
        raise HTTPException(status_code=400, detail="Folder name is required")
    parent_id = req.parent_id if (req.parent_id and req.parent_id != "root") else None
    user_id = user["id"]

    clean_slug = re.sub(r'[^a-zA-Z0-9_-]', '_', folder_name).lower()
    folder_id = f"f_{clean_slug}_{os.urandom(3).hex()}"

    with get_db() as conn:
        conn.execute("INSERT INTO folders (id, user_id, name, parent_id) VALUES (?, ?, ?, ?)", (folder_id, user_id, folder_name, parent_id))
        conn.commit()

    # Log folder to Telegram channel
    c = get_client()
    if c.is_connected() and await c.is_user_authorized():
        try:
            channel = await get_database_channel(c)
            await c.send_message(channel, f"#USER_FOLDER user_id={user_id} id={folder_id} name={clean_slug} parent_id={parent_id}")
        except Exception:
            pass

    return {"status": "ok", "folder": {"id": folder_id, "name": folder_name, "parent_id": parent_id}}

@app.delete("/api/folders/{folder_id}")
async def delete_folder(folder_id: str, user: dict = Depends(get_current_user)):
    user_id = user["id"]
    c = get_client()
    with get_db() as conn:
        files_to_delete = conn.execute("SELECT message_id FROM files WHERE user_id = ? AND folder_id = ?", (user_id, folder_id)).fetchall()
        msg_ids = [r["message_id"] for r in files_to_delete]
        if msg_ids and c.is_connected() and await c.is_user_authorized():
            try:
                channel = await get_database_channel(c)
                await c.delete_messages(channel, msg_ids)
            except Exception as e:
                print("Error deleting messages from TG:", e)

        conn.execute("DELETE FROM files WHERE user_id = ? AND folder_id = ?", (user_id, folder_id))
        conn.execute("DELETE FROM folders WHERE user_id = ? AND id = ?", (user_id, folder_id))
        conn.commit()

    return {"status": "ok"}

# Per-User Files API
@app.get("/api/files")
async def list_files(
    folder_id: Optional[str] = None,
    filter: str = "all",
    search: str = "",
    authorization: Optional[str] = Header(None),
    x_auth_token: Optional[str] = Header(None),
    token: Optional[str] = Query(None),
    user: dict = Depends(get_current_user)
):
    user_id = user["id"]
    curr_token = ""
    if authorization and authorization.startswith("Bearer "):
        curr_token = authorization.split("Bearer ")[1].strip()
    elif x_auth_token:
        curr_token = x_auth_token.strip()
    elif token:
        curr_token = token.strip()

    actual_folder_id = folder_id if (folder_id and folder_id != "root") else None
    with get_db() as conn:
        query = "SELECT * FROM files WHERE user_id = ? "
        params = [user_id]
        if actual_folder_id:
            query += "AND folder_id = ? "
            params.append(actual_folder_id)
        else:
            query += "AND (folder_id IS NULL OR folder_id = 'root') "

        if filter != "all":
            query += "AND media_type = ? "
            params.append(filter)

        if search:
            query += "AND name LIKE ? "
            params.append(f"%{search.strip()}%")

        query += "ORDER BY id DESC"
        cur = conn.execute(query, tuple(params))
        files = [dict(r) for r in cur.fetchall()]

    t_param = f"?token={curr_token}" if curr_token else ""
    for f in files:
        f["size_formatted"] = format_size(f["size"])
        f["stream_url"] = f"/api/stream/{f['message_id']}{t_param}"
        f["download_url"] = f"/api/download/{f['message_id']}{t_param}"
        f["direct_link"] = f"/d/{f['message_id']}{t_param}"
        f["thumb_url"] = f"/api/thumb/{f['message_id']}{t_param}"

    return {"files": files}

# Background Telegram Upload Worker (Tagged to User & Channel)
async def background_telegram_upload(
    task_id: str,
    temp_path: str,
    temp_dir: str,
    filename: str,
    folder_id: Optional[str],
    user_id: str,
    username: str,
    file_size: int,
    mime_type: str,
    media_type: str
):
    c = get_client()
    start_time = time.time()

    def progress_cb(current, total):
        elapsed = time.time() - start_time
        speed = current / elapsed if elapsed > 0 else 0
        pct = round((current / total) * 100, 1) if total > 0 else 0
        upload_tasks[task_id].update({
            "status": "saving_to_cloud",
            "percent": pct,
            "uploaded": current,
            "total": total,
            "speed": f"{format_size(int(speed))}/s",
            "formatted": f"{format_size(current)} / {format_size(total)}"
        })

    def is_cancelled():
        return upload_tasks.get(task_id, {}).get("cancelled", False)

    try:
        upload_tasks[task_id]["status"] = "saving_to_cloud"
        channel = await get_database_channel(c)
        folder_tag = f"[Folder: {folder_id}]" if folder_id and folder_id != "root" else "[Root]"
        
        # High-speed pipelined upload with cancel check
        uploaded_file = await fast_pipelined_upload(
            c,
            temp_path,
            file_name=filename,
            progress_callback=progress_cb,
            cancel_check=is_cancelled
        )

        if is_cancelled():
            raise asyncio.CancelledError("Upload cancelled by user")

        # Send to userdatabase channel tagged with User ID
        is_video = media_type == "video"
        caption = f"#USER_FILE user_id={user_id} folder_id={folder_id or 'root'} mime={mime_type} media={media_type}\n{filename}"
        sent_msg = await c.send_file(
            channel,
            uploaded_file,
            caption=caption,
            supports_streaming=is_video,
            force_document=not is_video
        )

        # Record in SQLite database linked strictly to this user
        actual_folder = folder_id if (folder_id and folder_id != "root") else None
        with get_db() as conn:
            cur = conn.execute("""
                INSERT OR IGNORE INTO files (user_id, message_id, folder_id, name, size, mime_type, media_type, date)
                VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
            """, (user_id, sent_msg.id, actual_folder, filename, file_size, mime_type, media_type))
            file_id = cur.lastrowid
            conn.commit()

        upload_tasks[task_id].update({
            "status": "completed",
            "percent": 100.0,
            "formatted": f"{format_size(file_size)} / {format_size(file_size)}",
            "file": {
                "id": file_id,
                "message_id": sent_msg.id,
                "name": filename,
                "size": file_size,
                "size_formatted": format_size(file_size),
                "media_type": media_type,
            }
        })

    except asyncio.CancelledError:
        print(f"Upload task {task_id} was cancelled.")
        upload_tasks[task_id]["status"] = "cancelled"
    except Exception as e:
        print(f"Error in background upload task {task_id}: {e}")
        upload_tasks[task_id].update({
            "status": "error",
            "error": str(e)
        })
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

# Upload endpoint - checks user authentication
@app.post("/api/upload")
async def upload_file(
    folder_id: Optional[str] = Form(None),
    file: UploadFile = File(...),
    user: dict = Depends(get_current_user)
):
    c = get_client()
    if not c.is_connected():
        await c.connect()

    filename = file.filename or "upload_file"
    temp_dir = tempfile.mkdtemp()
    temp_path = os.path.join(temp_dir, filename)

    task_id = str(uuid.uuid4())
    upload_tasks[task_id] = {
        "task_id": task_id,
        "filename": filename,
        "status": "receiving",
        "cancelled": False,
        "percent": 0.0,
        "uploaded": 0,
        "total": 0,
        "speed": "0 B/s",
        "formatted": "0 B / 0 B"
    }

    try:
        size = 0
        with open(temp_path, "wb") as buffer:
            while chunk := await file.read(4 * 1024 * 1024):
                if upload_tasks[task_id]["cancelled"]:
                    raise asyncio.CancelledError("Cancelled while receiving")
                buffer.write(chunk)
                size += len(chunk)

        mime_type = file.content_type or mimetypes.guess_type(filename)[0] or "application/octet-stream"
        media_type = "document"
        if mime_type.startswith("video/"):
            media_type = "video"
        elif mime_type.startswith("audio/"):
            media_type = "audio"
        elif mime_type.startswith("image/"):
            media_type = "image"

        upload_tasks[task_id].update({
            "status": "queued",
            "total": size,
            "formatted": f"0 B / {format_size(size)}"
        })

        asyncio.create_task(
            background_telegram_upload(
                task_id, temp_path, temp_dir, filename, folder_id, user["id"], user["username"], size, mime_type, media_type
            )
        )

        return {"status": "ok", "task_id": task_id, "size": size}

    except Exception as e:
        shutil.rmtree(temp_dir, ignore_errors=True)
        upload_tasks[task_id] = {"status": "error", "error": str(e), "cancelled": True}
        raise HTTPException(status_code=500, detail=str(e))

# Cancel upload endpoint
@app.post("/api/upload/cancel")
async def cancel_upload(task_id: str = Query(...)):
    if task_id in upload_tasks:
        upload_tasks[task_id]["cancelled"] = True
        upload_tasks[task_id]["status"] = "cancelled"
        return {"status": "ok", "message": "Upload cancelled"}
    raise HTTPException(status_code=404, detail="Task not found")

# Progress polling endpoint
@app.get("/api/upload/progress")
async def get_upload_progress(task_id: str = Query(...)):
    if task_id not in upload_tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    return upload_tasks[task_id]

# Delete file - only uploader can delete
@app.delete("/api/files/{message_id}")
async def delete_file(message_id: int, user: dict = Depends(get_current_user)):
    user_id = user["id"]
    c = get_client()

    with get_db() as conn:
        f = conn.execute("SELECT id FROM files WHERE message_id = ? AND user_id = ?", (message_id, user_id)).fetchone()
        if not f:
            raise HTTPException(status_code=403, detail="Not authorized to delete this file.")

        conn.execute("DELETE FROM files WHERE message_id = ? AND user_id = ?", (message_id, user_id))
        conn.commit()

    if c.is_connected():
        try:
            channel = await get_database_channel(c)
            await c.delete_messages(channel, [message_id])
        except Exception as e:
            print("TG delete error:", e)

    return {"status": "ok"}

# Verify File Access: Strictly ensures only the user who uploaded the file can access/stream/download it
async def verify_file_access(message_id: int, token: Optional[str] = None, auth_header: Optional[str] = None) -> str:
    extracted_token = None
    if auth_header and auth_header.startswith("Bearer "):
        extracted_token = auth_header.split("Bearer ")[1].strip()
    elif token:
        extracted_token = token.strip()

    if not extracted_token:
        raise HTTPException(status_code=401, detail="Authentication token required. Only the uploader can access this file.")

    with get_db() as conn:
        t_row = conn.execute("SELECT user_id FROM user_tokens WHERE token = ?", (extracted_token,)).fetchone()
        if not t_row:
            raise HTTPException(status_code=401, detail="Invalid or expired session token.")
        current_user_id = t_row["user_id"]

        f_row = conn.execute("SELECT user_id FROM files WHERE message_id = ?", (message_id,)).fetchone()
        if f_row:
            if f_row["user_id"] != current_user_id:
                raise HTTPException(status_code=403, detail="Access denied. Only the uploader can access this file.")
            return current_user_id

    # If file record is not found in local SQLite (e.g. server restart / Vercel instance), check Telegram channel
    c = get_client()
    if not c.is_connected():
        await c.connect()
    channel = await get_database_channel(c)
    msg = await c.get_messages(channel, ids=message_id)
    if not msg:
        raise HTTPException(status_code=404, detail="File not found.")

    text = msg.text or ""
    parts = dict(re.findall(r'(\w+)=([^\s]+)', text.split("\n")[0]))
    file_owner_id = parts.get("user_id")

    if not file_owner_id or file_owner_id != current_user_id:
        raise HTTPException(status_code=403, detail="Access denied. Only the uploader can access this file.")

    with get_db() as conn:
        f_size = msg.file.size if msg.file else 0
        f_mime = (msg.file.mime_type if msg.file else None) or "application/octet-stream"
        f_name = (msg.file.name if msg.file else None) or (text.split("\n", 1)[1] if "\n" in text else "file")
        m_type = "document"
        if f_mime.startswith("video/"):
            m_type = "video"
        elif f_mime.startswith("audio/"):
            m_type = "audio"
        elif f_mime.startswith("image/"):
            m_type = "image"
        conn.execute("""
            INSERT OR IGNORE INTO files (user_id, message_id, folder_id, name, size, mime_type, media_type, date)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (file_owner_id, message_id, parts.get("folder_id"), f_name, f_size, f_mime, m_type, str(msg.date)))
        conn.commit()

    return current_user_id

# Short link / Direct CDN redirect
@app.get("/d/{message_id}")
async def direct_cdn_link(message_id: int, token: Optional[str] = Query(None), download: bool = False):
    action = "download" if download else "stream"
    query = f"?token={token}" if token else ""
    return RedirectResponse(url=f"/api/{action}/{message_id}{query}", status_code=307)

# Direct Stream / Download Endpoint with HTTP Range 206
@app.get("/api/stream/{message_id}")
@app.get("/api/download/{message_id}")
async def stream_media(
    message_id: int,
    request: Request,
    token: Optional[str] = Query(None),
    authorization: Optional[str] = Header(None)
):
    await verify_file_access(message_id, token=token, auth_header=authorization)
    c = get_client()
    if not c.is_connected():
        await c.connect()

    is_download = "download" in request.url.path
    channel = await get_database_channel(c)
    msg = await c.get_messages(channel, ids=message_id)
    if not msg or not msg.media:
        # Fallback to Saved Messages if not found in channel
        msg = await c.get_messages("me", ids=message_id)
    if not msg or not msg.media:
        raise HTTPException(status_code=404, detail="Media not found on ascloud")

    file_size = msg.file.size if msg.file else 0
    file_name = (msg.file.name if msg.file else None) or f"file_{msg.id}{msg.file.ext if msg.file else ''}"
    guessed_mime, _ = mimetypes.guess_type(file_name)
    mime_type = (msg.file.mime_type if msg.file else None) or guessed_mime or "application/octet-stream"
    if mime_type == "application/octet-stream" and guessed_mime:
        mime_type = guessed_mime

    range_header = request.headers.get("Range")
    start = 0
    end = file_size - 1

    status_code = 200
    headers = {
        "Accept-Ranges": "bytes",
        "Content-Type": mime_type,
        "Access-Control-Allow-Origin": "*",
        "Cache-Control": "public, max-age=86400",
    }

    # RFC 6266 latin-1 safe Content-Disposition with UTF-8 filename*
    ascii_filename = re.sub(r'[^\x20-\x7E]', '_', file_name).replace('"', '')
    encoded_filename = urllib.parse.quote(file_name, safe='')
    if is_download:
        headers["Content-Disposition"] = f'attachment; filename="{ascii_filename}"; filename*=UTF-8\'\'{encoded_filename}'
    else:
        headers["Content-Disposition"] = f'inline; filename="{ascii_filename}"; filename*=UTF-8\'\'{encoded_filename}'

    if range_header and not is_download:
        range_str = range_header.replace("bytes=", "").strip()
        parts = range_str.split("-")
        start = int(parts[0]) if parts[0] else 0
        if len(parts) > 1 and parts[1]:
            end = int(parts[1])
        if end >= file_size:
            end = file_size - 1
        if start > end:
            start = end
        status_code = 206
        length = end - start + 1
        headers["Content-Range"] = f"bytes {start}-{end}/{file_size}"
        headers["Content-Length"] = str(length)
    else:
        headers["Content-Length"] = str(file_size)

    async def file_streamer():
        length = end - start + 1
        bytes_sent = 0
        try:
            async for chunk in c.iter_download(msg, offset=start, request_size=512 * 1024):
                if bytes_sent + len(chunk) > length:
                    chunk = chunk[:length - bytes_sent]
                yield chunk
                bytes_sent += len(chunk)
                if bytes_sent >= length:
                    break
        except (asyncio.CancelledError, ConnectionResetError, GeneratorExit):
            pass
        except Exception as e:
            print(f"Stream interrupted on msg {message_id}: {e}")

    return StreamingResponse(file_streamer(), status_code=status_code, headers=headers)

# Thumbnail preview endpoint
@app.get("/api/thumb/{message_id}")
async def get_thumb(
    message_id: int,
    token: Optional[str] = Query(None),
    authorization: Optional[str] = Header(None)
):
    await verify_file_access(message_id, token=token, auth_header=authorization)
    c = get_client()
    if not c.is_connected():
        await c.connect()

    channel = await get_database_channel(c)
    msg = await c.get_messages(channel, ids=message_id)
    if not msg or not msg.media:
        msg = await c.get_messages("me", ids=message_id)
    if not msg or not msg.media:
        raise HTTPException(status_code=404, detail="Not found")

    try:
        thumb_data = await c.download_media(msg, file=bytes, thumb=-1)
        if not thumb_data and msg.photo:
            thumb_data = await c.download_media(msg, file=bytes)
        if thumb_data:
            return Response(content=thumb_data, media_type="image/jpeg", headers={"Cache-Control": "public, max-age=604800"})
    except Exception as e:
        print("Thumbnail error:", e)

    return Response(content=b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82", media_type="image/png")

# anonc by ascloud - Multi-User Apple iOS OLED Dark Theme Frontend
HTML_PAGE = """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>anonc by ascloud • Encrypted Cloud Workspace</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://unpkg.com/lucide@latest"></script>
  <style>
    :root {
      --apple-bg: #000000;
      --apple-card: #121214;
      --apple-card-hover: #19191c;
      --apple-border: rgba(255, 255, 255, 0.08);
      --apple-blue: #0A84FF;
    }
    body {
      background-color: var(--apple-bg);
      font-family: -apple-system, BlinkMacSystemFont, "SF Pro Display", "SF Pro Text", "Helvetica Neue", sans-serif;
      -webkit-font-smoothing: antialiased;
      scroll-behavior: smooth;
    }
    ::-webkit-scrollbar { width: 4px; height: 4px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb { background: rgba(255, 255, 255, 0.15); border-radius: 999px; }
    ::-webkit-scrollbar-thumb:hover { background: rgba(255, 255, 255, 0.3); }

    .ios-blur {
      background: rgba(18, 18, 20, 0.85);
      backdrop-filter: blur(28px) saturate(190%);
      -webkit-backdrop-filter: blur(28px) saturate(190%);
    }

    .ios-card {
      background: var(--apple-card);
      border: 1px solid var(--apple-border);
      transition: transform 0.25s cubic-bezier(0.16, 1, 0.3, 1),
                  box-shadow 0.25s cubic-bezier(0.16, 1, 0.3, 1),
                  border-color 0.2s ease,
                  background-color 0.2s ease;
      will-change: transform, box-shadow;
    }
    .ios-card:hover {
      background: var(--apple-card-hover);
      border-color: rgba(255, 255, 255, 0.18);
      transform: translateY(-2px);
      box-shadow: 0 14px 34px -8px rgba(0, 0, 0, 0.65), 0 0 1px 1px rgba(255, 255, 255, 0.08);
    }
    .ios-card:active {
      transform: scale(0.985);
      transition: transform 0.1s ease;
    }

    .ios-button {
      background: #1c1c1e;
      border: 1px solid var(--apple-border);
      transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
    }
    .ios-button:hover {
      background: #28282b;
      border-color: rgba(255, 255, 255, 0.16);
      transform: translateY(-1px);
    }
    .ios-button:active {
      transform: scale(0.96);
    }

    .ios-button-blue {
      background: var(--apple-blue);
      transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
      box-shadow: 0 4px 14px 0 rgba(10, 132, 255, 0.25);
    }
    .ios-button-blue:hover {
      background: #0077ED;
      box-shadow: 0 6px 20px 0 rgba(10, 132, 255, 0.4);
      transform: translateY(-1px);
    }
    .ios-button-blue:active {
      transform: scale(0.96);
    }

    /* Modal Animation */
    .modal-backdrop {
      animation: backdropIn 0.26s cubic-bezier(0.16, 1, 0.3, 1) forwards;
    }
    .modal-content {
      animation: modalScaleIn 0.28s cubic-bezier(0.16, 1, 0.3, 1) forwards;
      will-change: transform, opacity;
    }
    @keyframes backdropIn {
      from { opacity: 0; backdrop-filter: blur(0px); }
      to { opacity: 1; backdrop-filter: blur(28px); }
    }
    @keyframes modalScaleIn {
      from { opacity: 0; transform: scale(0.94) translateY(10px); }
      to { opacity: 1; transform: scale(1) translateY(0); }
    }

    /* Staggered Card Fade In */
    @keyframes cardFadeIn {
      from { opacity: 0; transform: translateY(8px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .card-animate {
      animation: cardFadeIn 0.32s cubic-bezier(0.16, 1, 0.3, 1) forwards;
    }

    /* Pulsing Emerald Dot for Live Cloud Sync */
    @keyframes pulseLive {
      0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(52, 199, 89, 0.7); }
      70% { transform: scale(1); box-shadow: 0 0 0 7px rgba(52, 199, 89, 0); }
      100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(52, 199, 89, 0); }
    }
    .pulse-live {
      animation: pulseLive 2s infinite cubic-bezier(0.4, 0, 0.6, 1);
    }

    /* Toggle Switch */
    .ios-switch {
      position: relative;
      width: 44px;
      height: 24px;
      border-radius: 999px;
      background: rgba(255, 255, 255, 0.12);
      transition: background-color 0.25s cubic-bezier(0.16, 1, 0.3, 1);
      cursor: pointer;
    }
    .ios-switch.active {
      background: #0A84FF;
    }
    .ios-switch-knob {
      position: absolute;
      top: 2px;
      left: 2px;
      width: 20px;
      height: 20px;
      border-radius: 50%;
      background: white;
      transition: transform 0.25s cubic-bezier(0.16, 1, 0.3, 1);
      box-shadow: 0 2px 4px rgba(0, 0, 0, 0.4);
    }
    .ios-switch.active .ios-switch-knob {
      transform: translateX(20px);
    }

    .brand-glow {
      box-shadow: 0 0 20px -5px rgba(10, 132, 255, 0.35);
    }
  </style>
</head>
<body class="text-white min-h-screen flex flex-col selection:bg-blue-600 selection:text-white">

  <!-- Floating Toast Notification -->
  <div id="toast" class="fixed top-5 left-1/2 -translate-x-1/2 z-50 transform -translate-y-12 opacity-0 transition-all duration-300 pointer-events-none">
    <div class="ios-blur border border-white/10 text-white text-xs px-4 py-2.5 rounded-full shadow-2xl flex items-center gap-2 font-medium">
      <i id="toastIcon" data-lucide="check" class="w-3.5 h-3.5 text-blue-400"></i>
      <span id="toastMessage">Done</span>
    </div>
  </div>

  <!-- iOS Top Bar with "anonc by ascloud" Branding -->
  <header class="sticky top-0 z-30 ios-blur border-b border-white/[0.06]">
    <div class="max-w-6xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between gap-4">
      
      <!-- Brand Logo & Title -->
      <div class="flex items-center gap-3 cursor-pointer" onclick="navigateToFolder('root')">
        <div class="w-9 h-9 rounded-2xl bg-gradient-to-tr from-sky-500 via-blue-600 to-indigo-600 flex items-center justify-center brand-glow">
          <i data-lucide="cloud" class="w-5 h-5 text-white"></i>
        </div>
        <div class="flex flex-col">
          <div class="flex items-center gap-2 leading-none">
            <span class="text-base font-bold tracking-tight text-white">anonc</span>
            <span class="text-[9px] font-semibold tracking-wider uppercase px-2 py-0.5 rounded-full bg-blue-500/15 text-blue-400 border border-blue-500/20">by ascloud</span>
          </div>
          <span class="text-[10px] text-white/40 mt-1 font-medium hidden sm:inline">Encrypted Cloud Storage</span>
        </div>
      </div>

      <!-- Action Buttons -->
      <div id="authActions" class="flex items-center gap-2">
        <button id="newFolderBtn" class="ios-button text-xs font-medium px-3.5 py-2 rounded-xl text-white/90 flex items-center gap-1.5">
          <i data-lucide="folder-plus" class="w-3.5 h-3.5 text-blue-400"></i>
          <span>New Folder</span>
        </button>

        <button id="uploadTriggerBtn" class="ios-button-blue text-xs font-semibold px-4 py-2 rounded-xl text-white flex items-center gap-1.5 shadow-md shadow-blue-500/10">
          <i data-lucide="arrow-up" class="w-3.5 h-3.5"></i>
          <span>Upload</span>
        </button>

        <!-- User / Settings Dropdown Button with live Avatar -->
        <button id="userSettingsBtn" class="flex items-center gap-2 p-1.5 pl-2 pr-3 rounded-2xl bg-[#1c1c1e] border border-white/[0.08] hover:border-white/20 transition group" title="Account Settings">
          <div id="navAvatar" class="w-6 h-6 rounded-full overflow-hidden bg-gradient-to-tr from-blue-600 to-indigo-600 flex items-center justify-center text-[11px] font-bold text-white shadow-sm ring-1 ring-white/10 transition-all duration-300">
            <img id="navAvatarImg" class="w-full h-full object-cover hidden" alt="Avatar" />
            <span id="navAvatarInitial">U</span>
          </div>
          <span id="navDisplayName" class="text-xs font-semibold text-white/90 group-hover:text-white transition max-w-[120px] truncate">User</span>
          <i data-lucide="chevron-down" class="w-3 h-3 text-white/40 group-hover:text-white/80 transition"></i>
        </button>
      </div>

      <!-- Unauthenticated State Button -->
      <div id="unauthActions" class="hidden flex items-center gap-2">
        <button id="openAuthModalBtn" class="ios-button-blue text-xs font-semibold px-4 py-2 rounded-xl text-white">
          Sign In
        </button>
      </div>

    </div>
  </header>

  <!-- Main Content -->
  <main class="max-w-6xl mx-auto px-4 sm:px-6 py-6 flex-1 flex flex-col gap-6 w-full">

    <!-- Breadcrumb & Search -->
    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
      
      <!-- iOS Breadcrumb Path -->
      <nav id="breadcrumbs" class="flex items-center gap-1.5 text-sm font-medium text-white/50 overflow-x-auto py-1">
        <button class="hover:text-white transition flex items-center gap-1 text-white" onclick="navigateToFolder('root')">
          <i data-lucide="hard-drive" class="w-3.5 h-3.5 text-blue-400"></i>
          <span>Files</span>
        </button>
      </nav>

      <!-- Search & Filters -->
      <div class="flex items-center gap-2">
        <div class="relative flex-1 sm:w-60">
          <i data-lucide="search" class="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-white/40"></i>
          <input type="text" id="searchInput" placeholder="Search my files..." class="w-full bg-[#121214] border border-white/[0.08] text-xs rounded-xl pl-8 pr-3 py-2 text-white placeholder-white/30 focus:outline-none focus:border-blue-500 transition">
        </div>
        
        <div class="flex items-center bg-[#121214] border border-white/[0.08] rounded-xl p-0.5 text-xs">
          <button data-filter="all" class="filter-btn active px-2.5 py-1.5 rounded-lg bg-blue-500 text-white font-medium">All</button>
          <button data-filter="video" class="filter-btn px-2.5 py-1.5 rounded-lg text-white/60 hover:text-white">Videos</button>
          <button data-filter="image" class="filter-btn px-2.5 py-1.5 rounded-lg text-white/60 hover:text-white">Photos</button>
          <button data-filter="document" class="filter-btn px-2.5 py-1.5 rounded-lg text-white/60 hover:text-white">Docs</button>
        </div>
      </div>

    </div>

    <!-- Hidden File Input -->
    <input type="file" id="filePicker" class="hidden" multiple>

    <!-- Upload Progress Modal / Floating Pill with CANCEL Button -->
    <div id="uploadBanner" class="fixed bottom-6 right-6 z-40 ios-blur border border-white/10 rounded-2xl p-4 shadow-2xl max-w-sm w-full hidden">
      <div class="flex items-center justify-between text-xs mb-1.5">
        <span id="uploadFileName" class="font-medium text-white/90 truncate max-w-[190px]">Uploading...</span>
        <div class="flex items-center gap-2">
          <span id="uploadPercent" class="text-blue-400 font-mono font-semibold">0%</span>
          <button id="cancelUploadBtn" class="p-1 rounded-lg text-white/40 hover:text-red-400 hover:bg-white/10 transition" title="Cancel upload">
            <i data-lucide="x" class="w-3.5 h-3.5"></i>
          </button>
        </div>
      </div>
      
      <!-- Stage & Speed status -->
      <div class="flex items-center justify-between text-[11px] text-white/40 mb-2 font-mono">
        <span id="uploadStageText">Sending...</span>
        <span id="uploadSpeedText">0 MB/s</span>
      </div>

      <div class="w-full bg-white/10 h-1.5 rounded-full overflow-hidden">
        <div id="uploadBar" class="bg-blue-500 h-1.5 rounded-full transition-all duration-300" style="width: 0%"></div>
      </div>
    </div>

    <!-- Folders Section -->
    <div id="foldersSection">
      <h3 class="text-xs font-semibold uppercase tracking-wider text-white/40 mb-3 px-1">My Folders</h3>
      <div id="foldersGrid" class="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 gap-3">
        <!-- Folders injected here -->
      </div>
    </div>

    <!-- Files Section -->
    <div id="filesSection">
      <div class="flex items-center justify-between mb-3 px-1">
        <h3 class="text-xs font-semibold uppercase tracking-wider text-white/40">My Files</h3>
        <span id="filesCount" class="text-xs text-white/30 font-mono">0 items</span>
      </div>
      
      <div id="filesGrid" class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
        <!-- Files injected here -->
      </div>
    </div>

    <!-- Empty State -->
    <div id="emptyContainer" class="hidden py-24 flex flex-col items-center justify-center text-center">
      <div class="w-14 h-14 rounded-2xl bg-[#121214] border border-white/[0.08] flex items-center justify-center text-white/30 mb-3">
        <i data-lucide="cloud-off" class="w-6 h-6"></i>
      </div>
      <p class="text-sm font-medium text-white/70">Your cloud space is empty</p>
      <p class="text-xs text-white/40 mt-1">Upload files or create folders to get started.</p>
    </div>

    <!-- Loading -->
    <div id="loadingIndicator" class="py-20 flex flex-col items-center justify-center">
      <div class="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mb-3"></div>
      <span class="text-xs text-white/40 font-mono">Connecting to anonc cloud...</span>
    </div>

  </main>

  <!-- Multi-User Auth Modal (Sign In / Create Account) -->
  <div id="authModal" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-2xl hidden modal-backdrop">
    <div class="bg-[#121214] border border-white/[0.12] rounded-3xl w-full max-w-sm p-6 shadow-2xl relative modal-content">
      <div class="text-center mb-5">
        <div class="w-12 h-12 rounded-2xl bg-gradient-to-tr from-sky-500 to-blue-600 mx-auto flex items-center justify-center mb-3 shadow-lg shadow-blue-500/20">
          <i data-lucide="cloud" class="w-6 h-6 text-white"></i>
        </div>
        <h2 class="text-lg font-bold text-white">anonc <span class="text-xs font-normal text-white/40">by ascloud</span></h2>
        <p class="text-xs text-white/50 mt-0.5">Encrypted Personal Storage</p>
      </div>

      <!-- Tab Switcher -->
      <div class="flex items-center bg-[#1c1c1e] p-1 rounded-2xl border border-white/[0.08] mb-5">
        <button id="tabSignIn" class="flex-1 py-1.5 text-xs font-semibold rounded-xl bg-blue-500 text-white transition">Sign In</button>
        <button id="tabSignUp" class="flex-1 py-1.5 text-xs font-semibold rounded-xl text-white/50 hover:text-white transition">Create Account</button>
      </div>

      <div id="authError" class="hidden mb-4 p-2.5 bg-red-500/10 border border-red-500/20 rounded-xl text-xs text-red-400 text-center"></div>

      <!-- Form Inputs -->
      <div class="flex flex-col gap-3 mb-5">
        <div>
          <label class="block text-[11px] font-medium text-white/60 mb-1">Username</label>
          <input type="text" id="authUsernameInput" placeholder="Choose a username" class="w-full bg-[#1c1c1e] border border-white/[0.08] rounded-xl px-3.5 py-2.5 text-xs text-white placeholder-white/20 focus:outline-none focus:border-blue-500 transition">
        </div>
        <div>
          <label class="block text-[11px] font-medium text-white/60 mb-1">Password</label>
          <input type="password" id="authPasswordInput" placeholder="Your password" class="w-full bg-[#1c1c1e] border border-white/[0.08] rounded-xl px-3.5 py-2.5 text-xs text-white placeholder-white/20 focus:outline-none focus:border-blue-500 transition">
        </div>
      </div>

      <button id="authSubmitBtn" class="w-full ios-button-blue font-semibold py-2.5 rounded-xl text-xs text-white shadow-lg shadow-blue-500/10">
        Sign In
      </button>

      <p class="text-[10px] text-center text-white/30 mt-4 flex items-center justify-center gap-1">
        <i data-lucide="shield-check" class="w-3.5 h-3.5 text-emerald-400"></i>
        <span>Encrypted Cloud Vault • Zero-Knowledge Isolation</span>
      </p>
    </div>
  </div>

  <!-- New Folder Modal -->
  <div id="folderModal" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-2xl hidden modal-backdrop">
    <div class="bg-[#121214] border border-white/[0.12] rounded-3xl w-full max-w-sm p-6 shadow-2xl modal-content">
      <h3 class="text-base font-bold text-white mb-1">New Folder</h3>
      <p class="text-xs text-white/50 mb-4">Enter a name for this folder.</p>
      <input type="text" id="folderNameInput" placeholder="Folder Name" class="w-full bg-[#1c1c1e] border border-white/[0.08] rounded-xl px-3.5 py-2.5 text-sm text-white placeholder-white/30 focus:outline-none focus:border-blue-500 mb-4 transition">
      <div class="flex items-center justify-end gap-2">
        <button id="cancelFolderBtn" class="ios-button text-xs font-medium px-4 py-2 rounded-xl text-white/70">Cancel</button>
        <button id="createFolderSubmitBtn" class="ios-button-blue text-xs font-semibold px-4 py-2 rounded-xl text-white">Create</button>
      </div>
    </div>
  </div>

  <!-- Media Player Modal (Clean iOS Sheet) -->
  <div id="playerModal" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/90 backdrop-blur-2xl hidden modal-backdrop">
    <div class="bg-[#121214] border border-white/[0.12] rounded-3xl w-full max-w-3xl overflow-hidden shadow-2xl flex flex-col modal-content">
      <!-- Player Header -->
      <div class="px-5 py-3 border-b border-white/[0.06] flex items-center justify-between">
        <span id="playerFilename" class="text-xs font-medium text-white/80 truncate max-w-md">Playing</span>
        <div class="flex items-center gap-1.5">
          <button id="playerCopyCdnBtn" class="ios-button text-xs px-2.5 py-1.5 rounded-lg text-white/70 hover:text-white flex items-center gap-1.5" title="Copy Direct CDN Link">
            <i data-lucide="link-2" class="w-3.5 h-3.5 text-blue-400"></i>
            <span class="text-[11px]">Direct Link</span>
          </button>
          <a id="playerDownloadBtn" href="#" download class="ios-button p-1.5 rounded-lg text-white/70 hover:text-white" title="Download">
            <i data-lucide="download" class="w-3.5 h-3.5"></i>
          </a>
          <button id="closePlayerBtn" class="ios-button p-1.5 rounded-lg text-white/70 hover:text-white">
            <i data-lucide="x" class="w-3.5 h-3.5"></i>
          </button>
        </div>
      </div>

      <!-- Player Body -->
      <div id="playerBody" class="bg-black min-h-[320px] max-h-[70vh] flex items-center justify-center">
      </div>
    </div>
  </div>

  <!-- Advanced User / ascloud Settings Sheet (Synced with Cloud Database) -->
  <div id="settingsModal" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-2xl hidden modal-backdrop">
    <div class="bg-[#121214] border border-white/[0.12] rounded-3xl w-full max-w-lg overflow-hidden shadow-2xl modal-content flex flex-col max-h-[90vh]">
      <!-- Modal Header -->
      <div class="px-6 py-4 border-b border-white/[0.06] flex items-center justify-between">
        <div class="flex items-center gap-2.5">
          <div class="w-7 h-7 rounded-xl bg-blue-500/20 flex items-center justify-center text-blue-400">
            <i data-lucide="settings" class="w-4 h-4"></i>
          </div>
          <div>
            <h3 class="text-sm font-bold text-white leading-tight">Settings & Profile</h3>
            <p class="text-[10px] text-white/40">Synced with encrypted cloud database</p>
          </div>
        </div>
        <button id="closeSettingsBtn" class="p-1.5 text-white/40 hover:text-white rounded-xl hover:bg-white/10 transition">
          <i data-lucide="x" class="w-4 h-4"></i>
        </button>
      </div>

      <!-- Cloud Sync Status Bar -->
      <div class="px-6 py-2.5 bg-[#18181b]/60 border-b border-white/[0.04] flex items-center justify-between text-[11px]">
        <div class="flex items-center gap-2">
          <div class="w-2 h-2 rounded-full bg-emerald-400 pulse-live"></div>
          <span class="text-white/70 font-medium">Cloud Database: <span class="text-emerald-400 font-semibold">Connected & Synced</span></span>
        </div>
        <span id="syncUserBadge" class="text-[10px] text-white/40 font-mono">u_id</span>
      </div>

      <!-- Settings Navigation Tabs -->
      <div class="flex items-center px-6 pt-3 gap-1 bg-[#121214] border-b border-white/[0.06]">
        <button id="tabSettingsProfile" class="settings-tab-btn flex-1 pb-2.5 text-xs font-semibold text-blue-400 border-b-2 border-blue-500 transition flex items-center justify-center gap-1.5" data-tab="profile">
          <i data-lucide="user" class="w-3.5 h-3.5"></i>
          <span>Profile</span>
        </button>
        <button id="tabSettingsSecurity" class="settings-tab-btn flex-1 pb-2.5 text-xs font-semibold text-white/40 hover:text-white/70 border-b-2 border-transparent transition flex items-center justify-center gap-1.5" data-tab="security">
          <i data-lucide="lock" class="w-3.5 h-3.5"></i>
          <span>Security</span>
        </button>
        <button id="tabSettingsCloud" class="settings-tab-btn flex-1 pb-2.5 text-xs font-semibold text-white/40 hover:text-white/70 border-b-2 border-transparent transition flex items-center justify-center gap-1.5" data-tab="cloud">
          <i data-lucide="sliders" class="w-3.5 h-3.5"></i>
          <span>Preferences</span>
        </button>
      </div>

      <!-- Tab Content Area -->
      <div class="p-6 overflow-y-auto space-y-4">
        
        <!-- PROFILE TAB -->
        <div id="paneProfile" class="space-y-4">
          <!-- Cloud Profile Picture (PFP) Upload -->
          <div class="p-4 bg-[#18181b] rounded-2xl border border-white/[0.06] flex items-center gap-4">
            <div class="relative group cursor-pointer" id="avatarUploadTrigger" title="Click to change profile photo">
              <div class="w-16 h-16 rounded-full overflow-hidden bg-gradient-to-tr from-blue-600 to-indigo-600 flex items-center justify-center text-xl font-bold text-white shadow-xl ring-2 ring-white/10 group-hover:ring-blue-500/50 transition-all duration-300">
                <img id="settingsAvatarImg" class="w-full h-full object-cover hidden" alt="Profile Picture" />
                <span id="settingsAvatarInitial">U</span>
              </div>
              <div class="absolute inset-0 rounded-full bg-black/50 opacity-0 group-hover:opacity-100 flex items-center justify-center transition-opacity duration-200">
                <i data-lucide="camera" class="w-5 h-5 text-white"></i>
              </div>
              <div id="avatarLoadingSpinner" class="hidden absolute inset-0 rounded-full bg-black/70 flex items-center justify-center">
                <div class="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
              </div>
            </div>

            <div class="flex-1 min-w-0">
              <div class="flex items-center gap-2 mb-0.5">
                <h4 class="text-xs font-semibold text-white/90">Profile Photo</h4>
                <span class="text-[10px] px-1.5 py-0.5 rounded-md bg-blue-500/10 text-blue-400 font-mono">Cloud Synced</span>
              </div>
              <p class="text-[11px] text-white/40 mb-2.5 truncate">JPG, PNG or WebP up to 5MB</p>
              <div class="flex items-center gap-2">
                <input type="file" id="avatarFileInput" accept="image/png,image/jpeg,image/webp,image/gif" class="hidden">
                <button type="button" id="chooseAvatarBtn" class="px-3 py-1.5 rounded-xl bg-white/10 hover:bg-white/15 active:scale-95 text-xs font-medium text-white transition flex items-center gap-1.5">
                  <i data-lucide="upload" class="w-3.5 h-3.5"></i>
                  <span>Change Photo</span>
                </button>
                <button type="button" id="removeAvatarBtn" class="hidden px-3 py-1.5 rounded-xl bg-red-500/10 hover:bg-red-500/20 active:scale-95 text-xs font-medium text-red-400 transition flex items-center gap-1.5">
                  <i data-lucide="trash-2" class="w-3.5 h-3.5"></i>
                  <span>Remove</span>
                </button>
              </div>
            </div>
          </div>

          <div>
            <label class="block text-[11px] font-medium text-white/60 mb-1">Display Name</label>
            <input type="text" id="editDisplayNameInput" placeholder="Your display name" class="w-full bg-[#1c1c1e] border border-white/[0.08] rounded-xl px-3.5 py-2.5 text-xs text-white placeholder-white/20 focus:outline-none focus:border-blue-500 transition">
          </div>

          <div>
            <label class="block text-[11px] font-medium text-white/60 mb-1">Username (Cloud ID)</label>
            <div class="relative">
              <span class="absolute left-3.5 top-2.5 text-xs text-white/40">@</span>
              <input type="text" id="editUsernameInput" placeholder="username" class="w-full bg-[#1c1c1e] border border-white/[0.08] rounded-xl pl-7 pr-3.5 py-2.5 text-xs text-white placeholder-white/20 focus:outline-none focus:border-blue-500 transition font-mono">
            </div>
          </div>

          <div id="profileMsg" class="hidden p-2.5 rounded-xl text-xs text-center"></div>

          <button id="saveProfileBtn" class="w-full ios-button-blue font-semibold py-2.5 rounded-xl text-xs text-white flex items-center justify-center gap-2">
            <i data-lucide="cloud" class="w-3.5 h-3.5"></i>
            <span>Save Profile to Cloud</span>
          </button>
        </div>

        <!-- SECURITY TAB -->
        <div id="paneSecurity" class="hidden space-y-4">
          <div class="p-3.5 bg-blue-500/10 border border-blue-500/20 rounded-2xl flex items-center gap-3">
            <i data-lucide="shield-check" class="w-5 h-5 text-blue-400 flex-shrink-0"></i>
            <p class="text-[11px] text-blue-200">Changing your password updates your encrypted credentials in the cloud database immediately.</p>
          </div>

          <div>
            <label class="block text-[11px] font-medium text-white/60 mb-1">Current Password</label>
            <input type="password" id="editCurrentPasswordInput" placeholder="Enter current password" class="w-full bg-[#1c1c1e] border border-white/[0.08] rounded-xl px-3.5 py-2.5 text-xs text-white placeholder-white/20 focus:outline-none focus:border-blue-500 transition">
          </div>

          <div>
            <label class="block text-[11px] font-medium text-white/60 mb-1">New Password</label>
            <input type="password" id="editNewPasswordInput" placeholder="Minimum 4 characters" class="w-full bg-[#1c1c1e] border border-white/[0.08] rounded-xl px-3.5 py-2.5 text-xs text-white placeholder-white/20 focus:outline-none focus:border-blue-500 transition">
          </div>

          <div>
            <label class="block text-[11px] font-medium text-white/60 mb-1">Confirm New Password</label>
            <input type="password" id="editConfirmPasswordInput" placeholder="Re-type new password" class="w-full bg-[#1c1c1e] border border-white/[0.08] rounded-xl px-3.5 py-2.5 text-xs text-white placeholder-white/20 focus:outline-none focus:border-blue-500 transition">
          </div>

          <div id="securityMsg" class="hidden p-2.5 rounded-xl text-xs text-center"></div>

          <button id="savePasswordBtn" class="w-full ios-button-blue font-semibold py-2.5 rounded-xl text-xs text-white flex items-center justify-center gap-2">
            <i data-lucide="key-round" class="w-3.5 h-3.5"></i>
            <span>Update Password</span>
          </button>
        </div>

        <!-- CLOUD PREFERENCES TAB -->
        <div id="paneCloud" class="hidden space-y-4">
          <!-- Storage Meter -->
          <div class="p-4 bg-[#18181b] rounded-2xl border border-white/[0.06]">
            <div class="flex items-center justify-between mb-2">
              <span class="text-xs font-semibold text-white">Cloud Storage Allocation</span>
              <span id="prefStorageFormatted" class="text-xs font-mono font-bold text-blue-400">0 B</span>
            </div>
            <div class="w-full h-2 rounded-full bg-white/10 overflow-hidden mb-2">
              <div id="prefStorageBar" class="h-full bg-gradient-to-r from-blue-500 to-indigo-500 rounded-full transition-all duration-500" style="width: 5%;"></div>
            </div>
            <div class="flex items-center justify-between text-[10px] text-white/40">
              <span id="prefFilesCount">0 files saved</span>
              <span>Unlimited Private Vault</span>
            </div>
          </div>

          <!-- Preferences List -->
          <div class="space-y-3">
            <div class="flex items-center justify-between p-3.5 bg-[#18181b] rounded-2xl border border-white/[0.06]">
              <div>
                <div class="text-xs font-semibold text-white">Instant Media Auto-Preview</div>
                <div class="text-[10px] text-white/40">Stream audio & video automatically on card click</div>
              </div>
              <div id="switchAutoPreview" class="ios-switch active" data-pref="auto_preview">
                <div class="ios-switch-knob"></div>
              </div>
            </div>

            <div class="flex items-center justify-between p-3.5 bg-[#18181b] rounded-2xl border border-white/[0.06]">
              <div>
                <div class="text-xs font-semibold text-white">Fast Seek Hardware Acceleration</div>
                <div class="text-[10px] text-white/40">HTTP 206 range buffer optimization</div>
              </div>
              <div id="switchFastSeek" class="ios-switch active" data-pref="fast_seek">
                <div class="ios-switch-knob"></div>
              </div>
            </div>
          </div>

          <div class="pt-2">
            <button id="logoutBtn" class="w-full ios-button text-xs font-semibold py-2.5 rounded-xl text-red-400 hover:bg-red-500/10 hover:text-red-300 transition flex items-center justify-center gap-2">
              <i data-lucide="log-out" class="w-3.5 h-3.5"></i>
              <span>Sign Out</span>
            </button>
          </div>
        </div>

      </div>
    </div>
  </div>

  <script>
    let currentFolderId = 'root';
    let currentFilter = 'all';
    let currentFiles = [];
    let directCdnUrl = '';
    let currentUploadXhr = null;
    let currentTaskId = null;
    let isUploadCancelled = false;
    let authMode = 'login';
    let currentUser = null;

    function getAuthToken() {
      return localStorage.getItem('anonc_token');
    }

    function setAuthToken(token) {
      if (token) localStorage.setItem('anonc_token', token);
      else localStorage.removeItem('anonc_token');
    }

    function showToast(message, isSuccess = true) {
      const toast = document.getElementById('toast');
      const toastMessage = document.getElementById('toastMessage');
      const toastIcon = document.getElementById('toastIcon');
      toastMessage.textContent = message;
      toastIcon.setAttribute('data-lucide', isSuccess ? 'check' : 'alert-circle');
      toast.classList.remove('-translate-y-12', 'opacity-0');
      toast.classList.add('translate-y-0', 'opacity-100');
      lucide.createIcons();
      setTimeout(() => {
        toast.classList.remove('translate-y-0', 'opacity-100');
        toast.classList.add('-translate-y-12', 'opacity-0');
      }, 2500);
    }

    // Check User Authentication
    async function checkAuth() {
      const token = getAuthToken();
      if (!token) {
        showAuthModal();
        return;
      }
      try {
        const res = await fetch('/api/user/me', {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        if (res.ok) {
          const data = await res.json();
          currentUser = data.user;
          document.getElementById('authModal').classList.add('hidden');
          document.getElementById('authActions').classList.remove('hidden');
          document.getElementById('unauthActions').classList.add('hidden');
          
          updateUserDisplay(currentUser, data.stats);
          loadContent();
        } else {
          setAuthToken(null);
          showAuthModal();
        }
      } catch (e) {
        console.error('Auth error:', e);
        showAuthModal();
      }
    }

    function updateUserDisplay(user, stats) {
      if (!user) return;
      const initial = (user.display_name || user.username || 'U')[0].toUpperCase();

      // Topbar Avatar & Name
      const navAvatarImg = document.getElementById('navAvatarImg');
      const navAvatarInitial = document.getElementById('navAvatarInitial');
      const navName = document.getElementById('navDisplayName');
      navName.textContent = user.display_name || `@${user.username}`;

      // Settings Modal Avatar Elements
      const settingsAvatarImg = document.getElementById('settingsAvatarImg');
      const settingsAvatarInitial = document.getElementById('settingsAvatarInitial');
      const removeAvatarBtn = document.getElementById('removeAvatarBtn');

      if (user.avatar_url) {
        if (navAvatarImg) {
          navAvatarImg.src = user.avatar_url;
          navAvatarImg.classList.remove('hidden');
        }
        if (navAvatarInitial) navAvatarInitial.classList.add('hidden');

        if (settingsAvatarImg) {
          settingsAvatarImg.src = user.avatar_url;
          settingsAvatarImg.classList.remove('hidden');
        }
        if (settingsAvatarInitial) settingsAvatarInitial.classList.add('hidden');

        if (removeAvatarBtn) removeAvatarBtn.classList.remove('hidden');
      } else {
        if (navAvatarImg) navAvatarImg.classList.add('hidden');
        if (navAvatarInitial) {
          navAvatarInitial.classList.remove('hidden');
          navAvatarInitial.textContent = initial;
        }

        if (settingsAvatarImg) settingsAvatarImg.classList.add('hidden');
        if (settingsAvatarInitial) {
          settingsAvatarInitial.classList.remove('hidden');
          settingsAvatarInitial.textContent = initial;
        }

        if (removeAvatarBtn) removeAvatarBtn.classList.add('hidden');
      }

      document.getElementById('editDisplayNameInput').value = user.display_name || '';
      document.getElementById('editUsernameInput').value = user.username || '';
      document.getElementById('syncUserBadge').textContent = user.id;

      // Stats
      if (stats) {
        document.getElementById('prefStorageFormatted').textContent = stats.total_formatted || '0 B';
        document.getElementById('prefFilesCount').textContent = `${stats.total_files || 0} files saved`;
        const pct = Math.min(Math.max((stats.total_bytes / (100 * 1024 * 1024 * 1024)) * 100, 4), 100);
        document.getElementById('prefStorageBar').style.width = `${pct}%`;
      }

      // Switches
      const prefs = user.settings || {};
      const autoSw = document.getElementById('switchAutoPreview');
      const seekSw = document.getElementById('switchFastSeek');
      if (prefs.auto_preview !== false) autoSw.classList.add('active'); else autoSw.classList.remove('active');
      if (prefs.fast_seek !== false) seekSw.classList.add('active'); else seekSw.classList.remove('active');

      lucide.createIcons();
    }

    function showAuthModal() {
      document.getElementById('loadingIndicator').classList.add('hidden');
      document.getElementById('authModal').classList.remove('hidden');
      document.getElementById('authActions').classList.add('hidden');
      document.getElementById('unauthActions').classList.remove('hidden');
    }

    async function loadContent() {
      document.getElementById('loadingIndicator').classList.remove('hidden');
      await Promise.all([loadFolders(), loadFiles()]);
      document.getElementById('loadingIndicator').classList.add('hidden');
    }

    async function loadFolders() {
      const token = getAuthToken();
      if (!token) return;
      try {
        const res = await fetch(`/api/folders?parent_id=${currentFolderId}`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        const data = await res.json();
        renderBreadcrumbs(data.breadcrumbs || []);
        renderFolders(data.folders || []);
      } catch (e) {
        console.error('Error loading folders:', e);
      }
    }

    async function loadFiles() {
      const token = getAuthToken();
      if (!token) return;
      try {
        const query = document.getElementById('searchInput').value.trim();
        const res = await fetch(`/api/files?folder_id=${currentFolderId}&filter=${currentFilter}&search=${encodeURIComponent(query)}`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        const data = await res.json();
        currentFiles = data.files || [];
        renderFiles(currentFiles);
      } catch (e) {
        console.error('Error loading files:', e);
      }
    }

    function renderBreadcrumbs(crumbs) {
      const container = document.getElementById('breadcrumbs');
      container.innerHTML = `
        <button class="hover:text-white transition flex items-center gap-1 ${currentFolderId === 'root' ? 'text-white font-semibold' : 'text-white/50'}" onclick="navigateToFolder('root')">
          <i data-lucide="hard-drive" class="w-3.5 h-3.5 text-blue-400"></i>
          <span>Files</span>
        </button>
      `;
      crumbs.forEach((c, idx) => {
        const isLast = idx === crumbs.length - 1;
        container.innerHTML += `
          <i data-lucide="chevron-right" class="w-3.5 h-3.5 text-white/20"></i>
          <button class="hover:text-white transition truncate max-w-[120px] ${isLast ? 'text-white font-semibold' : 'text-white/50'}" onclick="navigateToFolder('${c.id}')">
            ${c.name}
          </button>
        `;
      });
      lucide.createIcons();
    }

    function renderFolders(folders) {
      const container = document.getElementById('foldersGrid');
      const section = document.getElementById('foldersSection');
      container.innerHTML = '';
      if (!folders.length) {
        section.classList.add('hidden');
        return;
      }
      section.classList.remove('hidden');
      folders.forEach((f, idx) => {
        const div = document.createElement('div');
        div.className = 'ios-card p-3.5 rounded-2xl cursor-pointer group flex items-center justify-between card-animate';
        div.style.animationDelay = `${idx * 0.03}s`;
        div.innerHTML = `
          <div class="flex items-center gap-3 truncate" onclick="navigateToFolder('${f.id}')">
            <div class="w-9 h-9 rounded-xl bg-blue-500/10 flex items-center justify-center text-blue-400 group-hover:scale-105 transition flex-shrink-0">
              <i data-lucide="folder" class="w-5 h-5 fill-blue-500/20"></i>
            </div>
            <div class="truncate">
              <div class="text-xs font-semibold text-white truncate">${f.name}</div>
              <div class="text-[10px] text-white/40 mt-0.5">${f.item_count} items</div>
            </div>
          </div>
          <button class="delete-folder-btn p-1.5 text-white/20 hover:text-red-400 transition rounded-lg" data-id="${f.id}" title="Delete folder">
            <i data-lucide="trash-2" class="w-3.5 h-3.5"></i>
          </button>
        `;
        container.appendChild(div);
      });

      document.querySelectorAll('.delete-folder-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
          e.stopPropagation();
          const fid = btn.getAttribute('data-id');
          if (confirm('Delete this folder and its files?')) {
            await fetch(`/api/folders/${fid}`, {
              method: 'DELETE',
              headers: { 'Authorization': `Bearer ${getAuthToken()}` }
            });
            showToast('Folder deleted');
            loadContent();
          }
        });
      });
      lucide.createIcons();
    }

    function renderFiles(files) {
      const container = document.getElementById('filesGrid');
      const emptyContainer = document.getElementById('emptyContainer');
      const filesCount = document.getElementById('filesCount');
      const filesSection = document.getElementById('filesSection');

      filesCount.textContent = `${files.length} items`;
      container.innerHTML = '';

      const foldersCount = document.querySelectorAll('#foldersGrid > div').length;
      if (!files.length && !foldersCount) {
        emptyContainer.classList.remove('hidden');
        filesSection.classList.add('hidden');
        return;
      }
      emptyContainer.classList.add('hidden');
      filesSection.classList.remove('hidden');

      files.forEach((f, idx) => {
        const card = document.createElement('div');
        card.className = 'ios-card rounded-2xl p-3 flex flex-col justify-between group card-animate';
        card.style.animationDelay = `${idx * 0.03}s`;
        
        let typeIcon = 'file';
        let badgeColor = 'bg-white/10 text-white/70';
        if (f.media_type === 'video') { typeIcon = 'video'; badgeColor = 'bg-purple-500/20 text-purple-300'; }
        else if (f.media_type === 'audio') { typeIcon = 'music'; badgeColor = 'bg-emerald-500/20 text-emerald-300'; }
        else if (f.media_type === 'image') { typeIcon = 'image'; badgeColor = 'bg-amber-500/20 text-amber-300'; }

        const directLink = `${window.location.origin}${f.direct_link}`;

        card.innerHTML = `
          <div>
            <!-- Thumbnail / Header -->
            <div class="h-28 rounded-xl bg-black/40 border border-white/[0.04] mb-2.5 overflow-hidden relative flex items-center justify-center cursor-pointer open-file" data-id="${f.message_id}">
              ${f.media_type === 'image' || f.media_type === 'video' ? `
                <img src="${f.thumb_url}" class="w-full h-full object-cover group-hover:scale-105 transition duration-300" onerror="this.style.display='none'">
              ` : ''}
              <div class="absolute w-10 h-10 rounded-full bg-white/10 backdrop-blur-md flex items-center justify-center text-white/80 group-hover:scale-110 transition">
                <i data-lucide="${f.media_type === 'video' ? 'play' : typeIcon}" class="w-4 h-4 ${f.media_type === 'video' ? 'ml-0.5' : ''}"></i>
              </div>
            </div>

            <div class="flex items-center justify-between gap-2 mb-1">
              <span class="text-[9px] uppercase px-1.5 py-0.5 rounded font-mono font-semibold ${badgeColor}">
                ${f.media_type}
              </span>
              <span class="text-[11px] font-mono text-white/40">${f.size_formatted}</span>
            </div>

            <h4 class="text-xs font-medium text-white/90 truncate group-hover:text-blue-400 transition" title="${f.name}">
              ${f.name}
            </h4>
          </div>

          <!-- Bottom Actions -->
          <div class="mt-3 pt-2 border-t border-white/[0.06] flex items-center justify-between">
            <button class="open-file text-[11px] font-medium text-blue-400 hover:text-blue-300 flex items-center gap-1" data-id="${f.message_id}">
              <i data-lucide="play-circle" class="w-3.5 h-3.5"></i>
              <span>Open</span>
            </button>

            <div class="flex items-center gap-1">
              <button class="copy-cdn-btn ios-button p-1.5 rounded-lg text-white/50 hover:text-blue-400" data-link="${directLink}" title="Copy Direct CDN Link">
                <i data-lucide="link-2" class="w-3.5 h-3.5"></i>
              </button>
              <a href="${f.download_url}" download class="ios-button p-1.5 rounded-lg text-white/50 hover:text-white" title="Download">
                <i data-lucide="download" class="w-3.5 h-3.5"></i>
              </a>
              <button class="delete-file-btn ios-button p-1.5 rounded-lg text-white/30 hover:text-red-400" data-id="${f.message_id}" title="Delete">
                <i data-lucide="trash-2" class="w-3.5 h-3.5"></i>
              </button>
            </div>
          </div>
        `;

        container.appendChild(card);
      });

      // Bind Open / Play
      document.querySelectorAll('.open-file').forEach(el => {
        el.addEventListener('click', () => {
          const mid = parseInt(el.getAttribute('data-id'));
          openPlayer(mid);
        });
      });

      // Bind Direct CDN Copy
      document.querySelectorAll('.copy-cdn-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
          e.stopPropagation();
          const link = btn.getAttribute('data-link');
          navigator.clipboard.writeText(link);
          showToast('Direct CDN link copied!');
        });
      });

      // Bind Delete File
      document.querySelectorAll('.delete-file-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
          e.stopPropagation();
          const mid = btn.getAttribute('data-id');
          if (confirm('Delete this file from your anonc storage?')) {
            await fetch(`/api/files/${mid}`, {
              method: 'DELETE',
              headers: { 'Authorization': `Bearer ${getAuthToken()}` }
            });
            showToast('File deleted');
            loadFiles();
            checkAuth();
          }
        });
      });

      lucide.createIcons();
    }

    function navigateToFolder(fid) {
      currentFolderId = fid;
      loadContent();
    }

    // Player Modal
    function openPlayer(messageId) {
      const file = currentFiles.find(f => f.message_id === messageId);
      if (!file) return;

      const modal = document.getElementById('playerModal');
      const body = document.getElementById('playerBody');
      const name = document.getElementById('playerFilename');
      const download = document.getElementById('playerDownloadBtn');
      const copyCdn = document.getElementById('playerCopyCdnBtn');

      name.textContent = `${file.name} (${file.size_formatted})`;
      download.href = file.download_url;
      directCdnUrl = `${window.location.origin}${file.direct_link}`;

      body.innerHTML = '';
      body.className = 'p-4 flex items-center justify-center bg-black min-h-[300px]';
      if (file.media_type === 'video') {
        const video = document.createElement('video');
        video.controls = true;
        video.autoplay = true;
        video.playsInline = true;
        video.preload = 'auto';
        video.className = 'w-full max-h-[70vh] rounded-xl outline-none';
        video.src = file.stream_url;
        body.appendChild(video);
      } else if (file.media_type === 'audio') {
        body.className = 'bg-black p-12 flex flex-col items-center justify-center gap-6';
        body.innerHTML = `
          <div class="w-20 h-20 rounded-2xl bg-blue-500/20 flex items-center justify-center text-blue-400">
            <i data-lucide="music" class="w-10 h-10"></i>
          </div>
          <audio controls autoplay preload="auto" class="w-full max-w-md outline-none" src="${file.stream_url}"></audio>
        `;
      } else if (file.media_type === 'image') {
        const img = document.createElement('img');
        img.className = 'max-w-full max-h-[70vh] object-contain';
        img.src = file.stream_url;
        body.appendChild(img);
      } else {
        body.innerHTML = `
          <div class="p-10 text-center">
            <i data-lucide="file-text" class="w-12 h-12 text-white/30 mx-auto mb-3"></i>
            <p class="text-xs text-white/60 mb-4">Preview not available for this document format.</p>
            <a href="${file.download_url}" download class="ios-button-blue text-xs font-semibold px-4 py-2 rounded-xl text-white inline-flex items-center gap-1.5">
              <i data-lucide="download" class="w-3.5 h-3.5"></i> Download File
            </a>
          </div>
        `;
      }

      modal.classList.remove('hidden');
      lucide.createIcons();
    }

    document.getElementById('playerCopyCdnBtn').addEventListener('click', () => {
      if (directCdnUrl) {
        navigator.clipboard.writeText(directCdnUrl);
        showToast('Direct CDN link copied!');
      }
    });

    document.getElementById('closePlayerBtn').addEventListener('click', () => {
      document.getElementById('playerBody').innerHTML = '';
      document.getElementById('playerModal').classList.add('hidden');
    });

    // Upload files
    const filePicker = document.getElementById('filePicker');
    document.getElementById('uploadTriggerBtn').addEventListener('click', () => filePicker.click());

    filePicker.addEventListener('change', () => {
      if (filePicker.files.length) uploadFileList(filePicker.files);
    });

    window.addEventListener('dragover', (e) => e.preventDefault());
    window.addEventListener('drop', (e) => {
      e.preventDefault();
      if (e.dataTransfer.files.length) uploadFileList(e.dataTransfer.files);
    });

    // Cancel Upload Button Listener
    document.getElementById('cancelUploadBtn').addEventListener('click', async () => {
      isUploadCancelled = true;
      if (currentUploadXhr) {
        currentUploadXhr.abort();
      }
      if (currentTaskId) {
        try {
          await fetch(`/api/upload/cancel?task_id=${currentTaskId}`, { method: 'POST' });
        } catch (e) {}
      }
      showToast('Upload cancelled', false);
      const banner = document.getElementById('uploadBanner');
      banner.classList.add('hidden');
      filePicker.value = '';
    });

    // Fast Upload with Real-Time Progress Polling & Cancellation
    async function uploadFileList(files) {
      const banner = document.getElementById('uploadBanner');
      const bar = document.getElementById('uploadBar');
      const name = document.getElementById('uploadFileName');
      const percent = document.getElementById('uploadPercent');
      const stageText = document.getElementById('uploadStageText');
      const speedText = document.getElementById('uploadSpeedText');

      isUploadCancelled = false;
      banner.classList.remove('hidden');

      for (let i = 0; i < files.length; i++) {
        if (isUploadCancelled) break;

        const file = files[i];
        name.textContent = `${file.name} (${i + 1}/${files.length})`;
        stageText.textContent = 'Buffering & encrypting...';
        speedText.textContent = '0%';
        bar.style.width = '0%';
        percent.textContent = '0%';

        const formData = new FormData();
        formData.append('folder_id', currentFolderId);
        formData.append('file', file);

        try {
          // Stage 1: Send file from browser to server
          const uploadRes = await new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest();
            currentUploadXhr = xhr;
            xhr.open('POST', '/api/upload', true);
            xhr.setRequestHeader('Authorization', `Bearer ${getAuthToken()}`);
            xhr.upload.onprogress = (e) => {
              if (isUploadCancelled) {
                xhr.abort();
                return;
              }
              if (e.lengthComputable) {
                const p = Math.round((e.loaded / e.total) * 100);
                bar.style.width = `${Math.min(p, 98)}%`;
                percent.textContent = `${p}%`;
                stageText.textContent = `Buffering (${formatBytes(e.loaded)} / ${formatBytes(e.total)})`;
              }
            };
            xhr.onload = () => {
              if (xhr.status === 200) {
                try {
                  resolve(JSON.parse(xhr.responseText));
                } catch (err) {
                  reject(new Error('Invalid response'));
                }
              } else {
                reject(new Error(xhr.responseText || 'Upload failed'));
              }
            };
            xhr.onerror = () => reject(new Error('Network error uploading file'));
            xhr.onabort = () => reject(new Error('Upload cancelled'));
            xhr.send(formData);
          });

          if (isUploadCancelled) break;

          currentTaskId = uploadRes.task_id;
          if (!currentTaskId) throw new Error('No task ID returned');

          // Stage 2: Track cloud vault save progress via polling
          stageText.textContent = 'Saving to anonc cloud vault...';
          bar.style.width = '0%';
          percent.textContent = '0%';

          let completed = false;
          while (!completed && !isUploadCancelled) {
            await new Promise(r => setTimeout(r, 500));
            if (isUploadCancelled) break;

            const progRes = await fetch(`/api/upload/progress?task_id=${currentTaskId}`);
            if (!progRes.ok) break;
            const progData = await progRes.json();

            if (progData.status === 'saving_to_cloud') {
              const p = progData.percent || 0;
              bar.style.width = `${p}%`;
              percent.textContent = `${p}%`;
              stageText.textContent = `Cloud: ${progData.formatted || ''}`;
              speedText.textContent = progData.speed || '';
            } else if (progData.status === 'completed') {
              completed = true;
              bar.style.width = '100%';
              percent.textContent = '100%';
              stageText.textContent = 'Saved to your private vault!';
              speedText.textContent = 'Done';
            } else if (progData.status === 'cancelled') {
              break;
            } else if (progData.status === 'error') {
              throw new Error(progData.error || 'Upload failed');
            }
          }

        } catch (err) {
          if (!isUploadCancelled) {
            alert('Upload error: ' + err.message);
            stageText.textContent = 'Error: ' + err.message;
          }
        } finally {
          currentUploadXhr = null;
          currentTaskId = null;
        }
      }

      if (!isUploadCancelled) {
        showToast('All files saved to anonc cloud!');
        checkAuth();
      }

      setTimeout(() => {
        banner.classList.add('hidden');
        bar.style.width = '0%';
        filePicker.value = '';
        loadFiles();
      }, 1000);
    }

    function formatBytes(bytes) {
      if (!bytes || bytes <= 0) return '0 B';
      const k = 1024;
      const sizes = ['B', 'KB', 'MB', 'GB'];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    // New Folder Modal
    const folderModal = document.getElementById('folderModal');
    const folderNameInput = document.getElementById('folderNameInput');
    document.getElementById('newFolderBtn').addEventListener('click', () => {
      folderNameInput.value = '';
      folderModal.classList.remove('hidden');
      folderNameInput.focus();
    });
    document.getElementById('cancelFolderBtn').addEventListener('click', () => folderModal.classList.add('hidden'));

    document.getElementById('createFolderSubmitBtn').addEventListener('click', async () => {
      const name = folderNameInput.value.trim();
      if (!name) return;
      await fetch('/api/folders', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${getAuthToken()}`
        },
        body: JSON.stringify({ name, parent_id: currentFolderId })
      });
      folderModal.classList.add('hidden');
      showToast('Folder created');
      loadFolders();
      checkAuth();
    });

    // Filters
    document.querySelectorAll('.filter-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.filter-btn').forEach(b => {
          b.classList.remove('active', 'bg-blue-500', 'text-white');
          b.classList.add('text-white/60');
        });
        btn.classList.add('active', 'bg-blue-500', 'text-white');
        btn.classList.remove('text-white/60');
        currentFilter = btn.getAttribute('data-filter');
        loadFiles();
      });
    });

    document.getElementById('searchInput').addEventListener('input', () => loadFiles());

    // Settings Modal Tabs & Switcher
    const settingsModal = document.getElementById('settingsModal');
    document.getElementById('userSettingsBtn').addEventListener('click', () => {
      checkAuth();
      settingsModal.classList.remove('hidden');
    });
    document.getElementById('closeSettingsBtn').addEventListener('click', () => settingsModal.classList.add('hidden'));

    document.querySelectorAll('.settings-tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const tab = btn.getAttribute('data-tab');
        document.querySelectorAll('.settings-tab-btn').forEach(b => {
          b.classList.remove('text-blue-400', 'border-blue-500');
          b.classList.add('text-white/40', 'border-transparent');
        });
        btn.classList.add('text-blue-400', 'border-blue-500');
        btn.classList.remove('text-white/40', 'border-transparent');

        document.getElementById('paneProfile').classList.add('hidden');
        document.getElementById('paneSecurity').classList.add('hidden');
        document.getElementById('paneCloud').classList.add('hidden');

        if (tab === 'profile') document.getElementById('paneProfile').classList.remove('hidden');
        else if (tab === 'security') document.getElementById('paneSecurity').classList.remove('hidden');
        else if (tab === 'cloud') document.getElementById('paneCloud').classList.remove('hidden');
      });
    });

    // Cloud Profile Picture (PFP) Upload & Removal Listeners
    const avatarUploadTrigger = document.getElementById('avatarUploadTrigger');
    const avatarFileInput = document.getElementById('avatarFileInput');
    const chooseAvatarBtn = document.getElementById('chooseAvatarBtn');
    const removeAvatarBtn = document.getElementById('removeAvatarBtn');
    const avatarSpinner = document.getElementById('avatarLoadingSpinner');

    if (avatarUploadTrigger && avatarFileInput) {
      avatarUploadTrigger.addEventListener('click', () => avatarFileInput.click());
    }
    if (chooseAvatarBtn && avatarFileInput) {
      chooseAvatarBtn.addEventListener('click', () => avatarFileInput.click());
    }

    if (avatarFileInput) {
      avatarFileInput.addEventListener('change', async () => {
        const file = avatarFileInput.files[0];
        if (!file) return;

        if (file.size > 5 * 1024 * 1024) {
          showToast('Image must be under 5MB');
          avatarFileInput.value = '';
          return;
        }

        if (avatarSpinner) avatarSpinner.classList.remove('hidden');
        const formData = new FormData();
        formData.append('avatar', file);

        try {
          const res = await fetch('/api/user/avatar', {
            method: 'POST',
            headers: {
              'Authorization': `Bearer ${getAuthToken()}`
            },
            body: formData
          });

          const data = await res.json();
          if (!res.ok) throw new Error(data.detail || 'Failed to upload profile photo');

          if (currentUser) {
            currentUser.avatar_url = data.avatar_url;
            currentUser.avatar_msg_id = data.avatar_msg_id;
            updateUserDisplay(currentUser);
          }
          showToast('Profile photo updated & synced to cloud!');
        } catch (err) {
          showToast(err.message || 'Avatar upload failed');
        } finally {
          if (avatarSpinner) avatarSpinner.classList.add('hidden');
          avatarFileInput.value = '';
        }
      });
    }

    if (removeAvatarBtn) {
      removeAvatarBtn.addEventListener('click', async () => {
        if (!confirm('Remove profile photo and reset to default?')) return;
        if (avatarSpinner) avatarSpinner.classList.remove('hidden');

        try {
          const res = await fetch('/api/user/avatar', {
            method: 'DELETE',
            headers: {
              'Authorization': `Bearer ${getAuthToken()}`
            }
          });

          const data = await res.json();
          if (!res.ok) throw new Error(data.detail || 'Failed to remove photo');

          if (currentUser) {
            currentUser.avatar_url = null;
            currentUser.avatar_msg_id = null;
            updateUserDisplay(currentUser);
          }
          showToast('Profile photo removed');
        } catch (err) {
          showToast(err.message || 'Failed to remove photo');
        } finally {
          if (avatarSpinner) avatarSpinner.classList.add('hidden');
        }
      });
    }

    // Preferences Toggle Switches Listener
    document.querySelectorAll('.ios-switch').forEach(sw => {
      sw.addEventListener('click', async () => {
        sw.classList.toggle('active');
        const prefKey = sw.getAttribute('data-pref');
        const isActive = sw.classList.contains('active');
        if (currentUser) {
          if (!currentUser.settings) currentUser.settings = {};
          currentUser.settings[prefKey] = isActive;
          // Sync setting in background
          try {
            await fetch('/api/user/settings', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${getAuthToken()}`
              },
              body: JSON.stringify({ settings: { [prefKey]: isActive } })
            });
          } catch (e) {}
        }
      });
    });

    // Save Profile to Cloud
    document.getElementById('saveProfileBtn').addEventListener('click', async () => {
      const btn = document.getElementById('saveProfileBtn');
      const msg = document.getElementById('profileMsg');
      const displayName = document.getElementById('editDisplayNameInput').value.trim();
      const username = document.getElementById('editUsernameInput').value.trim();

      btn.disabled = true;
      btn.innerHTML = `<div class="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div> <span>Syncing to Cloud...</span>`;
      msg.classList.add('hidden');

      try {
        const res = await fetch('/api/user/settings', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${getAuthToken()}`
          },
          body: JSON.stringify({
            display_name: displayName,
            username: username
          })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Failed to update profile');

        currentUser = data.user;
        updateUserDisplay(currentUser);
        msg.textContent = 'Profile updated and synchronized to cloud!';
        msg.className = 'p-2.5 rounded-xl text-xs text-center bg-emerald-500/15 text-emerald-400 border border-emerald-500/20';
        msg.classList.remove('hidden');
        showToast('Profile synced to cloud!');
      } catch (err) {
        msg.textContent = err.message;
        msg.className = 'p-2.5 rounded-xl text-xs text-center bg-red-500/15 text-red-400 border border-red-500/20';
        msg.classList.remove('hidden');
      } finally {
        btn.disabled = false;
        btn.innerHTML = `<i data-lucide="cloud" class="w-3.5 h-3.5"></i> <span>Save Profile to Cloud</span>`;
        lucide.createIcons();
      }
    });

    // Update Password in Cloud
    document.getElementById('savePasswordBtn').addEventListener('click', async () => {
      const btn = document.getElementById('savePasswordBtn');
      const msg = document.getElementById('securityMsg');
      const currPwd = document.getElementById('editCurrentPasswordInput').value.trim();
      const newPwd = document.getElementById('editNewPasswordInput').value.trim();
      const confirmPwd = document.getElementById('editConfirmPasswordInput').value.trim();

      if (!currPwd) {
        msg.textContent = 'Please enter your current password.';
        msg.className = 'p-2.5 rounded-xl text-xs text-center bg-red-500/15 text-red-400 border border-red-500/20';
        msg.classList.remove('hidden');
        return;
      }
      if (!newPwd || newPwd.length < 4) {
        msg.textContent = 'New password must be at least 4 characters.';
        msg.className = 'p-2.5 rounded-xl text-xs text-center bg-red-500/15 text-red-400 border border-red-500/20';
        msg.classList.remove('hidden');
        return;
      }
      if (newPwd !== confirmPwd) {
        msg.textContent = 'New passwords do not match.';
        msg.className = 'p-2.5 rounded-xl text-xs text-center bg-red-500/15 text-red-400 border border-red-500/20';
        msg.classList.remove('hidden');
        return;
      }

      btn.disabled = true;
      btn.innerHTML = `<div class="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div> <span>Updating in Cloud...</span>`;
      msg.classList.add('hidden');

      try {
        const res = await fetch('/api/user/settings', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${getAuthToken()}`
          },
          body: JSON.stringify({
            current_password: currPwd,
            new_password: newPwd
          })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Password update failed');

        document.getElementById('editCurrentPasswordInput').value = '';
        document.getElementById('editNewPasswordInput').value = '';
        document.getElementById('editConfirmPasswordInput').value = '';

        msg.textContent = 'Password updated and synchronized in cloud database!';
        msg.className = 'p-2.5 rounded-xl text-xs text-center bg-emerald-500/15 text-emerald-400 border border-emerald-500/20';
        msg.classList.remove('hidden');
        showToast('Password updated!');
      } catch (err) {
        msg.textContent = err.message;
        msg.className = 'p-2.5 rounded-xl text-xs text-center bg-red-500/15 text-red-400 border border-red-500/20';
        msg.classList.remove('hidden');
      } finally {
        btn.disabled = false;
        btn.innerHTML = `<i data-lucide="key-round" class="w-3.5 h-3.5"></i> <span>Update Password</span>`;
        lucide.createIcons();
      }
    });

    document.getElementById('logoutBtn').addEventListener('click', async () => {
      if (confirm('Sign out from anonc by ascloud?')) {
        await fetch('/api/user/logout', {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${getAuthToken()}` }
        });
        setAuthToken(null);
        location.reload();
      }
    });

    // Auth Modal Tabs & Submit
    const tabSignIn = document.getElementById('tabSignIn');
    const tabSignUp = document.getElementById('tabSignUp');
    const authSubmitBtn = document.getElementById('authSubmitBtn');
    const authError = document.getElementById('authError');
    const authUsernameInput = document.getElementById('authUsernameInput');
    const authPasswordInput = document.getElementById('authPasswordInput');

    tabSignIn.addEventListener('click', () => {
      authMode = 'login';
      tabSignIn.classList.add('bg-blue-500', 'text-white');
      tabSignIn.classList.remove('text-white/50');
      tabSignUp.classList.remove('bg-blue-500', 'text-white');
      tabSignUp.classList.add('text-white/50');
      authSubmitBtn.textContent = 'Sign In';
      authError.classList.add('hidden');
    });

    tabSignUp.addEventListener('click', () => {
      authMode = 'register';
      tabSignUp.classList.add('bg-blue-500', 'text-white');
      tabSignUp.classList.remove('text-white/50');
      tabSignIn.classList.remove('bg-blue-500', 'text-white');
      tabSignIn.classList.add('text-white/50');
      authSubmitBtn.textContent = 'Create Account';
      authError.classList.add('hidden');
    });

    authSubmitBtn.addEventListener('click', async () => {
      const username = authUsernameInput.value.trim();
      const password = authPasswordInput.value.trim();
      if (!username || !password) {
        authError.textContent = 'Please enter both username and password.';
        authError.classList.remove('hidden');
        return;
      }

      authSubmitBtn.disabled = true;
      authSubmitBtn.textContent = 'Processing...';
      authError.classList.add('hidden');

      const endpoint = authMode === 'register' ? '/api/user/register' : '/api/user/login';
      try {
        const res = await fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Authentication failed');

        setAuthToken(data.token);
        document.getElementById('authModal').classList.add('hidden');
        showToast(authMode === 'register' ? 'Account created! Welcome.' : 'Signed in successfully!');
        checkAuth();
      } catch (err) {
        authError.textContent = err.message;
        authError.classList.remove('hidden');
      } finally {
        authSubmitBtn.disabled = false;
        authSubmitBtn.textContent = authMode === 'register' ? 'Create Account' : 'Sign In';
      }
    });

    document.getElementById('openAuthModalBtn').addEventListener('click', () => {
      document.getElementById('authModal').classList.remove('hidden');
    });

    // Init App
    checkAuth();
    lucide.createIcons();
  </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def serve_index():
    return HTMLResponse(content=HTML_PAGE)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("index:app", host="127.0.0.1", port=8000, reload=True)
