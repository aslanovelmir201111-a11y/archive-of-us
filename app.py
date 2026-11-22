import os
import sys
import time
import re
import uuid
import secrets
import hashlib
import hmac
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Tuple
from contextlib import contextmanager, asynccontextmanager

from fastapi import (
    FastAPI,
    Request,
    Response,
    Depends,
    HTTPException,
    UploadFile,
    File,
    status
)
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

# ==========================================
# 1. QOVLUQ VƏ KONFİQURASİYA YOLLARI
# ==========================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "archive.db")
STATIC_DIR = os.path.join(BASE_DIR, "static")
UPLOADS_DIR = os.path.join(BASE_DIR, "uploads")

os.makedirs(STATIC_DIR, exist_ok=True)
os.makedirs(UPLOADS_DIR, exist_ok=True)


# ==========================================
# 2. TƏHLÜKƏSİZLİK VƏ AUTENTİFİKASİYA (AUTH)
# ==========================================
_failed_attempts: dict[str, list[float]] = {}
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = 900  # 15 dəqiqə bloklanma (saniyə ilə)
WINDOW_DURATION = 300   # 5 dəqiqə ərzindəki cəhdlər


def hash_password(password: str) -> str:
    """Parolu 100,000 iterasiyalı PBKDF2-HMAC-SHA256 və 16-baytlıq təsadüfi duz ilə heşləyir."""
    salt = secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return f"{salt.hex()}${key.hex()}"


def verify_password(password: str, hashed: str) -> bool:
    """Təhlükəsiz zaman-müstəqil (constant-time) müqayisə ilə parolu yoxlayır."""
    try:
        salt_hex, key_hex = hashed.split("$")
        salt = bytes.fromhex(salt_hex)
        expected_key = bytes.fromhex(key_hex)
        key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
        return hmac.compare_digest(key, expected_key)
    except Exception:
        return False


def check_rate_limit(client_ip: str) -> Tuple[bool, int]:
    """
    Brute-force hücumlarına qarşı yoxlama.
    Qaytarır: (bloklanıb?, neçə saniyə qalıb)
    """
    now = time.time()
    attempts = _failed_attempts.get(client_ip, [])

    recent_attempts = [t for t in attempts if now - t < LOCKOUT_DURATION]
    _failed_attempts[client_ip] = recent_attempts

    short_window_attempts = [t for t in recent_attempts if now - t < WINDOW_DURATION]
    if len(short_window_attempts) >= MAX_FAILED_ATTEMPTS:
        time_since_last = now - short_window_attempts[-1]
        remaining = int(LOCKOUT_DURATION - time_since_last)
        if remaining > 0:
            return True, remaining

    return False, 0


def record_failed_attempt(client_ip: str):
    now = time.time()
    if client_ip not in _failed_attempts:
        _failed_attempts[client_ip] = []
    _failed_attempts[client_ip].append(now)


def clear_failed_attempts(client_ip: str):
    if client_ip in _failed_attempts:
        del _failed_attempts[client_ip]


def generate_session_token() -> str:
    """256-bit kriptoqrafik təhlükəsiz unikal token."""
    return secrets.token_urlsafe(32)


# ==========================================
# 3. VERİLƏNLƏR BAZASI (SQLITE) MODULU
# ==========================================
STARTER_CHRONICLES = [
    {
        "title": "The Beginning",
        "date": "September 2026",
        "memory": "The first chapter of our story. A beginning that became part of our history.",
        "moment": "The day we started calling this 'us'.",
        "future": "Remember how a whole story began with one day.",
        "is_starter": 1
    },
    {
        "title": "Becoming",
        "date": "October 2026",
        "memory": "A month of learning each other a little more, collecting moments and making this story our own.",
        "moment": "Add the moment you never want to forget.",
        "future": "I hope we are still finding new reasons to choose this story.",
        "is_starter": 1
    },
    {
        "title": "Unwritten",
        "date": "November 2026",
        "memory": "This chapter is still being written.",
        "moment": "Leave this space for a memory from this month.",
        "future": "May we never stop making memories worth keeping.",
        "is_starter": 1
    },
    {
        "title": "A Sealed Chapter",
        "date": "December 2026",
        "memory": "A page reserved for the days still ahead.",
        "moment": "To be written when the month has passed.",
        "future": "We'll meet this chapter when it becomes a memory.",
        "is_starter": 1
    }
]

STARTER_CATALOGUE = [
    {
        "title": "The little things",
        "body": "Favourite phrases, familiar habits, tiny details and all the things that might seem ordinary to anyone else.",
        "is_starter": 1
    },
    {
        "title": "Our discoveries",
        "body": "Places, songs, jokes and new things we find along the way.",
        "is_starter": 1
    }
]


@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with get_db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS chronicles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            date TEXT NOT NULL,
            memory TEXT NOT NULL,
            moment TEXT DEFAULT '',
            future TEXT DEFAULT '',
            is_starter INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS catalogue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            is_starter INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS letters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            open_date TEXT NOT NULL,
            hint TEXT DEFAULT '',
            body TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS favorites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            sender TEXT DEFAULT '',
            date TEXT DEFAULT '',
            body TEXT NOT NULL,
            image_url TEXT DEFAULT '',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS nights (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            date TEXT DEFAULT '',
            photo_url TEXT DEFAULT '',
            note TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS matching_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT DEFAULT '',
            song TEXT DEFAULT '',
            mine TEXT NOT NULL,
            theirs TEXT NOT NULL,
            detail TEXT DEFAULT '',
            image_url TEXT DEFAULT '',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS todos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            text TEXT NOT NULL,
            done INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        );
        """)

        # İlkin arxiv şifrəsi: 210826 (PBKDF2 heşi olaraq saxlanılır)
        row = conn.execute("SELECT value FROM settings WHERE key = 'access_code_hash'").fetchone()
        if not row:
            default_hash = hash_password("210826")
            conn.execute("INSERT INTO settings (key, value) VALUES ('access_code_hash', ?)", (default_hash,))

        # Münasibət başlanğıc tarixi: August 21, 2026
        row_date = conn.execute("SELECT value FROM settings WHERE key = 'relationship_start'").fetchone()
        if not row_date:
            conn.execute("INSERT INTO settings (key, value) VALUES ('relationship_start', '2026-08-21T00:00:00')")

        # İlkin fəsillər
        chron_count = conn.execute("SELECT COUNT(*) FROM chronicles").fetchone()[0]
        if chron_count == 0:
            now_iso = datetime.now(timezone.utc).isoformat()
            for ch in STARTER_CHRONICLES:
                conn.execute(
                    "INSERT INTO chronicles (title, date, memory, moment, future, is_starter, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (ch["title"], ch["date"], ch["memory"], ch["moment"], ch["future"], ch["is_starter"], now_iso)
                )

        # İlkin kataloq qeydləri
        cat_count = conn.execute("SELECT COUNT(*) FROM catalogue").fetchone()[0]
        if cat_count == 0:
            now_iso = datetime.now(timezone.utc).isoformat()
            for ct in STARTER_CATALOGUE:
                conn.execute(
                    "INSERT INTO catalogue (title, body, is_starter, created_at) VALUES (?, ?, ?, ?)",
                    (ct["title"], ct["body"], ct["is_starter"], now_iso)
                )


def get_setting(key: str) -> str:
    with get_db() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else ""


def set_setting(key: str, value: str):
    with get_db() as conn:
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))


# --- Real-time Canlı Sinxronizasiya Versiyası ---
_current_data_version: float = time.time()


def bump_data_version():
    global _current_data_version
    _current_data_version = time.time()


def get_data_version() -> float:
    return _current_data_version


def create_session(token: str, days: int = 30) -> str:
    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=days)
    with get_db() as conn:
        conn.execute(
            "INSERT INTO sessions (token, created_at, expires_at) VALUES (?, ?, ?)",
            (token, now.isoformat(), expires.isoformat())
        )
    return token


def validate_session(token: str) -> bool:
    if not token:
        return False
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        row = conn.execute(
            "SELECT 1 FROM sessions WHERE token = ? AND expires_at > ?",
            (token, now_iso)
        ).fetchone()
        return bool(row)


def delete_session(token: str):
    with get_db() as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))


def cleanup_expired_sessions():
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (now_iso,))


def get_chronicles():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM chronicles ORDER BY id ASC").fetchall()
        return [dict(r) for r in rows]


def add_chronicle(title: str, date: str, memory: str, moment: str = "", future: str = ""):
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO chronicles (title, date, memory, moment, future, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (title, date, memory, moment, future, now_iso)
        )
        bump_data_version()
        return cur.lastrowid


def delete_chronicle(chronicle_id: int):
    with get_db() as conn:
        conn.execute("DELETE FROM chronicles WHERE id = ?", (chronicle_id,))
        bump_data_version()


def get_catalogue():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM catalogue ORDER BY id ASC").fetchall()
        return [dict(r) for r in rows]


def add_catalogue(title: str, body: str):
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO catalogue (title, body, created_at) VALUES (?, ?, ?)",
            (title, body, now_iso)
        )
        bump_data_version()
        return cur.lastrowid


def delete_catalogue(item_id: int):
    with get_db() as conn:
        conn.execute("DELETE FROM catalogue WHERE id = ?", (item_id,))
        bump_data_version()


def get_letters(include_sealed_bodies: bool = False):
    """
    Təhlükəsizlik: include_sealed_bodies False olduqda, əgər məktubun tarixi bugünkü server
    tarixindən irəlidədirsə, onun 'body' sahəsi mütləq gizlədilir!
    """
    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM letters ORDER BY open_date ASC").fetchall()
        result = []
        for r in rows:
            d = dict(r)
            is_unlocked = (d["open_date"] <= today_str)
            d["opened"] = is_unlocked
            if not is_unlocked and not include_sealed_bodies:
                d["body"] = None
            result.append(d)
        return result


def add_letter(title: str, open_date: str, hint: str, body: str):
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO letters (title, open_date, hint, body, created_at) VALUES (?, ?, ?, ?, ?)",
            (title, open_date, hint, body, now_iso)
        )
        bump_data_version()
        return cur.lastrowid


def delete_letter(letter_id: int):
    with get_db() as conn:
        conn.execute("DELETE FROM letters WHERE id = ?", (letter_id,))
        bump_data_version()


def get_favorites():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM favorites ORDER BY id DESC").fetchall()
        return [dict(r) for r in rows]


def add_favorite(title: str, sender: str, date: str, body: str, image_url: str = ""):
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO favorites (title, sender, date, body, image_url, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (title, sender, date, body, image_url, now_iso)
        )
        bump_data_version()
        return cur.lastrowid


def delete_favorite(item_id: int):
    with get_db() as conn:
        conn.execute("DELETE FROM favorites WHERE id = ?", (item_id,))
        bump_data_version()


def get_nights():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM nights ORDER BY id DESC").fetchall()
        return [dict(r) for r in rows]


def add_night(title: str, date: str, photo_url: str, note: str):
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO nights (title, date, photo_url, note, created_at) VALUES (?, ?, ?, ?, ?)",
            (title, date, photo_url, note, now_iso)
        )
        bump_data_version()
        return cur.lastrowid


def delete_night(item_id: int):
    with get_db() as conn:
        conn.execute("DELETE FROM nights WHERE id = ?", (item_id,))
        bump_data_version()


def get_matching():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM matching_notes ORDER BY id DESC").fetchall()
        return [dict(r) for r in rows]


def add_matching(date: str, song: str, mine: str, theirs: str, detail: str = "", image_url: str = ""):
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO matching_notes (date, song, mine, theirs, detail, image_url, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (date, song, mine, theirs, detail, image_url, now_iso)
        )
        bump_data_version()
        return cur.lastrowid


def delete_matching(item_id: int):
    with get_db() as conn:
        conn.execute("DELETE FROM matching_notes WHERE id = ?", (item_id,))
        bump_data_version()


def get_todos():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM todos ORDER BY id ASC").fetchall()
        return [dict(r) for r in rows]


def add_todo(text: str):
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO todos (text, done, created_at) VALUES (?, 0, ?)",
            (text, now_iso)
        )
        bump_data_version()
        return cur.lastrowid


def toggle_todo(todo_id: int, done: bool):
    with get_db() as conn:
        conn.execute("UPDATE todos SET done = ? WHERE id = ?", (1 if done else 0, todo_id))
        bump_data_version()


def delete_todo(todo_id: int):
    with get_db() as conn:
        conn.execute("DELETE FROM todos WHERE id = ?", (todo_id,))
        bump_data_version()


def export_all_data() -> dict:
    with get_db() as conn:
        return {
            "chronicles": [dict(r) for r in conn.execute("SELECT * FROM chronicles").fetchall()],
            "catalogue": [dict(r) for r in conn.execute("SELECT * FROM catalogue").fetchall()],
            "letters": [dict(r) for r in conn.execute("SELECT * FROM letters").fetchall()],
            "favorites": [dict(r) for r in conn.execute("SELECT * FROM favorites").fetchall()],
            "nights": [dict(r) for r in conn.execute("SELECT * FROM nights").fetchall()],
            "matchingNotes": [dict(r) for r in conn.execute("SELECT * FROM matching_notes").fetchall()],
            "todos": [dict(r) for r in conn.execute("SELECT * FROM todos").fetchall()]
        }


def import_all_data(data: dict):
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        if "chronicles" in data and isinstance(data["chronicles"], list):
            conn.execute("DELETE FROM chronicles")
            for ch in data["chronicles"]:
                conn.execute(
                    "INSERT INTO chronicles (title, date, memory, moment, future, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (ch.get("title", ""), ch.get("date", ""), ch.get("memory", ""), ch.get("moment", ""), ch.get("future", ""), now_iso)
                )

        if "catalogue" in data and isinstance(data["catalogue"], list):
            conn.execute("DELETE FROM catalogue")
            for ct in data["catalogue"]:
                conn.execute(
                    "INSERT INTO catalogue (title, body, created_at) VALUES (?, ?, ?)",
                    (ct.get("title", ""), ct.get("body", ""), now_iso)
                )

        if "letters" in data and isinstance(data["letters"], list):
            conn.execute("DELETE FROM letters")
            for lt in data["letters"]:
                conn.execute(
                    "INSERT INTO letters (title, open_date, hint, body, created_at) VALUES (?, ?, ?, ?, ?)",
                    (lt.get("title", ""), lt.get("date") or lt.get("open_date", ""), lt.get("hint", ""), lt.get("body", ""), now_iso)
                )

        if "favorites" in data and isinstance(data["favorites"], list):
            conn.execute("DELETE FROM favorites")
            for fv in data["favorites"]:
                conn.execute(
                    "INSERT INTO favorites (title, sender, date, body, image_url, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (fv.get("title", ""), fv.get("from") or fv.get("sender", ""), fv.get("date", ""), fv.get("body", ""), fv.get("image") or fv.get("image_url", ""), now_iso)
                )

        if "nights" in data and isinstance(data["nights"], list):
            conn.execute("DELETE FROM nights")
            for n in data["nights"]:
                conn.execute(
                    "INSERT INTO nights (title, date, photo_url, note, created_at) VALUES (?, ?, ?, ?, ?)",
                    (n.get("title", ""), n.get("date", ""), n.get("photo") or n.get("photo_url", ""), n.get("note", ""), now_iso)
                )

        if "matchingNotes" in data and isinstance(data["matchingNotes"], list):
            conn.execute("DELETE FROM matching_notes")
            for mn in data["matchingNotes"]:
                conn.execute(
                    "INSERT INTO matching_notes (date, song, mine, theirs, detail, image_url, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (mn.get("date", ""), mn.get("song", ""), mn.get("mine", ""), mn.get("theirs", ""), mn.get("detail", ""), mn.get("image") or mn.get("image_url", ""), now_iso)
                )

        if "todos" in data and isinstance(data["todos"], list):
            conn.execute("DELETE FROM todos")
            for td in data["todos"]:
                conn.execute(
                    "INSERT INTO todos (text, done, created_at) VALUES (?, ?, ?)",
                    (td.get("text", ""), 1 if td.get("done") else 0, now_iso)
                )
        bump_data_version()


def reset_to_starter():
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        conn.execute("DELETE FROM chronicles")
        conn.execute("DELETE FROM catalogue")
        conn.execute("DELETE FROM letters")
        conn.execute("DELETE FROM favorites")
        conn.execute("DELETE FROM nights")
        conn.execute("DELETE FROM matching_notes")
        conn.execute("DELETE FROM todos")

        for ch in STARTER_CHRONICLES:
            conn.execute(
                "INSERT INTO chronicles (title, date, memory, moment, future, is_starter, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (ch["title"], ch["date"], ch["memory"], ch["moment"], ch["future"], ch["is_starter"], now_iso)
            )

        for ct in STARTER_CATALOGUE:
            conn.execute(
                "INSERT INTO catalogue (title, body, is_starter, created_at) VALUES (?, ?, ?, ?)",
                (ct["title"], ct["body"], ct["is_starter"], now_iso)
            )
        bump_data_version()


# ==========================================
# 4. FASTAPI VƏ TƏHLÜKƏSİZLİK ORTAQ QATI
# ==========================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    cleanup_expired_sessions()
    yield


app = FastAPI(
    title="The Archive of Us - Secure API",
    description="Şəxsi və romantik xatirə arxivi üçün təhlükəsiz Python backend sistemi",
    version="2.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


def get_current_session(request: Request) -> str:
    token = None
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()

    if not token:
        token = request.cookies.get("session_token")

    if not token or not validate_session(token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Giriş icazəsi yoxdur və ya sessiyanın vaxtı bitib."
        )
    return token


# ==========================================
# 5. PYDANTIC MODELLƏRİ VƏ VALİDASİYA
# ==========================================
def sanitize_text(v: Optional[str]) -> str:
    return v.strip() if v is not None else ""


class LoginRequest(BaseModel):
    code: str = Field(..., min_length=1, max_length=64)


class ChangeCodeRequest(BaseModel):
    old_code: str = Field(..., min_length=1, max_length=64)
    new_code: str = Field(..., min_length=4, max_length=64)


class ChronicleCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    date: str = Field(..., min_length=1, max_length=100)
    memory: str = Field(..., min_length=1, max_length=10000)
    moment: Optional[str] = Field("", max_length=5000)
    future: Optional[str] = Field("", max_length=5000)

    @field_validator("title", "date", "memory", "moment", "future", mode="before")
    def clean_text(cls, v):
        return sanitize_text(v)


class CatalogueCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    body: str = Field(..., min_length=1, max_length=10000)

    @field_validator("title", "body", mode="before")
    def clean_text(cls, v):
        return sanitize_text(v)


class LetterCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    open_date: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}$")
    hint: Optional[str] = Field("", max_length=500)
    body: str = Field(..., min_length=1, max_length=20000)

    @field_validator("title", "hint", "body", mode="before")
    def clean_text(cls, v):
        return sanitize_text(v)


class FavoriteCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    sender: Optional[str] = Field("", max_length=100)
    date: Optional[str] = Field("", max_length=100)
    body: str = Field(..., min_length=1, max_length=15000)
    image_url: Optional[str] = Field("", max_length=500)

    @field_validator("title", "sender", "date", "body", "image_url", mode="before")
    def clean_text(cls, v):
        return sanitize_text(v)


class NightCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    date: Optional[str] = Field("", max_length=100)
    photo_url: Optional[str] = Field("", max_length=500)
    note: str = Field(..., min_length=1, max_length=15000)

    @field_validator("title", "date", "photo_url", "note", mode="before")
    def clean_text(cls, v):
        val = sanitize_text(v)
        if val and not (val.startswith("http://") or val.startswith("https://") or val.startswith("/uploads/")):
            if v == "photo_url":
                return ""
        return val


class MatchingCreate(BaseModel):
    date: Optional[str] = Field("", max_length=100)
    song: Optional[str] = Field("", max_length=200)
    mine: str = Field(..., min_length=1, max_length=10000)
    theirs: str = Field(..., min_length=1, max_length=10000)
    detail: Optional[str] = Field("", max_length=5000)
    image_url: Optional[str] = Field("", max_length=500)

    @field_validator("date", "song", "mine", "theirs", "detail", "image_url", mode="before")
    def clean_text(cls, v):
        return sanitize_text(v)


class TodoCreate(BaseModel):
    text: str = Field(..., min_length=1, max_length=1000)

    @field_validator("text", mode="before")
    def clean_text(cls, v):
        return sanitize_text(v)


class TodoToggle(BaseModel):
    done: bool


# ==========================================
# 6. API ENDPOİNT-LƏRİ
# ==========================================

# --- Autentifikasiya ---
@app.post("/api/auth/login")
async def login(req: LoginRequest, request: Request, response: Response):
    client_ip = get_client_ip(request)

    blocked, remaining = check_rate_limit(client_ip)
    if blocked:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Çoxsaylı uğursuz cəhd! Zəhmət olmasa {remaining // 60 + 1} dəqiqə sonra yenidən cəhd edin."
        )

    stored_hash = get_setting("access_code_hash")
    if not verify_password(req.code, stored_hash):
        record_failed_attempt(client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Daxil edilən arxiv kodu düzgün deyil."
        )

    clear_failed_attempts(client_ip)
    token = generate_session_token()
    create_session(token, days=30)

    response.set_cookie(
        key="session_token",
        value=token,
        max_age=30 * 24 * 3600,
        httponly=True,
        samesite="lax",
        secure=False
    )

    return {"status": "ok", "token": token, "message": "Arxivə xoş gəldiniz."}


@app.post("/api/auth/logout")
async def logout(response: Response, session: str = Depends(get_current_session)):
    delete_session(session)
    response.delete_cookie(key="session_token")
    return {"status": "ok", "message": "Çıxış edildi."}


@app.get("/api/auth/check")
async def check_auth(request: Request):
    auth_header = request.headers.get("Authorization")
    token = None
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
    if not token:
        token = request.cookies.get("session_token")

    is_valid = validate_session(token) if token else False
    return {"authenticated": is_valid}


@app.post("/api/auth/change-code")
async def change_code(req: ChangeCodeRequest, session: str = Depends(get_current_session)):
    stored_hash = get_setting("access_code_hash")
    if not verify_password(req.old_code, stored_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Köhnə arxiv kodu düzgün deyil."
        )

    new_hash = hash_password(req.new_code)
    set_setting("access_code_hash", new_hash)
    return {"status": "ok", "message": "Arxiv kodu uğurla dəyişdirildi."}


# --- Server Vaxtı və Taymer ---
@app.get("/api/time")
async def get_server_time():
    now = datetime.now(timezone.utc)
    rel_start_str = get_setting("relationship_start") or "2026-08-21T00:00:00"
    try:
        rel_start = datetime.fromisoformat(rel_start_str)
    except Exception:
        rel_start = datetime(2026, 8, 21, 0, 0, 0)

    elapsed_seconds = max(0, int((now.timestamp() - rel_start.timestamp())))

    return {
        "server_time": now.isoformat(),
        "today_date": now.strftime("%Y-%m-%d"),
        "relationship_start": rel_start_str,
        "elapsed_seconds": elapsed_seconds
    }


# --- Canlı Sinxronizasiya Yoxlanışı ---
@app.get("/api/sync/version")
async def get_sync_version(session: str = Depends(get_current_session)):
    return {"version": get_data_version()}


# --- Chronicles ---
@app.get("/api/chronicles")
async def list_chronicles(session: str = Depends(get_current_session)):
    return get_chronicles()


@app.post("/api/chronicles")
async def create_chronicle(item: ChronicleCreate, session: str = Depends(get_current_session)):
    new_id = add_chronicle(item.title, item.date, item.memory, item.moment, item.future)
    return {"status": "ok", "id": new_id, "message": "Yeni fəsil əlavə edildi."}


@app.delete("/api/chronicles/{item_id}")
async def remove_chronicle(item_id: int, session: str = Depends(get_current_session)):
    delete_chronicle(item_id)
    return {"status": "ok", "message": "Fəsil silindi."}


# --- Catalogue ---
@app.get("/api/catalogue")
async def list_catalogue(session: str = Depends(get_current_session)):
    return get_catalogue()


@app.post("/api/catalogue")
async def create_catalogue(item: CatalogueCreate, session: str = Depends(get_current_session)):
    new_id = add_catalogue(item.title, item.body)
    return {"status": "ok", "id": new_id, "message": "Qeyd kataloqa əlavə edildi."}


@app.delete("/api/catalogue/{item_id}")
async def remove_catalogue(item_id: int, session: str = Depends(get_current_session)):
    delete_catalogue(item_id)
    return {"status": "ok", "message": "Qeyd silindi."}


# --- Sealed Letters ---
@app.get("/api/letters")
async def list_letters(session: str = Depends(get_current_session)):
    return get_letters(include_sealed_bodies=False)


@app.post("/api/letters")
async def create_letter(item: LetterCreate, session: str = Depends(get_current_session)):
    new_id = add_letter(item.title, item.open_date, item.hint, item.body)
    return {"status": "ok", "id": new_id, "message": "Məktubunuz möhürləndi."}


@app.delete("/api/letters/{item_id}")
async def remove_letter(item_id: int, session: str = Depends(get_current_session)):
    delete_letter(item_id)
    return {"status": "ok", "message": "Məktub silindi."}


# --- Favorites ---
@app.get("/api/favorites")
async def list_favorites(session: str = Depends(get_current_session)):
    return get_favorites()


@app.post("/api/favorites")
async def create_favorite(item: FavoriteCreate, session: str = Depends(get_current_session)):
    new_id = add_favorite(item.title, item.sender, item.date, item.body, item.image_url)
    return {"status": "ok", "id": new_id, "message": "Sevgi mesajı saxlanıldı."}


@app.delete("/api/favorites/{item_id}")
async def remove_favorite(item_id: int, session: str = Depends(get_current_session)):
    delete_favorite(item_id)
    return {"status": "ok", "message": "Mesaj silindi."}


# --- Memories / Nights ---
@app.get("/api/nights")
async def list_nights(session: str = Depends(get_current_session)):
    return get_nights()


@app.post("/api/nights")
async def create_night(item: NightCreate, session: str = Depends(get_current_session)):
    new_id = add_night(item.title, item.date, item.photo_url, item.note)
    return {"status": "ok", "id": new_id, "message": "Xatirə alboma əlavə edildi."}


@app.delete("/api/nights/{item_id}")
async def remove_night(item_id: int, session: str = Depends(get_current_session)):
    delete_night(item_id)
    return {"status": "ok", "message": "Xatirə silindi."}


# --- Matching Notes ---
@app.get("/api/matching")
async def list_matching(session: str = Depends(get_current_session)):
    return get_matching()


@app.post("/api/matching")
async def create_matching(item: MatchingCreate, session: str = Depends(get_current_session)):
    new_id = add_matching(item.date, item.song, item.mine, item.theirs, item.detail, item.image_url)
    return {"status": "ok", "id": new_id, "message": "Uyğunlaşan qeydlər saxlanıldı."}


@app.delete("/api/matching/{item_id}")
async def remove_matching(item_id: int, session: str = Depends(get_current_session)):
    delete_matching(item_id)
    return {"status": "ok", "message": "Qeyd silindi."}


# --- To-Do List ---
@app.get("/api/todos")
async def list_todos(session: str = Depends(get_current_session)):
    return get_todos()


@app.post("/api/todos")
async def create_todo(item: TodoCreate, session: str = Depends(get_current_session)):
    new_id = add_todo(item.text)
    return {"status": "ok", "id": new_id, "message": "Plan siyahıya əlavə edildi."}


@app.put("/api/todos/{item_id}")
async def toggle_todo_status(item_id: int, item: TodoToggle, session: str = Depends(get_current_session)):
    toggle_todo(item_id, item.done)
    return {"status": "ok"}


@app.delete("/api/todos/{item_id}")
async def remove_todo(item_id: int, session: str = Depends(get_current_session)):
    delete_todo(item_id)
    return {"status": "ok", "message": "Plan silindi."}


# --- Şəkil Yükləmə (Upload) ---
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".gif"}
ALLOWED_MIME_TYPES = {"image/jpeg", "image/png", "image/webp", "image/gif"}
MAX_FILE_SIZE = 15 * 1024 * 1024  # 15 MB


@app.post("/api/upload")
async def upload_image(file: UploadFile = File(...), session: str = Depends(get_current_session)):
    _, ext = os.path.splitext(file.filename.lower() if file.filename else "")
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Yalnız şəkil faylları (.jpg, .jpeg, .png, .webp, .gif) qəbul edilir."
        )

    if file.content_type not in ALLOWED_MIME_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Fayl tipi düzgün şəkil formatı deyil."
        )

    content = await file.read()
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Şəkil ölçüsü 15 MB-dan çox ola bilməz."
        )

    is_valid_image = False
    if ext in {".jpg", ".jpeg"} and content.startswith(b"\xff\xd8\xff"):
        is_valid_image = True
    elif ext == ".png" and content.startswith(b"\x89PNG\r\n\x1a\n"):
        is_valid_image = True
    elif ext == ".gif" and (content.startswith(b"GIF87a") or content.startswith(b"GIF89a")):
        is_valid_image = True
    elif ext == ".webp" and content.startswith(b"RIFF") and b"WEBP" in content[:16]:
        is_valid_image = True

    if not is_valid_image:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Fayl başlığı etibarsızdır və ya zədələnib."
        )

    safe_filename = f"{uuid.uuid4().hex}{ext}"
    file_path = os.path.join(UPLOADS_DIR, safe_filename)

    with open(file_path, "wb") as f:
        f.write(content)

    return {
        "status": "ok",
        "url": f"/uploads/{safe_filename}",
        "filename": safe_filename
    }


# --- Backup, Export, Import & Reset ---
@app.get("/api/backup/export")
async def export_backup(session: str = Depends(get_current_session)):
    return export_all_data()


@app.post("/api/backup/import")
async def import_backup(data: dict, session: str = Depends(get_current_session)):
    if not isinstance(data, dict):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Etibarsız backup formatı.")
    import_all_data(data)
    return {"status": "ok", "message": "Bütün arxiv məlumatları uğurla bərpa edildi."}


@app.post("/api/backup/reset")
async def reset_backup(session: str = Depends(get_current_session)):
    reset_to_starter()
    return {"status": "ok", "message": "Arxiv ilkin vəziyyətinə sıfırlandı."}


# --- Statik Fayllar və Kök Səhifə ---
app.mount("/uploads", StaticFiles(directory=UPLOADS_DIR), name="uploads")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
async def root():
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return JSONResponse({"status": "Archive API running"})


# ==========================================
# 7. BİRBAŞA İŞƏ SALMA (STANDALONE ENTRYPOINT)
# ==========================================
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    print("========================================================")
    print("       THE ARCHIVE OF US - SECURE PYTHON BACKEND")
    print("========================================================")
    print(f"Server işə düşür: http://127.0.0.1:{port}")
    print("İlkin arxiv kodu: 210826")
    print("Dayandırmaq üçün: Ctrl + C basın\n")
    uvicorn.run("app:app", host="0.0.0.0", port=port, reload=False)
