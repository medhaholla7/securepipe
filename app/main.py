"""
Notes API - a deliberately vulnerable app for the SecurePipe project.

This app contains INTENTIONAL security flaws. It exists only so the CI/CD
security pipeline in this repo can be shown catching them. Do NOT deploy it
to the public internet. Each flaw is tagged with  # VULN:  and listed in
VULNERABILITIES.md.
"""
import logging
import os
import sqlite3

import jwt
from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="Notes API (intentionally vulnerable)")

log = logging.getLogger("notes")
log.setLevel(logging.INFO)
_h = logging.FileHandler(os.environ.get("LOG_FILE", "app.log"))
_h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
log.addHandler(_h)

# VULN 1 (CWE-798): hardcoded secret committed to source control.
# A real app loads this from a secret manager, never hardcodes it.
JWT_SECRET = "s3cr3t-signing-key-do-not-ship"

# VULN 2 (CWE-942): CORS allows any origin with credentials.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB = "notes.db"


def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT, phone TEXT);
        CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, owner_id INTEGER, body TEXT);
        """
    )
    conn.execute("DELETE FROM users"); conn.execute("DELETE FROM notes")
    # VULN 3 (CWE-256): passwords stored in plain text.
    conn.execute("INSERT INTO users VALUES (1,'alice','alicepw','alice@example.com','+61 412 345 678')")
    conn.execute("INSERT INTO users VALUES (2,'bob','bobpw','bob@example.com','+44 7700 900123')")
    conn.execute("INSERT INTO notes VALUES (1,1,'alice private note')")
    conn.execute("INSERT INTO notes VALUES (2,2,'bob private note')")
    conn.commit(); conn.close()


init_db()


class Login(BaseModel):
    username: str
    password: str


class Signup(BaseModel):
    username: str
    password: str
    email: str
    phone: str


def current_user(authorization: str) -> int:
    try:
        token = authorization.split(" ", 1)[1]
        data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return int(data["uid"])
    except Exception:
        raise HTTPException(401, "bad token")


@app.post("/login")
def login(body: Login):
    # VULN 10 (CWE-532, GDPR Art. 5(1)(f) and 32): credentials written to logs.
    log.info(f"login attempt username={body.username} password={body.password}")
    conn = db()
    # VULN 4 (CWE-89): SQL injection, user input concatenated into the query.
    q = f"SELECT id FROM users WHERE username='{body.username}' AND password='{body.password}'"
    row = conn.execute(q).fetchone()
    conn.close()
    if not row:
        raise HTTPException(401, "bad credentials")
    return {"token": jwt.encode({"uid": row["id"]}, JWT_SECRET, algorithm="HS256")}


@app.get("/notes/{note_id}")
def get_note(note_id: int, authorization: str = Header(...)):
    current_user(authorization)  # checks the token is valid...
    conn = db()
    row = conn.execute("SELECT * FROM notes WHERE id=?", (note_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "not found")
    # VULN 5 (CWE-639): IDOR / broken object level authorization.
    # It never checks that row["owner_id"] == the caller, so any logged-in
    # user can read any note by changing the id.
    return {"id": row["id"], "owner_id": row["owner_id"], "body": row["body"]}


@app.get("/debug")
def debug():
    # VULN 6 (CWE-215): debug endpoint leaks config, including the secret.
    return {"jwt_secret": JWT_SECRET, "env": dict(os.environ)}


@app.post("/signup")
def signup(body: Signup):
    conn = db()
    conn.execute(
        "INSERT INTO users (username, password, email, phone) VALUES (?,?,?,?)",
        (body.username, body.password, body.email, body.phone),
    )
    conn.commit(); conn.close()
    # VULN 10 (CWE-532): full email and phone number written to logs.
    log.info(f"new signup username={body.username} email={body.email} phone={body.phone}")
    return {"ok": True}


@app.get("/users")
def list_users(authorization: str = Header(...)):
    current_user(authorization)
    conn = db()
    rows = conn.execute("SELECT id, username, email, phone FROM users").fetchall()
    conn.close()
    # VULN 11 (CWE-359, GDPR Art. 5(1)(c) data minimisation): any logged-in
    # user gets every other user's email and phone number.
    return [dict(r) for r in rows]
