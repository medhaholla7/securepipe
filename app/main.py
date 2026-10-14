"""
Notes API - a deliberately vulnerable app for the SecurePipe project.

This app contains INTENTIONAL security flaws. It exists only so the CI/CD
security pipeline in this repo can be shown catching them. Do NOT deploy it
to the public internet. Each flaw is tagged with  # VULN:  and listed in
VULNERABILITIES.md.
"""
import os
import sqlite3

import jwt
from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="Notes API (intentionally vulnerable)")

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
        CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT);
        CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, owner_id INTEGER, body TEXT);
        """
    )
    conn.execute("DELETE FROM users"); conn.execute("DELETE FROM notes")
    # VULN 3 (CWE-256): passwords stored in plain text.
    conn.execute("INSERT INTO users VALUES (1,'alice','alicepw')")
    conn.execute("INSERT INTO users VALUES (2,'bob','bobpw')")
    conn.execute("INSERT INTO notes VALUES (1,1,'alice private note')")
    conn.execute("INSERT INTO notes VALUES (2,2,'bob private note')")
    conn.commit(); conn.close()


init_db()


class Login(BaseModel):
    username: str
    password: str


def current_user(authorization: str) -> int:
    try:
        token = authorization.split(" ", 1)[1]
        data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return int(data["uid"])
    except Exception:
        raise HTTPException(401, "bad token")


@app.post("/login")
def login(body: Login):
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
