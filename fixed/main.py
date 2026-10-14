"""
Notes API - FIXED version. Same app as app/main.py with every code flaw
remediated. The pipeline runs the custom Semgrep rules against this file and
expects 0 findings, which proves the rules do not raise false positives.
"""
import hashlib
import hmac
import os
import sqlite3

import jwt
from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="Notes API (fixed)")

# FIX 1: secret comes from the environment, never from source.
JWT_SECRET = os.environ["JWT_SECRET"]

# FIX 2: only a known front-end origin may send credentials.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://notes.example.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

DB = "notes.db"


def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def hash_pw(pw: str, salt: bytes) -> str:
    # FIX 3: store a salted, slow hash instead of the raw value.
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200_000).hex()


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
    # FIX 4: parameterised query, user input never becomes SQL.
    row = conn.execute(
        "SELECT id, pw_hash, salt FROM users WHERE username=?", (body.username,)
    ).fetchone()
    conn.close()
    if not row or not hmac.compare_digest(
        row["pw_hash"], hash_pw(body.password, bytes.fromhex(row["salt"]))
    ):
        raise HTTPException(401, "bad credentials")
    return {"token": jwt.encode({"uid": row["id"]}, JWT_SECRET, algorithm="HS256")}


@app.get("/notes/{note_id}")
def get_note(note_id: int, authorization: str = Header(...)):
    uid = current_user(authorization)
    conn = db()
    # FIX 5: ownership is part of the lookup, so other users' notes 404.
    row = conn.execute(
        "SELECT * FROM notes WHERE id=? AND owner_id=?", (note_id, uid)
    ).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "not found")
    return {"id": row["id"], "body": row["body"]}

# FIX 6: no debug endpoint.
