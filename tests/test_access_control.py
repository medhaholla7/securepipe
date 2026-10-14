"""
Access-control tests. Scanners cannot see logic flaws like IDOR (the code
looks fine, it just forgets an ownership check), so this test does what an
attacker would: log in as one user and ask for another user's note.
"""
import os
import sys

from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
from main import app  # noqa: E402

client = TestClient(app)


def token(user, pw):
    r = client.post("/login", json={"username": user, "password": pw})
    assert r.status_code == 200
    return {"authorization": f"Bearer {r.json()['token']}"}


def test_user_can_read_own_note():
    assert client.get("/notes/2", headers=token("bob", "bobpw")).status_code == 200


def test_user_cannot_read_another_users_note():
    # CWE-639: bob must not be able to read alice's note (id 1).
    r = client.get("/notes/1", headers=token("bob", "bobpw"))
    assert r.status_code in (403, 404), f"IDOR: bob read alice's note: {r.json()}"
