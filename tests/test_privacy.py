"""
Privacy tests. They exercise the app the way real users would (sign up, log
in) so the log it writes can be scanned by ci/pii_scan.py, and they check the
API does not hand one user other users' personal data.
"""
import os
import sys

os.environ.setdefault("LOG_FILE", "app.log")

from fastapi.testclient import TestClient  # noqa: E402

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
from main import app  # noqa: E402

client = TestClient(app)


def test_signup_and_login_flow():
    r = client.post("/signup", json={"username": "carol", "password": "carolpw1",
                                     "email": "carol@example.com", "phone": "+61 400 111 222"})
    assert r.status_code == 200
    assert client.post("/login", json={"username": "carol", "password": "carolpw1"}).status_code == 200


def test_users_endpoint_does_not_expose_other_users():
    # GDPR Art. 5(1)(c): bob has no need to see alice's email or phone.
    tok = client.post("/login", json={"username": "bob", "password": "bobpw"}).json()["token"]
    r = client.get("/users", headers={"authorization": f"Bearer {tok}"})
    assert "alice@example.com" not in r.text, "data minimisation: bob received alice's personal data"
