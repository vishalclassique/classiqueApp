import os
import requests
import pytest

BASE_URL = os.environ.get("EXPO_PUBLIC_BACKEND_URL", "https://bold-kilby-6.preview.emergentagent.com").rstrip("/")

CREDS = {
    "founder": ("founder@classique.one", "Classique2026!"),
    "sales":   ("sales@classique.one",   "Sales2026!"),
    "planner": ("planner@classique.one", "Planner2026!"),
    "ops":     ("ops@classique.one",     "Ops2026!"),
}


def _login(email, password):
    r = requests.post(
        f"{BASE_URL}/api/auth/login",
        data={"username": email, "password": password},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=20,
    )
    return r


def _token(email, password):
    r = _login(email, password)
    assert r.status_code == 200, f"login failed for {email}: {r.status_code} {r.text}"
    return r.json()["access_token"]


@pytest.fixture(scope="session")
def base_url():
    return BASE_URL


@pytest.fixture(scope="session")
def tokens():
    return {k: _token(e, p) for k, (e, p) in CREDS.items()}


def auth_client(token):
    s = requests.Session()
    s.headers.update({"Authorization": f"Bearer {token}"})
    return s
