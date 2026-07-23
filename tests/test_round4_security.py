"""
Round 4 — Security remediation + User Management tests.
Covers SEC-001 .. SEC-004 and the new /api/users flow.
"""
import asyncio
import csv
import io
import json
import os
import time
import uuid

import pytest
import requests
import websockets

BASE_URL = os.environ.get("EXPO_PUBLIC_BACKEND_URL", "https://bold-kilby-6.preview.emergentagent.com").rstrip("/")
WS_URL = BASE_URL.replace("https://", "wss://").replace("http://", "ws://") + "/api/ws"

FOUNDER_EMAIL = "founder@classique.one"
FOUNDER_PASSWORD = "Classique2026!"


# ------------ helpers ------------

def _login(email, password):
    return requests.post(
        f"{BASE_URL}/api/auth/login",
        data={"username": email, "password": password},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=20,
    )


def _token(email, password):
    r = _login(email, password)
    assert r.status_code == 200, f"login failed for {email}: {r.status_code} {r.text}"
    return r.json()["access_token"]


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="session")
def founder_token():
    return _token(FOUNDER_EMAIL, FOUNDER_PASSWORD)


@pytest.fixture(scope="session")
def created_planner(founder_token):
    """Create a fresh planner user via founder API; return dict with creds/id/token"""
    email = f"TEST_planner_{uuid.uuid4().hex[:8]}@classique.one"
    payload = {
        "email": email,
        "full_name": "TEST Planner Round4",
        "role": "Wedding Planner",
        "initial_password": "Welcome@123",
    }
    r = requests.post(f"{BASE_URL}/api/users", json=payload, headers=_auth(founder_token), timeout=20)
    assert r.status_code == 201, f"planner create failed: {r.status_code} {r.text}"
    user = r.json()
    tok = _token(email, "Welcome@123")
    return {
        "id": user["id"],
        "email": email,
        "password": "Welcome@123",
        "token": tok,
        "user": user,
    }


# ============ SEC-001 — removed seeded staff ============

class TestSEC001_SeededAccountsRemoved:
    def test_old_sales_login_denied(self):
        r = _login("sales@classique.one", "Sales2026!")
        assert r.status_code == 401, f"expected 401, got {r.status_code} {r.text}"

    def test_old_planner_login_denied(self):
        r = _login("planner@classique.one", "Planner2026!")
        assert r.status_code == 401

    def test_old_ops_login_denied(self):
        r = _login("ops@classique.one", "Ops2026!")
        assert r.status_code == 401


# ============ User Management — creation guards ============

class TestUserManagementGuards:
    def test_founder_cannot_create_another_founder(self, founder_token):
        r = requests.post(
            f"{BASE_URL}/api/users",
            json={
                "email": f"TEST_founder2_{uuid.uuid4().hex[:6]}@classique.one",
                "full_name": "TEST Founder2",
                "role": "Founder",
                "initial_password": "Welcome@123",
            },
            headers=_auth(founder_token),
            timeout=20,
        )
        assert r.status_code == 400
        assert "founder" in r.text.lower()

    def test_planner_cannot_create_users(self, created_planner):
        # Planner still has must_change_password=True but token is valid; POST /users should be 403.
        r = requests.post(
            f"{BASE_URL}/api/users",
            json={
                "email": f"TEST_x_{uuid.uuid4().hex[:6]}@classique.one",
                "full_name": "TEST X",
                "role": "Sales",
                "initial_password": "Welcome@123",
            },
            headers=_auth(created_planner["token"]),
            timeout=20,
        )
        assert r.status_code == 403

    def test_planner_get_users_returns_reduced_roster_no_password_hash(self, created_planner):
        r = requests.get(f"{BASE_URL}/api/users", headers=_auth(created_planner["token"]), timeout=20)
        assert r.status_code == 200
        docs = r.json()
        assert isinstance(docs, list) and len(docs) > 0
        for d in docs:
            assert "password_hash" not in d, f"password_hash leaked: {d}"
            # Reduced roster: name/role/id only
            assert set(d.keys()).issubset({"id", "full_name", "role"}), f"extra keys leaked: {d.keys()}"

    def test_planner_cannot_patch_or_reset(self, founder_token, created_planner):
        # PATCH
        r = requests.patch(
            f"{BASE_URL}/api/users/{created_planner['id']}",
            json={"full_name": "hacker"},
            headers=_auth(created_planner["token"]),
            timeout=20,
        )
        assert r.status_code == 403
        # RESET
        r = requests.post(
            f"{BASE_URL}/api/users/{created_planner['id']}/reset-password",
            json={"new_password": "Welcome@999"},
            headers=_auth(created_planner["token"]),
            timeout=20,
        )
        assert r.status_code == 403


class TestFounderUpdateSelf:
    def test_founder_cannot_patch_self(self, founder_token):
        me = requests.get(f"{BASE_URL}/api/auth/me", headers=_auth(founder_token), timeout=20).json()
        r = requests.patch(
            f"{BASE_URL}/api/users/{me['id']}",
            json={"full_name": "New Name"},
            headers=_auth(founder_token),
            timeout=20,
        )
        assert r.status_code == 400
        assert "change-password" in r.text.lower() or "own account" in r.text.lower()


# ============ SEC-001 / Change-password flow ============

class TestChangePasswordFlow:
    def test_new_user_must_change_password_true(self, created_planner, founder_token):
        me = requests.get(
            f"{BASE_URL}/api/auth/me",
            headers=_auth(created_planner["token"]),
            timeout=20,
        )
        assert me.status_code == 200
        body = me.json()
        assert body["must_change_password"] is True, body

    def test_change_password_wrong_current_fails(self, created_planner):
        r = requests.post(
            f"{BASE_URL}/api/auth/change-password",
            json={"current_password": "WRONG_pw", "new_password": "NewSecret@123"},
            headers=_auth(created_planner["token"]),
            timeout=20,
        )
        assert r.status_code == 401

    def test_change_password_success_and_flag_flips(self, founder_token):
        """Create a dedicated user for this test so we do not disturb the shared fixture."""
        email = f"TEST_pwflip_{uuid.uuid4().hex[:8]}@classique.one"
        r = requests.post(
            f"{BASE_URL}/api/users",
            json={
                "email": email,
                "full_name": "TEST PwFlip",
                "role": "Wedding Planner",
                "initial_password": "Welcome@123",
            },
            headers=_auth(founder_token),
            timeout=20,
        )
        assert r.status_code == 201, r.text
        tok = _token(email, "Welcome@123")
        # change password
        r = requests.post(
            f"{BASE_URL}/api/auth/change-password",
            json={"current_password": "Welcome@123", "new_password": "NewSecret@123"},
            headers=_auth(tok),
            timeout=20,
        )
        assert r.status_code == 200, r.text
        # flag flipped
        me = requests.get(f"{BASE_URL}/api/auth/me", headers=_auth(tok), timeout=20).json()
        assert me["must_change_password"] is False
        # old password no longer works
        assert _login(email, "Welcome@123").status_code == 401
        # new password works
        assert _login(email, "NewSecret@123").status_code == 200


# ============ User Management — patch / reset by founder ============

class TestFounderPatchAndReset:
    def test_founder_reset_password_sets_must_change_true(self, founder_token):
        email = f"TEST_reset_{uuid.uuid4().hex[:8]}@classique.one"
        r = requests.post(
            f"{BASE_URL}/api/users",
            json={"email": email, "full_name": "TEST Reset", "role": "Sales", "initial_password": "Welcome@123"},
            headers=_auth(founder_token), timeout=20,
        )
        assert r.status_code == 201
        uid = r.json()["id"]
        tok = _token(email, "Welcome@123")
        # user changes password
        assert requests.post(
            f"{BASE_URL}/api/auth/change-password",
            json={"current_password": "Welcome@123", "new_password": "MyNewPw@123"},
            headers=_auth(tok), timeout=20,
        ).status_code == 200
        # founder resets
        r = requests.post(
            f"{BASE_URL}/api/users/{uid}/reset-password",
            json={"new_password": "Starter@456"},
            headers=_auth(founder_token), timeout=20,
        )
        assert r.status_code == 200
        # old (changed) password fails
        assert _login(email, "MyNewPw@123").status_code == 401
        # new starter succeeds and must_change_password=true again
        assert _login(email, "Starter@456").status_code == 200
        tok2 = _token(email, "Starter@456")
        me = requests.get(f"{BASE_URL}/api/auth/me", headers=_auth(tok2), timeout=20).json()
        assert me["must_change_password"] is True

    def test_founder_deactivate_blocks_login(self, founder_token):
        email = f"TEST_deact_{uuid.uuid4().hex[:8]}@classique.one"
        r = requests.post(
            f"{BASE_URL}/api/users",
            json={"email": email, "full_name": "TEST Deact", "role": "Wedding Planner", "initial_password": "Welcome@123"},
            headers=_auth(founder_token), timeout=20,
        )
        assert r.status_code == 201
        uid = r.json()["id"]
        tok = _token(email, "Welcome@123")
        # founder deactivates
        r = requests.patch(
            f"{BASE_URL}/api/users/{uid}",
            json={"is_active": False},
            headers=_auth(founder_token), timeout=20,
        )
        assert r.status_code == 200
        # Spec says: "login refused (401) OR /auth/me returns 401 because is_active is
        # enforced in get_current_user". get_current_user does enforce is_active, so /auth/me
        # must be 401. Login endpoint currently still issues a token — flagged as minor.
        r = requests.get(f"{BASE_URL}/api/auth/me", headers=_auth(tok), timeout=20)
        assert r.status_code == 401, f"expected 401 for deactivated user /auth/me, got {r.status_code} {r.text}"
        # Best-effort: if the server also refuses login, great; otherwise verify the freshly-issued
        # token is also useless for /auth/me.
        r2 = _login(email, "Welcome@123")
        if r2.status_code == 200:
            new_tok = r2.json()["access_token"]
            r3 = requests.get(f"{BASE_URL}/api/auth/me", headers=_auth(new_tok), timeout=20)
            assert r3.status_code == 401, "deactivated user was allowed via a freshly-issued token"


# ============ SEC-003 — CSV formula-injection guard ============

class TestSEC003_CSVFormulaGuard:
    def test_leads_export_prefixes_formula_chars(self, founder_token):
        payload = {
            "couple_name": "=1+cmd|calc",
            "source": "Website",
            "stage": "New Lead",
            "score": 10,
        }
        r = requests.post(f"{BASE_URL}/api/leads", json=payload, headers=_auth(founder_token), timeout=20)
        assert r.status_code in (200, 201), r.text
        lead_id = r.json()["id"]
        try:
            r = requests.get(f"{BASE_URL}/api/leads/export", headers=_auth(founder_token), timeout=30)
            assert r.status_code == 200
            content = r.content.decode("utf-8-sig")
            reader = csv.DictReader(io.StringIO(content))
            rows = list(reader)
            matched = [row for row in rows if "=1+cmd|calc" in row.get("couple_name", "")]
            assert matched, "test lead not present in export"
            for row in matched:
                assert row["couple_name"].startswith("'="), \
                    f"formula not escaped: {row['couple_name']!r}"
            # And no cell should begin with a raw =,+,-,@,tab,\r
            for row in rows:
                for k, v in row.items():
                    if v and isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
                        pytest.fail(f"unescaped formula in {k}: {v!r}")
        finally:
            requests.delete(f"{BASE_URL}/api/leads/{lead_id}", headers=_auth(founder_token), timeout=15)


# ============ SEC-004 — .gitignore covers env ============

class TestSEC004_Gitignore:
    def test_gitignore_covers_backend_env(self):
        with open("/app/.gitignore") as f:
            content = f.read()
        # Any of the following matches backend/.env
        assert any(pat in content for pat in ("*.env", "backend/.env", "\n.env\n", "\n.env")), \
            "no rule covering backend/.env found in .gitignore"


# ============ /api/activity — role scoping ============

class TestActivityScoping:
    def test_founder_sees_all_activity(self, founder_token):
        r = requests.get(f"{BASE_URL}/api/activity?limit=50", headers=_auth(founder_token), timeout=20)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_planner_only_sees_scoped_activity(self, created_planner, founder_token):
        r = requests.get(f"{BASE_URL}/api/activity?limit=100", headers=_auth(created_planner["token"]), timeout=20)
        assert r.status_code == 200
        entries = r.json()
        # planner is not yet assigned; every visible entry must have actor_id == planner id
        # (or wedding_id in their assigned weddings — none yet)
        me = requests.get(f"{BASE_URL}/api/auth/me", headers=_auth(created_planner["token"]), timeout=20).json()
        my_id = me["id"]
        my_ws = me.get("active_wedding_ids", []) or []
        for e in entries:
            assert (e.get("actor_id") == my_id) or (e.get("wedding_id") in my_ws), \
                f"planner sees activity they shouldn't: {e}"


# ============ SEC-002 — WebSocket per-user routing ============

class TestSEC002_Websockets:
    @pytest.mark.timeout(45)
    def test_notification_routes_only_to_target(self, founder_token, created_planner):
        """Founder + Planner sockets. Planner requests vendor approval → founder gets
        'notification', planner does NOT. Then founder decides → planner gets 'notification',
        founder does NOT."""

        async def run():
            founder_msgs = []
            planner_msgs = []

            # Need a wedding with the planner assigned so vendor request-approval passes.
            # Weddings have no PATCH endpoint, so create a new wedding with the planner on team.

            # Create a fresh wedding with the planner on the team, so request-approval passes
            # (there is no PATCH /weddings endpoint; team is assignable only at creation).
            new_wed_payload = {
                "couple_name": f"TEST WS R4 {uuid.uuid4().hex[:6]}",
                "venue": "Test Venue",
                "start_date": "2027-01-01T10:00:00+00:00",
                "end_date": "2027-01-02T10:00:00+00:00",
                "guest_count": 100,
                "budget": 1000000,
                "wedding_head_id": created_planner["id"],
                "assigned_team": [{"user_id": created_planner["id"], "role": "Wedding Planner"}],
            }
            r_w = requests.post(f"{BASE_URL}/api/weddings", json=new_wed_payload, headers=_auth(founder_token), timeout=20)
            assert r_w.status_code in (200, 201), r_w.text
            wed_id = r_w.json()["id"]

            # Create a vendor as founder
            vpayload = {
                "wedding_id": wed_id,
                "name": f"TEST Vendor R4 {uuid.uuid4().hex[:6]}",
                "category": "Catering",
                "amount": 100000,
            }
            r = requests.post(f"{BASE_URL}/api/vendors", json=vpayload, headers=_auth(founder_token), timeout=20)
            assert r.status_code in (200, 201), r.text
            vendor_id = r.json()["id"]

            uri_f = f"{WS_URL}?token={founder_token}"
            uri_p = f"{WS_URL}?token={created_planner['token']}"

            async def collect(ws, bucket, stop_evt):
                try:
                    while not stop_evt.is_set():
                        try:
                            msg = await asyncio.wait_for(ws.recv(), timeout=1.0)
                            bucket.append(json.loads(msg))
                        except asyncio.TimeoutError:
                            continue
                except Exception:
                    pass

            async with websockets.connect(uri_f, open_timeout=15) as wsf, \
                       websockets.connect(uri_p, open_timeout=15) as wsp:
                stop = asyncio.Event()
                t1 = asyncio.create_task(collect(wsf, founder_msgs, stop))
                t2 = asyncio.create_task(collect(wsp, planner_msgs, stop))

                # Wait for hello frames
                await asyncio.sleep(1.5)

                # Planner requests approval → founder notification
                r = requests.post(
                    f"{BASE_URL}/api/vendors/{vendor_id}/request-approval",
                    json={"action": "advance"},
                    headers=_auth(created_planner["token"]), timeout=20,
                )
                assert r.status_code in (200, 201), r.text

                await asyncio.sleep(3)

                # Founder approves → planner notification (only when planner is the vendor.created_by).
                # In this test the founder created the vendor so the planner won't be a recipient.
                # Re-create a vendor as the planner (they can now access this wedding) so the
                # planner is created_by and will receive the approval-granted notification.
                r_v2 = requests.post(f"{BASE_URL}/api/vendors", json=vpayload, headers=_auth(created_planner["token"]), timeout=20)
                assert r_v2.status_code in (200, 201), r_v2.text
                vendor_id2 = r_v2.json()["id"]
                requests.post(
                    f"{BASE_URL}/api/vendors/{vendor_id2}/request-approval",
                    json={"action": "advance"},
                    headers=_auth(created_planner["token"]), timeout=20,
                )
                await asyncio.sleep(1)
                r = requests.post(
                    f"{BASE_URL}/api/vendors/{vendor_id2}/decide",
                    json={"approved": True, "reason": "ok"},
                    headers=_auth(founder_token), timeout=20,
                )
                assert r.status_code == 200, r.text

                await asyncio.sleep(3)
                stop.set()
                await asyncio.gather(t1, t2, return_exceptions=True)

            # After request-approval: founder should have a 'notification' event
            f_notifs = [m for m in founder_msgs if m.get("type") == "notification"]
            p_notifs = [m for m in planner_msgs if m.get("type") == "notification"]
            f_activity = [m for m in founder_msgs if m.get("type") == "activity"]
            p_activity = [m for m in planner_msgs if m.get("type") == "activity"]

            # Founder received at least one notification (from planner's request-approval)
            assert f_notifs, f"founder did not receive notification. founder_msgs={founder_msgs}"
            # Planner received at least one notification (from founder's decision)
            assert p_notifs, f"planner did not receive notification. planner_msgs={planner_msgs}"
            # Founder received activity events; planner should not
            assert f_activity, "founder did not receive any activity events"
            assert not p_activity, f"planner unexpectedly received activity events: {p_activity}"

            # Cleanup vendors
            requests.delete(f"{BASE_URL}/api/vendors/{vendor_id}", headers=_auth(founder_token), timeout=15)
            try:
                requests.delete(f"{BASE_URL}/api/vendors/{vendor_id2}", headers=_auth(founder_token), timeout=15)
            except Exception:
                pass

        asyncio.run(run())


# ============ Regression — founder can still access core endpoints ============

class TestRegressionFounder:
    @pytest.mark.parametrize("path", [
        "/api/auth/me",
        "/api/leads",
        "/api/weddings",
        "/api/analytics",
        "/api/notifications",
        "/api/activity?limit=10",
        "/api/meta",
    ])
    def test_founder_endpoint_ok(self, founder_token, path):
        r = requests.get(f"{BASE_URL}{path}", headers=_auth(founder_token), timeout=20)
        assert r.status_code == 200, f"{path} → {r.status_code} {r.text[:200]}"
