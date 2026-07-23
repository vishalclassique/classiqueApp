"""Round 2 additions: settings, notifications, analytics, websocket."""
import asyncio
import json
import pytest
import requests
import websockets
from conftest import BASE_URL, auth_client


# ---------- Settings ----------
class TestSettings:
    def test_get_settings_all_roles(self, tokens):
        for role in ("founder", "sales", "planner", "ops"):
            r = auth_client(tokens[role]).get(f"{BASE_URL}/api/settings")
            assert r.status_code == 200, f"{role} could not GET settings: {r.text}"
            j = r.json()
            for k in ("vendor_categories", "room_categories", "guest_tags", "wedding_stages"):
                assert k in j, f"missing key {k} in settings for {role}"
                assert isinstance(j[k], list) and len(j[k]) > 0

    def test_patch_settings_founder(self, tokens):
        c = auth_client(tokens["founder"])
        cur = c.get(f"{BASE_URL}/api/settings").json()
        original = list(cur["vendor_categories"])
        new_cat = "TEST_Fireworks"
        # ensure clean
        target = [c for c in original if c != new_cat] + [new_cat]
        r = c.patch(f"{BASE_URL}/api/settings", json={"vendor_categories": target})
        assert r.status_code == 200, r.text
        assert new_cat in r.json()["vendor_categories"]
        # Persistence
        r2 = c.get(f"{BASE_URL}/api/settings")
        assert new_cat in r2.json()["vendor_categories"]
        # Restore
        c.patch(f"{BASE_URL}/api/settings", json={"vendor_categories": original})

    def test_patch_settings_non_founder_403(self, tokens):
        for role in ("sales", "planner", "ops"):
            r = auth_client(tokens[role]).patch(f"{BASE_URL}/api/settings", json={"vendor_categories": ["X"]})
            assert r.status_code == 403, f"{role} PATCH should be 403 but got {r.status_code}"


# ---------- Notifications ----------
class TestNotifications:
    def test_get_notifications_shape(self, tokens):
        for role in ("founder", "sales", "planner", "ops"):
            r = auth_client(tokens[role]).get(f"{BASE_URL}/api/notifications")
            assert r.status_code == 200
            j = r.json()
            assert "items" in j and isinstance(j["items"], list)
            assert "unread" in j and isinstance(j["unread"], int)

    def test_notifications_user_scoped(self, tokens):
        f = auth_client(tokens["founder"]).get(f"{BASE_URL}/api/notifications").json()
        p = auth_client(tokens["planner"]).get(f"{BASE_URL}/api/notifications").json()
        f_ids = {n["id"] for n in f["items"]}
        p_ids = {n["id"] for n in p["items"]}
        # No overlap: user_id-scoped
        assert f_ids.isdisjoint(p_ids), "Notifications leak across users"

    def test_planner_request_approval_creates_founder_notification(self, tokens):
        cf = auth_client(tokens["founder"])
        cp = auth_client(tokens["planner"])
        wid = cf.get(f"{BASE_URL}/api/weddings").json()[0]["id"]
        # Create vendor not pending
        v = cp.post(f"{BASE_URL}/api/vendors", json={
            "wedding_id": wid, "name": "TEST_ notif vendor", "category": "Decor", "quoted_amount": 25000
        }).json()
        vid = v["id"]
        before = cf.get(f"{BASE_URL}/api/notifications").json()["unread"]
        r = cp.post(f"{BASE_URL}/api/vendors/{vid}/request-approval", json={"action": "advance"})
        assert r.status_code == 200
        after = cf.get(f"{BASE_URL}/api/notifications").json()["unread"]
        assert after >= before + 1, f"Founder unread should increase: before={before} after={after}"

    def test_decide_creates_requester_notification(self, tokens):
        cf = auth_client(tokens["founder"])
        cp = auth_client(tokens["planner"])
        wid = cf.get(f"{BASE_URL}/api/weddings").json()[0]["id"]

        for approved in (True, False):
            v = cp.post(f"{BASE_URL}/api/vendors", json={
                "wedding_id": wid, "name": f"TEST_ decide {approved}", "category": "Decor", "quoted_amount": 15000
            }).json()
            vid = v["id"]
            cp.post(f"{BASE_URL}/api/vendors/{vid}/request-approval", json={"action": "advance"})
            before = cp.get(f"{BASE_URL}/api/notifications").json()["unread"]
            r = cf.post(f"{BASE_URL}/api/vendors/{vid}/decide", json={"approved": approved, "reason": "TEST"})
            assert r.status_code == 200
            after = cp.get(f"{BASE_URL}/api/notifications").json()["unread"]
            assert after >= before + 1, f"Planner unread should increase after {approved}: before={before} after={after}"

    def test_task_created_notifies_assignee(self, tokens):
        cf = auth_client(tokens["founder"])
        cp = auth_client(tokens["planner"])
        # Planner id
        me_p = cp.get(f"{BASE_URL}/api/auth/me").json()
        wid = cf.get(f"{BASE_URL}/api/weddings").json()[0]["id"]
        before = cp.get(f"{BASE_URL}/api/notifications").json()["unread"]
        r = cf.post(f"{BASE_URL}/api/tasks", json={
            "wedding_id": wid, "title": "TEST_ notify task", "assignee_id": me_p["id"]
        })
        assert r.status_code == 200
        after = cp.get(f"{BASE_URL}/api/notifications").json()["unread"]
        assert after >= before + 1, f"Assignee should receive a notification: before={before} after={after}"

    def test_mark_read_single_and_all(self, tokens):
        cp = auth_client(tokens["planner"])
        items = cp.get(f"{BASE_URL}/api/notifications").json()["items"]
        unread_items = [n for n in items if not n["read"]]
        if not unread_items:
            # create one via founder->planner task
            cf = auth_client(tokens["founder"])
            me = cp.get(f"{BASE_URL}/api/auth/me").json()
            wid = cf.get(f"{BASE_URL}/api/weddings").json()[0]["id"]
            cf.post(f"{BASE_URL}/api/tasks", json={"wedding_id": wid, "title": "TEST_ mark-read", "assignee_id": me["id"]})
            items = cp.get(f"{BASE_URL}/api/notifications").json()["items"]
            unread_items = [n for n in items if not n["read"]]
        assert unread_items, "Could not create an unread notification"
        one = unread_items[0]
        r = cp.post(f"{BASE_URL}/api/notifications/{one['id']}/read")
        assert r.status_code == 200
        after = cp.get(f"{BASE_URL}/api/notifications").json()
        assert not any(n["id"] == one["id"] and not n["read"] for n in after["items"])
        # Mark all read
        r2 = cp.post(f"{BASE_URL}/api/notifications/mark-all-read")
        assert r2.status_code == 200
        final = cp.get(f"{BASE_URL}/api/notifications").json()
        assert final["unread"] == 0


# ---------- Analytics ----------
class TestAnalytics:
    def test_analytics_founder(self, tokens):
        r = auth_client(tokens["founder"]).get(f"{BASE_URL}/api/analytics")
        assert r.status_code == 200, r.text
        j = r.json()
        expected_keys = ("pipeline_value", "leads_by_stage", "conversion_rate", "weddings",
                         "team_workload", "approvals_pending", "rsvp_completion_avg",
                         "avg_margin_pct", "total_budget", "total_cost")
        for k in expected_keys:
            assert k in j, f"missing key: {k}"
        # leads_by_stage should have all 8 stages
        assert isinstance(j["leads_by_stage"], dict)
        assert len(j["leads_by_stage"]) == 8, f"expected 8 stages, got {len(j['leads_by_stage'])}: {list(j['leads_by_stage'].keys())}"
        # Weddings shape
        for w in j["weddings"]:
            for k in ("id", "couple_name", "budget", "cost", "margin", "margin_pct"):
                assert k in w, f"wedding entry missing key: {k}"
        # types
        assert isinstance(j["pipeline_value"], (int, float))
        assert isinstance(j["conversion_rate"], (int, float))

    def test_analytics_non_founder_403(self, tokens):
        for role in ("sales", "planner", "ops"):
            r = auth_client(tokens[role]).get(f"{BASE_URL}/api/analytics")
            assert r.status_code == 403, f"{role}: expected 403 got {r.status_code}"


# ---------- WebSocket ----------
def _ws_url_base():
    # https://host -> wss://host, http://host -> ws://host
    if BASE_URL.startswith("https://"):
        return "wss://" + BASE_URL[len("https://"):]
    if BASE_URL.startswith("http://"):
        return "ws://" + BASE_URL[len("http://"):]
    return BASE_URL


class TestWebsocket:
    def test_ws_valid_token(self, tokens):
        url = f"{_ws_url_base()}/api/ws?token={tokens['founder']}"

        async def run():
            async with websockets.connect(url, open_timeout=10, close_timeout=5) as ws:
                msg = await asyncio.wait_for(ws.recv(), timeout=5)
                data = json.loads(msg)
                assert data.get("type") == "hello", f"unexpected: {data}"
                assert "user_id" in data
        asyncio.get_event_loop().run_until_complete(run())

    def test_ws_invalid_token(self):
        url = f"{_ws_url_base()}/api/ws?token=not-a-valid-jwt"

        async def run():
            try:
                async with websockets.connect(url, open_timeout=10, close_timeout=5) as ws:
                    # Should not reach recv; server closes with 4401
                    await asyncio.wait_for(ws.recv(), timeout=5)
                    pytest.fail("Expected close with 4401 for invalid token")
            except websockets.exceptions.InvalidStatus as e:
                # Some proxies convert to HTTP error before handshake
                assert True
            except websockets.exceptions.ConnectionClosed as e:
                assert e.code == 4401, f"expected 4401 close, got {e.code}"
        asyncio.get_event_loop().run_until_complete(run())

    def test_ws_missing_token(self):
        url = f"{_ws_url_base()}/api/ws"

        async def run():
            try:
                async with websockets.connect(url, open_timeout=10, close_timeout=5) as ws:
                    await asyncio.wait_for(ws.recv(), timeout=5)
                    pytest.fail("Expected close with 4401 for missing token")
            except websockets.exceptions.InvalidStatus:
                assert True
            except websockets.exceptions.ConnectionClosed as e:
                assert e.code == 4401, f"expected 4401 close, got {e.code}"
        asyncio.get_event_loop().run_until_complete(run())


# ---------- Regression ----------
class TestRegression:
    def test_login_ok(self, tokens):
        assert tokens["founder"] and tokens["sales"] and tokens["planner"]

    def test_dashboard_ok(self, tokens):
        r = auth_client(tokens["founder"]).get(f"{BASE_URL}/api/dashboard")
        assert r.status_code == 200

    def test_leads_ok(self, tokens):
        r = auth_client(tokens["founder"]).get(f"{BASE_URL}/api/leads")
        assert r.status_code == 200 and isinstance(r.json(), list)

    def test_weddings_ok(self, tokens):
        r = auth_client(tokens["founder"]).get(f"{BASE_URL}/api/weddings")
        assert r.status_code == 200
        arr = r.json()
        assert len(arr) >= 1
        r2 = auth_client(tokens["founder"]).get(f"{BASE_URL}/api/weddings/{arr[0]['id']}")
        assert r2.status_code == 200

    def test_approvals_pending_ok(self, tokens):
        r = auth_client(tokens["founder"]).get(f"{BASE_URL}/api/approvals/pending")
        assert r.status_code == 200

    def test_activity_ok(self, tokens):
        r = auth_client(tokens["founder"]).get(f"{BASE_URL}/api/activity")
        assert r.status_code == 200
