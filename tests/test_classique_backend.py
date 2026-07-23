"""Backend tests for Classique One API."""
import requests
import pytest
from conftest import BASE_URL, auth_client, _login


# ---------- Auth ----------
class TestAuth:
    def test_login_success(self):
        r = _login("founder@classique.one", "Classique2026!")
        assert r.status_code == 200
        assert "access_token" in r.json()

    def test_login_bad_password(self):
        r = _login("founder@classique.one", "wrongpass")
        assert r.status_code == 401

    def test_me(self, tokens):
        r = auth_client(tokens["founder"]).get(f"{BASE_URL}/api/auth/me")
        assert r.status_code == 200
        j = r.json()
        assert j["email"] == "founder@classique.one"
        assert j["role"] == "Founder"


# ---------- Dashboard ----------
class TestDashboard:
    def test_founder(self, tokens):
        r = auth_client(tokens["founder"]).get(f"{BASE_URL}/api/dashboard")
        assert r.status_code == 200
        j = r.json()
        assert j["role"] == "Founder"
        for k in ("pipeline_leads", "conversion_rate", "approvals_due", "weddings_active"):
            assert k in j

    def test_sales(self, tokens):
        r = auth_client(tokens["sales"]).get(f"{BASE_URL}/api/dashboard")
        assert r.status_code == 200
        j = r.json()
        assert j["role"] == "Sales"
        assert "leads_total" in j and "leads_hot" in j

    def test_planner(self, tokens):
        r = auth_client(tokens["planner"]).get(f"{BASE_URL}/api/dashboard")
        assert r.status_code == 200
        assert "my_weddings" in r.json()


# ---------- RBAC ----------
class TestRBAC:
    def test_sales_cannot_access_approvals(self, tokens):
        r = auth_client(tokens["sales"]).get(f"{BASE_URL}/api/approvals/pending")
        assert r.status_code == 403

    def test_founder_can_access_approvals(self, tokens):
        r = auth_client(tokens["founder"]).get(f"{BASE_URL}/api/approvals/pending")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_sales_cannot_access_wedding(self, tokens):
        # founder lists weddings, sales tries to fetch one
        r = auth_client(tokens["founder"]).get(f"{BASE_URL}/api/weddings")
        assert r.status_code == 200
        wid = r.json()[0]["id"]
        r2 = auth_client(tokens["sales"]).get(f"{BASE_URL}/api/weddings/{wid}")
        assert r2.status_code == 403


# ---------- Leads ----------
class TestLeads:
    def test_list_leads(self, tokens):
        r = auth_client(tokens["sales"]).get(f"{BASE_URL}/api/leads")
        assert r.status_code == 200
        leads = r.json()
        assert len(leads) >= 6

    def test_patch_lead_and_convert(self, tokens):
        c = auth_client(tokens["founder"])
        leads = c.get(f"{BASE_URL}/api/leads").json()
        # Pick an unconverted non-Booked lead
        target = next(l for l in leads if not l.get("converted_wedding_id") and l["stage"] != "Booked")
        lid = target["id"]
        # PATCH stage + note
        r = c.patch(f"{BASE_URL}/api/leads/{lid}", json={"stage": "Negotiation", "note": "TEST_ note"})
        assert r.status_code == 200
        assert r.json()["stage"] == "Negotiation"
        assert any(n["text"] == "TEST_ note" for n in r.json().get("notes", []))
        # Convert
        r2 = c.post(f"{BASE_URL}/api/leads/{lid}/convert")
        assert r2.status_code == 200
        wid = r2.json()["id"]
        # Verify lead marked booked + wedding exists
        lead = c.get(f"{BASE_URL}/api/leads/{lid}").json()
        assert lead["converted_wedding_id"] == wid
        assert lead["stage"] == "Booked"
        w = c.get(f"{BASE_URL}/api/weddings/{wid}").json()
        assert w["couple_name"] == target["couple_name"]


# ---------- Weddings ----------
class TestWeddings:
    def test_list_weddings_founder(self, tokens):
        r = auth_client(tokens["founder"]).get(f"{BASE_URL}/api/weddings")
        assert r.status_code == 200
        weddings = r.json()
        assert len(weddings) >= 2
        for w in weddings:
            assert "war_room_active" in w
            assert "stats" in w
        # At least one wedding within 48h should have war_room_active true
        assert any(w["war_room_active"] for w in weddings)

    def test_get_wedding_stats(self, tokens):
        c = auth_client(tokens["founder"])
        wid = c.get(f"{BASE_URL}/api/weddings").json()[0]["id"]
        w = c.get(f"{BASE_URL}/api/weddings/{wid}").json()
        for k in ("vendors_total", "guests_total", "tasks_total", "client_collected"):
            assert k in w["stats"]

    def test_war_room_override(self, tokens):
        c = auth_client(tokens["founder"])
        wid = c.get(f"{BASE_URL}/api/weddings").json()[0]["id"]
        r = c.post(f"{BASE_URL}/api/weddings/{wid}/war-room?override=true")
        assert r.status_code == 200
        assert r.json()["war_room_override"] is True
        # Reset
        c.post(f"{BASE_URL}/api/weddings/{wid}/war-room?override=false")


# ---------- Tasks ----------
class TestTasks:
    def test_task_crud(self, tokens):
        c = auth_client(tokens["planner"])
        weddings = c.get(f"{BASE_URL}/api/weddings").json()
        wid = weddings[0]["id"]
        # Create
        r = c.post(f"{BASE_URL}/api/tasks", json={"wedding_id": wid, "title": "TEST_ task"})
        assert r.status_code == 200
        tid = r.json()["id"]
        # Patch through cycle
        for st in ("In Progress", "Awaiting Approval", "Completed"):
            r2 = c.patch(f"{BASE_URL}/api/tasks/{tid}", json={"status": st})
            assert r2.status_code == 200
            assert r2.json()["status"] == st
        # List
        tasks = c.get(f"{BASE_URL}/api/weddings/{wid}/tasks").json()
        assert any(t["id"] == tid for t in tasks)


# ---------- Vendors ----------
class TestVendors:
    def test_approve_flow(self, tokens):
        cf = auth_client(tokens["founder"])
        cp = auth_client(tokens["planner"])
        wid = cf.get(f"{BASE_URL}/api/weddings").json()[0]["id"]
        # Planner creates a vendor and requests advance approval
        v = cp.post(f"{BASE_URL}/api/vendors", json={
            "wedding_id": wid, "name": "TEST_ vendor A", "category": "Decor", "quoted_amount": 100000
        }).json()
        vid = v["id"]
        # Non-founder cannot directly set Advance Paid
        r_forbidden = cp.patch(f"{BASE_URL}/api/vendors/{vid}", json={"stage": "Advance Paid"})
        assert r_forbidden.status_code == 400
        # Request approval
        r = cp.post(f"{BASE_URL}/api/vendors/{vid}/request-approval", json={"action": "advance"})
        assert r.status_code == 200
        # Founder approves
        r2 = cf.post(f"{BASE_URL}/api/vendors/{vid}/decide", json={"approved": True})
        assert r2.status_code == 200
        assert r2.json()["stage"] == "Advance Paid"
        assert r2.json()["approval_status"] == "approved"

    def test_reject_flow(self, tokens):
        cf = auth_client(tokens["founder"])
        cp = auth_client(tokens["planner"])
        wid = cf.get(f"{BASE_URL}/api/weddings").json()[0]["id"]
        v = cp.post(f"{BASE_URL}/api/vendors", json={
            "wedding_id": wid, "name": "TEST_ vendor B", "category": "Catering", "quoted_amount": 50000
        }).json()
        vid = v["id"]
        cp.post(f"{BASE_URL}/api/vendors/{vid}/request-approval", json={"action": "final"})
        r = cf.post(f"{BASE_URL}/api/vendors/{vid}/decide", json={"approved": False, "reason": "Too costly"})
        assert r.status_code == 200
        assert r.json()["approval_status"] == "rejected"
        assert r.json()["stage"] == "Closed"


# ---------- Guests ----------
class TestGuests:
    def test_guest_flow(self, tokens):
        cp = auth_client(tokens["planner"])
        wid = cp.get(f"{BASE_URL}/api/weddings").json()[0]["id"]
        g = cp.post(f"{BASE_URL}/api/guests", json={"wedding_id": wid, "name": "TEST_ guest", "side": "Bride"}).json()
        gid = g["id"]
        assert g["rsvp_status"] == "Pending"
        r = cp.patch(f"{BASE_URL}/api/guests/{gid}", json={"rsvp_status": "Confirmed", "room_assignment": "Suite 999"})
        assert r.status_code == 200
        assert r.json()["rsvp_status"] == "Confirmed"
        assert r.json()["room_assignment"] == "Suite 999"


# ---------- Payments ----------
class TestPayments:
    def test_five_milestones_and_founder_mark(self, tokens):
        cf = auth_client(tokens["founder"])
        cp = auth_client(tokens["planner"])
        weddings = cf.get(f"{BASE_URL}/api/weddings").json()
        wid = next(w["id"] for w in weddings if w["couple_name"] == "Ananya & Arjun")
        payments = cf.get(f"{BASE_URL}/api/weddings/{wid}/payments").json()
        labels = sorted([p["milestone_label"] for p in payments])
        assert labels == sorted(["Booking", "Contract Signing", "1 Month Before", "15 Days Before", "Day Zero"])
        # Non-founder cannot mark
        pid = next(p["id"] for p in payments if p["status"] == "Upcoming")
        r = cp.post(f"{BASE_URL}/api/payments/{pid}/mark-received")
        assert r.status_code == 403
        # Founder can
        r2 = cf.post(f"{BASE_URL}/api/payments/{pid}/mark-received")
        assert r2.status_code == 200
        assert r2.json()["status"] == "Received"


# ---------- Activity ----------
class TestActivity:
    def test_activity_log(self, tokens):
        c = auth_client(tokens["founder"])
        r = c.get(f"{BASE_URL}/api/activity")
        assert r.status_code == 200
        docs = r.json()
        assert isinstance(docs, list)
        # After all above mutations, there should be entries
        assert len(docs) > 0
