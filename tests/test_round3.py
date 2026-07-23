"""
Round 3 backend tests: Classique One.
Covers: meta enums, seeded weddings, budget stripping for planners, founder-deck,
CSV export/import, lead conversion with body + milestones, reminders, team endpoint,
and PATCH stage to new stages ('In Talks', 'Non-Responsive', 'Spam').
"""
import io
import csv
import uuid
import requests
import pytest

from conftest import BASE_URL, auth_client


# ---------- Meta ----------
class TestMeta:
    def test_meta_sources_and_stages(self, tokens):
        c = auth_client(tokens["founder"])
        r = c.get(f"{BASE_URL}/api/meta")
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["lead_sources"] == [
            "Website", "Referrals", "Instagram", "Panel Properties", "Wed Me Good", "Wedding Wire"
        ]
        stages = data["lead_stages"]
        for s in ("In Talks", "Non-Responsive", "Spam"):
            assert s in stages, f"missing stage {s}: {stages}"


# ---------- Seeded weddings & budget stripping ----------
class TestSeededWeddings:
    def test_founder_sees_three_seeded_with_budget(self, tokens):
        c = auth_client(tokens["founder"])
        r = c.get(f"{BASE_URL}/api/weddings")
        assert r.status_code == 200, r.text
        docs = r.json()
        by_couple = {d["couple_name"]: d for d in docs}
        expected = {
            "Siddharth & Pranaya": ("Anantara Jewel Bagh, Jaipur", "2026-11-10"),
            "Somyadip & Shrisha":  ("La Pearl River Resort, Jim Corbett", "2026-12-11"),
            "Aditya & Vanshika":   ("The Roseate, Delhi", "2027-02-12"),
        }
        for name, (venue, date) in expected.items():
            assert name in by_couple, f"missing wedding {name}: got {list(by_couple.keys())}"
            w = by_couple[name]
            assert w["venue"] == venue, f"venue mismatch for {name}: {w['venue']}"
            assert w["start_date"].startswith(date), f"start_date mismatch for {name}: {w['start_date']}"
            assert "budget" in w and w["budget"] > 0, f"founder must see budget for {name}: {w}"

    def test_planner_list_and_detail_no_budget(self, tokens):
        c = auth_client(tokens["planner"])
        r = c.get(f"{BASE_URL}/api/weddings")
        assert r.status_code == 200, r.text
        docs = r.json()
        assert len(docs) > 0
        for d in docs:
            assert "budget" not in d, f"planner should not see budget in list: {d.keys()}"

        wid = docs[0]["id"]
        r2 = c.get(f"{BASE_URL}/api/weddings/{wid}")
        assert r2.status_code == 200, r2.text
        detail = r2.json()
        assert "budget" not in detail, "planner detail should not have budget"
        assert "est_profit" not in detail.get("stats", {}), "planner detail stats should not have est_profit"

    def test_founder_detail_has_budget_and_est_profit(self, tokens):
        c = auth_client(tokens["founder"])
        docs = c.get(f"{BASE_URL}/api/weddings").json()
        wid = docs[0]["id"]
        r = c.get(f"{BASE_URL}/api/weddings/{wid}")
        assert r.status_code == 200
        d = r.json()
        assert "budget" in d and d["budget"] > 0
        assert "est_profit" in d["stats"]


# ---------- Founder Deck ----------
class TestFounderDeck:
    def test_founder_deck_full_shape(self, tokens):
        c = auth_client(tokens["founder"])
        docs = c.get(f"{BASE_URL}/api/weddings").json()
        # Use Siddharth & Pranaya - has vendors + milestones
        target = next(d for d in docs if d["couple_name"] == "Siddharth & Pranaya")
        r = c.get(f"{BASE_URL}/api/weddings/{target['id']}/founder-deck")
        assert r.status_code == 200, r.text
        deck = r.json()
        for key in ("wedding", "financials", "vendor_lines", "milestones", "progress", "team"):
            assert key in deck, f"missing top-level key {key}"
        for f in ("contract_value", "gross_margin", "margin_pct",
                  "client_received", "client_scheduled", "client_outstanding",
                  "vendor_committed", "vendor_paid", "vendor_outstanding"):
            assert f in deck["financials"], f"missing financial field {f}"
        for p in ("tasks_pct", "rsvp_pct", "vendors_pct"):
            assert p in deck["progress"], f"missing progress field {p}"
        assert isinstance(deck["vendor_lines"], list) and len(deck["vendor_lines"]) > 0
        assert isinstance(deck["milestones"], list) and len(deck["milestones"]) > 0
        assert isinstance(deck["team"], list)

    def test_planner_forbidden(self, tokens):
        c_founder = auth_client(tokens["founder"])
        wid = c_founder.get(f"{BASE_URL}/api/weddings").json()[0]["id"]
        c = auth_client(tokens["planner"])
        r = c.get(f"{BASE_URL}/api/weddings/{wid}/founder-deck")
        assert r.status_code == 403, r.text


# ---------- CSV Export / Import ----------
class TestLeadsCSV:
    def test_export_csv(self, tokens):
        c = auth_client(tokens["founder"])
        r = c.get(f"{BASE_URL}/api/leads/export")
        assert r.status_code == 200, r.text
        assert "text/csv" in r.headers.get("content-type", ""), r.headers
        assert "attachment" in r.headers.get("content-disposition", "").lower()
        text = r.content.decode("utf-8-sig")
        rows = list(csv.DictReader(io.StringIO(text)))
        assert len(rows) >= 1
        # sanity check: has couple_name column
        assert "couple_name" in rows[0]

    def test_import_csv_valid_and_coerce_and_skip(self, tokens):
        c = auth_client(tokens["founder"])
        # 3-row CSV: valid, bad source, empty couple
        csv_text = (
            "couple_name,source,stage,score,phone,email,follow_up_date\n"
            "TESTR3_Valid1,Instagram,New Lead,50,,,\n"
            "TESTR3_Valid2,NotARealSource,New Lead,50,,,\n"
            ",Instagram,New Lead,50,,,\n"
        )
        files = {"file": ("leads.csv", csv_text.encode("utf-8"), "text/csv")}
        # requests will set proper multipart when using files=; remove default JSON header
        r = requests.post(
            f"{BASE_URL}/api/leads/import",
            files=files,
            headers={"Authorization": f"Bearer {tokens['founder']}"},
            timeout=30,
        )
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["added"] == 2, f"expected added=2, got {data}"
        assert data["skipped"] == 1, f"expected skipped=1, got {data}"
        # Verify row2 was coerced to Website
        leads = c.get(f"{BASE_URL}/api/leads").json()
        v2 = next((l for l in leads if l["couple_name"] == "TESTR3_Valid2"), None)
        assert v2 is not None, "TESTR3_Valid2 not persisted"
        assert v2["source"] == "Website", f"expected coerced Website, got {v2['source']}"

    def test_import_planner_forbidden(self, tokens):
        csv_text = "couple_name,source\nTESTR3_ShouldNot,Instagram\n"
        files = {"file": ("l.csv", csv_text.encode("utf-8"), "text/csv")}
        r = requests.post(
            f"{BASE_URL}/api/leads/import",
            files=files,
            headers={"Authorization": f"Bearer {tokens['planner']}"},
            timeout=30,
        )
        assert r.status_code == 403, r.text


# ---------- Lead → Wedding conversion with body ----------
class TestLeadConvert:
    def test_convert_with_body_seeds_milestones(self, tokens):
        c = auth_client(tokens["founder"])
        # Create a fresh lead
        payload = {"couple_name": f"TESTR3_Convert_{uuid.uuid4().hex[:6]}", "source": "Instagram", "stage": "Booked"}
        r = c.post(f"{BASE_URL}/api/leads", json=payload)
        assert r.status_code == 200, r.text
        lead_id = r.json()["id"]

        body = {
            "venue": "The Roseate, Delhi",
            "start_date": "2027-02-12T00:00:00Z",
            "end_date": "2027-02-14T00:00:00Z",
            "guest_count": 250,
            "budget": 38000000,
        }
        r2 = c.post(f"{BASE_URL}/api/leads/{lead_id}/convert", json=body)
        assert r2.status_code == 200, r2.text
        w = r2.json()
        assert w["venue"] == "The Roseate, Delhi"
        assert w["guest_count"] == 250
        assert float(w["budget"]) == 38000000.0
        assert w["start_date"].startswith("2027-02-12")
        assert w["end_date"].startswith("2027-02-14")

        # verify 5 milestones sum to 38000000
        pays = c.get(f"{BASE_URL}/api/weddings/{w['id']}/payments").json()
        client_milestones = [p for p in pays if p.get("type") == "ClientMilestone"]
        assert len(client_milestones) == 5, f"expected 5, got {len(client_milestones)}"
        total = sum(p["amount"] for p in client_milestones)
        assert abs(total - 38000000) < 1, f"milestones sum {total} != 38000000"

        # Second convert on same lead -> 400
        r3 = c.post(f"{BASE_URL}/api/leads/{lead_id}/convert", json=body)
        assert r3.status_code == 400, r3.text
        assert "converted" in r3.text.lower()


# ---------- Reminders ----------
class TestReminders:
    def test_founder_reminder_creates_planner_notification(self, tokens):
        cf = auth_client(tokens["founder"])
        cp = auth_client(tokens["planner"])
        # find planner user id
        planner_id = cp.get(f"{BASE_URL}/api/auth/me").json()["id"]
        title = f"TESTR3_Reminder_{uuid.uuid4().hex[:6]}"
        body = "please review vendor list"
        r = cf.post(f"{BASE_URL}/api/reminders", json={
            "user_id": planner_id, "title": title, "body": body,
        })
        assert r.status_code == 200, r.text
        # planner should see notification
        notifs = cp.get(f"{BASE_URL}/api/notifications").json()
        titles = [n["title"] for n in notifs["items"]]
        assert title in titles, f"reminder title not in planner notifications: {titles[:5]}"

    def test_planner_reminder_forbidden(self, tokens):
        cp = auth_client(tokens["planner"])
        planner_id = cp.get(f"{BASE_URL}/api/auth/me").json()["id"]
        r = cp.post(f"{BASE_URL}/api/reminders", json={
            "user_id": planner_id, "title": "x", "body": "y",
        })
        assert r.status_code == 403, r.text


# ---------- Team ----------
class TestTeam:
    def test_team_founder_returns_non_founders(self, tokens):
        c = auth_client(tokens["founder"])
        r = c.get(f"{BASE_URL}/api/team")
        assert r.status_code == 200, r.text
        docs = r.json()
        assert len(docs) > 0
        for u in docs:
            assert u["role"] != "Founder", f"founder leaked in team: {u}"
            assert isinstance(u["open_tasks"], int)
            assert isinstance(u["active_weddings"], int)

    def test_team_planner_forbidden(self, tokens):
        c = auth_client(tokens["planner"])
        r = c.get(f"{BASE_URL}/api/team")
        assert r.status_code == 403, r.text


# ---------- PATCH lead new stages ----------
class TestLeadStages:
    def test_patch_lead_to_new_stages(self, tokens):
        c = auth_client(tokens["founder"])
        # Create a fresh lead
        r = c.post(f"{BASE_URL}/api/leads", json={
            "couple_name": f"TESTR3_Stage_{uuid.uuid4().hex[:6]}", "source": "Instagram",
        })
        assert r.status_code == 200
        lid = r.json()["id"]
        for stage in ("In Talks", "Non-Responsive", "Spam"):
            r2 = c.patch(f"{BASE_URL}/api/leads/{lid}", json={"stage": stage})
            assert r2.status_code == 200, r2.text
            assert r2.json()["stage"] == stage, f"stage not updated to {stage}: {r2.json()}"
