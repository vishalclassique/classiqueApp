"""
Classique One - Internal Ops Backend
FastAPI + MongoDB + JWT + RBAC
"""
import os
import io
import csv
import uuid
import json
import asyncio
import logging
from enum import Enum
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Any, Set
from pathlib import Path

import jwt
from jwt.exceptions import InvalidTokenError
from fastapi import FastAPI, APIRouter, Depends, HTTPException, status, Request, WebSocket, WebSocketDisconnect, UploadFile, File
from fastapi.responses import Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, Field
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import DuplicateKeyError
from pwdlib import PasswordHash
from dotenv import load_dotenv

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("classique")

# ---------- Config ----------
MONGO_URL = os.environ["MONGO_URL"]
DB_NAME = os.environ["DB_NAME"]
JWT_SECRET_KEY = os.environ["JWT_SECRET_KEY"]
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))
FOUNDER_EMAIL = os.environ["FOUNDER_EMAIL"].lower().strip()
FOUNDER_PASSWORD = os.environ["FOUNDER_PASSWORD"]

password_hash = PasswordHash.recommended()
DUMMY_HASH = password_hash.hash("dummy")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

client = AsyncIOMotorClient(MONGO_URL)
db = client[DB_NAME]


# ---------- Enums ----------
class Role(str, Enum):
    founder = "Founder"
    sales = "Sales"
    wedding_planner = "Wedding Planner"
    operations_manager = "Operations Manager"
    rsvp_caller = "RSVP Caller"
    rsvp_messenger = "RSVP Messenger"
    freelancer = "Freelancer"


LEAD_STAGES = ["New Lead", "Contacted", "In Talks", "Discovery Call", "Proposal Shared", "Negotiation", "Follow-up", "Booked", "Non-Responsive", "Spam", "Lost"]
LEAD_SOURCES = ["Website", "Referrals", "Instagram", "Panel Properties", "Wed Me Good", "Wedding Wire"]
WEDDING_STATUS = ["Planning", "Active", "Completed"]
TASK_STATUS = ["Pending", "In Progress", "Awaiting Approval", "Completed"]
VENDOR_STAGES = ["Suggested", "Shortlisted", "Negotiation", "Approval Requested", "Closed", "Advance Paid", "Active", "Final Settlement"]
RSVP_STATUS = ["Pending", "Confirmed", "Declined"]
PAYMENT_MILESTONES = [
    {"label": "Booking", "pct": 20},
    {"label": "Contract Signing", "pct": 30},
    {"label": "1 Month Before", "pct": 20},
    {"label": "15 Days Before", "pct": 20},
    {"label": "Day Zero", "pct": 10},
]


# ---------- Models ----------
def now_iso():
    return datetime.now(timezone.utc).isoformat()


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserPublic(BaseModel):
    id: str
    email: EmailStr
    full_name: Optional[str] = None
    role: Role
    active_wedding_ids: List[str] = []
    is_active: bool = True
    must_change_password: bool = False


class UserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: Optional[str] = None
    role: Role
    active_wedding_ids: List[str] = []


class LeadCreate(BaseModel):
    couple_name: str
    source: str = "Instagram"
    stage: str = "New Lead"
    score: int = 0
    phone: Optional[str] = None
    email: Optional[str] = None
    follow_up_date: Optional[str] = None
    assigned_sales_rep: Optional[str] = None


class LeadUpdate(BaseModel):
    stage: Optional[str] = None
    score: Optional[int] = None
    follow_up_date: Optional[str] = None
    note: Optional[str] = None


class WeddingCreate(BaseModel):
    couple_name: str
    venue: str
    start_date: str
    end_date: str
    guest_count: int = 0
    budget: float = 0
    wedding_head_id: Optional[str] = None
    assigned_team: List[dict] = []


class TaskCreate(BaseModel):
    wedding_id: str
    title: str
    assignee_id: Optional[str] = None
    due_date: Optional[str] = None


class TaskUpdate(BaseModel):
    status: Optional[str] = None
    title: Optional[str] = None
    comment: Optional[str] = None


class VendorCreate(BaseModel):
    wedding_id: str
    name: str
    category: str
    phone: Optional[str] = None
    email: Optional[str] = None
    quoted_amount: float = 0


class VendorUpdate(BaseModel):
    stage: Optional[str] = None
    negotiated_amount: Optional[float] = None
    final_amount: Optional[float] = None
    advance_paid: Optional[float] = None
    note: Optional[str] = None


class VendorApprovalRequest(BaseModel):
    action: str  # 'advance' or 'final'


class ApprovalDecision(BaseModel):
    approved: bool
    reason: Optional[str] = None


class GuestCreate(BaseModel):
    wedding_id: str
    name: str
    side: str = "Bride"
    tags: List[str] = []
    phone: Optional[str] = None


class GuestUpdate(BaseModel):
    rsvp_status: Optional[str] = None
    room_assignment: Optional[str] = None
    pickup_flight: Optional[str] = None
    pickup_time: Optional[str] = None
    pickup_vehicle: Optional[str] = None
    note: Optional[str] = None


class ReminderCreate(BaseModel):
    user_id: str
    title: str
    body: str
    wedding_id: Optional[str] = None


# ---------- Helpers ----------
def strip_id(doc: dict) -> dict:
    if not doc:
        return doc
    doc.pop("_id", None)
    doc.pop("password_hash", None)
    return doc


def create_access_token(data: dict) -> str:
    payload = data.copy()
    payload["exp"] = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


async def get_current_user(token: str = Depends(oauth2_scheme)) -> UserPublic:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
            raise credentials_exception
    except InvalidTokenError:
        raise credentials_exception
    user = await db.users.find_one({"id": user_id}, {"_id": 0, "password_hash": 0})
    if not user or not user.get("is_active", True):
        raise credentials_exception
    return UserPublic(**user)


def require_roles(*allowed: Role):
    async def guard(current_user: UserPublic = Depends(get_current_user)) -> UserPublic:
        if current_user.role not in allowed:
            raise HTTPException(status_code=403, detail="Forbidden")
        return current_user
    return guard


async def user_can_access_wedding(user: UserPublic, wedding_id: str) -> bool:
    if user.role == Role.founder:
        return True
    wedding = await db.weddings.find_one({"id": wedding_id}, {"_id": 0, "assigned_team": 1})
    if not wedding:
        return False
    team_ids = [m.get("user_id") for m in wedding.get("assigned_team", [])]
    return user.id in team_ids


async def log_activity(entity_type: str, entity_id: str, wedding_id: Optional[str], action: str, actor: UserPublic):
    entry = {
        "id": str(uuid.uuid4()),
        "entity_type": entity_type,
        "entity_id": entity_id,
        "wedding_id": wedding_id,
        "action": action,
        "actor_id": actor.id,
        "actor_name": actor.full_name or actor.email,
        "actor_role": actor.role,
        "created_at": now_iso(),
    }
    await db.activity_log.insert_one(entry.copy())
    await broadcaster.publish_founders({"type": "activity", "payload": {k: v for k, v in entry.items() if k != "_id"}})


# ---------- Notifications + WebSocket broadcaster ----------
class Broadcaster:
    """Per-user fanout. Each socket is registered against its authenticated user_id.
       Events are delivered only to that user's sockets (SEC-002)."""
    def __init__(self):
        self._per_user: dict[str, Set[WebSocket]] = {}
        self._all: Set[WebSocket] = set()  # only used for role-scoped events (e.g., 'activity' → founder)
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket, user_id: str, role: str):
        async with self._lock:
            self._per_user.setdefault(user_id, set()).add(ws)
            if role == Role.founder.value:
                self._all.add(ws)

    async def disconnect(self, ws: WebSocket, user_id: str):
        async with self._lock:
            self._per_user.get(user_id, set()).discard(ws)
            if not self._per_user.get(user_id):
                self._per_user.pop(user_id, None)
            self._all.discard(ws)

    async def publish_user(self, user_id: str, event: dict):
        payload = json.dumps(event)
        async with self._lock:
            targets = list(self._per_user.get(user_id, set()))
        for ws in targets:
            try:
                await ws.send_text(payload)
            except Exception:
                async with self._lock:
                    self._per_user.get(user_id, set()).discard(ws)
                    self._all.discard(ws)

    async def publish_founders(self, event: dict):
        """Broadcast to founder sockets only (used for activity feed)."""
        payload = json.dumps(event)
        async with self._lock:
            targets = list(self._all)
        for ws in targets:
            try:
                await ws.send_text(payload)
            except Exception:
                async with self._lock:
                    self._all.discard(ws)


broadcaster = Broadcaster()


async def notify(user_ids: List[str], title: str, body: str, kind: str, ref: Optional[dict] = None):
    """Create in-app notifications and push to that user's sockets only."""
    for uid in set(u for u in user_ids if u):
        doc = {
            "id": str(uuid.uuid4()),
            "user_id": uid,
            "title": title,
            "body": body,
            "kind": kind,
            "ref": ref or {},
            "read": False,
            "created_at": now_iso(),
        }
        await db.notifications.insert_one(doc.copy())
        doc.pop("_id", None)
        await broadcaster.publish_user(uid, {"type": "notification", "payload": doc})


async def founder_ids() -> List[str]:
    docs = await db.users.find({"role": Role.founder.value}, {"_id": 0, "id": 1}).to_list(50)
    return [d["id"] for d in docs]


# ---------- App / Router ----------
app = FastAPI(title="Classique One API")
api = APIRouter(prefix="/api")

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup():
    await db.users.create_index("email", unique=True)
    await db.users.create_index("id", unique=True)
    await db.leads.create_index("id", unique=True)
    await db.weddings.create_index("id", unique=True)
    await db.tasks.create_index("id", unique=True)
    await db.vendors.create_index("id", unique=True)
    await db.guests.create_index("id", unique=True)
    await db.payments.create_index("id", unique=True)
    await db.activity_log.create_index("id", unique=True)
    await db.notifications.create_index("id", unique=True)
    await db.notifications.create_index([("user_id", 1), ("created_at", -1)])
    await seed_data()
    await seed_settings()


async def seed_data():
    """Idempotent seed: founder + demo staff + demo wedding + demo leads."""
    # Founder
    founder = await db.users.find_one({"email": FOUNDER_EMAIL})
    if not founder:
        founder_id = str(uuid.uuid4())
        await db.users.insert_one({
            "id": founder_id,
            "email": FOUNDER_EMAIL,
            "full_name": "Simar Saluja",
            "password_hash": password_hash.hash(FOUNDER_PASSWORD),
            "role": Role.founder.value,
            "active_wedding_ids": [],
            "is_active": True,
            "must_change_password": False,
            "created_at": now_iso(),
        })
        founder = await db.users.find_one({"email": FOUNDER_EMAIL})
    else:
        # Keep founder identity in sync with brand config
        await db.users.update_one({"email": FOUNDER_EMAIL}, {"$set": {"full_name": "Simar Saluja"}})

    # SEC-001 remediation: remove any previously-seeded demo staff (sales/planner/ops)
    # whose passwords were hard-coded. Founder now creates real employees via User Management.
    demo_emails = ["sales@classique.one", "planner@classique.one", "ops@classique.one"]
    demo_users = await db.users.find({"email": {"$in": demo_emails}}, {"_id": 0, "id": 1}).to_list(20)
    if demo_users:
        demo_ids = [u["id"] for u in demo_users]
        # Unlink from weddings & tasks so the app remains consistent
        await db.weddings.update_many(
            {"assigned_team.user_id": {"$in": demo_ids}},
            {"$pull": {"assigned_team": {"user_id": {"$in": demo_ids}}}},
        )
        await db.weddings.update_many(
            {"wedding_head_id": {"$in": demo_ids}},
            {"$set": {"wedding_head_id": None}},
        )
        await db.tasks.update_many(
            {"assignee_id": {"$in": demo_ids}},
            {"$set": {"assignee_id": None}},
        )
        await db.users.delete_many({"id": {"$in": demo_ids}})

    # Migration: drop old placeholder weddings + their linked data (from earlier seed)
    placeholder_names = ["Ananya & Arjun", "Meera & Vikram", "Nikita & Ayaan"]
    old = await db.weddings.find({"couple_name": {"$in": placeholder_names}}, {"_id": 0, "id": 1}).to_list(50)
    if old:
        old_ids = [w["id"] for w in old]
        await db.vendors.delete_many({"wedding_id": {"$in": old_ids}})
        await db.tasks.delete_many({"wedding_id": {"$in": old_ids}})
        await db.guests.delete_many({"wedding_id": {"$in": old_ids}})
        await db.payments.delete_many({"wedding_id": {"$in": old_ids}})
        await db.weddings.delete_many({"id": {"$in": old_ids}})
        # Also unwind any conversion pointers from leads
        await db.leads.update_many({"converted_wedding_id": {"$in": old_ids}}, {"$set": {"converted_wedding_id": None}})

    if await db.weddings.count_documents({}) == 0:
        planner = None  # SEC-001: staff no longer seeded; founder creates real employees
        ops = None

        REAL_WEDDINGS = [
            {
                "couple_name": "Siddharth & Pranaya",
                "venue": "Anantara Jewel Bagh, Jaipur",
                "start": "2026-11-10", "days": 3, "guest_count": 280, "budget": 42000000,
                "status": "Active",
                "vendors": [
                    {"name": "Devika Narain Design", "category": "Decor", "quoted": 8500000, "stage": "Closed", "advance": 4250000, "final": 8500000},
                    {"name": "The Wedding Filmer", "category": "Photography", "quoted": 3200000, "stage": "Advance Paid", "advance": 1600000, "final": 3200000},
                    {"name": "Rajwadi Catering", "category": "Catering", "quoted": 11000000, "stage": "Closed", "advance": 5500000, "final": 11000000},
                    {"name": "Shivam Sound & Lights", "category": "Sound & Lighting", "quoted": 1500000, "stage": "Approval Requested", "advance": 0, "final": 1500000, "approval": "advance"},
                    {"name": "Bloom & Petal Florists", "category": "Florist", "quoted": 2200000, "stage": "Negotiation", "advance": 0, "final": 0},
                    {"name": "Kohl by Karishma", "category": "Makeup", "quoted": 900000, "stage": "Shortlisted", "advance": 0, "final": 0},
                ],
                "tasks": [
                    ("Confirm menu tasting date (Rajwadi)", "In Progress"),
                    ("Finalize mandap decor moodboard", "In Progress"),
                    ("Lock in transportation for outstation guests", "Pending"),
                    ("Sign off on invite design", "Awaiting Approval"),
                    ("Confirm hotel room block at Anantara", "Completed"),
                ],
                "guests": [
                    ("Vikram Saluja", "Groom", "Confirmed", "Deluxe 312"),
                    ("Anaya Malhotra", "Bride", "Confirmed", "Suite 205"),
                    ("Kunal Bansal", "Groom", "Pending", None),
                    ("Ritu Nair", "Bride", "Confirmed", "Deluxe 314"),
                    ("Aarav Kapoor", "Bride", "Declined", None),
                    ("Meher Iyer", "Bride", "Pending", None),
                ],
                "milestones": ["Booking", "Contract Signing"],  # received milestones
            },
            {
                "couple_name": "Somyadip & Shrisha",
                "venue": "La Pearl River Resort, Jim Corbett",
                "start": "2026-12-11", "days": 3, "guest_count": 180, "budget": 25000000,
                "status": "Active",
                "vendors": [
                    {"name": "Aashna Studios", "category": "Decor", "quoted": 4800000, "stage": "Closed", "advance": 2400000, "final": 4800000},
                    {"name": "Cinema of Poetry", "category": "Photography", "quoted": 2100000, "stage": "Closed", "advance": 1050000, "final": 2100000},
                    {"name": "Truffles Catering", "category": "Catering", "quoted": 6800000, "stage": "Negotiation", "advance": 0, "final": 0},
                    {"name": "Woods DJ Collective", "category": "Sound & Lighting", "quoted": 900000, "stage": "Shortlisted", "advance": 0, "final": 0},
                    {"name": "Meraki Florist", "category": "Florist", "quoted": 1400000, "stage": "Shortlisted", "advance": 0, "final": 0},
                ],
                "tasks": [
                    ("Recce La Pearl River Resort layout", "Completed"),
                    ("Confirm catering tasting menu", "In Progress"),
                    ("Draft transport plan from Delhi/Doon airports", "Pending"),
                    ("Finalize decor moodboard", "In Progress"),
                ],
                "guests": [
                    ("Rehan Chatterjee", "Groom", "Confirmed", "River Villa 4"),
                    ("Ishita Roy", "Bride", "Confirmed", "River Villa 6"),
                    ("Aniket Das", "Groom", "Pending", None),
                    ("Aditi Mukherjee", "Bride", "Confirmed", "Suite 12"),
                    ("Yash Ghosh", "Groom", "Declined", None),
                ],
                "milestones": ["Booking"],
            },
            {
                "couple_name": "Aditya & Vanshika",
                "venue": "The Roseate, Delhi",
                "start": "2027-02-12", "days": 3, "guest_count": 320, "budget": 48000000,
                "status": "Planning",
                "vendors": [
                    {"name": "Devika Narain Design", "category": "Decor", "quoted": 9200000, "stage": "Shortlisted", "advance": 0, "final": 0},
                    {"name": "House on the Clouds", "category": "Photography", "quoted": 3500000, "stage": "Shortlisted", "advance": 0, "final": 0},
                    {"name": "Foodlink Catering", "category": "Catering", "quoted": 12500000, "stage": "Suggested", "advance": 0, "final": 0},
                    {"name": "Rewind Sound", "category": "Sound & Lighting", "quoted": 1800000, "stage": "Suggested", "advance": 0, "final": 0},
                ],
                "tasks": [
                    ("Site visit to The Roseate", "Completed"),
                    ("Shortlist decor partners", "In Progress"),
                    ("Draft first budget cut for client", "Pending"),
                ],
                "guests": [
                    ("Karan Aditya", "Groom", "Pending", None),
                    ("Naina Vanshika", "Bride", "Pending", None),
                    ("Sneha Aditya", "Groom", "Pending", None),
                ],
                "milestones": [],  # nothing collected yet
            },
        ]

        for w in REAL_WEDDINGS:
            wid = str(uuid.uuid4())
            start_dt = datetime.fromisoformat(w["start"]).replace(tzinfo=timezone.utc, hour=10)
            end_dt = start_dt + timedelta(days=w["days"])
            team: List[dict] = []
            if planner: team.append({"user_id": planner["id"], "role": Role.wedding_planner.value})
            if ops and w["status"] == "Active": team.append({"user_id": ops["id"], "role": Role.operations_manager.value})
            await db.weddings.insert_one({
                "id": wid,
                "couple_name": w["couple_name"],
                "venue": w["venue"],
                "start_date": start_dt.isoformat(),
                "end_date": end_dt.isoformat(),
                "guest_count": w["guest_count"],
                "budget": w["budget"],
                "wedding_head_id": planner["id"] if planner else None,
                "assigned_team": team,
                "status": w["status"],
                "war_room_override": None,
                "created_at": now_iso(),
            })

            for v in w["vendors"]:
                await db.vendors.insert_one({
                    "id": str(uuid.uuid4()),
                    "wedding_id": wid,
                    "name": v["name"], "category": v["category"],
                    "phone": "+91 98XXX XXXXX",
                    "email": v["name"].lower().replace(" ", "").replace("&", "and") + "@vendor.co",
                    "stage": v["stage"],
                    "quoted_amount": v["quoted"],
                    "negotiated_amount": v["quoted"] * 0.95,
                    "final_amount": v["final"],
                    "advance_paid": v["advance"],
                    "retention_pct": 15,
                    "approval_status": "pending" if v.get("approval") else "none",
                    "pending_action": v.get("approval"),
                    "notes": [],
                    "created_by": planner["id"] if planner else None,
                    "created_at": now_iso(),
                })

            for title, st in w["tasks"]:
                await db.tasks.insert_one({
                    "id": str(uuid.uuid4()),
                    "wedding_id": wid, "title": title,
                    "assignee_id": planner["id"] if planner else None,
                    "due_date": (datetime.now(timezone.utc) + timedelta(days=7)).isoformat(),
                    "status": st, "comments": [], "created_at": now_iso(),
                })

            for name, side, rsvp, room in w["guests"]:
                await db.guests.insert_one({
                    "id": str(uuid.uuid4()),
                    "wedding_id": wid, "name": name, "side": side,
                    "tags": [],
                    "phone": "+91 98XXX XXXXX",
                    "rsvp_status": rsvp,
                    "room_assignment": room,
                    "pickup_flight": "AI-864" if rsvp == "Confirmed" else None,
                    "pickup_time": "14:30 IST" if rsvp == "Confirmed" else None,
                    "pickup_vehicle": "Sedan" if rsvp == "Confirmed" else None,
                    "notes": [], "created_at": now_iso(),
                })

            for m in PAYMENT_MILESTONES:
                amt = w["budget"] * (m["pct"] / 100)
                await db.payments.insert_one({
                    "id": str(uuid.uuid4()),
                    "wedding_id": wid,
                    "type": "ClientMilestone",
                    "milestone_label": m["label"],
                    "vendor_id": None,
                    "amount": amt,
                    "status": "Received" if m["label"] in w["milestones"] else "Upcoming",
                    "created_at": now_iso(),
                })

        # Sync active_wedding_ids for team (no-op when staff isn't seeded)
        all_ids = [w["id"] for w in await db.weddings.find({}, {"_id": 0, "id": 1}).to_list(50)]
        if planner:
            await db.users.update_one({"id": planner["id"]}, {"$set": {"active_wedding_ids": all_ids}})
        if ops:
            active_only = [w["id"] for w in await db.weddings.find({"status": "Active"}, {"_id": 0, "id": 1}).to_list(50)]
            await db.users.update_one({"id": ops["id"]}, {"$set": {"active_wedding_ids": active_only}})

    # Leads: also unlink sales_rep pointers to demo users
    sales_stale = await db.leads.find({"assigned_sales_rep": {"$ne": None}}, {"_id": 0, "assigned_sales_rep": 1}).to_list(500)
    stale_reps = {l["assigned_sales_rep"] for l in sales_stale}
    for rep_id in stale_reps:
        exists = await db.users.find_one({"id": rep_id}, {"_id": 0, "id": 1})
        if not exists:
            await db.leads.update_many({"assigned_sales_rep": rep_id}, {"$set": {"assigned_sales_rep": None}})

    # Migration: normalize old lead sources to the new canonical set
    src_map = {"WedMeGood": "Wed Me Good", "Wed me good": "Wed Me Good", "WeddingWire": "Wedding Wire",
               "Referral": "Referrals", "Phone": "Referrals", "WhatsApp": "Referrals"}
    for old, new in src_map.items():
        await db.leads.update_many({"source": old}, {"$set": {"source": new}})

    # Leads
    if await db.leads.count_documents({}) == 0:
        sales = None  # SEC-001: staff no longer seeded
        lead_seed = [
            ("Naina & Arjun", "Instagram", "New Lead", 82),
            ("Sanjana & Rehan", "Referrals", "Proposal Shared", 68),
            ("Kiara & Yash", "Wed Me Good", "Negotiation", 91),
            ("Tara & Dev", "Website", "Contacted", 54),
            ("Nikita & Ayaan", "Panel Properties", "Discovery Call", 73),
            ("Meher & Zayn", "Wedding Wire", "Booked", 88),
        ]
        for name, src, stage, score in lead_seed:
            await db.leads.insert_one({
                "id": str(uuid.uuid4()),
                "couple_name": name,
                "source": src,
                "stage": stage,
                "score": score,
                "phone": "+91 98XXX XXXXX",
                "email": name.split(" ")[0].lower() + "@mail.com",
                "follow_up_date": (datetime.now(timezone.utc) + timedelta(days=2)).isoformat(),
                "assigned_sales_rep": sales["id"] if sales else None,
                "notes": [],
                "converted_wedding_id": None,
                "created_at": now_iso(),
            })


# ---------- Auth ----------
@api.post("/auth/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    email = form_data.username.lower().strip()
    user = await db.users.find_one({"email": email})
    if not user:
        password_hash.verify(form_data.password, DUMMY_HASH)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not password_hash.verify(form_data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.get("is_active", True):
        raise HTTPException(status_code=401, detail="Account is inactive")
    return Token(access_token=create_access_token({"sub": user["id"], "role": user["role"]}))


@api.get("/auth/me", response_model=UserPublic)
async def me(current: UserPublic = Depends(get_current_user)):
    return current


@api.get("/users")
async def list_users(current: UserPublic = Depends(get_current_user)):
    if current.role != Role.founder:
        # Non-founders get a minimal roster (no PII beyond name/role) for team pickers
        docs = await db.users.find({"is_active": True}, {"_id": 0, "id": 1, "full_name": 1, "role": 1}).to_list(500)
        return docs
    docs = await db.users.find({}, {"_id": 0, "password_hash": 0}).to_list(500)
    return docs


class UserCreatePayload(BaseModel):
    email: EmailStr
    full_name: str
    role: Role
    initial_password: str = Field(min_length=8)


class UserUpdatePayload(BaseModel):
    full_name: Optional[str] = None
    role: Optional[Role] = None
    is_active: Optional[bool] = None


class PasswordResetPayload(BaseModel):
    new_password: str = Field(min_length=8)


class ChangePasswordPayload(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8)


@api.post("/users", status_code=201)
async def create_user(payload: UserCreatePayload, current: UserPublic = Depends(require_roles(Role.founder))):
    email = payload.email.lower().strip()
    if payload.role == Role.founder:
        raise HTTPException(400, "Cannot create another Founder account")
    if await db.users.find_one({"email": email}):
        raise HTTPException(409, "A user with this email already exists")
    doc = {
        "id": str(uuid.uuid4()),
        "email": email,
        "full_name": payload.full_name.strip(),
        "password_hash": password_hash.hash(payload.initial_password),
        "role": payload.role.value,
        "active_wedding_ids": [],
        "is_active": True,
        "must_change_password": True,
        "created_at": now_iso(),
        "created_by": current.id,
    }
    await db.users.insert_one(doc.copy())
    await log_activity("user", doc["id"], None, f"Created account for {payload.full_name} ({payload.role.value})", current)
    doc.pop("_id", None); doc.pop("password_hash", None)
    return doc


@api.patch("/users/{user_id}")
async def update_user(user_id: str, payload: UserUpdatePayload, current: UserPublic = Depends(require_roles(Role.founder))):
    if user_id == current.id:
        raise HTTPException(400, "Use /auth/change-password to update your own account")
    target = await db.users.find_one({"id": user_id}, {"_id": 0, "role": 1, "full_name": 1, "email": 1})
    if not target:
        raise HTTPException(404, "User not found")
    if target.get("role") == Role.founder.value:
        raise HTTPException(400, "Cannot modify the Founder account")
    update: dict = {}
    if payload.full_name is not None:
        update["full_name"] = payload.full_name.strip()
    if payload.role is not None:
        if payload.role == Role.founder:
            raise HTTPException(400, "Cannot promote to Founder")
        update["role"] = payload.role.value
    if payload.is_active is not None:
        update["is_active"] = payload.is_active
    if update:
        await db.users.update_one({"id": user_id}, {"$set": update})
        await log_activity("user", user_id, None, f"Updated {target.get('full_name') or target.get('email')}: {', '.join(update.keys())}", current)
    return await db.users.find_one({"id": user_id}, {"_id": 0, "password_hash": 0})


@api.post("/users/{user_id}/reset-password")
async def reset_password(user_id: str, payload: PasswordResetPayload, current: UserPublic = Depends(require_roles(Role.founder))):
    target = await db.users.find_one({"id": user_id}, {"_id": 0, "role": 1, "email": 1, "full_name": 1})
    if not target:
        raise HTTPException(404, "User not found")
    if target.get("role") == Role.founder.value:
        raise HTTPException(400, "Founder resets their own password via /auth/change-password")
    await db.users.update_one({"id": user_id}, {"$set": {
        "password_hash": password_hash.hash(payload.new_password),
        "must_change_password": True,
    }})
    await log_activity("user", user_id, None, f"Reset password for {target.get('full_name') or target.get('email')}", current)
    return {"ok": True}


@api.post("/auth/change-password")
async def change_password(payload: ChangePasswordPayload, current: UserPublic = Depends(get_current_user)):
    user = await db.users.find_one({"id": current.id})
    if not user or not password_hash.verify(payload.current_password, user["password_hash"]):
        raise HTTPException(401, "Current password is incorrect")
    await db.users.update_one({"id": current.id}, {"$set": {
        "password_hash": password_hash.hash(payload.new_password),
        "must_change_password": False,
    }})
    await log_activity("user", current.id, None, "Changed own password", current)
    return {"ok": True}


# ---------- Meta ----------
@api.get("/meta")
async def meta():
    return {
        "lead_stages": LEAD_STAGES,
        "lead_sources": LEAD_SOURCES,
        "wedding_status": WEDDING_STATUS,
        "task_status": TASK_STATUS,
        "vendor_stages": VENDOR_STAGES,
        "rsvp_status": RSVP_STATUS,
        "payment_milestones": PAYMENT_MILESTONES,
    }


# ---------- Leads ----------
@api.get("/leads")
async def list_leads(
    stage: Optional[str] = None,
    current: UserPublic = Depends(get_current_user),
):
    if current.role not in (Role.founder, Role.sales):
        raise HTTPException(403, "Forbidden")
    q: dict = {}
    if stage:
        q["stage"] = stage
    docs = await db.leads.find(q, {"_id": 0}).sort("created_at", -1).to_list(1000)
    return docs


@api.get("/leads/export")
async def export_leads(current: UserPublic = Depends(get_current_user)):
    if current.role not in (Role.founder, Role.sales):
        raise HTTPException(403, "Forbidden")
    docs = await db.leads.find({}, {"_id": 0}).sort("created_at", -1).to_list(5000)

    def safe(v: Any) -> str:
        """SEC-003: prefix a leading =,+,-,@,tab,CR with a single quote to prevent
        CSV formula injection when the file is opened in Excel/Sheets."""
        s = "" if v is None else str(v)
        if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
            return "'" + s
        return s

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["couple_name", "source", "stage", "score", "phone", "email", "follow_up_date", "created_at"])
    for d in docs:
        writer.writerow([
            safe(d.get("couple_name", "")),
            safe(d.get("source", "")),
            safe(d.get("stage", "")),
            d.get("score", 0),
            safe(d.get("phone", "")),
            safe(d.get("email", "")),
            safe(d.get("follow_up_date", "")),
            safe(d.get("created_at", "")),
        ])
    csv_bytes = buf.getvalue().encode("utf-8-sig")
    return Response(
        content=csv_bytes,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=classique_leads.csv"},
    )


@api.post("/leads/import")
async def import_leads(file: UploadFile = File(...), current: UserPublic = Depends(require_roles(Role.founder, Role.sales))):
    raw = (await file.read()).decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(raw))
    valid_stages = set(LEAD_STAGES)
    valid_sources = set(LEAD_SOURCES)
    added = 0
    skipped = 0
    errors: List[str] = []
    for i, row in enumerate(reader, start=2):
        couple = (row.get("couple_name") or "").strip()
        if not couple:
            skipped += 1; errors.append(f"Row {i}: missing couple_name"); continue
        source = (row.get("source") or "Website").strip()
        if source not in valid_sources:
            source = "Website"
        stage = (row.get("stage") or "New Lead").strip()
        if stage not in valid_stages:
            stage = "New Lead"
        try:
            score = int(float(row.get("score") or 0))
        except Exception:
            score = 0
        follow = (row.get("follow_up_date") or "").strip() or None
        doc = {
            "id": str(uuid.uuid4()),
            "couple_name": couple,
            "source": source,
            "stage": stage,
            "score": score,
            "phone": (row.get("phone") or "").strip(),
            "email": (row.get("email") or "").strip(),
            "follow_up_date": follow,
            "assigned_sales_rep": current.id if current.role == Role.sales else None,
            "notes": [],
            "converted_wedding_id": None,
            "created_at": now_iso(),
            "created_by": current.id,
            "imported": True,
        }
        await db.leads.insert_one(doc.copy())
        added += 1
    await log_activity("lead", "bulk", None, f"Imported {added} leads from CSV (skipped {skipped})", current)
    return {"added": added, "skipped": skipped, "errors": errors[:20]}


@api.post("/leads")
async def create_lead(payload: LeadCreate, current: UserPublic = Depends(require_roles(Role.founder, Role.sales))):
    doc = payload.dict()
    doc.update({
        "id": str(uuid.uuid4()),
        "notes": [],
        "converted_wedding_id": None,
        "created_at": now_iso(),
        "created_by": current.id,
    })
    await db.leads.insert_one(doc.copy())
    doc.pop("_id", None)
    return doc


@api.get("/leads/{lead_id}")
async def get_lead(lead_id: str, current: UserPublic = Depends(get_current_user)):
    if current.role not in (Role.founder, Role.sales):
        raise HTTPException(403, "Forbidden")
    doc = await db.leads.find_one({"id": lead_id}, {"_id": 0})
    if not doc:
        raise HTTPException(404, "Not found")
    return doc


@api.patch("/leads/{lead_id}")
async def update_lead(lead_id: str, payload: LeadUpdate, current: UserPublic = Depends(require_roles(Role.founder, Role.sales))):
    update: dict = {}
    if payload.stage:
        update["stage"] = payload.stage
    if payload.score is not None:
        update["score"] = payload.score
    if payload.follow_up_date:
        update["follow_up_date"] = payload.follow_up_date
    if update:
        await db.leads.update_one({"id": lead_id}, {"$set": update})
    if payload.note:
        await db.leads.update_one({"id": lead_id}, {"$push": {"notes": {
            "author_id": current.id, "author_name": current.full_name or current.email,
            "text": payload.note, "created_at": now_iso(),
        }}})
    return await db.leads.find_one({"id": lead_id}, {"_id": 0})


class LeadConvert(BaseModel):
    venue: Optional[str] = None
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    guest_count: int = 0
    budget: float = 0
    wedding_head_id: Optional[str] = None


@api.post("/leads/{lead_id}/convert")
async def convert_lead(lead_id: str, payload: Optional[LeadConvert] = None, current: UserPublic = Depends(require_roles(Role.founder, Role.sales))):
    lead = await db.leads.find_one({"id": lead_id}, {"_id": 0})
    if not lead:
        raise HTTPException(404, "Lead not found")
    if lead.get("converted_wedding_id"):
        raise HTTPException(400, "Already converted")
    p = payload or LeadConvert()
    wedding_id = str(uuid.uuid4())
    try:
        start_dt = datetime.fromisoformat(p.start_date.replace("Z", "+00:00")) if p.start_date else (datetime.now(timezone.utc) + timedelta(days=60))
    except Exception:
        start_dt = datetime.now(timezone.utc) + timedelta(days=60)
    try:
        end_dt = datetime.fromisoformat(p.end_date.replace("Z", "+00:00")) if p.end_date else (start_dt + timedelta(days=3))
    except Exception:
        end_dt = start_dt + timedelta(days=3)
    team: List[dict] = []
    if p.wedding_head_id:
        team.append({"user_id": p.wedding_head_id, "role": Role.wedding_planner.value})
    wedding = {
        "id": wedding_id,
        "couple_name": lead["couple_name"],
        "venue": p.venue or "TBD",
        "start_date": start_dt.isoformat(),
        "end_date": end_dt.isoformat(),
        "guest_count": p.guest_count or 0,
        "budget": p.budget or 0,
        "wedding_head_id": p.wedding_head_id,
        "assigned_team": team,
        "status": "Planning",
        "war_room_override": None,
        "created_at": now_iso(),
        "created_by": current.id,
        "source_lead_id": lead_id,
    }
    await db.weddings.insert_one(wedding.copy())
    # Seed the 5 client milestones for the new wedding
    for m in PAYMENT_MILESTONES:
        amt = (p.budget or 0) * (m["pct"] / 100)
        await db.payments.insert_one({
            "id": str(uuid.uuid4()),
            "wedding_id": wedding_id,
            "type": "ClientMilestone",
            "milestone_label": m["label"],
            "vendor_id": None,
            "amount": amt,
            "status": "Upcoming",
            "created_at": now_iso(),
        })
    await db.leads.update_one({"id": lead_id}, {"$set": {"converted_wedding_id": wedding_id, "stage": "Booked"}})
    await log_activity("wedding", wedding_id, wedding_id, f"Converted from lead {lead['couple_name']}", current)
    wedding.pop("_id", None)
    return wedding


# ---------- Weddings ----------
def compute_war_room(wedding: dict) -> bool:
    override = wedding.get("war_room_override")
    if override is not None:
        return bool(override)
    raw = wedding.get("start_date")
    if not raw:
        return False
    try:
        start = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except Exception:
        return False
    # Ensure timezone-aware for comparison
    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)
    delta = start - datetime.now(timezone.utc)
    return delta <= timedelta(hours=48) and delta >= timedelta(hours=-72)


@api.get("/weddings")
async def list_weddings(current: UserPublic = Depends(get_current_user)):
    q: dict = {}
    if current.role != Role.founder:
        q = {"assigned_team.user_id": current.id}
    docs = await db.weddings.find(q, {"_id": 0}).sort("start_date", 1).to_list(500)
    for d in docs:
        d["war_room_active"] = compute_war_room(d)
        if current.role != Role.founder:
            d.pop("budget", None)  # commercial figure — founder only
        # attach quick counts (used by war-room banner on Home)
        wid = d["id"]
        vendors = await db.vendors.find({"wedding_id": wid}, {"_id": 0, "stage": 1}).to_list(500)
        guests = await db.guests.find({"wedding_id": wid}, {"_id": 0, "rsvp_status": 1, "room_assignment": 1}).to_list(2000)
        tasks_open = await db.tasks.count_documents({"wedding_id": wid, "status": {"$ne": "Completed"}})
        d["stats"] = {
            "vendors_total": len(vendors),
            "vendors_ready": sum(1 for v in vendors if v.get("stage") in ("Closed", "Advance Paid", "Active", "Final Settlement")),
            "guests_total": len(guests),
            "guests_confirmed": sum(1 for g in guests if g.get("rsvp_status") == "Confirmed"),
            "rooms_assigned": sum(1 for g in guests if g.get("room_assignment")),
            "tasks_open": tasks_open,
        }
    return docs


@api.get("/weddings/{wedding_id}")
async def get_wedding(wedding_id: str, current: UserPublic = Depends(get_current_user)):
    if not await user_can_access_wedding(current, wedding_id):
        raise HTTPException(403, "Forbidden")
    w = await db.weddings.find_one({"id": wedding_id}, {"_id": 0})
    if not w:
        raise HTTPException(404, "Not found")
    w["war_room_active"] = compute_war_room(w)

    # Aggregated stats for wedding hub
    vendors = await db.vendors.find({"wedding_id": wedding_id}, {"_id": 0}).to_list(500)
    tasks = await db.tasks.find({"wedding_id": wedding_id}, {"_id": 0}).to_list(500)
    guests = await db.guests.find({"wedding_id": wedding_id}, {"_id": 0}).to_list(2000)
    payments = await db.payments.find({"wedding_id": wedding_id}, {"_id": 0}).to_list(500)

    vendors_ready = sum(1 for v in vendors if v["stage"] in ("Closed", "Advance Paid", "Active", "Final Settlement"))
    guests_confirmed = sum(1 for g in guests if g["rsvp_status"] == "Confirmed")
    pickups_pending = sum(1 for g in guests if g["rsvp_status"] == "Confirmed" and not g.get("pickup_flight"))
    rooms_assigned = sum(1 for g in guests if g.get("room_assignment"))
    payments_pending = sum(1 for p in payments if p["status"] in ("Upcoming", "Pending Approval"))
    tasks_open = sum(1 for t in tasks if t["status"] != "Completed")

    total_paid_client = sum(p["amount"] for p in payments if p["type"] == "ClientMilestone" and p["status"] == "Received")
    total_client = sum(p["amount"] for p in payments if p["type"] == "ClientMilestone")
    vendor_total = sum(v.get("final_amount", 0) or 0 for v in vendors)
    vendor_paid = sum(v.get("advance_paid", 0) or 0 for v in vendors)

    w["stats"] = {
        "vendors_total": len(vendors),
        "vendors_ready": vendors_ready,
        "guests_total": len(guests),
        "guests_confirmed": guests_confirmed,
        "pickups_pending": pickups_pending,
        "rooms_assigned": rooms_assigned,
        "payments_pending": payments_pending,
        "tasks_total": len(tasks),
        "tasks_open": tasks_open,
        "client_collected": total_paid_client,
        "client_total": total_client,
        "vendor_committed": vendor_total,
        "vendor_paid": vendor_paid,
    }
    if current.role == Role.founder:
        w["stats"]["est_profit"] = (w.get("budget", 0) or 0) - vendor_total
    else:
        w.pop("budget", None)  # commercial figure — founder only
    return w


@api.post("/weddings")
async def create_wedding(payload: WeddingCreate, current: UserPublic = Depends(require_roles(Role.founder))):
    doc = {
        "id": str(uuid.uuid4()),
        "couple_name": payload.couple_name,
        "venue": payload.venue,
        "start_date": payload.start_date,
        "end_date": payload.end_date,
        "guest_count": payload.guest_count,
        "budget": payload.budget,
        "wedding_head_id": payload.wedding_head_id,
        "assigned_team": payload.assigned_team,
        "status": "Planning",
        "war_room_override": None,
        "created_at": now_iso(),
        "created_by": current.id,
    }
    await db.weddings.insert_one(doc.copy())
    await log_activity("wedding", doc["id"], doc["id"], f"Created wedding {doc['couple_name']}", current)
    doc.pop("_id", None)
    return doc


@api.post("/weddings/{wedding_id}/war-room")
async def toggle_war_room(wedding_id: str, override: Optional[bool] = None, current: UserPublic = Depends(get_current_user)):
    if not await user_can_access_wedding(current, wedding_id):
        raise HTTPException(403, "Forbidden")
    await db.weddings.update_one({"id": wedding_id}, {"$set": {"war_room_override": override}})
    await log_activity("wedding", wedding_id, wedding_id, f"War Room override set to {override}", current)
    return {"ok": True, "war_room_override": override}


# ---------- Tasks ----------
@api.get("/weddings/{wedding_id}/tasks")
async def list_tasks(wedding_id: str, current: UserPublic = Depends(get_current_user)):
    if not await user_can_access_wedding(current, wedding_id):
        raise HTTPException(403, "Forbidden")
    return await db.tasks.find({"wedding_id": wedding_id}, {"_id": 0}).sort("created_at", -1).to_list(500)


@api.post("/tasks")
async def create_task(payload: TaskCreate, current: UserPublic = Depends(get_current_user)):
    if not await user_can_access_wedding(current, payload.wedding_id):
        raise HTTPException(403, "Forbidden")
    doc = {
        "id": str(uuid.uuid4()),
        "wedding_id": payload.wedding_id,
        "title": payload.title,
        "assignee_id": payload.assignee_id,
        "due_date": payload.due_date,
        "status": "Pending",
        "comments": [],
        "created_at": now_iso(),
        "created_by": current.id,
    }
    await db.tasks.insert_one(doc.copy())
    await log_activity("task", doc["id"], payload.wedding_id, f"Created task '{payload.title}'", current)
    if payload.assignee_id and payload.assignee_id != current.id:
        await notify(
            [payload.assignee_id],
            "New task assigned",
            payload.title,
            "task",
            {"task_id": doc["id"], "wedding_id": payload.wedding_id},
        )
    doc.pop("_id", None)
    return doc


@api.patch("/tasks/{task_id}")
async def update_task(task_id: str, payload: TaskUpdate, current: UserPublic = Depends(get_current_user)):
    task = await db.tasks.find_one({"id": task_id}, {"_id": 0})
    if not task:
        raise HTTPException(404, "Not found")
    if not await user_can_access_wedding(current, task["wedding_id"]):
        raise HTTPException(403, "Forbidden")
    update: dict = {}
    if payload.status:
        if payload.status not in TASK_STATUS:
            raise HTTPException(400, "Invalid status")
        update["status"] = payload.status
    if payload.title:
        update["title"] = payload.title
    if update:
        await db.tasks.update_one({"id": task_id}, {"$set": update})
    if payload.comment:
        await db.tasks.update_one({"id": task_id}, {"$push": {"comments": {
            "author_id": current.id, "text": payload.comment, "created_at": now_iso(),
        }}})
    await log_activity("task", task_id, task["wedding_id"], f"Updated task '{task['title']}'", current)
    return await db.tasks.find_one({"id": task_id}, {"_id": 0})


# ---------- Vendors ----------
@api.get("/weddings/{wedding_id}/vendors")
async def list_vendors(wedding_id: str, current: UserPublic = Depends(get_current_user)):
    if not await user_can_access_wedding(current, wedding_id):
        raise HTTPException(403, "Forbidden")
    return await db.vendors.find({"wedding_id": wedding_id}, {"_id": 0}).sort("created_at", -1).to_list(500)


@api.post("/vendors")
async def create_vendor(payload: VendorCreate, current: UserPublic = Depends(get_current_user)):
    if not await user_can_access_wedding(current, payload.wedding_id):
        raise HTTPException(403, "Forbidden")
    doc = {
        "id": str(uuid.uuid4()),
        "wedding_id": payload.wedding_id,
        "name": payload.name,
        "category": payload.category,
        "phone": payload.phone,
        "email": payload.email,
        "stage": "Shortlisted",
        "quoted_amount": payload.quoted_amount,
        "negotiated_amount": 0,
        "final_amount": 0,
        "advance_paid": 0,
        "retention_pct": 15,
        "approval_status": "none",
        "pending_action": None,
        "notes": [],
        "created_at": now_iso(),
        "created_by": current.id,
    }
    await db.vendors.insert_one(doc.copy())
    await log_activity("vendor", doc["id"], payload.wedding_id, f"Added vendor {payload.name}", current)
    doc.pop("_id", None)
    return doc


@api.get("/vendors/{vendor_id}")
async def get_vendor(vendor_id: str, current: UserPublic = Depends(get_current_user)):
    v = await db.vendors.find_one({"id": vendor_id}, {"_id": 0})
    if not v:
        raise HTTPException(404, "Not found")
    if not await user_can_access_wedding(current, v["wedding_id"]):
        raise HTTPException(403, "Forbidden")
    return v


@api.patch("/vendors/{vendor_id}")
async def update_vendor(vendor_id: str, payload: VendorUpdate, current: UserPublic = Depends(get_current_user)):
    v = await db.vendors.find_one({"id": vendor_id}, {"_id": 0})
    if not v:
        raise HTTPException(404, "Not found")
    if not await user_can_access_wedding(current, v["wedding_id"]):
        raise HTTPException(403, "Forbidden")
    update: dict = {}
    if payload.stage:
        if payload.stage not in VENDOR_STAGES:
            raise HTTPException(400, "Invalid stage")
        # Guard: advance-paid / final settlement require founder approval
        if payload.stage in ("Advance Paid", "Final Settlement") and current.role != Role.founder:
            raise HTTPException(403, "Payment stages require founder approval — use /vendors/{id}/request-approval")
        update["stage"] = payload.stage
    if payload.negotiated_amount is not None:
        update["negotiated_amount"] = payload.negotiated_amount
    if payload.final_amount is not None:
        update["final_amount"] = payload.final_amount
    if payload.advance_paid is not None:
        update["advance_paid"] = payload.advance_paid
    if update:
        await db.vendors.update_one({"id": vendor_id}, {"$set": update})
    if payload.note:
        await db.vendors.update_one({"id": vendor_id}, {"$push": {"notes": {
            "author_id": current.id, "text": payload.note, "created_at": now_iso(),
        }}})
    await log_activity("vendor", vendor_id, v["wedding_id"], f"Updated vendor {v['name']}", current)
    return await db.vendors.find_one({"id": vendor_id}, {"_id": 0})


@api.post("/vendors/{vendor_id}/request-approval")
async def request_vendor_approval(vendor_id: str, payload: VendorApprovalRequest, current: UserPublic = Depends(get_current_user)):
    v = await db.vendors.find_one({"id": vendor_id}, {"_id": 0})
    if not v:
        raise HTTPException(404, "Not found")
    if not await user_can_access_wedding(current, v["wedding_id"]):
        raise HTTPException(403, "Forbidden")
    if payload.action not in ("advance", "final"):
        raise HTTPException(400, "Invalid action")
    await db.vendors.update_one({"id": vendor_id}, {"$set": {
        "approval_status": "pending",
        "pending_action": payload.action,
        "stage": "Approval Requested",
    }})
    await log_activity("vendor", vendor_id, v["wedding_id"], f"Requested {payload.action} approval for {v['name']}", current)
    await notify(
        await founder_ids(),
        "Approval requested",
        f"{current.full_name or current.email} requested {payload.action} approval for {v['name']}.",
        "approval",
        {"vendor_id": vendor_id, "wedding_id": v["wedding_id"], "action": payload.action},
    )
    return {"ok": True}


@api.post("/vendors/{vendor_id}/decide")
async def decide_vendor(vendor_id: str, payload: ApprovalDecision, current: UserPublic = Depends(require_roles(Role.founder))):
    v = await db.vendors.find_one({"id": vendor_id}, {"_id": 0})
    if not v:
        raise HTTPException(404, "Not found")
    if v.get("approval_status") != "pending":
        raise HTTPException(400, "No pending approval")
    if payload.approved:
        new_stage = "Advance Paid" if v.get("pending_action") == "advance" else "Final Settlement"
        set_doc = {"approval_status": "approved", "pending_action": None, "stage": new_stage}
        if v.get("pending_action") == "advance":
            set_doc["advance_paid"] = (v.get("final_amount") or v.get("quoted_amount") or 0) * 0.5
        await db.vendors.update_one({"id": vendor_id}, {"$set": set_doc})
        await log_activity("vendor", vendor_id, v["wedding_id"], f"Approved {v.get('pending_action')} for {v['name']}", current)
        if v.get("created_by"):
            await notify(
                [v["created_by"]],
                "Approval granted",
                f"Your {v.get('pending_action')} request for {v['name']} was approved.",
                "approval",
                {"vendor_id": vendor_id, "wedding_id": v["wedding_id"], "approved": True},
            )
    else:
        await db.vendors.update_one({"id": vendor_id}, {"$set": {
            "approval_status": "rejected", "pending_action": None, "stage": "Closed",
        }})
        await log_activity("vendor", vendor_id, v["wedding_id"], f"Rejected approval for {v['name']}: {payload.reason or ''}", current)
        if v.get("created_by"):
            await notify(
                [v["created_by"]],
                "Approval rejected",
                f"Your request for {v['name']} was rejected. {payload.reason or ''}".strip(),
                "approval",
                {"vendor_id": vendor_id, "wedding_id": v["wedding_id"], "approved": False},
            )
    return await db.vendors.find_one({"id": vendor_id}, {"_id": 0})


@api.get("/approvals/pending")
async def pending_approvals(current: UserPublic = Depends(require_roles(Role.founder))):
    vendors = await db.vendors.find({"approval_status": "pending"}, {"_id": 0}).to_list(500)
    # attach couple_name
    for v in vendors:
        w = await db.weddings.find_one({"id": v["wedding_id"]}, {"_id": 0, "couple_name": 1})
        v["couple_name"] = w["couple_name"] if w else "—"
    return vendors


# ---------- Guests ----------
@api.get("/weddings/{wedding_id}/guests")
async def list_guests(wedding_id: str, rsvp_status: Optional[str] = None, current: UserPublic = Depends(get_current_user)):
    if not await user_can_access_wedding(current, wedding_id):
        raise HTTPException(403, "Forbidden")
    q: dict = {"wedding_id": wedding_id}
    if rsvp_status:
        q["rsvp_status"] = rsvp_status
    return await db.guests.find(q, {"_id": 0}).sort("name", 1).to_list(5000)


@api.post("/guests")
async def create_guest(payload: GuestCreate, current: UserPublic = Depends(get_current_user)):
    if not await user_can_access_wedding(current, payload.wedding_id):
        raise HTTPException(403, "Forbidden")
    doc = {
        "id": str(uuid.uuid4()),
        "wedding_id": payload.wedding_id,
        "name": payload.name,
        "side": payload.side,
        "tags": payload.tags,
        "phone": payload.phone,
        "rsvp_status": "Pending",
        "room_assignment": None,
        "pickup_flight": None,
        "pickup_time": None,
        "pickup_vehicle": None,
        "notes": [],
        "created_at": now_iso(),
        "created_by": current.id,
    }
    await db.guests.insert_one(doc.copy())
    await log_activity("guest", doc["id"], payload.wedding_id, f"Added guest {payload.name}", current)
    doc.pop("_id", None)
    return doc


@api.patch("/guests/{guest_id}")
async def update_guest(guest_id: str, payload: GuestUpdate, current: UserPublic = Depends(get_current_user)):
    g = await db.guests.find_one({"id": guest_id}, {"_id": 0})
    if not g:
        raise HTTPException(404, "Not found")
    if not await user_can_access_wedding(current, g["wedding_id"]):
        raise HTTPException(403, "Forbidden")
    update: dict = {}
    for f in ("rsvp_status", "room_assignment", "pickup_flight", "pickup_time", "pickup_vehicle"):
        v = getattr(payload, f)
        if v is not None:
            update[f] = v
    if update:
        await db.guests.update_one({"id": guest_id}, {"$set": update})
    if payload.note:
        await db.guests.update_one({"id": guest_id}, {"$push": {"notes": {
            "author_id": current.id, "text": payload.note, "created_at": now_iso(),
        }}})
    await log_activity("guest", guest_id, g["wedding_id"], f"Updated guest {g['name']}", current)
    return await db.guests.find_one({"id": guest_id}, {"_id": 0})


# ---------- Payments ----------
@api.get("/weddings/{wedding_id}/payments")
async def list_payments(wedding_id: str, current: UserPublic = Depends(get_current_user)):
    if not await user_can_access_wedding(current, wedding_id):
        raise HTTPException(403, "Forbidden")
    return await db.payments.find({"wedding_id": wedding_id}, {"_id": 0}).to_list(500)


@api.post("/payments/{payment_id}/mark-received")
async def mark_payment(payment_id: str, current: UserPublic = Depends(require_roles(Role.founder))):
    p = await db.payments.find_one({"id": payment_id}, {"_id": 0})
    if not p:
        raise HTTPException(404, "Not found")
    await db.payments.update_one({"id": payment_id}, {"$set": {"status": "Received"}})
    await log_activity("payment", payment_id, p["wedding_id"], f"Marked {p['milestone_label']} as received", current)
    return await db.payments.find_one({"id": payment_id}, {"_id": 0})


# ---------- Activity ----------
@api.get("/activity")
async def activity(wedding_id: Optional[str] = None, limit: int = 100, current: UserPublic = Depends(get_current_user)):
    q: dict = {}
    if wedding_id:
        if not await user_can_access_wedding(current, wedding_id):
            raise HTTPException(403, "Forbidden")
        q["wedding_id"] = wedding_id
    else:
        # SEC-002: scope non-founder feed to weddings they can access
        if current.role != Role.founder:
            my_ws = await db.weddings.find(
                {"assigned_team.user_id": current.id}, {"_id": 0, "id": 1}
            ).to_list(500)
            allowed_wids = [w["id"] for w in my_ws]
            q["$or"] = [
                {"wedding_id": {"$in": allowed_wids}},
                {"actor_id": current.id},
            ]
    docs = await db.activity_log.find(q, {"_id": 0}).sort("created_at", -1).to_list(max(1, min(limit, 500)))
    return docs


# ---------- Dashboard ----------
@api.get("/dashboard")
async def dashboard(current: UserPublic = Depends(get_current_user)):
    """Role-aware dashboard stats."""
    out: dict = {"role": current.role}
    if current.role == Role.founder:
        pipeline_value = 0
        leads = await db.leads.find({}, {"_id": 0}).to_list(2000)
        active_stages = ("New Lead", "Contacted", "Discovery Call", "Proposal Shared", "Negotiation", "Follow-up")
        pipeline_value = sum(1 for l in leads if l["stage"] in active_stages)
        booked = sum(1 for l in leads if l["stage"] == "Booked")
        conv_rate = round((booked / len(leads)) * 100) if leads else 0
        approvals = await db.vendors.count_documents({"approval_status": "pending"})
        weddings_active = await db.weddings.count_documents({"status": {"$in": ["Planning", "Active"]}})
        out.update({
            "pipeline_leads": pipeline_value,
            "conversion_rate": conv_rate,
            "approvals_due": approvals,
            "weddings_active": weddings_active,
        })
    elif current.role == Role.sales:
        leads = await db.leads.find({}, {"_id": 0}).to_list(2000)
        due_today = sum(1 for l in leads if l.get("follow_up_date"))
        out.update({
            "leads_total": len(leads),
            "leads_hot": sum(1 for l in leads if l["score"] >= 70),
            "follow_ups_due": due_today,
        })
    else:
        # wedding-scoped roles
        weddings = await db.weddings.find({"assigned_team.user_id": current.id}, {"_id": 0}).to_list(50)
        tasks_open = 0
        for w in weddings:
            tasks_open += await db.tasks.count_documents({"wedding_id": w["id"], "status": {"$ne": "Completed"}})
        out.update({
            "my_weddings": len(weddings),
            "my_open_tasks": tasks_open,
        })
    return out


# ---------- Settings ----------
DEFAULT_SETTINGS = {
    "id": "singleton",
    "vendor_categories": ["Decor", "Photography", "Videography", "Catering", "Sound & Lighting", "Makeup", "Choreography", "Florist", "Bar", "Transport"],
    "room_categories": ["Standard", "Deluxe", "Suite", "Presidential"],
    "guest_tags": ["VIP", "Family", "Corporate", "Friends", "Elderly"],
    "wedding_stages": ["Planning", "Active", "Completed"],
    "payment_schedule_template": PAYMENT_MILESTONES,
}


async def seed_settings():
    existing = await db.settings.find_one({"id": "singleton"})
    if not existing:
        await db.settings.insert_one({**DEFAULT_SETTINGS, "created_at": now_iso()})


class SettingsUpdate(BaseModel):
    vendor_categories: Optional[List[str]] = None
    room_categories: Optional[List[str]] = None
    guest_tags: Optional[List[str]] = None
    wedding_stages: Optional[List[str]] = None


@api.get("/settings")
async def get_settings(_: UserPublic = Depends(get_current_user)):
    s = await db.settings.find_one({"id": "singleton"}, {"_id": 0})
    return s or DEFAULT_SETTINGS


@api.patch("/settings")
async def update_settings(payload: SettingsUpdate, current: UserPublic = Depends(require_roles(Role.founder))):
    update = {k: v for k, v in payload.dict().items() if v is not None}
    if not update:
        raise HTTPException(400, "Nothing to update")
    update["updated_at"] = now_iso()
    update["updated_by"] = current.id
    await db.settings.update_one({"id": "singleton"}, {"$set": update}, upsert=True)
    await log_activity("settings", "singleton", None, f"Updated settings: {', '.join(update.keys())}", current)
    s = await db.settings.find_one({"id": "singleton"}, {"_id": 0})
    return s


# ---------- Notifications ----------
@api.get("/notifications")
async def list_notifications(current: UserPublic = Depends(get_current_user)):
    docs = await db.notifications.find({"user_id": current.id}, {"_id": 0}).sort("created_at", -1).to_list(200)
    unread = await db.notifications.count_documents({"user_id": current.id, "read": False})
    return {"items": docs, "unread": unread}


@api.post("/notifications/{notif_id}/read")
async def mark_notif_read(notif_id: str, current: UserPublic = Depends(get_current_user)):
    await db.notifications.update_one({"id": notif_id, "user_id": current.id}, {"$set": {"read": True}})
    return {"ok": True}


@api.post("/notifications/mark-all-read")
async def mark_all_read(current: UserPublic = Depends(get_current_user)):
    await db.notifications.update_many({"user_id": current.id, "read": False}, {"$set": {"read": True}})
    return {"ok": True}


# ---------- Reminders (Founder → teammate) ----------
@api.post("/reminders")
async def create_reminder(payload: ReminderCreate, current: UserPublic = Depends(require_roles(Role.founder))):
    target = await db.users.find_one({"id": payload.user_id}, {"_id": 0, "id": 1, "full_name": 1, "email": 1})
    if not target:
        raise HTTPException(404, "Teammate not found")
    ref = {"from_founder": True, "sent_by": current.id}
    if payload.wedding_id:
        ref["wedding_id"] = payload.wedding_id
    await notify(
        [payload.user_id],
        payload.title.strip() or "Reminder from Founder",
        payload.body.strip(),
        "reminder",
        ref,
    )
    await log_activity(
        "reminder",
        payload.user_id,
        payload.wedding_id,
        f"Sent reminder to {target.get('full_name') or target.get('email')}: {payload.body[:60]}",
        current,
    )
    return {"ok": True}


@api.get("/team")
async def team_list(current: UserPublic = Depends(require_roles(Role.founder))):
    """Founder-only list of teammates (for reminders + workload)."""
    docs = await db.users.find(
        {"role": {"$ne": Role.founder.value}, "is_active": True},
        {"_id": 0, "password_hash": 0}
    ).sort("full_name", 1).to_list(500)
    for u in docs:
        u["open_tasks"] = await db.tasks.count_documents({"assignee_id": u["id"], "status": {"$ne": "Completed"}})
        u["active_weddings"] = await db.weddings.count_documents({"assigned_team.user_id": u["id"], "status": {"$ne": "Completed"}})
    return docs


# ---------- Founder Deck (per wedding, founder only) ----------
@api.get("/weddings/{wedding_id}/founder-deck")
async def founder_deck(wedding_id: str, _: UserPublic = Depends(require_roles(Role.founder))):
    w = await db.weddings.find_one({"id": wedding_id}, {"_id": 0})
    if not w:
        raise HTTPException(404, "Not found")

    vendors = await db.vendors.find({"wedding_id": wedding_id}, {"_id": 0}).to_list(500)
    payments = await db.payments.find({"wedding_id": wedding_id}, {"_id": 0}).to_list(500)
    tasks = await db.tasks.find({"wedding_id": wedding_id}, {"_id": 0, "status": 1}).to_list(2000)
    guests = await db.guests.find({"wedding_id": wedding_id}, {"_id": 0, "rsvp_status": 1}).to_list(5000)

    # Financials
    budget = float(w.get("budget", 0) or 0)
    client_received = sum(p["amount"] for p in payments if p.get("type") == "ClientMilestone" and p.get("status") == "Received")
    client_scheduled = sum(p["amount"] for p in payments if p.get("type") == "ClientMilestone")
    client_outstanding = max(0.0, client_scheduled - client_received)

    vendor_committed = sum(float(v.get("final_amount", 0) or 0) for v in vendors)
    vendor_paid = sum(float(v.get("advance_paid", 0) or 0) for v in vendors)
    vendor_outstanding = max(0.0, vendor_committed - vendor_paid)

    gross_margin = budget - vendor_committed
    margin_pct = round((gross_margin / budget) * 100) if budget else 0

    # Per-vendor breakdown
    vendor_lines = []
    for v in vendors:
        final = float(v.get("final_amount", 0) or 0)
        paid = float(v.get("advance_paid", 0) or 0)
        vendor_lines.append({
            "id": v["id"],
            "name": v["name"],
            "category": v["category"],
            "stage": v["stage"],
            "quoted": float(v.get("quoted_amount", 0) or 0),
            "final": final,
            "paid": paid,
            "outstanding": max(0.0, final - paid),
            "approval_status": v.get("approval_status", "none"),
        })
    vendor_lines.sort(key=lambda x: x["final"], reverse=True)

    # Progress
    tasks_total = len(tasks)
    tasks_done = sum(1 for t in tasks if t.get("status") == "Completed")
    tasks_pct = round((tasks_done / tasks_total) * 100) if tasks_total else 0

    guests_total = len(guests)
    guests_confirmed = sum(1 for g in guests if g.get("rsvp_status") == "Confirmed")
    guests_declined = sum(1 for g in guests if g.get("rsvp_status") == "Declined")
    rsvp_pct = round((guests_confirmed / guests_total) * 100) if guests_total else 0

    vendors_ready = sum(1 for v in vendors if v.get("stage") in ("Closed", "Advance Paid", "Active", "Final Settlement"))
    vendors_pct = round((vendors_ready / len(vendors)) * 100) if vendors else 0

    try:
        start = datetime.fromisoformat(w["start_date"].replace("Z", "+00:00"))
        days_to = (start - datetime.now(timezone.utc)).days
    except Exception:
        days_to = None

    # Team
    team = []
    for m in (w.get("assigned_team") or []):
        if not m or not m.get("user_id"):
            continue
        u = await db.users.find_one({"id": m["user_id"]}, {"_id": 0, "password_hash": 0})
        if u:
            open_tasks = await db.tasks.count_documents({"wedding_id": wedding_id, "assignee_id": u["id"], "status": {"$ne": "Completed"}})
            team.append({"user_id": u["id"], "name": u.get("full_name") or u["email"], "role": u["role"], "open_tasks": open_tasks})

    # Milestones (client)
    milestones = [
        {"id": p["id"], "label": p.get("milestone_label"), "amount": p["amount"], "status": p["status"]}
        for p in payments if p.get("type") == "ClientMilestone"
    ]

    return {
        "wedding": {
            "id": w["id"], "couple_name": w["couple_name"], "venue": w["venue"],
            "start_date": w["start_date"], "end_date": w["end_date"],
            "status": w.get("status"), "guest_count": w.get("guest_count", 0),
            "days_to": days_to,
        },
        "financials": {
            "contract_value": budget,
            "client_received": client_received,
            "client_scheduled": client_scheduled,
            "client_outstanding": client_outstanding,
            "vendor_committed": vendor_committed,
            "vendor_paid": vendor_paid,
            "vendor_outstanding": vendor_outstanding,
            "gross_margin": gross_margin,
            "margin_pct": margin_pct,
        },
        "vendor_lines": vendor_lines,
        "milestones": milestones,
        "progress": {
            "tasks_total": tasks_total, "tasks_done": tasks_done, "tasks_pct": tasks_pct,
            "guests_total": guests_total, "guests_confirmed": guests_confirmed, "guests_declined": guests_declined, "rsvp_pct": rsvp_pct,
            "vendors_total": len(vendors), "vendors_ready": vendors_ready, "vendors_pct": vendors_pct,
        },
        "team": team,
    }


# ---------- Founder Analytics ----------
@api.get("/analytics")
async def analytics(current: UserPublic = Depends(require_roles(Role.founder))):
    leads = await db.leads.find({}, {"_id": 0}).to_list(5000)
    active_stages = ("New Lead", "Contacted", "Discovery Call", "Proposal Shared", "Negotiation", "Follow-up")
    booked = sum(1 for l in leads if l["stage"] == "Booked")
    lost = sum(1 for l in leads if l["stage"] == "Lost")
    conv_rate = round((booked / len(leads)) * 100) if leads else 0
    leads_by_stage = {s: sum(1 for l in leads if l["stage"] == s) for s in LEAD_STAGES}
    # Pipeline value: approx sum of (score * 1L) for active leads (proxy since leads don't carry budget)
    pipeline_value = sum(int(l.get("score", 0)) * 100000 for l in leads if l["stage"] in active_stages)

    # Wedding profitability
    weddings = await db.weddings.find({}, {"_id": 0}).to_list(500)
    wed_out: List[dict] = []
    total_budget = 0.0
    total_cost = 0.0
    for w in weddings:
        vendors_w = await db.vendors.find({"wedding_id": w["id"]}, {"_id": 0, "final_amount": 1, "advance_paid": 1}).to_list(500)
        cost = sum(v.get("final_amount", 0) or 0 for v in vendors_w)
        budget = w.get("budget", 0) or 0
        margin = budget - cost
        margin_pct = round((margin / budget) * 100) if budget else 0
        total_budget += budget
        total_cost += cost
        wed_out.append({
            "id": w["id"], "couple_name": w["couple_name"], "status": w.get("status"),
            "budget": budget, "cost": cost, "margin": margin, "margin_pct": margin_pct,
        })
    wed_out.sort(key=lambda x: x["margin"], reverse=True)
    avg_margin_pct = round(((total_budget - total_cost) / total_budget) * 100) if total_budget else 0

    # Team workload — for planners/ops
    users = await db.users.find({"role": {"$in": [Role.wedding_planner.value, Role.operations_manager.value, Role.rsvp_caller.value, Role.rsvp_messenger.value]}}, {"_id": 0, "password_hash": 0}).to_list(200)
    workload = []
    for u in users:
        my_weddings = await db.weddings.count_documents({"assigned_team.user_id": u["id"]})
        open_tasks = await db.tasks.count_documents({"assignee_id": u["id"], "status": {"$ne": "Completed"}})
        workload.append({"user_id": u["id"], "name": u.get("full_name") or u["email"], "role": u["role"], "weddings": my_weddings, "open_tasks": open_tasks})
    workload.sort(key=lambda x: x["open_tasks"], reverse=True)

    approvals_pending = await db.vendors.count_documents({"approval_status": "pending"})

    # RSVP completion across active weddings
    active_weddings = [w for w in weddings if w.get("status") != "Completed"]
    rsvp_rates = []
    for w in active_weddings:
        gs = await db.guests.find({"wedding_id": w["id"]}, {"_id": 0, "rsvp_status": 1}).to_list(5000)
        if gs:
            confirmed = sum(1 for g in gs if g["rsvp_status"] == "Confirmed")
            rsvp_rates.append(confirmed / len(gs))
    rsvp_avg = round(100 * sum(rsvp_rates) / len(rsvp_rates)) if rsvp_rates else 0

    return {
        "pipeline_value": pipeline_value,
        "leads_total": len(leads),
        "leads_booked": booked,
        "leads_lost": lost,
        "leads_by_stage": leads_by_stage,
        "conversion_rate": conv_rate,
        "weddings": wed_out,
        "avg_margin_pct": avg_margin_pct,
        "total_budget": total_budget,
        "total_cost": total_cost,
        "team_workload": workload,
        "approvals_pending": approvals_pending,
        "rsvp_completion_avg": rsvp_avg,
    }


# ---------- WebSocket ----------
@app.websocket("/api/ws")
async def ws_endpoint(websocket: WebSocket, token: Optional[str] = None):
    """Auth via ?token=<jwt>. Server-side per-user routing (SEC-002)."""
    if not token:
        await websocket.close(code=4401); return
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("sub")
        role = payload.get("role") or ""
        if not user_id:
            await websocket.close(code=4401); return
        # Ensure user is still active
        user = await db.users.find_one({"id": user_id}, {"_id": 0, "is_active": 1, "role": 1})
        if not user or not user.get("is_active", True):
            await websocket.close(code=4401); return
        role = user.get("role", role)
    except InvalidTokenError:
        await websocket.close(code=4401); return

    await websocket.accept()
    await broadcaster.connect(websocket, user_id, role)
    try:
        await websocket.send_text(json.dumps({"type": "hello", "user_id": user_id}))
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        await broadcaster.disconnect(websocket, user_id)


# Mount
app.include_router(api)


@app.on_event("shutdown")
async def shutdown():
    client.close()
