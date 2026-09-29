from dotenv import load_dotenv
from pathlib import Path
load_dotenv(Path(__file__).parent / ".env")

import hashlib
import json
import os
import sqlite3
import shutil
import glob
from fastapi.responses import FileResponse
from datetime import datetime, timezone, timedelta
from typing import Optional

import bcrypt
import jwt
from fastapi import FastAPI, APIRouter, HTTPException, Request, Response, Depends, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

ROOT_DIR = Path(__file__).parent
app = FastAPI(title="CaseVault Secure Records API")
api = APIRouter(prefix="/api")
JWT_ALGORITHM = "HS256"

def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        val = row[idx]
        if col[0] in ['permissions', 'versions'] and val is not None:
            try: val = json.loads(val)
            except: pass
        if col[0] not in ['_id', '_seed']:
            d[col[0]] = val
    return d

db_path = ROOT_DIR / "dastawej.db"
UPLOAD_DIR = ROOT_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)
db = sqlite3.connect(db_path, check_same_thread=False)
db.row_factory = dict_factory

def execute(query, args=()):
    c = db.cursor()
    c.execute(query, args)
    db.commit()
    return c

def fetchone(query, args=()):
    return db.cursor().execute(query, args).fetchone()

def fetchall(query, args=()):
    return db.cursor().execute(query, args).fetchall()

# YAHAN TUMHARE DOSTON KE NAYE NAAM AUR ROLES HAIN
OFFICERS = {
    "anuj.prasad": {"email": "anuj.prasad", "password": "Anuj@7003", "name": "Anuj Prasad", "officer_id": "OFF-ADMIN-001", "role": "Administrator", "permissions": ["view", "upload", "edit", "download", "audit", "manage"]},
    "amit.rajak": {"email": "amit.rajak", "password": "Anuj@7003", "name": "Amit Rajak", "officer_id": "OFF-INV-002", "role": "Investigation Officer", "permissions": ["view", "upload", "edit", "download", "audit"]},
    "pintu.yadav": {"email": "pintu.yadav", "password": "Anuj@7003", "name": "Pintu Yadav", "officer_id": "OFF-EVD-003", "role": "Evidence Officer", "permissions": ["view", "upload", "download", "audit"]},
    "pratik.pandey": {"email": "pratik.pandey", "password": "Anuj@7003", "name": "Pratik Pandey", "officer_id": "OFF-POL-004", "role": "Police Department", "permissions": ["view", "download", "audit"]},
    "abhishek.mahato": {"email": "abhishek.mahato", "password": "Anuj@7003", "name": "Abhishek Mahato", "officer_id": "OFF-AUD-005", "role": "Audit Reviewer", "permissions": ["view", "download", "audit"]},
    "records.manager": {"email": "records.manager", "password": "Anuj@7003", "name": "Records Manager", "officer_id": "OFF-REC-006", "role": "Records Officer", "permissions": ["view", "download", "audit"]},
    "omprakash.yadav": {"email": "omprakash.yadav", "password": "Anuj@7003", "name": "OmPrakash Yadav", "officer_id": "OFF-LEG-007", "role": "Legal Officer", "permissions": ["view", "download", "audit"]},
}

def now(): return datetime.now(timezone.utc).isoformat()
def hash_password(value): return bcrypt.hashpw(value.encode(), bcrypt.gensalt()).decode()
def verify_password(value, hashed): return bcrypt.checkpw(value.encode(), hashed.encode())
def token_for(user): return jwt.encode({"sub": user["email"], "exp": datetime.now(timezone.utc) + timedelta(hours=8)}, os.environ.get("JWT_SECRET", "supersecret"), algorithm=JWT_ALGORITHM)

async def current_user(request: Request):
    token = request.cookies.get("access_token") or request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token: raise HTTPException(401, "Not authenticated")
    try: payload = jwt.decode(token, os.environ.get("JWT_SECRET", "supersecret"), algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError: raise HTTPException(401, "Session expired")
    user = fetchone("SELECT * FROM users WHERE email=?", (payload.get("sub"),))
    if not user: raise HTTPException(401, "Officer not found")
    user.pop("password_hash", None)
    return user

class LoginBody(BaseModel): officer_id: str; password: str
class ActionBody(BaseModel): action: str

@app.on_event("startup")
async def seed():
    execute("""CREATE TABLE IF NOT EXISTS users (email TEXT PRIMARY KEY, name TEXT, officer_id TEXT, role TEXT, permissions TEXT, password_hash TEXT)""")
    execute("""CREATE TABLE IF NOT EXISTS documents (document_id TEXT PRIMARY KEY, case_id TEXT, document_type TEXT, document_name TEXT, department TEXT, owner TEXT, classification TEXT, created_date TEXT, modified_date TEXT, version INTEGER, status TEXT, integrity_status TEXT, trusted_hash TEXT, current_hash TEXT, versions TEXT, last_accessed_by TEXT, last_accessed_at TEXT, _seed INTEGER)""")
    execute("""CREATE TABLE IF NOT EXISTS audits (id INTEGER PRIMARY KEY AUTOINCREMENT, officer_name TEXT, officer_id TEXT, action TEXT, document_name TEXT, document_id TEXT, case_id TEXT, date TEXT, time TEXT, result TEXT, document_version TEXT, department TEXT)""")

    for key, officer in OFFICERS.items():
        exists = fetchone("SELECT email FROM users WHERE email=?", (key,))
        hashed_pw = hash_password(officer["password"])
        perms = json.dumps(officer["permissions"])
        if not exists: execute("INSERT INTO users (email, name, officer_id, role, permissions, password_hash) VALUES (?, ?, ?, ?, ?, ?)", (key, officer["name"], officer["officer_id"], officer["role"], perms, hashed_pw))
        else: execute("UPDATE users SET name=?, officer_id=?, role=?, permissions=? WHERE email=?", (officer["name"], officer["officer_id"], officer["role"], perms, key))

    if fetchone("SELECT COUNT(*) as c FROM documents")['c'] == 0:
        base = [
            ("DOC-2026-008923", "CASE-2026-00125", "Forensic Report", "Forensic Examination — Device 04", "Tampered", "CONFIDENTIAL", "3", "Amit Rajak"),
            ("DOC-2026-008924", "CASE-2026-00125", "FIR", "First Information Report", "Verified", "RESTRICTED", "1", "Amit Rajak"),
        ]
        for i, (did, case, typ, name, status, classification, version, owner) in enumerate(base):
            content = f"{did}|{case}|{version}".encode(); trusted = hashlib.sha256(content).hexdigest()
            current_hash = trusted if status != "Tampered" else hashlib.sha256(b"unexpected-edit").hexdigest()
            versions_json = json.dumps([{"version": int(version), "modified_by": owner, "modified_at": now(), "integrity": status if status == "Tampered" else "Verified"}])
            dept = "Investigation Officer" if owner == "Amit Rajak" else "Police Department"
            execute("""INSERT INTO documents (document_id, case_id, document_type, document_name, department, owner, classification, created_date, modified_date, version, status, integrity_status, trusted_hash, current_hash, versions, _seed) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", (did, case, typ, name, dept, owner, classification, "2026-09-25", "2026-09-25", int(version), status, status, trusted, current_hash, versions_json, i))

    if fetchone("SELECT COUNT(*) as c FROM audits")['c'] == 0:
        events = [("Amit Rajak", "Viewed", "Forensic Examination — Device 04", "DOC-2026-008923", "CASE-2026-00125", "10:42 PM", "3")]
        for o,a,n,d,c,t,v in events:
            oid = "OFF-INV-002" if o == "Amit Rajak" else "OFF-POL-004"
            dept = "Investigation Officer" if o == "Amit Rajak" else "Police Department"
            execute("INSERT INTO audits (officer_name, officer_id, action, document_name, document_id, case_id, date, time, result, document_version, department) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (o, oid, a, n, d, c, "25 Sep 2026", t, "Success", v, dept))

@api.post("/auth/login")
async def login(body: LoginBody, response: Response):
    officer = OFFICERS.get(body.officer_id.strip().lower())
    if not officer: raise HTTPException(401, "Officer ID not recognized")
    user = fetchone("SELECT * FROM users WHERE email=?", (officer["email"],))
    if not user or not verify_password(body.password, user["password_hash"]): raise HTTPException(401, "Incorrect password")
    response.set_cookie("access_token", token_for(officer), httponly=True, samesite="lax", max_age=28800)
    user.pop("password_hash", None)
    return user

@api.post("/auth/logout")
async def logout(response: Response): response.delete_cookie("access_token"); return {"ok": True}

@api.get("/auth/me")
async def me(user=Depends(current_user)): return user

@api.get("/dashboard")
async def dashboard(user=Depends(current_user)):
    docs = fetchall("SELECT * FROM documents ORDER BY modified_date DESC LIMIT 100")
    audits = fetchall("SELECT * FROM audits ORDER BY date DESC, time DESC LIMIT 20")
    total_audits = fetchone("SELECT COUNT(*) as c FROM audits")['c']
    cases = len(set(d["case_id"] for d in docs))
    alerts = sum(1 for d in docs if d["integrity_status"] == "Tampered")
    return {"metrics": {"cases": cases, "documents": len(docs), "activities": total_audits, "alerts": alerts}, "documents": docs, "audits": audits, "user": user}

@api.get("/documents")
async def documents(search: str = "", user=Depends(current_user)):
    if search:
        s = f"%{search}%"
        return fetchall("SELECT * FROM documents WHERE document_id LIKE ? OR case_id LIKE ? OR document_type LIKE ? OR document_name LIKE ? OR owner LIKE ? LIMIT 100", (s, s, s, s, s))
    return fetchall("SELECT * FROM documents LIMIT 100")

@api.get("/documents/{document_id}")
async def document(document_id: str, user=Depends(current_user)):
    doc = fetchone("SELECT * FROM documents WHERE document_id=?", (document_id,))
    if not doc: raise HTTPException(404, "Document not found")
    return doc

@api.post("/documents/{document_id}/action")
async def document_action(document_id: str, body: ActionBody, user=Depends(current_user)):
    doc = fetchone("SELECT * FROM documents WHERE document_id=?", (document_id,))
    accessed_at = now()
    execute("INSERT INTO audits (officer_name, officer_id, action, document_name, document_id, case_id, date, time, result, document_version, department) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (user["name"], user["officer_id"], body.action, doc["document_name"], document_id, doc["case_id"], accessed_at[:10], datetime.now().strftime("%I:%M:%S %p"), "Success", str(doc["version"]), user["role"]))
    return {"ok": True}

@api.post("/documents/{document_id}/version")
async def upload_version(document_id: str, file: UploadFile = File(...), user=Depends(current_user)):
    if "upload" not in user["permissions"]: raise HTTPException(403, "Upload permission required")
    doc = fetchone("SELECT * FROM documents WHERE document_id=?", (document_id,))
    if not doc: raise HTTPException(404, "Document not found")
    
    new_version = doc["version"] + 1
    filepath = UPLOAD_DIR / f"{document_id}_v{new_version}_{file.filename}"
    
    with open(filepath, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    
    with open(filepath, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    
    new_ver_entry = {"version": new_version, "modified_by": user["name"], "modified_at": now(), "integrity": "Verified", "filename": file.filename}
    versions = doc.get("versions") or []
    versions.append(new_ver_entry)
    
    execute("UPDATE documents SET version=?, modified_date=?, current_hash=?, integrity_status=?, status=?, versions=? WHERE document_id=?", 
            (new_version, now()[:10], digest, "Verified", "Modified", json.dumps(versions), document_id))
    execute("INSERT INTO audits (officer_name, officer_id, action, document_name, document_id, case_id, date, time, result, document_version, department) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (user["name"], user["officer_id"], "Uploaded file", doc["document_name"], document_id, doc["case_id"], now()[:10], datetime.now().strftime("%I:%M:%S %p"), "Success", str(new_version), user["role"]))
    
    return {"ok": True, "version": new_version, "hash": digest}

@api.get("/documents/{document_id}/download")
async def download_document(document_id: str, version: int = None, user=Depends(current_user)):
    doc = fetchone("SELECT * FROM documents WHERE document_id=?", (document_id,))
    if not doc: raise HTTPException(404, "Document not found")
    
    target_version = version if version else doc["version"]
    
    matches = glob.glob(str(UPLOAD_DIR / f"{document_id}_v{target_version}_*"))
    if not matches:
        raise HTTPException(404, "Physical file not found on server. Please upload a file first.")
        
    execute("INSERT INTO audits (officer_name, officer_id, action, document_name, document_id, case_id, date, time, result, document_version, department) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (user["name"], user["officer_id"], "Downloaded file", doc["document_name"], document_id, doc["case_id"], now()[:10], datetime.now().strftime("%I:%M:%S %p"), "Success", str(target_version), user["role"]))
            
    return FileResponse(path=matches[0], filename=os.path.basename(matches[0]))

app.include_router(api)
app.add_middleware(CORSMiddleware, allow_credentials=True, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.on_event("shutdown")
async def shutdown(): db.close()