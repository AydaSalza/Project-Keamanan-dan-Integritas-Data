from fastapi import FastAPI, Form, UploadFile, File, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.exceptions import InvalidSignature
import base64, json, os
from datetime import datetime, timedelta
import jwt

# ================= CONFIG =================
DB_FILE = "users_db.json"
SECRET_KEY = "STELLA_SECRET_KEY_2025"
ALGORITHM = "HS256"
TOKEN_EXPIRE_MIN = 30

security = HTTPBearer()
app = FastAPI(title="Security Service - STELLA", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ================= DATABASE =================
def load_db():
    if not os.path.exists(DB_FILE):
        return {}
    with open(DB_FILE, "r") as f:
        return json.load(f)

def save_db(db):
    with open(DB_FILE, "w") as f:
        json.dump(db, f, indent=4)

# ================= AUTH =================
def create_token(username: str):
    payload = {
        "sub": username,
        "exp": datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRE_MIN)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        return payload["sub"]
    except:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

# ================= HEALTH =================
@app.get("/health")
async def health():
    return {
        "status": "Security Service is running",
        "timestamp": datetime.now().isoformat()
    }

# ================= STORE PUBLIC KEY =================
@app.post("/store")
async def store_pubkey(
    username: str = Form(...),
    fullname: str = Form(...),
    public_key: UploadFile = File(...)
):
    text = (await public_key.read()).decode()

    if "BEGIN PUBLIC KEY" not in text:
        raise HTTPException(status_code=400, detail="Invalid public key")

    filename = f"{username}_public_key.pem"
    with open(filename, "w") as f:
        f.write(text)

    db = load_db()
    db[username] = {
        "fullname": fullname,
        "public_key": filename,
        "inbox": [],
        "last_message_hash": ""
    }
    save_db(db)

    return {"message": "Public key stored", "user": username}

# ================= LOGIN =================
@app.post("/login")
async def login(username: str = Form(...)):
    db = load_db()
    if username not in db:
        raise HTTPException(status_code=404, detail="User not registered")

    token = create_token(username)
    return {"access_token": token}

# ================= VERIFY SIGNATURE =================
@app.post("/verify")
async def verify(
    username: str = Form(...),
    message: str = Form(...),
    signature: str = Form(...),
    current_user: str = Depends(get_current_user)
):
    if username != current_user:
        raise HTTPException(status_code=403, detail="Token-user mismatch")

    db = load_db()
    if username not in db:
        raise HTTPException(status_code=404, detail="User not found")

    with open(db[username]["public_key"], "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    message_bytes = base64.b64decode(message)
    signature_bytes = base64.b64decode(signature)

    try:
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                signature_bytes,
                message_bytes,
                ec.ECDSA(hashes.SHA256())
            )
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(signature_bytes, message_bytes)
        else:
            raise Exception("Unsupported key type")

        digest = hashes.Hash(hashes.SHA256())
        digest.update(message_bytes)
        msg_hash = digest.finalize().hex()

        db[username]["last_message_hash"] = msg_hash
        save_db(db)

        return {
            "message": "Signature VALID",
            "hash": msg_hash
        }

    except InvalidSignature:
        return {"message": "Signature INVALID"}

# ================= RELAY MESSAGE =================
@app.post("/relay")
async def relay(
    sender: str = Form(...),
    receiver: str = Form(...),
    message: str = Form(...),
    current_user: str = Depends(get_current_user)
):
    if sender != current_user:
        raise HTTPException(status_code=403, detail="Unauthorized sender")

    db = load_db()
    if sender not in db or receiver not in db:
        raise HTTPException(status_code=404, detail="User not found")

    entry = {
        "from": sender,
        "message": message,
        "timestamp": datetime.now().isoformat()
    }

    db[receiver]["inbox"].append(entry)
    save_db(db)

    return {"message": "Message relayed", "to": receiver}

# ================= UPLOAD PDF =================
@app.post("/upload-pdf")
async def upload_pdf(
    file: UploadFile = File(...),
    current_user: str = Depends(get_current_user)
):
    pdf_bytes = await file.read()

    digest = hashes.Hash(hashes.SHA256())
    digest.update(pdf_bytes)
    pdf_hash = digest.finalize().hex()

    with open("uploaded.pdf", "wb") as f:
        f.write(pdf_bytes)

    return {
        "message": "PDF uploaded",
        "hash": pdf_hash,
        "uploaded_by": current_user
    }

@app.post("/verify-pdf")
async def verify_pdf(
    file: UploadFile = File(...),
    signature: str = Form(...),
    username: str = Form(...),
    current_user: str = Depends(get_current_user)
):
    db = load_db()
    if username not in db:
        raise HTTPException(status_code=404, detail="User not found")

    pdf_bytes = await file.read()
    signature_bytes = base64.b64decode(signature)

    with open(db[username]["public_key"], "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    digest = hashes.Hash(hashes.SHA256())
    digest.update(pdf_bytes)
    pdf_hash = digest.finalize()

    try:
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                signature_bytes,
                pdf_hash,
                ec.ECDSA(hashes.SHA256())
            )
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(signature_bytes, pdf_hash)

        return {"message": "PDF signature VALID"}

    except InvalidSignature:
        return {"message": "PDF signature INVALID"}

# ================= VIEW USERS =================
@app.get("/users")
async def users(current_user: str = Depends(get_current_user)):
    return load_db()

