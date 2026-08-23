import os
import hashlib
import jwt
import sqlite3
import secrets
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv

from fastapi import FastAPI, Depends, HTTPException, Request, Header, Query
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from sqlalchemy import create_engine, Column, Integer, String, Boolean, text
from sqlalchemy.orm import sessionmaker, declarative_base, Session

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


load_dotenv()
JWT_SECRET = os.getenv("JWT_SECRET", "super-secret-key-123")
OTT_SECRET = os.getenv("OTT_SECRET", "super-secret-ott-123")

# --- RAW SQLITE MIGRATION ---
def migrate_db():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(users)")
    columns = [col[1] for col in cursor.fetchall()]
    
    if "hwid" not in columns:
        print("Migrating DB: adding hwid column...")
        cursor.execute("ALTER TABLE users ADD COLUMN hwid VARCHAR DEFAULT NULL")
    if "is_hwid_banned" not in columns:
        print("Migrating DB: adding is_hwid_banned column...")
        cursor.execute("ALTER TABLE users ADD COLUMN is_hwid_banned INTEGER DEFAULT 0")
        
    conn.commit()
    conn.close()

migrate_db()

# --- SQLALCHEMY SETUP ---
DATABASE_URL = "sqlite:///./database.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    password_hash = Column(String)
    subscription_end = Column(String, default="Нет активной подписки")
    hwid = Column(String, default=None)
    is_admin = Column(Integer, default=0)
    is_banned = Column(Integer, default=0)
    is_hwid_banned = Column(Integer, default=0)

class Key(Base):
    __tablename__ = "keys"
    id = Column(Integer, primary_key=True, index=True)
    key_string = Column(String, unique=True, index=True)
    duration_days = Column(Integer)
    is_used = Column(Integer, default=0)

Base.metadata.create_all(bind=engine)

# Admin Init
def init_admin():
    db = SessionLocal()
    admin = db.query(User).filter(User.username == "admin").first()
    if not admin:
        new_admin = User(
            username="admin",
            email="admin@heavyclient.com",
            password_hash=hashlib.sha256("admin_password_123".encode()).hexdigest(),
            subscription_end="Навсегда",
            is_admin=1
        )
        db.add(new_admin)
        db.commit()
    db.close()

init_admin()

app = FastAPI(title="Heavy Client Auth Server")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def read_root():
    return FileResponse("static/index.html")

def create_jwt(user_id: int):
    payload = {
        "user_id": user_id,
        "exp": datetime.utcnow() + timedelta(days=7)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def get_current_user(authorization: str = Header(None), db: Session = Depends(get_db)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized")
    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user_id = payload.get("user_id")
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

def add_days_to_sub(current_sub, days_to_add):
    if current_sub == "Навсегда (Forever)" or current_sub == "Навсегда" or days_to_add >= 999:
        return "Навсегда"
        
    try:
        try:
            parsed_date = datetime.strptime(current_sub, "%Y-%m-%d %H:%M")
        except ValueError:
            parsed_date = datetime.strptime(current_sub, "%d.%m.%Y %H:%M")
            
        if parsed_date < datetime.utcnow():
            parsed_date = datetime.utcnow()
    except (ValueError, TypeError):
        parsed_date = datetime.utcnow()
        
    new_date = parsed_date + timedelta(days=days_to_add)
    return new_date.strftime("%Y-%m-%d %H:%M")

def check_password_hash(req_password: str, db_hash: str) -> bool:
    if not req_password or not db_hash:
        return False
    if len(db_hash) == 32: 
        return hashlib.md5(req_password.encode()).hexdigest() == db_hash
    elif len(db_hash) == 64:
        return hashlib.sha256(req_password.encode()).hexdigest() == db_hash
    return False

# --- WEB API (React Panel) ---
class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str

@app.post("/api/register")
def web_register(req: RegisterRequest, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == req.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")
    if db.query(User).filter(User.email == req.email).first():
        raise HTTPException(status_code=400, detail="Email already taken")
        
    new_user = User(
        username=req.username,
        email=req.email,
        password_hash=hashlib.sha256(req.password.encode()).hexdigest()
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    token = create_jwt(new_user.id)
    return {"message": "Registration successful", "token": token}

class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/api/login")
def web_login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == req.username).first()
    if not user or not check_password_hash(req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
        
    if user.is_banned == 1:
        raise HTTPException(status_code=403, detail="Account is banned")
        
    token = create_jwt(user.id)
    return {"message": "Login successful", "token": token, "is_admin": user.is_admin == 1}

@app.get("/api/user/me")
def web_me(user: User = Depends(get_current_user)):
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "subscription_end": user.subscription_end,
        "is_admin": user.is_admin == 1,
        "is_banned": user.is_banned == 1,
        "hwid": user.hwid
    }

class ActivateKeyRequest(BaseModel):
    key: str

@app.post("/api/user/activate-key")
def activate_key_web(req: ActivateKeyRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    key_obj = db.query(Key).filter(Key.key_string == req.key).first()
    
    if not key_obj:
        raise HTTPException(status_code=400, detail="Invalid key")
    if key_obj.is_used == 1:
        raise HTTPException(status_code=400, detail="Key already used")
        
    user.subscription_end = add_days_to_sub(user.subscription_end, key_obj.duration_days)
    key_obj.is_used = 1
    
    db.commit()
    return {"message": "Key activated successfully", "new_sub": user.subscription_end}

# --- LOADER API ---
class LoaderRegRequest(BaseModel):
    username: str
    email: str
    password: str
    hwid: str

@app.post("/api/loader/register")
def loader_reg(req: LoaderRegRequest, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == req.username).first():
        return {"success": False, "error": "Пользователь с таким именем уже существует!"}
    if db.query(User).filter(User.email == req.email).first():
        return {"success": False, "error": "Этот E-mail уже используется!"}
        
    new_user = User(
        username=req.username,
        email=req.email,
        password_hash=hashlib.sha256(req.password.encode()).hexdigest(),
        hwid=req.hwid
    )
    db.add(new_user)
    db.commit()
    return {"success": True, "message": "Регистрация прошла успешно!"}

class LoaderActivateRequest(BaseModel):
    username: str
    password: str
    key: str

@app.post("/api/loader/activate-key")
def loader_activate(req: LoaderActivateRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == req.username).first()
    if not user or not check_password_hash(req.password, user.password_hash):
        return {"success": False, "error": "Неверный логин или пароль!"}
        
    key_obj = db.query(Key).filter(Key.key_string == req.key).first()
    if not key_obj:
        return {"success": False, "error": "Ключ не найден или не существует!"}
    if key_obj.is_used == 1:
        return {"success": False, "error": "Этот ключ уже был активирован!"}
        
    user.subscription_end = add_days_to_sub(user.subscription_end, key_obj.duration_days)
    key_obj.is_used = 1
    db.commit()
    
    return {"success": True, "message": "Подписка успешно продлена!", "new_sub": user.subscription_end}

# --- ADMIN API ---
def get_current_admin(authorization: str = Header(None), db: Session = Depends(get_db)):
    user = get_current_user(authorization, db)
    if user.is_admin != 1:
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return user

class AdminActionRequest(BaseModel):
    user_id: int

@app.get("/api/admin/users")
def admin_get_users(admin: User = Depends(get_current_admin), db: Session = Depends(get_db)):
    users = db.query(User).all()
    return [{
        "id": u.id, "username": u.username, "email": u.email, 
        "subscription_end": u.subscription_end, "hwid": u.hwid,
        "is_admin": u.is_admin == 1, "is_banned": u.is_banned == 1,
        "is_hwid_banned": u.is_hwid_banned == 1
    } for u in users]

@app.post("/api/admin/ban")
def admin_ban_user(req: AdminActionRequest, admin: User = Depends(get_current_admin), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == req.user_id).first()
    if not user: raise HTTPException(status_code=404)
    user.is_banned = 1 if user.is_banned == 0 else 0
    db.commit()
    return {"message": "Ban status toggled"}

@app.post("/api/admin/reset-hwid")
def admin_reset_hwid(req: AdminActionRequest, admin: User = Depends(get_current_admin), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == req.user_id).first()
    if not user: raise HTTPException(status_code=404)
    user.hwid = None
    db.commit()
    return {"message": "HWID reset successfully"}

@app.post("/api/admin/ban-hwid")
def admin_ban_hwid(req: AdminActionRequest, admin: User = Depends(get_current_admin), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == req.user_id).first()
    if not user: raise HTTPException(status_code=404)
    user.is_hwid_banned = 1 if user.is_hwid_banned == 0 else 0
    db.commit()
    return {"message": "HWID ban toggled"}

class AdminEditSubRequest(BaseModel):
    user_id: int
    subscription_end: str

@app.post("/api/admin/edit-sub")
def admin_edit_sub(req: AdminEditSubRequest, admin: User = Depends(get_current_admin), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == req.user_id).first()
    if not user: raise HTTPException(status_code=404)
    user.subscription_end = req.subscription_end
    db.commit()
    return {"message": "Subscription updated"}

# --- V1 LOADER COMPATIBILITY (If Needed) ---
class LoaderAuthRequest(BaseModel):
    username: str
    password: str
    hwid: str

@app.post("/api/loader/auth")
def loader_auth(req: LoaderAuthRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == req.username).first()
    
    if not user or not check_password_hash(req.password, user.password_hash):
        return {"access": False, "error": "Неверный логин или пароль"}
        
    if user.is_banned == 1 or user.is_hwid_banned == 1:
        return {"access": False, "error": "Аккаунт заблокирован"}

    if req.hwid:
        if not user.hwid or user.hwid == "UNKNOWN-HWID":
            user.hwid = req.hwid
            db.commit()
        elif user.hwid != req.hwid:
            return {"access": False, "error": "HWID не совпадает. Обратитесь в поддержку."}
            
    return {
        "access": True, 
        "username": user.username, 
        "subscription_end": user.subscription_end, 
        "subscription_expires": user.subscription_end,
        "role": "admin" if user.is_admin == 1 else "user",
        "is_admin": user.is_admin == 1,
        "message": "Авторизация успешна"
    }

class CheckSubRequest(BaseModel):
    username: str = None
    password: str = None
    hwid: str = None

@app.post("/api/loader/check-sub")
def loader_check_sub(request: Request, req: CheckSubRequest = None, db: Session = Depends(get_db)):
    auth_header = request.headers.get("Authorization")
    user = None
    
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            user_id = payload.get("user_id")
            user = db.query(User).filter(User.id == user_id).first()
        except Exception:
            pass
            
    if not user and req and req.username and req.password:
        user = db.query(User).filter(User.username == req.username).first()
        if user and not check_password_hash(req.password, user.password_hash):
            user = None
            
    if not user:
        return {"access": False, "error": "Не удалось авторизоваться"}
        
    if user.is_banned == 1 or user.is_hwid_banned == 1:
        return {"access": False, "error": "Доступ заблокирован администратором"}
        
    sub = user.subscription_end
    if not sub or sub == "Нет активной подписки" or sub == "Заблокирован":
        return {"access": False, "error": "У вас сейчас нет активной подписки"}

    if req and req.hwid:
        if not user.hwid:
            user.hwid = req.hwid
            db.commit()
        elif user.hwid != req.hwid:
            user.subscription_end = "Заблокирован"
            db.commit()
            return {"access": False, "error": "Аккаунт заблокирован навсегда за передачу данных (Неверный HWID)!"}

    if sub == "Навсегда (Forever)" or sub == "Навсегда":
        return {"access": True, "sub_status": "Навсегда"}
        
    try:
        try:
            parsed_date = datetime.strptime(sub, "%Y-%m-%d %H:%M")
        except ValueError:
            parsed_date = datetime.strptime(sub, "%d.%m.%Y %H:%M")
            
        if parsed_date > datetime.utcnow():
            return {"access": True, "sub_status": sub}
        else:
            return {"access": False, "error": "У вас сейчас нет активной подписки"}
    except ValueError:
        return {"access": False, "error": "У вас сейчас нет активной подписки"}

@app.get("/api/loader/download")
def download_loader(token: str = Query(None), authorization: str = Header(None), db: Session = Depends(get_db)):
    actual_token = token
    if not actual_token and authorization and authorization.startswith("Bearer "):
        actual_token = authorization.split(" ")[1]
        
    if not actual_token:
        raise HTTPException(status_code=401, detail="Unauthorized")
        
    try:
        payload = jwt.decode(actual_token, JWT_SECRET, algorithms=["HS256"])
        user = db.query(User).filter(User.id == payload.get("user_id")).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    sub = user.subscription_end
    is_sub_active = False
    if sub and sub != "Нет активной подписки":
        if sub == "Навсегда":
            is_sub_active = True
        else:
            try:
                if datetime.strptime(sub, "%d.%m.%Y %H:%M") > datetime.utcnow():
                    is_sub_active = True
            except ValueError:
                pass
                
    if not is_sub_active:
        raise HTTPException(status_code=403, detail="Доступно только после активации подписки")
        
    dropbox_url = "https://www.dropbox.com/s/ТВОЯ_ССЫЛКА_ТУТ/HeavyLoader.exe?dl=1"
    return RedirectResponse(url=dropbox_url)

# --- ONE-TIME TOKEN & SECURE PAYLOAD DELIVERY ---
class LaunchTokenRequest(BaseModel):
    username: str
    password: str
    hwid: str

@app.post("/api/loader/generate-launch-token")
def generate_launch_token(req: LaunchTokenRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == req.username).first()
    if not user or not check_password_hash(req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
        
    if user.is_banned == 1 or user.is_hwid_banned == 1:
        raise HTTPException(status_code=403, detail="Account banned")
        
    if not req.hwid:
        raise HTTPException(status_code=400, detail="HWID required")
        
    if not user.hwid:
        user.hwid = req.hwid
        db.commit()
    elif user.hwid != req.hwid:
        raise HTTPException(status_code=403, detail="HWID mismatch. Contact support.")
        
    sub = user.subscription_end
    if not sub or sub == "Нет активной подписки" or sub == "Заблокирован":
        raise HTTPException(status_code=403, detail="No active subscription")
        
    if sub not in ["Навсегда", "Навсегда (Forever)"]:
        try:
            try:
                parsed_date = datetime.strptime(sub, "%Y-%m-%d %H:%M")
            except ValueError:
                parsed_date = datetime.strptime(sub, "%d.%m.%Y %H:%M")
            if parsed_date < datetime.utcnow():
                raise HTTPException(status_code=403, detail="Subscription expired")
        except ValueError:
            raise HTTPException(status_code=403, detail="Invalid subscription format")
            
    aes_key = secrets.token_hex(32)
    aes_iv = secrets.token_hex(16)
    
    ott_payload = {
        "user_id": user.id,
        "hwid": req.hwid,
        "aes_key": aes_key,
        "aes_iv": aes_iv,
        "exp": datetime.now(timezone.utc) + timedelta(seconds=60)
    }
    ott = jwt.encode(ott_payload, OTT_SECRET, algorithm="HS256")
    
    return {
        "success": True,
        "ott": ott,
        "aes_key": aes_key,
        "aes_iv": aes_iv
    }

@app.get("/api/loader/download-payload")
def download_payload(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing OTT")
        
    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, OTT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="OTT expired. Please request a new one.")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid OTT")
        
    key = bytes.fromhex(payload["aes_key"])
    iv = bytes.fromhex(payload["aes_iv"])
    
    file_path = os.path.join("payloads", "wyvern.jar")
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Payload not found on server")
        
    def encrypt_generator():
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                yield encryptor.update(chunk)
        yield encryptor.finalize()
        
    return StreamingResponse(encrypt_generator(), media_type="application/octet-stream")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
