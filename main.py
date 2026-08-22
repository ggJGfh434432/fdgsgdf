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
    columns_to_add = [
        ("email", "TEXT"),
        ("hwid", "TEXT"),
        ("subscription_end", "TEXT DEFAULT 'Нет активной подписки'"),
        ("avatar_url", "TEXT"),
        ("is_admin", "INTEGER DEFAULT 0"),
        ("is_banned", "INTEGER DEFAULT 0"),
        ("is_hwid_banned", "INTEGER DEFAULT 0")
    ]
    for col_name, col_type in columns_to_add:
        try:
            cursor.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_type}")
        except Exception:
            pass
            
    try:
        cursor.execute("UPDATE users SET subscription_end = 'Нет активной подписки' WHERE subscription_end IS NULL")
    except Exception:
        pass
        
    conn.commit()
    conn.close()

migrate_db()
# ----------------------------

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
    hwid = Column(String, nullable=True)
    subscription_end = Column(String, default="Нет активной подписки")
    avatar_url = Column(String, nullable=True)
    is_admin = Column(Integer, default=0)
    is_banned = Column(Integer, default=0)
    is_hwid_banned = Column(Integer, default=0)

class PromoKey(Base):
    __tablename__ = "promo_keys"
    id = Column(Integer, primary_key=True, index=True)
    key_code = Column(String, unique=True, index=True)
    tariff = Column(String)
    days = Column(Integer)
    is_used = Column(Integer, default=0)
    used_by = Column(String, nullable=True)
    used_at = Column(String, nullable=True)

Base.metadata.create_all(bind=engine)

def init_admin():
    db = SessionLocal()
    admin = db.query(User).filter(User.username == "heaavya").first()
    if not admin:
        pw_hash = hashlib.sha256("heavy36fh4567788".encode('utf-8')).hexdigest()
        new_admin = User(
            username="heaavya",
            email="admin@heavyclient.onrender.com",
            password_hash=pw_hash,
            is_admin=1,
            subscription_end="Навсегда"
        )
        db.add(new_admin)
        db.commit()
    db.close()

init_admin()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

app = FastAPI(title="Heavy Software Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.api_route("/", methods=["GET", "HEAD"])
async def read_root():
    return FileResponse("static/index.html")

def create_jwt(user_id: int):
    payload = {
        "user_id": user_id,
        "exp": datetime.now(timezone.utc) + timedelta(days=7)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def get_current_user(authorization: str = Header(None), db: Session = Depends(get_db)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized")
    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user = db.query(User).filter(User.id == payload.get("user_id")).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

def add_days_to_sub(current_sub, days_to_add):
    if current_sub == "Навсегда (Forever)" or current_sub == "Навсегда":
        return "Навсегда (Forever)"
    
    now = datetime.utcnow()
    if not current_sub or current_sub == "Нет активной подписки":
        new_date = now + timedelta(days=days_to_add)
    else:
        try:
            parsed_date = datetime.strptime(current_sub, "%Y-%m-%d %H:%M")
        except ValueError:
            try:
                parsed_date = datetime.strptime(current_sub, "%d.%m.%Y %H:%M")
            except ValueError:
                parsed_date = now - timedelta(days=1)
                
        if parsed_date > now:
            new_date = parsed_date + timedelta(days=days_to_add)
        else:
            new_date = now + timedelta(days=days_to_add)
    
    return new_date.strftime("%Y-%m-%d %H:%M")

def check_password_hash(req_password: str, db_hash: str) -> bool:
    hashed = hashlib.sha256(req_password.encode('utf-8')).hexdigest()
    return db_hash == hashed

# --- WEB AUTH ENDPOINTS ---
class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str

@app.post("/api/register")
def web_register(req: RegisterRequest, db: Session = Depends(get_db)):
    if not req.username or not req.email or not req.password:
        raise HTTPException(status_code=400, detail="Заполните все поля")
    
    try:
        existing = db.query(User).filter((User.username == req.username) | (User.email == req.email)).first()
        if existing:
            raise HTTPException(status_code=400, detail="Логин или Email уже занят")
        
        hashed = hashlib.sha256(req.password.encode('utf-8')).hexdigest()
        new_user = User(
            username=req.username, 
            email=req.email, 
            password_hash=hashed, 
            subscription_end="Нет активной подписки"
        )
        db.add(new_user)
        db.commit()
        return {"status": "ok", "message": "Регистрация успешна!"}
    except HTTPException:
        raise
    except Exception as e:
        print(f"[ERROR REGISTER] {e}")
        raise HTTPException(status_code=500, detail="Внутренняя ошибка сервера")

class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/api/login")
def web_login(req: LoginRequest, db: Session = Depends(get_db)):
    if not req.username or not req.password:
        raise HTTPException(status_code=400, detail="Заполните все поля")
        
    user = db.query(User).filter((User.username == req.username) | (User.email == req.username)).first()
    if not user:
        raise HTTPException(status_code=401, detail="Неверный логин или пароль")
        
    if not check_password_hash(req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Неверный логин или пароль")
        
    return {"status": "success", "token": create_jwt(user.id)}

@app.api_route("/api/user/me", methods=["GET", "POST"])
def web_me(user: User = Depends(get_current_user)):
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "hwid": user.hwid,
        "subscription_end": user.subscription_end,
        "avatar_url": user.avatar_url,
        "is_admin": user.is_admin,
        "is_banned": user.is_banned,
        "is_hwid_banned": user.is_hwid_banned
    }

class ActivateKeyRequest(BaseModel):
    key: str

@app.post("/api/user/activate-key")
def activate_key_web(req: ActivateKeyRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    key_code = req.key.strip().upper()
    if not key_code:
        raise HTTPException(status_code=400, detail="Ключ не может быть пустым")
        
    promo = db.query(PromoKey).filter(PromoKey.key_code == key_code).first()
    if not promo:
        raise HTTPException(status_code=404, detail="Неверный ключ активации")
    
    if promo.is_used == 1:
        raise HTTPException(status_code=400, detail="Этот ключ уже был активирован")
        
    if promo.days == -1 or promo.tariff == "forever":
        new_sub_end = "Навсегда (Forever)"
    else:
        new_sub_end = add_days_to_sub(user.subscription_end, promo.days)
        
    promo.is_used = 1
    promo.used_by = user.username
    promo.used_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M")
    
    user.subscription_end = new_sub_end
    db.commit()
    
    return {"status": "ok", "message": "Подписка успешно активирована!", "subscription_end": new_sub_end}

class LoaderRegRequest(BaseModel):
    username: str
    email: str
    password: str
    hwid: str = None
    
@app.post("/api/loader/register")
def loader_reg(req: LoaderRegRequest, db: Session = Depends(get_db)):
    if not req.username or not req.email or not req.password:
        return {"success": False, "message": "Заполните все поля"}
        
    try:
        existing = db.query(User).filter((User.username == req.username) | (User.email == req.email)).first()
        if existing:
            return {"success": False, "message": "Логин или email уже заняты"}
            
        hashed = hashlib.sha256(req.password.encode('utf-8')).hexdigest()
        new_user = User(
            username=req.username, 
            email=req.email, 
            password_hash=hashed, 
            hwid=req.hwid,
            subscription_end="Нет активной подписки"
        )
        db.add(new_user)
        db.commit()
        return {"success": True, "message": "Регистрация успешна! Теперь вы можете войти."}
    except Exception as e:
        print(f"[ERROR LOADER REGISTER] {e}")
        return {"success": False, "message": "Внутренняя ошибка сервера"}

class LoaderActivateRequest(BaseModel):
    username: str
    password: str
    key: str

@app.post("/api/loader/activate-key")
def loader_activate(req: LoaderActivateRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == req.username).first()
    if not user:
        return {"success": False, "message": "Неверный логин или пароль"}
        
    if not check_password_hash(req.password, user.password_hash):
        return {"success": False, "message": "Неверный логин или пароль"}
        
    key_code = req.key.strip()
    promo = db.query(PromoKey).filter(PromoKey.key_code == key_code).first()
    if not promo:
        return {"success": False, "message": "Неверный код активации"}
        
    if promo.is_used == 1:
        return {"success": False, "message": "Этот ключ уже был активирован"}
        
    if promo.days >= 9999 or promo.tariff == "forever":
        new_sub_end = "Навсегда"
    else:
        new_sub_end = add_days_to_sub(user.subscription_end, promo.days)
        
    promo.is_used = 1
    promo.used_by = user.username
    promo.used_at = datetime.utcnow().strftime("%d.%m.%Y %H:%M")
    
    user.subscription_end = new_sub_end
    db.commit()
    
    return {"success": True, "subscription_end": new_sub_end, "message": "Подписка успешно активирована!"}

def get_current_admin(authorization: str = Header(None), db: Session = Depends(get_db)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized")
    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user = db.query(User).filter(User.id == payload.get("user_id")).first()
        if not user or user.is_admin != 1:
            raise HTTPException(status_code=403, detail="Forbidden")
        return user
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.get("/api/admin/users")
def admin_get_users(admin: User = Depends(get_current_admin), db: Session = Depends(get_db)):
    users = db.query(User).all()
    return [{"id": u.id, "username": u.username, "email": u.email, "subscription_end": u.subscription_end, "hwid": u.hwid, "is_banned": u.is_banned, "is_hwid_banned": u.is_hwid_banned, "is_admin": u.is_admin} for u in users]

class AdminActionRequest(BaseModel):
    user_id: int

@app.post("/api/admin/ban")
def admin_ban_user(req: AdminActionRequest, admin: User = Depends(get_current_admin), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == req.user_id).first()
    if user:
        user.is_banned = 1 if user.is_banned == 0 else 0
        db.commit()
        return {"success": True, "is_banned": user.is_banned}
    raise HTTPException(status_code=404)

@app.post("/api/admin/reset-hwid")
def admin_reset_hwid(req: AdminActionRequest, admin: User = Depends(get_current_admin), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == req.user_id).first()
    if user:
        user.hwid = None
        db.commit()
        return {"success": True}
    raise HTTPException(status_code=404)

@app.post("/api/admin/ban-hwid")
def admin_ban_hwid(req: AdminActionRequest, admin: User = Depends(get_current_admin), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == req.user_id).first()
    if user:
        user.is_hwid_banned = 1 if user.is_hwid_banned == 0 else 0
        db.commit()
        return {"success": True, "is_hwid_banned": user.is_hwid_banned}
    raise HTTPException(status_code=404)

class AdminEditSubRequest(BaseModel):
    user_id: int
    subscription_end: str

@app.post("/api/admin/edit-sub")
def admin_edit_sub(req: AdminEditSubRequest, admin: User = Depends(get_current_admin), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == req.user_id).first()
    if user:
        user.subscription_end = req.subscription_end
        db.commit()
        return {"success": True}
    raise HTTPException(status_code=404)

class LoaderAuthRequest(BaseModel):
    username: str
    password: str
    hwid: str = None

@app.post("/api/loader/auth")
def loader_auth(req: LoaderAuthRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == req.username).first()
    if not user:
        return {"access": False, "error": "Неверный логин или пароль"}
        
    if not check_password_hash(req.password, user.password_hash):
        return {"access": False, "error": "Неверный логин или пароль"}
        
    if user.is_banned == 1 or user.is_hwid_banned == 1:
        return {"access": False, "error": "Доступ заблокирован администратором"}
        
    sub = user.subscription_end
    if not sub or sub == "Нет активной подписки":
        return {"access": False, "error": "Нет активной подписки"}
        
    if sub != "Навсегда" and sub != "Навсегда (Forever)":
        try:
            try:
                parsed_date = datetime.strptime(sub, "%Y-%m-%d %H:%M")
            except ValueError:
                parsed_date = datetime.strptime(sub, "%d.%m.%Y %H:%M")
            if parsed_date < datetime.utcnow():
                return {"access": False, "error": "Подписка истекла"}
        except ValueError:
            return {"access": False, "error": "Ошибка формата подписки"}
            
    if req.hwid:
        if not user.hwid:
            user.hwid = req.hwid
            db.commit()
        elif user.hwid != req.hwid:
            return {"access": False, "error": "Неверная привязка железа (HWID)"}
            
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
