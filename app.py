from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Depends, Request
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from typing import List
from jose import JWTError, jwt
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
import os, shutil, uuid

app = FastAPI()

users_db = {}
files_db = {}

SECRET_KEY = "supersecretkey"
FERNET_KEY = Fernet.generate_key()
fernet = Fernet(FERNET_KEY)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

class User(BaseModel):
    email: EmailStr
    password: str
    role: str  
    is_verified: bool = False

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email not in users_db:
            raise HTTPException(status_code=401, detail="Invalid user")
        return users_db[email]
    except JWTError:
        raise HTTPException(status_code=403, detail="Invalid token")

@app.post("/auth/signup")
def signup(email: EmailStr = Form(...), password: str = Form(...)):
    if email in users_db:
        raise HTTPException(status_code=400, detail="Email already registered")
    token = create_access_token({"sub": email})
    users_db[email] = User(email=email, password=password, role="client")
    return {"verification_link": f"/auth/verify-email?token={token}"}

@app.get("/auth/verify-email")
def verify_email(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        user = users_db.get(email)
        if user:
            user.is_verified = True
            return {"message": "Email verified"}
        raise HTTPException(status_code=404, detail="User not found")
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid token")

@app.post("/auth/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = users_db.get(form_data.username)
    if not user or user.password != form_data.password:
        raise HTTPException(status_code=400, detail="Invalid credentials")
    token = create_access_token({"sub": user.email})
    return {"access_token": token, "token_type": "bearer"}

@app.post("/ops/upload")
def upload_file(file: UploadFile = File(...), user=Depends(get_current_user)):
    if user.role != "ops":
        raise HTTPException(status_code=403, detail="Only ops can upload")
    ext = file.filename.split(".")[-1]
    if ext not in ["pptx", "docx", "xlsx"]:
        raise HTTPException(status_code=400, detail="Invalid file type")
    file_id = str(uuid.uuid4())
    dest_path = os.path.join(UPLOAD_DIR, f"{file_id}.{ext}")
    with open(dest_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    files_db[file_id] = {"filename": file.filename, "path": dest_path}
    return {"file_id": file_id, "message": "File uploaded successfully"}

@app.get("/client/files")
def list_files(user=Depends(get_current_user)):
    if user.role != "client" or not user.is_verified:
        raise HTTPException(status_code=403, detail="Unauthorized")
    return [{"file_id": fid, "name": meta["filename"]} for fid, meta in files_db.items()]

@app.get("/client/download/{file_id}")
def generate_download_link(file_id: str, user=Depends(get_current_user)):
    if user.role != "client" or not user.is_verified:
        raise HTTPException(status_code=403, detail="Unauthorized")
    payload = f"{file_id}|{user.email}|{datetime.utcnow().isoformat()}"
    encrypted = fernet.encrypt(payload.encode()).decode()
    return {"download-link": f"/secure-download/{encrypted}", "message": "success"}

@app.get("/secure-download/{encrypted_id}")
def secure_download(encrypted_id: str, user=Depends(get_current_user)):
    if user.role != "client" or not user.is_verified:
        raise HTTPException(status_code=403, detail="Unauthorized")
    try:
        decrypted = fernet.decrypt(encrypted_id.encode()).decode()
        file_id, email, timestamp = decrypted.split("|")
        if user.email != email:
            raise HTTPException(status_code=403, detail="Unauthorized user")
        file_meta = files_db.get(file_id)
        if not file_meta:
            raise HTTPException(status_code=404, detail="File not found")
        return FileResponse(file_meta["path"], filename=file_meta["filename"])
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid or expired link")
