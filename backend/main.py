from fastapi import FastAPI, Request, Response, HTTPException, Depends, Cookie
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from passlib.context import CryptContext
import sqlite3

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5500"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# DB 초기화
conn = sqlite3.connect("users.db", check_same_thread=False)
cursor = conn.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
)
""")
conn.commit()

class UserCreate(BaseModel):
    username: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

@app.post("/register")
def register(user: UserCreate):
    hashed_pw = pwd_context.hash(user.password)
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (user.username, hashed_pw))
        conn.commit()
        return {"msg": "회원가입 성공"}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="이미 존재하는 아이디입니다.")

@app.post("/login")
def login(user: UserLogin, response: Response):
    cursor.execute("SELECT password FROM users WHERE username = ?", (user.username,))
    row = cursor.fetchone()
    if not row or not pwd_context.verify(user.password, row[0]):
        raise HTTPException(status_code=401, detail="아이디 또는 비밀번호가 올바르지 않습니다.")
    response.set_cookie(key="user", value=user.username, httponly=False)
    return {"msg": "로그인 성공"}

@app.get("/me")
def get_me(user: str = Cookie(None)):
    if not user:
        return {"is_admin": False, "msg": "로그인 필요"}
    if user == "admin":
        return {"is_admin": True, "msg": "관리자입니다."}
    return {"is_admin": False, "msg": f"{user}님, 일반 사용자입니다."} 