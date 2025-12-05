from fastapi import FastAPI, Depends, HTTPException, status, Response, Cookie
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional

app = FastAPI()

fake_users_db = {
    "alice": {"username": "alice", "password": "secret123"}
}

SECRET_KEY = "super-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7  # refresh token 有效期 7 天

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# 簡單的「被撤銷的 refresh token」清單示範（生存在記憶體）
# 真實系統應該存在資料庫或快取（redis）並支援過期清理等
revoked_refresh_tokens = set()  # CHANGED: 用以示範撤銷檢查

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "type": "access"})  # CHANGED: 明確標註為 access token
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))
    # CHANGED: 加上 type = "refresh" 以區分 refresh / access
    to_encode.update({"exp": expire, "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str):
    """
    驗證 access token（或一般用途，但不檢查 type == 'refresh'）
    若要專門驗 access token，可再檢查 payload['type'] == 'access'
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")
        # 可選擇檢查 type:
        if payload.get("type") == "refresh":
            # 如果不允許用 refresh 當 access，則拒絕
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
        return username
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token decode error")

# CHANGED: 新增專門驗證 refresh token 的函式
def verify_refresh_token(token: str):
    """
    驗證 refresh token:
     - 簽章與 exp（由 jwt.decode 處理）
     - 確認 payload type == 'refresh'
     - 確認 token 未被撤銷（示範用記憶體清單）
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token payload")
        # CHANGED: 檢查 token 類型是否為 refresh
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token is not a refresh token")
        # CHANGED: 檢查是否已被撤銷（示範）
        if token in revoked_refresh_tokens:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token revoked")
        return username
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token decode error")


@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), response: Response = None):
    user = fake_users_db.get(form_data.username)
    if not user or user["password"] != form_data.password:
        raise HTTPException(status_code=400, detail="Invalid credentials")

    access_token = create_access_token({"sub": user["username"]})
    refresh_token = create_refresh_token({"sub": user["username"]})

    # 設定 cookie
    # 注意：response 有可能是 None（視 FastAPI 的注入狀況），建議強制要求注入 response（可改成 response: Response）
    if response is None:
        raise HTTPException(status_code=500, detail="Response object not available")

    response.set_cookie(key="jwt", value=access_token, httponly=True, samesite="lax")
    response.set_cookie(key="refresh_jwt", value=refresh_token, httponly=True, samesite="lax")

    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


# CHANGED: /refresh 使用 verify_refresh_token 並更新 access token cookie
@app.post("/refresh")
def refresh_token(response: Response, refresh_jwt: Optional[str] = Cookie(None)):
    if not refresh_jwt:
        raise HTTPException(status_code=401, detail="Missing refresh token")

    # CHANGED: 使用專屬的 refresh token 驗證函式
    username = verify_refresh_token(refresh_jwt)

    new_access_token = create_access_token({"sub": username})

    # 更新 access token cookie（可視需求同時更新 refresh cookie）
    response.set_cookie(key="jwt", value=new_access_token, httponly=True, samesite="lax")

    return {"access_token": new_access_token, "token_type": "bearer"}


@app.get("/protected")
def protected(token: Optional[str] = Depends(oauth2_scheme), jwt_cookie: Optional[str] = Cookie(None)):
    if token:
        username = verify_token(token)
    elif jwt_cookie:
        username = verify_token(jwt_cookie)
    else:
        raise HTTPException(status_code=401, detail="Missing token or cookie")

    return {"message": f"Hello, {username}! You are authenticated."}


# 額外：示範撤銷 refresh token 的 endpoint（例如 user logout 時呼叫）
@app.post("/revoke_refresh")
def revoke_refresh(refresh_jwt: Optional[str] = Cookie(None)):
    if not refresh_jwt:
        raise HTTPException(status_code=400, detail="No refresh token provided")
    # 你可以先驗證該 refresh token 是否有效再加入撤銷清單
    try:
        _ = verify_refresh_token(refresh_jwt)
    except HTTPException:
        # 仍然加入撤銷清單以確保安全性（或回報錯誤）
        revoked_refresh_tokens.add(refresh_jwt)
        raise HTTPException(status_code=400, detail="Invalid refresh token; nonetheless revoked")

    revoked_refresh_tokens.add(refresh_jwt)
    return {"detail": "Refresh token revoked"}
