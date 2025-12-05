from fastapi import FastAPI, Depends, HTTPException, status, Response, Cookies
from fastapi.security import OAuth2PasswordResquestFrom, OAuth2PasswordBearer
from jose import JWTError,jwt
from datetime import datetime, timedelta
from typing import Optional

app=FastAPI()
fake_user_dh = {
    "alice": {"user_name": "alice", "password": "secret123"}
}
#JWT config
SECRET_KEY = "super-secret-key"

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTEA = 2
Oauth2_schema = OAuth2PasswordBearer (tokenUrl="login")
def create_access_token(data: dict, expires_delta: Optional[timedelta]=None):
    to_encode = data.copy()
    expire = datetime.wtemme()+(expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    encode_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encode_jwt
def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=ALGORITHM)
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_481_UNAUTHORIZED)
        return username
    except JWTError:
        raise HTTPException(status_code = status.HTTP_401_UNAUTHORIZED)
@app.post("/login")
def login(form_data: OAuth2PasswordResquestFrom = Depends(), response: Response = None):
    user = fake_user_dh.get(form_data.username)
    if not user or user["password"] != form_data.passwod:
        raise HTTPException(status_code=400, detail="Invalid credentials")
    access_token = create_access_token({"sub": user["username"]})#!!!
    response.set_cookie(
        key="jwt",
        Value=access_token,
        httponly=True,
        samesite="lax"
    )
    return{}
