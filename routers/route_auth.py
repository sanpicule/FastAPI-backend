from fastapi import APIRouter
from fastapi import Response, Request, Depends
from fastapi.encoders import jsonable_encoder
from schemas import UserBody, SuccessMsg, UserInfo, Csrf
from database import (
  db_signup,
  db_login
)
from auth_utils import AuthJWTCsrf
from fastapi_csrf_protect import CsrfProtect

router = APIRouter()
auth = AuthJWTCsrf()

@router.post("/api/csrftoken", response_model=Csrf)
def get_csrf_token(csrf_protect: CsrfProtect = Depends()):
    csrf_token = csrf_protect.generate_csrf()
    res = {'csrf_token': csrf_token}
    return res

# 登録用API
@router.post("/api/register", response_model=UserInfo)
async def signup(request: Request, user: UserBody, csrf_protect: CsrfProtect = Depends()):
    csrf_token = csrf_protect.get_csrf_from_headers(request.headers)
    csrf_protect.validate_csrf(csrf_token)
    user = jsonable_encoder(user)
    new_user = await db_signup(user)
    return new_user

# ログイン用API
@router.post("/api/login", response_model=SuccessMsg)
async def login(request: Request, response: Response, user: UserBody, csrf_protect: CsrfProtect = Depends()):
    csrf_token = csrf_protect.get_csrf_from_headers(request.headers)
    csrf_protect.validate_csrf(csrf_token)
    user = jsonable_encoder(user)
    token = await db_login(user)
    response.set_cookie(
      key="access_token",
      value=f"Bearer {token}",
      httponly=True,
      samesite="none",
      secure=True
    )
    return {"message": "Successfully logged-in"}

# ログアウト用エンドポイント
@router.post("/api/logout", response_model=SuccessMsg)
async def logout(request: Request, response: Response, csrf_protect: CsrfProtect = Depends()):
    csrf_token = csrf_protect.get_csrf_from_headers(request.headers)
    csrf_protect.validate_csrf(csrf_token)
    response.set_cookie(
      key="access_token",
      value="",
      httponly=True,
      samesite="none",
      secure=True
    )
    return {'message': 'Successfully logged-out'}

# ユーザ一覧取得API
@router.get('/api/user', response_model=UserInfo)
async def get_user_refresh_jwt(request: Request, response: Response):
    new_token, subject = auth.verify_update_jwt(request)
    response.set_cookie(
      key="access_token",
      value=f"Bearer {new_token}",
      httponly=True,
      samesite="none",
      secure=True
    )
    return {'email': subject}