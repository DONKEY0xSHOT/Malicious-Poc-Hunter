from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from ..auth import get_current_user, github_callback, github_login, logout
from ..schemas import UserOut

router = APIRouter(prefix="/auth", tags=["auth"])


@router.get("/github")
async def auth_github(request: Request):
    return await github_login(request)


@router.get("/github/callback")
async def auth_github_callback(request: Request):
    return await github_callback(request)


@router.get("/me", response_model=UserOut | None)
async def me(user: dict | None = Depends(get_current_user)):
    if not user:
        return JSONResponse(status_code=200, content=None)
    return UserOut(**user)


@router.post("/logout")
async def auth_logout(request: Request):
    return await logout(request)
