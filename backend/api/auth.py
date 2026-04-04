"""GitHub OAuth flow and session helpers."""
from __future__ import annotations

import logging
import secrets

import httpx
from fastapi import Depends, HTTPException, Request, status

from ..config import settings

logger = logging.getLogger(__name__)

GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL     = "https://github.com/login/oauth/access_token"
GITHUB_USER_URL      = "https://api.github.com/user"


def get_current_user(request: Request) -> dict | None:
    """Return session user dict, or None if not authenticated."""
    return request.session.get("user")


def require_auth(user: dict | None = Depends(get_current_user)) -> dict:
    """FastAPI dependency: raises 401 if unauthenticated."""
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please log in with GitHub.",
        )
    return user


async def github_login(request: Request):
    """Redirect browser to GitHub OAuth consent page."""
    from fastapi.responses import RedirectResponse

    state = secrets.token_urlsafe(16)
    request.session["oauth_state"] = state

    params = (
        f"client_id={settings.github_oauth_client_id}"
        f"&scope=read:user"
        f"&state={state}"
    )
    return RedirectResponse(url=f"{GITHUB_AUTHORIZE_URL}?{params}")


async def github_callback(request: Request):
    """Handle OAuth callback, exchange code for token, fetch user info."""
    from fastapi.responses import RedirectResponse

    code  = request.query_params.get("code")
    state = request.query_params.get("state")

    if not code or state != request.session.pop("oauth_state", None):
        raise HTTPException(status_code=400, detail="Invalid OAuth state")

    async with httpx.AsyncClient() as client:
        # Exchange code for access token
        resp = await client.post(
            GITHUB_TOKEN_URL,
            data={
                "client_id":     settings.github_oauth_client_id,
                "client_secret": settings.github_oauth_client_secret,
                "code":          code,
            },
            headers={"Accept": "application/json"},
        )
        if resp.status_code != 200:
            raise HTTPException(status_code=502, detail="GitHub token exchange failed")

        token_data = resp.json()
        access_token = token_data.get("access_token")
        if not access_token:
            raise HTTPException(status_code=502, detail="No access token returned")

        # Fetch user profile
        user_resp = await client.get(
            GITHUB_USER_URL,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept":        "application/vnd.github.v3+json",
            },
        )
        if user_resp.status_code != 200:
            raise HTTPException(status_code=502, detail="Failed to fetch GitHub user info")

        user_data = user_resp.json()

    request.session["user"] = {
        "github_user":       user_data["login"],
        "github_avatar_url": user_data.get("avatar_url"),
    }
    logger.info("User %s logged in via GitHub OAuth", user_data["login"])
    return RedirectResponse(url=f"{settings.frontend_url}/")


async def logout(request: Request):
    from fastapi.responses import JSONResponse
    request.session.pop("user", None)
    return JSONResponse({"ok": True})
