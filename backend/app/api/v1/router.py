from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import admin, auth, comments, decisions, gitlab, notifications, packages, requests

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(auth.router)
api_router.include_router(requests.router)
api_router.include_router(packages.router)
api_router.include_router(decisions.router)
api_router.include_router(comments.router)
api_router.include_router(notifications.router)
api_router.include_router(admin.router)
api_router.include_router(gitlab.router)
