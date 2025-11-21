"""API package for IntelliSniff web backend."""

from fastapi import APIRouter

from .logs import router as logs_router

__all__ = ["get_router"]


def get_router() -> APIRouter:
    router = APIRouter()
    router.include_router(logs_router, prefix="/logs")
    return router
