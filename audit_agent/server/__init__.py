"""Local FastAPI backend for scan jobs and runtime artifacts."""

from .app import create_app

__all__ = ["create_app"]
