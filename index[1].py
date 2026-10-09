"""Vercel entrypoint for the Guardrail FastAPI application."""
from backend.app import app

# Vercel's Python runtime detects this module-level FastAPI instance.
