"""
Website module for LLM-Protect.

Provides the web interface and API server for the pipeline.
"""

from website.serve import app, create_app

__all__ = ["app", "create_app"]
