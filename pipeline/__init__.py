"""
Pipeline module for LLM-Protect.

Provides the unified pipeline that chains:
Layer 0 → Input Prep → Image Processing → (Layer 1/2)
"""

from pipeline.main import (
    run_pipeline,
    run_pipeline_async,
    Pipeline,
)

__all__ = [
    "run_pipeline",
    "run_pipeline_async",
    "Pipeline",
]
