"""
Unified API server for LLM-Protect pipeline.

This is the SINGLE API entrypoint for all pipeline operations.
The website and external clients should ONLY interact through this API.

Design principles:
1. No business logic - all logic lives in pipeline/
2. Clean JSON responses with formatted results
3. Comprehensive error handling
4. Latency tracking on all endpoints
"""

import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


# ============================================================================
# Request/Response Models
# ============================================================================

class ScanRequest(BaseModel):
    """Request model for text scanning."""
    text: str = Field(..., min_length=1, description="User input text")
    external_chunks: Optional[List[str]] = Field(None, description="External data (RAG)")
    options: Optional[Dict[str, Any]] = Field(None, description="Processing options")


class ScanResponse(BaseModel):
    """Response model for scan results."""
    id: str = Field(..., description="Request ID")
    status: str = Field(..., description="Overall status")
    overall_score: float = Field(..., description="Combined risk score (0-1)")
    layer0_status: str = Field(..., description="Layer 0 result")
    layer0_score: float = Field(..., description="Layer 0 score")
    input_prep_status: str = Field(..., description="Input prep result")
    prep_score: float = Field(..., description="Prep score")
    image_status: Optional[str] = Field(None, description="Image processing result")
    image_score: float = Field(0.0, description="Image score")
    processing_time_ms: float = Field(..., description="Total processing time")
    layers_completed: List[str] = Field(..., description="Completed layers")
    flags: Dict[str, Any] = Field(..., description="Security flags")
    note: Optional[str] = Field(None, description="Additional notes")


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    version: str
    uptime_seconds: float
    layers: Dict[str, bool]


class DetailedResultResponse(BaseModel):
    """Detailed pipeline result for display."""
    id: str
    timestamp: str
    
    # Text info
    original_text: str
    clean_text: Optional[str]
    original_length: int
    clean_length: int
    token_estimate: int
    
    # Scores
    overall_score: float
    layer0_score: float
    prep_score: float
    image_score: float
    
    # Layer 0 details
    layer0: Dict[str, Any]
    
    # Input prep details
    input_prep: Dict[str, Any]
    
    # Image processing details
    image_processing: Dict[str, Any]
    
    # Flags
    flags: Dict[str, Any]
    
    # Timing
    processing_time_ms: float
    layer_times: Dict[str, float]


# ============================================================================
# Application Setup
# ============================================================================

# Track startup time
_start_time = time.time()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    logger.info("Starting LLM-Protect API Server...")
    
    # Pre-load pipeline
    try:
        from pipeline.main import get_pipeline
        pipeline = get_pipeline()
        logger.info("Pipeline loaded successfully")
    except Exception as e:
        logger.warning(f"Pipeline not available: {e}")
    
    yield
    
    logger.info("Shutting down LLM-Protect API Server...")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    
    application = FastAPI(
        title="LLM-Protect Pipeline API",
        description="Unified API for Layer 0, Input Prep, and Image Processing",
        version="1.0.0",
        lifespan=lifespan,
    )
    
    # CORS
    application.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Mount static files for web interface
    static_dir = os.path.join(os.path.dirname(__file__), "static")
    if os.path.exists(static_dir):
        application.mount("/static", StaticFiles(directory=static_dir), name="static")
    
    return application


app = create_app()


# ============================================================================
# Health Endpoints
# ============================================================================

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Check service health and layer availability."""
    layers = {
        "layer0": False,
        "input_prep": False,
        "image_processing": False,
    }
    
    try:
        from layer0.scanner import scanner
        layers["layer0"] = True
    except ImportError:
        pass
    
    try:
        from input_prep.core import normalize_text
        layers["input_prep"] = True
    except ImportError:
        pass
    
    try:
        from image_processing.core import analyze_image
        layers["image_processing"] = True
    except ImportError:
        pass
    
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        uptime_seconds=time.time() - _start_time,
        layers=layers,
    )


@app.get("/ready")
async def readiness_check():
    """Kubernetes readiness probe."""
    return {"status": "ready"}


@app.get("/live")
async def liveness_check():
    """Kubernetes liveness probe."""
    return {"status": "live"}


# ============================================================================
# Scan Endpoints
# ============================================================================

@app.post("/scan", response_model=ScanResponse)
async def scan_text(request: ScanRequest):
    """
    Scan text through the full pipeline.
    
    This is the main endpoint for text security analysis.
    """
    start_time = time.perf_counter()
    
    try:
        from pipeline.main import run_pipeline_async
        from contracts.manifest import AttachmentInfo
        
        # Run pipeline
        manifest = await run_pipeline_async(
            text=request.text,
            external_chunks=request.external_chunks,
        )
        
        processing_time = (time.perf_counter() - start_time) * 1000
        
        # Determine overall status
        statuses = [
            manifest.layer0_result.status.value,
            manifest.input_prep_result.status.value,
            manifest.image_processing_result.status.value,
        ]
        
        if "REJECTED" in statuses:
            overall_status = "REJECTED"
        elif "WARN" in statuses:
            overall_status = "WARN"
        elif "ERROR" in statuses:
            overall_status = "ERROR"
        else:
            overall_status = "CLEAN"
        
        return ScanResponse(
            id=manifest.id,
            status=overall_status,
            overall_score=manifest.overall_score,
            layer0_status=manifest.layer0_result.status.value,
            layer0_score=manifest.layer0_score,
            input_prep_status=manifest.input_prep_result.status.value,
            prep_score=manifest.prep_score,
            image_status=manifest.image_processing_result.status.value,
            image_score=manifest.image_score,
            processing_time_ms=processing_time,
            layers_completed=manifest.layers_completed,
            flags=manifest.flags.model_dump(),
            note=manifest.layer0_result.note or manifest.input_prep_result.note,
        )
        
    except ImportError as e:
        logger.error(f"Pipeline not available: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Pipeline components not available"
        )
    except Exception as e:
        logger.error(f"Scan error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@app.post("/scan/detailed", response_model=DetailedResultResponse)
async def scan_text_detailed(request: ScanRequest):
    """
    Scan text and return detailed results for display.
    
    Use this endpoint when you need full visibility into pipeline results.
    """
    try:
        from pipeline.main import run_pipeline_async
        
        manifest = await run_pipeline_async(
            text=request.text,
            external_chunks=request.external_chunks,
        )
        
        return DetailedResultResponse(
            id=manifest.id,
            timestamp=manifest.timestamp,
            original_text=manifest.text,
            clean_text=manifest.clean_text,
            original_length=len(manifest.text),
            clean_length=len(manifest.clean_text) if manifest.clean_text else 0,
            token_estimate=manifest.input_prep_result.token_estimate,
            overall_score=manifest.overall_score,
            layer0_score=manifest.layer0_score,
            prep_score=manifest.prep_score,
            image_score=manifest.image_score,
            layer0={
                "status": manifest.layer0_result.status.value,
                "score": manifest.layer0_result.score,
                "rule_id": manifest.layer0_result.rule_id,
                "dataset": manifest.layer0_result.dataset,
                "severity": manifest.layer0_result.severity.value if manifest.layer0_result.severity else None,
                "patterns_detected": manifest.layer0_result.patterns_detected,
                "audit_token": manifest.layer0_result.audit_token,
                "note": manifest.layer0_result.note,
            },
            input_prep={
                "status": manifest.input_prep_result.status.value,
                "zero_width_found": manifest.input_prep_result.zero_width_found,
                "invisible_chars_found": manifest.input_prep_result.invisible_chars_found,
                "unicode_obfuscation_detected": manifest.input_prep_result.unicode_obfuscation_detected,
                "suspicious_score": manifest.input_prep_result.suspicious_score,
                "detected_patterns": manifest.input_prep_result.detected_patterns,
                "emoji_count": manifest.input_prep_result.emoji_count,
                "emoji_descriptions": manifest.input_prep_result.emoji_descriptions,
                "hmacs_generated": manifest.input_prep_result.hmacs_generated,
                "note": manifest.input_prep_result.note,
            },
            image_processing={
                "status": manifest.image_processing_result.status.value,
                "images_processed": manifest.image_processing_result.images_processed,
                "stego_score": manifest.image_processing_result.stego_score,
                "stego_detected": manifest.image_processing_result.stego_detected,
                "ocr_text": manifest.image_processing_result.ocr_text,
                "caption": manifest.image_processing_result.caption,
                "note": manifest.image_processing_result.note,
            },
            flags=manifest.flags.model_dump(),
            processing_time_ms=manifest.total_processing_time_ms,
            layer_times={
                "layer0": manifest.layer0_result.processing_time_ms,
                "input_prep": manifest.input_prep_result.processing_time_ms,
                "image_processing": manifest.image_processing_result.processing_time_ms,
            },
        )
        
    except Exception as e:
        logger.error(f"Detailed scan error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@app.post("/scan/layer0")
async def scan_layer0_only(request: ScanRequest):
    """Run only Layer 0 scanning (fast path)."""
    try:
        from layer0.scanner import scanner
        from layer0.models import PreparedInput
        
        l0_input = PreparedInput(
            user_input=request.text,
            external_chunks=request.external_chunks,
        )
        
        result = await scanner.scan_async(l0_input)
        
        return {
            "status": result.status.value,
            "rule_id": result.rule_id,
            "dataset": result.dataset,
            "severity": result.severity.value if result.severity else None,
            "processing_time_ms": result.processing_time_ms,
            "audit_token": result.audit_token,
            "note": result.note,
        }
        
    except ImportError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Layer 0 not available"
        )


@app.post("/scan/with-media")
async def scan_with_media(
    text: str = Form(...),
    external_chunks: Optional[str] = Form(None),
    files: List[UploadFile] = File(None),
):
    """
    Scan text with media attachments.
    
    Use this endpoint when processing images alongside text.
    """
    try:
        from pipeline.main import run_pipeline_async
        from contracts.manifest import AttachmentInfo
        import tempfile
        import json
        
        # Parse external chunks
        chunks = None
        if external_chunks:
            try:
                chunks = json.loads(external_chunks)
            except json.JSONDecodeError:
                chunks = [external_chunks]
        
        # Process uploaded files
        attachments = []
        temp_files = []
        
        if files:
            for upload_file in files:
                if upload_file.filename:
                    # Save to temp file
                    suffix = os.path.splitext(upload_file.filename)[1]
                    temp_fd, temp_path = tempfile.mkstemp(suffix=suffix)
                    os.close(temp_fd)
                    
                    with open(temp_path, "wb") as f:
                        content = await upload_file.read()
                        f.write(content)
                    
                    temp_files.append(temp_path)
                    
                    # Create attachment
                    attachments.append(AttachmentInfo(
                        id=str(uuid.uuid4()),
                        type="image",
                        filename=upload_file.filename,
                        size_bytes=len(content),
                        metadata={"path": temp_path},
                    ))
        
        try:
            # Run pipeline
            manifest = await run_pipeline_async(
                text=text,
                external_chunks=chunks,
                attachments=attachments,
            )
            
            return {
                "id": manifest.id,
                "status": manifest.layer0_result.status.value,
                "overall_score": manifest.overall_score,
                "layer0_score": manifest.layer0_score,
                "prep_score": manifest.prep_score,
                "image_score": manifest.image_score,
                "images_processed": manifest.image_processing_result.images_processed,
                "stego_detected": manifest.image_processing_result.stego_detected,
                "processing_time_ms": manifest.total_processing_time_ms,
            }
            
        finally:
            # Cleanup temp files
            for path in temp_files:
                try:
                    os.unlink(path)
                except Exception:
                    pass
        
    except Exception as e:
        logger.error(f"Media scan error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


# ============================================================================
# Info Endpoints
# ============================================================================

@app.get("/info/rules")
async def get_rules_info():
    """Get information about loaded rules."""
    try:
        from layer0.rule_registry import rule_registry
        
        return {
            "rule_count": rule_registry.get_rule_count(),
            "dataset_count": rule_registry.get_dataset_count(),
            "version": rule_registry.get_version(),
        }
    except ImportError:
        return {"status": "Layer 0 not available"}


@app.post("/reload-rules")
async def reload_rules():
    """Reload Layer 0 rules (hot reload)."""
    try:
        from layer0.scanner import scanner
        
        result = scanner.reload_datasets()
        return result
    except ImportError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Layer 0 not available"
        )


# ============================================================================
# Web Interface Endpoint
# ============================================================================

@app.get("/")
async def root():
    """Serve web interface or redirect."""
    from fastapi.responses import FileResponse, RedirectResponse
    
    # Try to serve index.html from static
    static_dir = os.path.join(os.path.dirname(__file__), "static")
    index_path = os.path.join(static_dir, "index.html")
    
    if os.path.exists(index_path):
        return FileResponse(index_path)
    
    # Fallback: API info
    return {
        "name": "LLM-Protect Pipeline API",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health",
        "endpoints": {
            "scan": "POST /scan",
            "scan_detailed": "POST /scan/detailed",
            "scan_layer0": "POST /scan/layer0",
            "scan_with_media": "POST /scan/with-media",
        }
    }


# ============================================================================
# CLI Entry Point
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "website.serve:app",
        host="0.0.0.0",
        port=8080,
        reload=True,
    )
