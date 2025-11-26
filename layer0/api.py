"""
Enhanced FastAPI service with production hardening features.

Includes:
- Rate limiting
- Circuit breaker
- Health checks (liveness/readiness)
- API authentication
- Improved error handling
- Performance tracking
"""

import logging
import time
from typing import Dict, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, status, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from fastapi.security import APIKeyHeader
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from circuitbreaker import circuit
from prometheus_client import (
    Counter,
    Histogram,
    Gauge,
    generate_latest,
    CONTENT_TYPE_LATEST,
)

from layer0.config import settings
from layer0.models import PreparedInput, ScanResult, ScanStatus
from layer0.rule_registry import rule_registry
from layer0.scanner import scanner

# Configure logging
logging.basicConfig(
    level=settings.log_level,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Rate limiter
limiter = Limiter(key_func=get_remote_address)

# API Key authentication
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# Lifespan context manager for startup/shutdown
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting Layer-0 Security Filter System...")
    logger.info(f"Loaded {rule_registry.get_rule_count()} rules from {rule_registry.get_dataset_count()} datasets")
    yield
    # Shutdown
    logger.info("Shutting down Layer-0 Security Filter System...")

# Create FastAPI app
app = FastAPI(
    title="Layer-0 Security Filter System",
    description="Enterprise-grade security filter for LLM pipelines",
    version="1.0.0",
    lifespan=lifespan
)

# Add rate limit exception handler
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Prometheus metrics
if settings.metrics_enabled:
    requests_total = Counter(
        "layer0_requests_total",
        "Total scan requests",
        ["status", "endpoint"]
    )
    scan_duration = Histogram(
        "layer0_scan_duration_ms",
        "Scan duration in milliseconds",
        buckets=[5, 10, 20, 50, 100, 200, 500, 1000, 2000]
    )
    rules_matched = Counter(
        "layer0_rules_matched_total",
        "Total rule matches",
        ["dataset", "severity"]
    )
    regex_timeouts = Counter(
        "layer0_regex_timeouts_total",
        "Total regex timeouts"
    )
    dataset_reload_failures = Counter(
        "layer0_dataset_reload_failures_total",
        "Total dataset reload failures"
    )
    circuit_breaker_trips = Counter(
        "layer0_circuit_breaker_trips_total",
        "Total circuit breaker trips"
    )
    active_requests = Gauge(
        "layer0_active_requests",
        "Number of active requests"
    )
    auth_failures = Counter(
        "layer0_auth_failures_total",
        "Total authentication failures"
    )


def verify_api_key(api_key: Optional[str] = Depends(api_key_header)) -> str:
    """Verify API key authentication."""
    # If API key is not configured, allow all requests
    if not hasattr(settings, 'api_key') or not settings.api_key:
        return "anonymous"
    
    if not api_key or api_key != settings.api_key:
        if settings.metrics_enabled:
            auth_failures.inc()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    return api_key


@circuit(failure_threshold=10, recovery_timeout=60, expected_exception=Exception)
async def perform_scan(prepared_input: PreparedInput) -> ScanResult:
    """
    Perform scan with circuit breaker protection.
    
    Circuit breaker will open after 10 consecutive failures
    and attempt recovery after 60 seconds.
    """
    return await scanner.scan_async(prepared_input)


@app.get("/health/live")
async def liveness_probe() -> Dict[str, str]:
    """
    Kubernetes liveness probe.
    
    Returns 200 if the application is running.
    """
    return {"status": "alive", "timestamp": str(time.time())}


@app.get("/health/ready")
async def readiness_probe() -> Dict[str, str]:
    """
    Kubernetes readiness probe.
    
    Returns 200 if the application is ready to serve traffic.
    Returns 503 if not ready (e.g., datasets not loaded).
    """
    if rule_registry.get_rule_count() == 0:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service not ready: No rules loaded"
        )
    
    return {
        "status": "ready",
        "rule_count": str(rule_registry.get_rule_count()),
        "dataset_count": str(rule_registry.get_dataset_count()),
        "timestamp": str(time.time())
    }


@app.get("/health")
async def health_check() -> Dict[str, str]:
    """
    Legacy health check endpoint.
    
    Returns:
        Health status and rule set version
    """
    return {
        "status": "healthy",
        "rule_set_version": rule_registry.get_version(),
        "total_rules": str(rule_registry.get_rule_count()),
        "total_datasets": str(rule_registry.get_dataset_count()),
    }


@app.post("/scan", response_model=ScanResult)
@limiter.limit("100/minute")
async def scan_input(
    request: Request,
    prepared_input: PreparedInput,
    api_key: str = Depends(verify_api_key)
) -> ScanResult:
    """
    Scan input for security threats.
    
    Rate limit: 100 requests per minute per IP.
    Requires API key if configured.
    
    Args:
        request: FastAPI request object
        prepared_input: Input to scan
        api_key: API key for authentication
    
    Returns:
        ScanResult with status and metadata
    """
    if settings.metrics_enabled:
        active_requests.inc()
    
    try:
        start_time = time.perf_counter()
        
        # Perform scan with circuit breaker protection
        try:
            result = await perform_scan(prepared_input)
        except Exception as e:
            # Circuit breaker opened
            if settings.metrics_enabled:
                circuit_breaker_trips.inc()
            logger.error(f"Circuit breaker opened: {e}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Service temporarily unavailable due to high error rate"
            )
        
        elapsed = (time.perf_counter() - start_time) * 1000
        
        # Record metrics
        if settings.metrics_enabled:
            requests_total.labels(status=result.status.value, endpoint="scan").inc()
            scan_duration.observe(elapsed)
            
            if result.rule_id and result.severity:
                rules_matched.labels(
                    dataset=result.dataset or "unknown",
                    severity=result.severity.value
                ).inc()
        
        return result
    
    except HTTPException:
        raise
    except ValueError as e:
        logger.warning(f"Validation error: {e}", exc_info=True)
        if settings.metrics_enabled:
            requests_total.labels(status="validation_error", endpoint="scan").inc()
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Validation error: {str(e)}"
        )
    except TimeoutError as e:
        logger.warning(f"Timeout error: {e}")
        if settings.metrics_enabled:
            requests_total.labels(status="timeout", endpoint="scan").inc()
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Request timeout"
        )
    except Exception as e:
        logger.error(f"Scan endpoint error: {e}", exc_info=True)
        
        if settings.metrics_enabled:
            requests_total.labels(status="error", endpoint="scan").inc()
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scan failed: {str(e)}"
        )
    finally:
        if settings.metrics_enabled:
            active_requests.dec()


@app.get("/metrics")
async def metrics() -> PlainTextResponse:
    """
    Prometheus metrics endpoint.
    
    Returns:
        Prometheus metrics in text format
    """
    if not settings.metrics_enabled:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Metrics not enabled"
        )
    
    return PlainTextResponse(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST
    )


@app.post("/datasets/reload")
@limiter.limit("10/hour")
async def reload_datasets(
    request: Request,
    api_key: str = Depends(verify_api_key)
) -> Dict[str, str]:
    """
    Hot-reload datasets.
    
    Rate limit: 10 requests per hour per IP.
    Requires API key if configured.
    
    Returns:
        Reload status
    """
    try:
        result = scanner.reload_datasets()
        
        if result["status"] == "error":
            if settings.metrics_enabled:
                dataset_reload_failures.inc()
            
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=result.get("error", "Unknown error")
            )
        
        return result
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Dataset reload error: {e}", exc_info=True)
        
        if settings.metrics_enabled:
            dataset_reload_failures.inc()
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Reload failed: {str(e)}"
        )


@app.get("/stats")
async def get_stats(api_key: str = Depends(verify_api_key)) -> Dict:
    """
    Get scanner statistics.
    
    Requires API key if configured.
    
    Returns:
        Scanner statistics including rule matches and performance
    """
    try:
        stats = rule_registry.get_stats()
        return stats
    except Exception as e:
        logger.error(f"Stats endpoint error: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get stats: {str(e)}"
        )


@app.get("/")
async def root() -> Dict[str, str]:
    """
    Root endpoint.
    
    Returns:
        API information
    """
    return {
        "name": "Layer-0 Security Filter System",
        "version": "1.0.0",
        "status": "operational",
        "endpoints": {
            "scan": "POST /scan",
            "health": "GET /health",
            "liveness": "GET /health/live",
            "readiness": "GET /health/ready",
            "metrics": "GET /metrics",
            "reload": "POST /datasets/reload",
            "stats": "GET /stats",
        }
    }


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "layer0.api:app",
        host=settings.api_host,
        port=settings.api_port,
        workers=1,  # Use 1 worker for development
        reload=settings.api_reload,
        log_level=settings.log_level.lower(),
    )
