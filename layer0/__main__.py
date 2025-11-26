"""
Main entry point for Layer-0 Security Filter System API.

Run with: python -m layer0
"""

from layer0.api import app
from layer0.config import settings
import uvicorn
import logging

logging.basicConfig(
    level=settings.log_level,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

if __name__ == "__main__":
    logger.info("Starting Layer-0 Security Filter System API...")
    logger.info(f"Server: {settings.api_host}:{settings.api_port}")
    logger.info(f"Workers: {settings.api_workers}")
    
    uvicorn.run(
        "layer0.api:app",
        host=settings.api_host,
        port=settings.api_port,
        workers=1,  # Use 1 worker for development
        reload=settings.api_reload,
        log_level=settings.log_level.lower(),
    )
