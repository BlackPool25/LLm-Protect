"""
Simple startup script for Layer-0 API server.
"""

import logging
import sys
import os
from pathlib import Path

# Add parent directory to Python path
script_dir = Path(__file__).parent
project_root = script_dir.parent
sys.path.insert(0, str(project_root))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

def main():
    """Start the Layer-0 API server."""
    try:
        logger.info("Starting Layer-0 Security Filter System...")
        
        import uvicorn
        from layer0.api import app
        from layer0.config import settings
        
        logger.info("API initialized successfully")
        logger.info(f"Server will start on {settings.api_host}:{settings.api_port}")
        
        # Start uvicorn server
        uvicorn.run(
            app,
            host=settings.api_host,
            port=settings.api_port,
            log_level=settings.log_level.lower(),
        )
        
    except Exception as e:
        logger.error(f"Failed to start server: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
