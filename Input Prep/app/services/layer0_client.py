"""
Layer-0 Integration Client for Input Prep Module.

This module integrates Layer-0 security scanning into the Input Prep pipeline.
"""

import logging
import httpx
import time
from typing import Optional, Dict, Any, Tuple
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class Layer0ScanRequest(BaseModel):
    """Layer-0 scan request model."""
    user_input: str
    external_chunks: list[str] = []


class Layer0ScanResult(BaseModel):
    """Layer-0 scan result model."""
    status: str
    audit_token: str
    rule_id: Optional[str] = None
    dataset: Optional[str] = None
    severity: Optional[str] = None
    processing_time_ms: float
    rule_set_version: str
    scanner_version: str
    note: Optional[str] = None


class Layer0Client:
    """
    Client for Layer-0 Security Filter integration.
    
    Provides async scanning integration with the Layer-0 service.
    """
    
    def __init__(
        self,
        base_url: str = "http://layer0:8000",
        api_key: Optional[str] = None,
        timeout: float = 30.0,
        enabled: bool = True
    ):
        """
        Initialize Layer-0 client.
        
        Args:
            base_url: Layer-0 API base URL
            api_key: Optional API key for authentication
            timeout: Request timeout in seconds
            enabled: Whether Layer-0 integration is enabled
        """
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.timeout = timeout
        self.enabled = enabled
        self._client: Optional[httpx.AsyncClient] = None
        
        logger.info(
            f"Layer-0 client initialized: enabled={enabled}, "
            f"url={base_url}"
        )
    
    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create async HTTP client."""
        if self._client is None:
            headers = {}
            if self.api_key:
                headers["X-API-Key"] = self.api_key
            
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers=headers,
                timeout=self.timeout
            )
        return self._client
    
    async def close(self):
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Check Layer-0 service health.
        
        Returns:
            Health status dict
        """
        try:
            client = await self._get_client()
            response = await client.get("/health")
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Layer-0 health check failed: {e}")
            return {
                "status": "error",
                "error": str(e)
            }
    
    async def scan(
        self,
        user_input: str,
        external_chunks: Optional[list[str]] = None,
        fail_open: bool = True
    ) -> Tuple[bool, Optional[Layer0ScanResult], Optional[str]]:
        """
        Scan input with Layer-0 security filter.
        
        Args:
            user_input: User input text
            external_chunks: Optional external context chunks
            fail_open: If True, allow on error; if False, block on error
        
        Returns:
            Tuple of (allowed, scan_result, error_message)
            - allowed: True if input should be allowed
            - scan_result: Layer0ScanResult if successful
            - error_message: Error message if scanning failed
        """
        if not self.enabled:
            logger.debug("Layer-0 scanning disabled, allowing input")
            return True, None, None
        
        start_time = time.time()
        
        try:
            # Prepare request
            request_data = Layer0ScanRequest(
                user_input=user_input,
                external_chunks=external_chunks or []
            )
            
            # Make scan request
            client = await self._get_client()
            response = await client.post(
                "/scan",
                json=request_data.model_dump()
            )
            response.raise_for_status()
            
            # Parse result
            result_data = response.json()
            scan_result = Layer0ScanResult(**result_data)
            
            elapsed_ms = (time.time() - start_time) * 1000
            
            # Determine if input should be allowed
            allowed = scan_result.status in ["clean", "clean_code", "warn"]
            
            logger.info(
                f"Layer-0 scan complete: status={scan_result.status}, "
                f"allowed={allowed}, time={elapsed_ms:.2f}ms, "
                f"audit_token={scan_result.audit_token[:16]}..."
            )
            
            if not allowed:
                logger.warning(
                    f"Layer-0 BLOCKED input: rule={scan_result.rule_id}, "
                    f"severity={scan_result.severity}, "
                    f"dataset={scan_result.dataset}"
                )
            
            return allowed, scan_result, None
        
        except httpx.HTTPStatusError as e:
            error_msg = f"Layer-0 HTTP error: {e.response.status_code}"
            logger.error(f"{error_msg}: {e}")
            
            # Fail open or closed based on configuration
            if fail_open:
                logger.warning("Layer-0 scan failed, allowing (fail-open)")
                return True, None, error_msg
            else:
                logger.error("Layer-0 scan failed, blocking (fail-closed)")
                return False, None, error_msg
        
        except Exception as e:
            error_msg = f"Layer-0 scan error: {str(e)}"
            logger.error(error_msg, exc_info=True)
            
            # Fail open or closed based on configuration
            if fail_open:
                logger.warning("Layer-0 scan failed, allowing (fail-open)")
                return True, None, error_msg
            else:
                logger.error("Layer-0 scan failed, blocking (fail-closed)")
                return False, None, error_msg
    
    async def scan_and_raise(
        self,
        user_input: str,
        external_chunks: Optional[list[str]] = None
    ) -> Layer0ScanResult:
        """
        Scan input and raise exception if blocked.
        
        Args:
            user_input: User input text
            external_chunks: Optional external context chunks
        
        Returns:
            Layer0ScanResult if allowed
        
        Raises:
            ValueError: If input is blocked by Layer-0
        """
        allowed, result, error = await self.scan(
            user_input=user_input,
            external_chunks=external_chunks,
            fail_open=False
        )
        
        if not allowed:
            if result:
                raise ValueError(
                    f"Input blocked by Layer-0: {result.status} "
                    f"(rule: {result.rule_id}, severity: {result.severity})"
                )
            else:
                raise ValueError(f"Input blocked by Layer-0: {error}")
        
        return result


# Global client instance
_layer0_client: Optional[Layer0Client] = None


def get_layer0_client(
    base_url: Optional[str] = None,
    api_key: Optional[str] = None,
    enabled: bool = True
) -> Layer0Client:
    """
    Get or create global Layer-0 client instance.
    
    Args:
        base_url: Override base URL
        api_key: Override API key
        enabled: Override enabled status
    
    Returns:
        Layer0Client instance
    """
    global _layer0_client
    
    if _layer0_client is None:
        # Try to get from environment
        import os
        
        if base_url is None:
            base_url = os.getenv("LAYER0_API_URL", "http://layer0:8000")
        
        if api_key is None:
            api_key = os.getenv("LAYER0_API_KEY")
        
        if enabled is None:
            enabled = os.getenv("LAYER0_ENABLED", "true").lower() == "true"
        
        _layer0_client = Layer0Client(
            base_url=base_url,
            api_key=api_key,
            enabled=enabled
        )
    
    return _layer0_client


async def scan_with_layer0(
    user_input: str,
    external_chunks: Optional[list[str]] = None,
    fail_open: bool = True
) -> Tuple[bool, Optional[Layer0ScanResult], Optional[str]]:
    """
    Convenience function to scan with Layer-0.
    
    Args:
        user_input: User input text
        external_chunks: Optional external context chunks
        fail_open: If True, allow on error
    
    Returns:
        Tuple of (allowed, scan_result, error_message)
    """
    client = get_layer0_client()
    return await client.scan(
        user_input=user_input,
        external_chunks=external_chunks,
        fail_open=fail_open
    )
