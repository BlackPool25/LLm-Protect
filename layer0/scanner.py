"""
Async-enabled scanner engine with performance optimizations.
"""

import asyncio
import hashlib
import logging
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from typing import List, Optional, Tuple

from layer0.code_detector import code_detector
from layer0.config import settings
from layer0.dataset_loader import dataset_loader
from layer0.models import PreparedInput, RuleMatch, ScanResult, ScanStatus, Severity
from layer0.normalizer import normalizer
from layer0.regex_engine import regex_engine, RegexTimeout
from layer0.rule_registry import rule_registry

logger = logging.getLogger(__name__)


class Scanner:
    """Multi-source security scanner with async support."""

    def __init__(self) -> None:
        """Initialize scanner."""
        self.stop_on_first_match = settings.stop_on_first_match
        self.ensemble_scoring = settings.ensemble_scoring
        self.prefilter_enabled = settings.prefilter_enabled
        self.prefilter_keywords = settings.prefilter_keywords_list
        
        # Load datasets on initialization
        self._load_datasets()

    def _load_datasets(self) -> None:
        """Load all datasets into rule registry."""
        try:
            datasets_dict = dataset_loader.load_all_datasets()
            # Convert dict to list of datasets
            datasets_list = list(datasets_dict.values())
            rule_registry.load_datasets(datasets_list)
            logger.info(
                f"Scanner initialized with {rule_registry.get_rule_count()} rules "
                f"from {rule_registry.get_dataset_count()} datasets"
            )
        except Exception as e:
            logger.error(f"Failed to load datasets: {e}")
            if not settings.fail_open:
                raise

    def reload_datasets(self) -> dict:
        """
        Reload datasets (hot-reload).

        Returns:
            Dictionary with reload status
        """
        try:
            start_time = time.perf_counter()
            self._load_datasets()
            elapsed_ms = (time.perf_counter() - start_time) * 1000

            return {
                "status": "success",
                "rule_set_version": rule_registry.get_version(),
                "total_rules": rule_registry.get_rule_count(),
                "reload_time_ms": elapsed_ms,
            }
        except Exception as e:
            logger.error(f"Dataset reload failed: {e}")
            return {
                "status": "error",
                "error": str(e),
            }

    def scan(self, prepared_input: PreparedInput) -> ScanResult:
        """
        Scan input for security threats (synchronous).

        Args:
            prepared_input: Prepared input to scan

        Returns:
            ScanResult with status and metadata
        """
        return asyncio.run(self.scan_async(prepared_input))

    async def scan_async(self, prepared_input: PreparedInput) -> ScanResult:
        """
        Scan input for security threats (asynchronous).

        Args:
            prepared_input: Prepared input to scan

        Returns:
            ScanResult with status and metadata
        """
        start_time = time.perf_counter()

        try:
            # Stage 0: Hybrid prefilter check (ultra-fast, <1ms)
            # This rejects 90%+ of clean inputs before expensive processing
            from layer0.prefilter import prefilter
            
            if prefilter.enabled:
                prefilter_start = time.perf_counter()
                might_match, matched_keyword = prefilter.might_match(prepared_input.user_input)
                prefilter_time_ms = (time.perf_counter() - prefilter_start) * 1000
                
                if not might_match:
                    elapsed_ms = (time.perf_counter() - start_time) * 1000
                    logger.debug(f"Prefilter rejected input in {prefilter_time_ms:.2f}ms")
                    return self._create_result(
                        status=ScanStatus.CLEAN,
                        processing_time_ms=elapsed_ms,
                        note=f"Passed prefilter check ({prefilter_time_ms:.2f}ms)",
                    )
                
                logger.debug(f"Prefilter matched keyword '{matched_keyword}' in {prefilter_time_ms:.2f}ms")
        except Exception as e:
            # Prefilter failed, continue with normal scanning
            logger.warning(f"Prefilter error (continuing without it): {e}")
            
        try:
            
            # Stage 1: Normalize user input (fast, keep synchronous)
            normalized_user_input = normalizer.normalize(prepared_input.user_input)

            # Stage 2: Check for code (bypass if detected)
            is_code, code_confidence, code_reason = code_detector.detect(normalized_user_input)
            if is_code:
                elapsed_ms = (time.perf_counter() - start_time) * 1000
                return self._create_result(
                    status=ScanStatus.CLEAN_CODE,
                    processing_time_ms=elapsed_ms,
                    note=f"Code detected ({code_reason}, confidence={code_confidence:.2f})",
                )

            # Stage 3: Legacy prefilter check (keyword-based)
            if self.prefilter_enabled and not self._prefilter_check(normalized_user_input):
                elapsed_ms = (time.perf_counter() - start_time) * 1000
                return self._create_result(
                    status=ScanStatus.CLEAN,
                    processing_time_ms=elapsed_ms,
                    note="Passed legacy prefilter check",
                )

            # Stage 4: Normalize external chunks asynchronously
            normalized_chunks: List[str] = []
            if prepared_input.external_chunks:
                # Run normalization in thread pool for CPU-bound work
                loop = asyncio.get_event_loop()
                with ThreadPoolExecutor(max_workers=4) as executor:
                    tasks = [
                        loop.run_in_executor(executor, normalizer.normalize, chunk)
                        for chunk in prepared_input.external_chunks
                    ]
                    normalized_chunks = await asyncio.gather(*tasks)

            # Stage 5: Scan user input
            user_match = await self._scan_text_async(normalized_user_input, "user_input")
            if user_match and self.stop_on_first_match:
                elapsed_ms = (time.perf_counter() - start_time) * 1000
                return self._create_result_from_match(user_match, elapsed_ms)

            # Stage 6: Scan external chunks concurrently
            chunk_matches: List[RuleMatch] = []
            if normalized_chunks:
                chunk_matches = await self._scan_chunks_async(normalized_chunks)
                if chunk_matches and self.stop_on_first_match:
                    elapsed_ms = (time.perf_counter() - start_time) * 1000
                    return self._create_result_from_match(chunk_matches[0], elapsed_ms)

            # Stage 7: Scan combined text (detect split attacks)
            combined_text = " ".join([normalized_user_input] + normalized_chunks)
            combined_match = await self._scan_text_async(combined_text, "combined")
            if combined_match and self.stop_on_first_match:
                elapsed_ms = (time.perf_counter() - start_time) * 1000
                return self._create_result_from_match(combined_match, elapsed_ms)

            # Ensemble scoring mode
            if self.ensemble_scoring:
                all_matches = [m for m in [user_match, combined_match] + chunk_matches if m]
                if all_matches:
                    elapsed_ms = (time.perf_counter() - start_time) * 1000
                    return self._ensemble_decision(all_matches, elapsed_ms)

            # No matches found
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            return self._create_result(
                status=ScanStatus.CLEAN,
                processing_time_ms=elapsed_ms,
            )

        except Exception as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            logger.error(f"Scanner error: {e}")
            
            # Fail-closed behavior
            if not settings.fail_open:
                return self._create_result(
                    status=ScanStatus.REVIEW_REQUIRED,
                    processing_time_ms=elapsed_ms,
                    note=f"Scanner error (fail-closed): {str(e)[:100]}",
                )
            else:
                return self._create_result(
                    status=ScanStatus.ERROR,
                    processing_time_ms=elapsed_ms,
                    note=f"Scanner error (fail-open): {str(e)[:100]}",
                )

    def _prefilter_check(self, text: str) -> bool:
        """
        Fast prefilter check using keywords.

        Returns:
            True if text should be scanned, False if it can be skipped
        """
        text_lower = text.lower()
        for keyword in self.prefilter_keywords:
            if keyword in text_lower:
                return True
        return False

    async def _scan_text_async(self, text: str, source: str) -> Optional[RuleMatch]:
        """
        Scan text against all rules (async).

        Args:
            text: Normalized text to scan
            source: Source identifier

        Returns:
            RuleMatch if match found, None otherwise
        """
        # Run regex scanning in thread pool (CPU-bound)
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor(max_workers=1) as executor:
            return await loop.run_in_executor(executor, self._scan_text, text, source)

    def _scan_text(self, text: str, source: str) -> Optional[RuleMatch]:
        """
        Scan text against all rules (synchronous).

        Args:
            text: Normalized text to scan
            source: Source identifier

        Returns:
            RuleMatch if match found, None otherwise
        """
        rules = rule_registry.get_active_rules()

        for rule in rules:
            try:
                match = regex_engine.search(rule.pattern, text)
                if match:
                    # Record match for analytics
                    rule_registry.record_match(rule.id, 0.0)

                    # Create redacted preview
                    matched_text = match.group(0) if hasattr(match, 'group') else ""
                    preview = self._create_redacted_preview(matched_text)

                    return RuleMatch(
                        rule_id=rule.id,
                        dataset="unknown",
                        severity=rule.severity,
                        matched_preview=preview,
                        confidence=rule.impact_score,
                        source=source,
                    )

            except RegexTimeout:
                logger.warning(f"Regex timeout for rule '{rule.id}'")
                continue
            except Exception as e:
                logger.error(f"Error scanning rule '{rule.id}': {e}")
                continue

        return None

    async def _scan_chunks_async(self, chunks: List[str]) -> List[RuleMatch]:
        """
        Scan multiple chunks concurrently (async).

        Args:
            chunks: List of normalized chunks

        Returns:
            List of matches
        """
        tasks = [
            self._scan_text_async(chunk, f"chunk_{idx}")
            for idx, chunk in enumerate(chunks)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        matches = []
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Chunk processing error: {result}")
                continue
            if result:
                matches.append(result)
                if self.stop_on_first_match:
                    break
        
        return matches

    def _create_redacted_preview(self, matched_text: str) -> str:
        """
        Create redacted preview of matched text.

        Args:
            matched_text: Original matched text

        Returns:
            Redacted preview string
        """
        text_hash = hashlib.sha256(matched_text.encode()).hexdigest()[:16]
        return f"[REDACTED:match:sha256={text_hash}]"

    def _create_result(
        self,
        status: ScanStatus,
        processing_time_ms: float,
        rule_id: Optional[str] = None,
        dataset: Optional[str] = None,
        severity: Optional[Severity] = None,
        note: Optional[str] = None,
    ) -> ScanResult:
        """Create scan result."""
        return ScanResult(
            status=status,
            audit_token=self._generate_audit_token(),
            rule_id=rule_id,
            dataset=dataset,
            severity=severity,
            processing_time_ms=processing_time_ms,
            rule_set_version=rule_registry.get_version(),
            scanner_version="1.0.0",
            note=note,
        )

    def _create_result_from_match(
        self, match: RuleMatch, processing_time_ms: float
    ) -> ScanResult:
        """Create scan result from rule match."""
        status = ScanStatus.REJECTED if match.severity in [Severity.CRITICAL, Severity.HIGH] else ScanStatus.WARN

        return self._create_result(
            status=status,
            processing_time_ms=processing_time_ms,
            rule_id=match.rule_id,
            dataset=match.dataset,
            severity=match.severity,
            note=f"Matched in {match.source}",
        )

    def _ensemble_decision(
        self, matches: List[RuleMatch], processing_time_ms: float
    ) -> ScanResult:
        """
        Make ensemble decision based on multiple matches.

        Args:
            matches: List of rule matches
            processing_time_ms: Processing time

        Returns:
            ScanResult based on ensemble scoring
        """
        total_score = sum(match.confidence for match in matches) / len(matches)

        if total_score >= settings.ensemble_threshold_reject:
            status = ScanStatus.REJECTED
        elif total_score >= settings.ensemble_threshold_warn:
            status = ScanStatus.WARN
        else:
            status = ScanStatus.CLEAN

        top_match = max(matches, key=lambda m: m.confidence)

        return self._create_result(
            status=status,
            processing_time_ms=processing_time_ms,
            rule_id=top_match.rule_id,
            dataset=top_match.dataset,
            severity=top_match.severity,
            note=f"Ensemble score: {total_score:.2f} ({len(matches)} matches)",
        )

    def _generate_audit_token(self) -> str:
        """Generate audit token for traceability."""
        import base64
        import hmac

        timestamp = str(int(time.time()))
        version = rule_registry.get_version()
        
        message = f"{version}|{timestamp}".encode()
        signature = hmac.new(
            settings.dataset_hmac_secret.encode(),
            message,
            hashlib.sha256
        ).hexdigest()[:16]

        token_data = f"{signature}|{version}|{timestamp}"
        return base64.urlsafe_b64encode(token_data.encode()).decode()


# Global scanner instance
scanner = Scanner()
