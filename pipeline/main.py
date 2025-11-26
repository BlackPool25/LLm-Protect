"""
Unified Pipeline for LLM-Protect.

This module orchestrates the multi-layer security pipeline:

1. Layer 0 (Heuristics) - Fast regex/pattern matching (~1ms)
2. Input Preparation - Text normalization, HMAC, embeddings
3. Image Processing - Hash, EXIF, OCR, steganography detection

Each layer:
- Receives the manifest
- Processes its designated inputs
- Updates only its result section
- Passes manifest to next layer
"""

import asyncio
import logging
import time
from typing import Optional, List, Callable, Any

from contracts.manifest import (
    PipelineManifest,
    AttachmentInfo,
    create_manifest,
    compute_overall_score,
    ScanStatus,
)

logger = logging.getLogger(__name__)


class Pipeline:
    """
    Main pipeline orchestrator.
    
    Chains Layer 0 → Input Prep → Image Processing with:
    - Configurable layer enable/disable
    - Short-circuit on rejection
    - Comprehensive error handling
    - Latency tracking
    """
    
    def __init__(
        self,
        enable_layer0: bool = True,
        enable_input_prep: bool = True,
        enable_image_processing: bool = True,
        stop_on_reject: bool = True,
        fail_open: bool = False,
    ):
        """
        Initialize pipeline.
        
        Args:
            enable_layer0: Enable Layer 0 heuristic scanning
            enable_input_prep: Enable input preparation
            enable_image_processing: Enable image processing
            stop_on_reject: Stop pipeline if any layer rejects
            fail_open: If True, pass on errors; if False, reject on errors
        """
        self.enable_layer0 = enable_layer0
        self.enable_input_prep = enable_input_prep
        self.enable_image_processing = enable_image_processing
        self.stop_on_reject = stop_on_reject
        self.fail_open = fail_open
        
        # Lazy-load layer runners
        self._layer0_runner: Optional[Callable] = None
        self._input_prep_runner: Optional[Callable] = None
        self._image_proc_runner: Optional[Callable] = None
        
        logger.info(
            f"Pipeline initialized: layer0={enable_layer0}, "
            f"input_prep={enable_input_prep}, image_proc={enable_image_processing}"
        )
    
    def _get_layer0_runner(self):
        """Lazy-load Layer 0 runner."""
        if self._layer0_runner is None:
            try:
                from layer0.scanner import scanner
                self._layer0_runner = scanner
                logger.info("Layer 0 scanner loaded")
            except ImportError as e:
                logger.warning(f"Layer 0 not available: {e}")
                self._layer0_runner = None
        return self._layer0_runner
    
    def _get_input_prep_runner(self):
        """Lazy-load Input Prep runner."""
        if self._input_prep_runner is None:
            try:
                from input_prep.runner import run as input_prep_run
                self._input_prep_runner = input_prep_run
                logger.info("Input Prep runner loaded")
            except ImportError:
                # Fallback to inline import from Input Prep
                try:
                    from input_prep.core import run_input_prep
                    self._input_prep_runner = run_input_prep
                    logger.info("Input Prep core loaded")
                except ImportError as e:
                    logger.warning(f"Input Prep not available: {e}")
                    self._input_prep_runner = None
        return self._input_prep_runner
    
    def _get_image_proc_runner(self):
        """Lazy-load Image Processing runner."""
        if self._image_proc_runner is None:
            try:
                from image_processing.runner import run as image_proc_run
                self._image_proc_runner = image_proc_run
                logger.info("Image Processing runner loaded")
            except ImportError:
                try:
                    from image_processing.core import run_image_processing
                    self._image_proc_runner = run_image_processing
                    logger.info("Image Processing core loaded")
                except ImportError as e:
                    logger.warning(f"Image Processing not available: {e}")
                    self._image_proc_runner = None
        return self._image_proc_runner
    
    async def run_async(
        self,
        manifest: PipelineManifest | str,
    ) -> PipelineManifest:
        """
        Run the full pipeline asynchronously.
        
        Args:
            manifest: Input manifest to process, or a string (text input)
        
        Returns:
            Updated manifest with all layer results
        """
        pipeline_start = time.perf_counter()
        
        # Convert string input to manifest
        if isinstance(manifest, str):
            manifest = PipelineManifest(text=manifest)
        
        try:
            # Stage 1: Layer 0 (Heuristics) - Target: <1ms
            if self.enable_layer0:
                manifest = await self._run_layer0(manifest)
                manifest.layers_completed.append("layer0")
                
                if self.stop_on_reject and manifest.layer0_result.status == ScanStatus.REJECTED:
                    logger.info(f"Pipeline stopped at Layer 0: {manifest.layer0_result.note}")
                    return self._finalize(manifest, pipeline_start)
            
            # Stage 2: Input Preparation
            if self.enable_input_prep:
                manifest = await self._run_input_prep(manifest)
                manifest.layers_completed.append("input_prep")
                
                if self.stop_on_reject and manifest.input_prep_result.status == ScanStatus.REJECTED:
                    logger.info(f"Pipeline stopped at Input Prep: {manifest.input_prep_result.note}")
                    return self._finalize(manifest, pipeline_start)
            
            # Stage 3: Image Processing
            if self.enable_image_processing and manifest.attachments:
                manifest = await self._run_image_processing(manifest)
                manifest.layers_completed.append("image_processing")
            
            return self._finalize(manifest, pipeline_start)
            
        except Exception as e:
            logger.error(f"Pipeline error: {e}")
            manifest.errors.append({
                "layer": "pipeline",
                "error": str(e),
                "timestamp": time.time(),
            })
            
            if not self.fail_open:
                manifest.layer0_result.status = ScanStatus.ERROR
                manifest.layer0_result.note = f"Pipeline error: {e}"
            
            return self._finalize(manifest, pipeline_start)
    
    def run(self, manifest: PipelineManifest) -> PipelineManifest:
        """
        Run the full pipeline synchronously.
        
        Args:
            manifest: Input manifest to process
        
        Returns:
            Updated manifest with all layer results
        """
        return asyncio.run(self.run_async(manifest))
    
    async def _run_layer0(self, manifest: PipelineManifest) -> PipelineManifest:
        """Run Layer 0 scanning."""
        start = time.perf_counter()
        
        try:
            runner = self._get_layer0_runner()
            if runner is None:
                manifest.layer0_result.status = ScanStatus.CLEAN
                manifest.layer0_result.note = "Layer 0 not available (skipped)"
                return manifest
            
            # Prepare input for Layer 0
            from layer0.models import PreparedInput as L0PreparedInput
            l0_input = L0PreparedInput(
                user_input=manifest.text,
                external_chunks=manifest.external_chunks or None,
            )
            
            # Run scan
            result = await runner.scan_async(l0_input)
            
            # Update manifest
            manifest.layer0_result.status = ScanStatus(result.status.value)
            manifest.layer0_result.score = result.ml_suspicion_score or 0.0
            manifest.layer0_result.rule_id = result.rule_id
            manifest.layer0_result.dataset = result.dataset
            manifest.layer0_result.severity = result.severity
            manifest.layer0_result.audit_token = result.audit_token
            manifest.layer0_result.note = result.note
            manifest.layer0_result.processing_time_ms = result.processing_time_ms
            
            manifest.layer0_score = result.ml_suspicion_score or 0.0
            
        except Exception as e:
            logger.error(f"Layer 0 error: {e}")
            manifest.layer0_result.status = ScanStatus.ERROR
            manifest.layer0_result.note = str(e)
            manifest.errors.append({"layer": "layer0", "error": str(e)})
        
        manifest.layer0_result.processing_time_ms = (time.perf_counter() - start) * 1000
        return manifest
    
    async def _run_input_prep(self, manifest: PipelineManifest) -> PipelineManifest:
        """Run Input Preparation."""
        start = time.perf_counter()
        
        try:
            # Import input prep functions
            from input_prep.core import (
                normalize_text,
                analyze_unicode,
                run_heuristics,
                generate_embedding,
                generate_hmacs,
                extract_emojis,
            )
            
            # Normalize text
            clean_text = normalize_text(manifest.text)
            manifest.clean_text = clean_text
            manifest.flags.unicode_normalized = True
            
            # Unicode analysis
            unicode_result = analyze_unicode(manifest.text)
            manifest.input_prep_result.zero_width_found = unicode_result.get("zero_width_count", 0)
            manifest.input_prep_result.invisible_chars_found = unicode_result.get("invisible_count", 0)
            manifest.input_prep_result.unicode_obfuscation_detected = unicode_result.get("obfuscation_detected", False)
            manifest.flags.zero_width_removed = manifest.input_prep_result.zero_width_found > 0
            
            # Heuristics
            heuristic_result = run_heuristics(clean_text)
            manifest.input_prep_result.has_long_base64 = heuristic_result.get("has_long_base64", False)
            manifest.input_prep_result.has_system_delimiter = heuristic_result.get("has_system_delimiter", False)
            manifest.input_prep_result.suspicious_score = heuristic_result.get("suspicious_score", 0.0)
            manifest.input_prep_result.detected_patterns = heuristic_result.get("detected_patterns", [])
            
            # Text embedding
            embedding_hash = generate_embedding(clean_text)
            manifest.embeddings.text_embedding_hash = embedding_hash
            
            # HMAC generation for external chunks
            if manifest.external_chunks:
                hmacs = generate_hmacs(manifest.external_chunks)
                manifest.hashes.external_chunks_hmacs = hmacs
                manifest.input_prep_result.hmacs_generated = len(hmacs)
                manifest.flags.hmac_verified = True
            
            # Emoji extraction
            emoji_result = extract_emojis(manifest.text)
            manifest.flags.has_emojis = emoji_result.get("count", 0) > 0
            manifest.flags.emoji_count = emoji_result.get("count", 0)
            manifest.input_prep_result.emoji_count = emoji_result.get("count", 0)
            manifest.input_prep_result.emoji_descriptions = emoji_result.get("descriptions", [])
            
            # Update scores
            manifest.input_prep_result.status = ScanStatus.CLEAN
            manifest.input_prep_result.original_char_count = len(manifest.text)
            manifest.input_prep_result.normalized_char_count = len(clean_text)
            manifest.prep_score = manifest.input_prep_result.suspicious_score
            
        except ImportError as e:
            logger.warning(f"Input prep modules not available, using fallback: {e}")
            manifest = await self._run_input_prep_fallback(manifest)
        except Exception as e:
            logger.error(f"Input prep error: {e}")
            manifest.input_prep_result.status = ScanStatus.ERROR
            manifest.input_prep_result.note = str(e)
            manifest.errors.append({"layer": "input_prep", "error": str(e)})
        
        manifest.input_prep_result.processing_time_ms = (time.perf_counter() - start) * 1000
        return manifest
    
    async def _run_input_prep_fallback(self, manifest: PipelineManifest) -> PipelineManifest:
        """Fallback input prep using existing Input Prep modules."""
        try:
            # Try importing from Input Prep folder structure
            import sys
            sys.path.insert(0, "Input Prep")
            
            from app.services.text_normalizer import normalize_text
            from app.services.unicode_detector import analyze_unicode_obfuscation
            from app.services.heuristics import run_fast_heuristics
            from app.services.text_embeddings import generate_text_embedding
            from app.utils.hmac_utils import sign_chunks
            
            # Run processing
            clean_text = normalize_text(manifest.text)
            manifest.clean_text = clean_text
            
            unicode_result = analyze_unicode_obfuscation(manifest.text)
            manifest.input_prep_result.zero_width_found = unicode_result.zero_width_count
            manifest.input_prep_result.unicode_obfuscation_detected = unicode_result.unicode_obfuscation_flag
            
            heuristic_result = run_fast_heuristics(clean_text)
            manifest.input_prep_result.suspicious_score = heuristic_result.suspicious_score
            manifest.input_prep_result.detected_patterns = heuristic_result.detected_patterns
            
            embedding_hash = generate_text_embedding(clean_text)
            manifest.embeddings.text_embedding_hash = embedding_hash
            
            if manifest.external_chunks:
                hmacs = sign_chunks(manifest.external_chunks)
                manifest.hashes.external_chunks_hmacs = hmacs
            
            manifest.input_prep_result.status = ScanStatus.CLEAN
            
        except Exception as e:
            logger.error(f"Input prep fallback error: {e}")
            manifest.input_prep_result.status = ScanStatus.ERROR
            manifest.input_prep_result.note = f"Fallback error: {e}"
        
        return manifest
    
    async def _run_image_processing(self, manifest: PipelineManifest) -> PipelineManifest:
        """Run Image Processing."""
        start = time.perf_counter()
        
        if not manifest.attachments:
            manifest.image_processing_result.status = ScanStatus.CLEAN
            manifest.image_processing_result.note = "No attachments to process"
            return manifest
        
        try:
            from image_processing.core import (
                analyze_image,
                calculate_phash,
                extract_exif,
                detect_steganography,
                perform_ocr,
            )
            
            images_processed = 0
            total_stego_score = 0.0
            
            for attachment in manifest.attachments:
                if attachment.type != "image":
                    continue
                
                images_processed += 1
                
                # Get image path from attachment
                image_path = attachment.metadata.get("path")
                if not image_path:
                    continue
                
                # Full analysis
                result = analyze_image(image_path)
                
                # Update attachment
                attachment.hash = result.get("hash")
                attachment.description = result.get("caption")
                attachment.metadata["phash"] = result.get("phash")
                attachment.metadata["stego_score"] = result.get("stego_score", 0.0)
                attachment.metadata["ocr_text"] = result.get("ocr_text")
                
                total_stego_score = max(total_stego_score, result.get("stego_score", 0.0))
                
                # Update manifest result
                if result.get("phash"):
                    manifest.image_processing_result.phash = result["phash"]
                if result.get("ocr_text"):
                    manifest.image_processing_result.ocr_text = result["ocr_text"]
                    manifest.image_processing_result.ocr_performed = True
                if result.get("caption"):
                    manifest.image_processing_result.caption = result["caption"]
            
            manifest.image_processing_result.images_processed = images_processed
            manifest.image_processing_result.stego_score = total_stego_score
            manifest.image_processing_result.stego_detected = total_stego_score > 0.5
            manifest.flags.steganography_detected = total_stego_score > 0.5
            
            manifest.image_processing_result.status = ScanStatus.CLEAN
            manifest.image_score = total_stego_score
            
        except ImportError as e:
            logger.warning(f"Image processing modules not available, using fallback: {e}")
            manifest = await self._run_image_processing_fallback(manifest)
        except Exception as e:
            logger.error(f"Image processing error: {e}")
            manifest.image_processing_result.status = ScanStatus.ERROR
            manifest.image_processing_result.note = str(e)
            manifest.errors.append({"layer": "image_processing", "error": str(e)})
        
        manifest.image_processing_result.processing_time_ms = (time.perf_counter() - start) * 1000
        return manifest
    
    async def _run_image_processing_fallback(self, manifest: PipelineManifest) -> PipelineManifest:
        """Fallback image processing using existing modules."""
        try:
            import sys
            sys.path.insert(0, "Input Prep")
            
            from app.services.advanced_image_processor import (
                analyze_image_advanced,
                calculate_phash,
            )
            
            for attachment in manifest.attachments:
                if attachment.type != "image":
                    continue
                
                image_path = attachment.metadata.get("path")
                if not image_path:
                    continue
                
                result = analyze_image_advanced(image_path)
                attachment.hash = result.file_hash
                attachment.metadata["phash"] = result.phash
                attachment.metadata["stego_score"] = result.stego_score
                attachment.metadata["ocr_text"] = result.ocr_text
                
                manifest.image_processing_result.stego_score = max(
                    manifest.image_processing_result.stego_score,
                    result.stego_score
                )
                manifest.image_processing_result.images_processed += 1
            
            manifest.image_processing_result.status = ScanStatus.CLEAN
            
        except Exception as e:
            logger.error(f"Image processing fallback error: {e}")
            manifest.image_processing_result.status = ScanStatus.ERROR
            manifest.image_processing_result.note = f"Fallback error: {e}"
        
        return manifest
    
    def _finalize(
        self,
        manifest: PipelineManifest,
        pipeline_start: float,
    ) -> PipelineManifest:
        """Finalize manifest with overall scores and timing."""
        manifest.total_processing_time_ms = (time.perf_counter() - pipeline_start) * 1000
        manifest.overall_score = compute_overall_score(manifest)
        
        logger.info(
            f"Pipeline completed: layers={manifest.layers_completed}, "
            f"overall_score={manifest.overall_score:.3f}, "
            f"time={manifest.total_processing_time_ms:.2f}ms"
        )
        
        return manifest


# ============================================================================
# Convenience Functions
# ============================================================================

# Default pipeline instance
_default_pipeline: Optional[Pipeline] = None


def get_pipeline() -> Pipeline:
    """Get or create default pipeline instance."""
    global _default_pipeline
    if _default_pipeline is None:
        _default_pipeline = Pipeline()
    return _default_pipeline


async def run_pipeline_async(
    text: str,
    external_chunks: Optional[List[str]] = None,
    attachments: Optional[List[AttachmentInfo]] = None,
) -> PipelineManifest:
    """
    Run the full pipeline asynchronously.
    
    Args:
        text: User input text
        external_chunks: Optional external data (RAG)
        attachments: Optional file/image attachments
    
    Returns:
        Completed pipeline manifest
    """
    manifest = create_manifest(
        text=text,
        external_chunks=external_chunks,
        attachments=attachments,
    )
    
    pipeline = get_pipeline()
    return await pipeline.run_async(manifest)


def run_pipeline(
    text: str,
    external_chunks: Optional[List[str]] = None,
    attachments: Optional[List[AttachmentInfo]] = None,
) -> PipelineManifest:
    """
    Run the full pipeline synchronously.
    
    Args:
        text: User input text
        external_chunks: Optional external data (RAG)
        attachments: Optional file/image attachments
    
    Returns:
        Completed pipeline manifest
    """
    return asyncio.run(run_pipeline_async(text, external_chunks, attachments))


# ============================================================================
# CLI Entry Point
# ============================================================================

if __name__ == "__main__":
    import argparse
    import json
    
    parser = argparse.ArgumentParser(description="LLM-Protect Pipeline")
    parser.add_argument("text", help="Text to process")
    parser.add_argument("--external", nargs="*", help="External chunks")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    
    args = parser.parse_args()
    
    result = run_pipeline(args.text, args.external)
    
    if args.json:
        print(result.model_dump_json(indent=2))
    else:
        print(f"Status: {result.layer0_result.status}")
        print(f"Overall Score: {result.overall_score:.3f}")
        print(f"Processing Time: {result.total_processing_time_ms:.2f}ms")
        print(f"Layers: {', '.join(result.layers_completed)}")
