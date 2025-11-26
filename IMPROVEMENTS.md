# LLM-Protect Pipeline Improvements

## Completed Optimizations

### 1. Latency Optimizations
- **Pre-compiled regex patterns**: In `input_prep/core.py`, patterns are compiled once at module load (`_COMPILED_PATTERNS`)
- **LRU cached embeddings**: `generate_embedding()` uses `@lru_cache(maxsize=1000)` to avoid recomputation
- **Lazy-loaded models**: All ML models use lazy loading via `_get_*()` functions
- **Singleton model manager**: `contracts/shared.py` provides `ModelManager` for single instance

### 2. Redundancy Removed
- **Unified hashing**: `contracts/shared.py` provides `hash_sha256()`, `hash_file_sha256()` used everywhere
- **Single embedding model**: `ModelManager.get_embedding_model()` prevents multiple loads
- **Shared HMAC**: `HMACManager` consolidates all HMAC operations
- **Common normalization**: `normalize_text()` in `contracts/shared.py` is the single source

### 3. Manifest Contract
- **Single handoff object**: `PipelineManifest` in `contracts/manifest.py`
- **Layer-specific results**: Each layer updates only its section
- **Overall scoring**: `compute_overall_score()` with configurable weights

---

## Suggested Improvements (Actionable)

### 1. Convert to Full Async
**Current**: Mixed sync/async in scanner.py
**Suggested**: Make all layer entry points async-native

```python
# In pipeline/main.py - already done
async def _run_layer0(self, manifest) -> PipelineManifest:
    # Async throughout
```

**Action**: Ensure `layer0.scanner.scan_async()` is the primary interface.

### 2. Batch Inference for Embeddings
**Current**: Single text embeddings one at a time
**Suggested**: Batch multiple texts when processing chunks

```python
# In input_prep/core.py
def generate_embeddings_batch(texts: List[str]) -> List[str]:
    model = _get_embedding_model()
    embeddings = model.encode(texts, batch_size=32, convert_to_numpy=True)
    return [hash_sha256(e.tobytes())[:32] for e in embeddings]
```

**Benefit**: ~3-5x faster for multiple chunks.

### 3. Quantized Models
**Current**: Full precision sentence-transformers
**Suggested**: Use ONNX or quantized models

```python
# Replace in ModelManager
from sentence_transformers import SentenceTransformer
model = SentenceTransformer("all-MiniLM-L6-v2", device="cpu")
model = model.half()  # FP16 for faster inference
```

**Alternative**: Use `onnxruntime` with quantized ONNX export.

### 4. Add Tests for Manifest Consistency
**Suggested**: Create `tests/test_manifest.py`

```python
def test_manifest_layer_isolation():
    """Each layer should only modify its own section."""
    manifest = create_manifest("test")
    
    # Simulate Layer 0
    manifest.layer0_result.status = ScanStatus.CLEAN
    
    # Verify other layers untouched
    assert manifest.input_prep_result.status == ScanStatus.PENDING
    assert manifest.image_processing_result.status == ScanStatus.PENDING
```

### 5. Replace Heavy Vision Models
**Current**: Placeholder captioning
**Suggested**: Use lightweight models

Options:
- BLIP-base (smaller than BLIP-2)
- MobileViT for fast image understanding
- CLIP for embeddings without full captioning

### 6. Add Pipeline Metrics
**Suggested**: Prometheus metrics for monitoring

```python
# In pipeline/main.py
from prometheus_client import Histogram, Counter

PIPELINE_LATENCY = Histogram(
    "pipeline_latency_ms",
    "Pipeline processing latency",
    buckets=[1, 5, 10, 50, 100, 500, 1000]
)
```

### 7. Connection Pooling for Layer 0 API
**Current**: New HTTP client per request
**Suggested**: Use connection pooling

```python
# In website/serve.py
import httpx

_client = httpx.AsyncClient(
    limits=httpx.Limits(max_connections=100, max_keepalive_connections=20)
)
```

---

## Performance Benchmarks (Targets)

| Layer | Current | Target |
|-------|---------|--------|
| Layer 0 (prefilter hit) | <1ms | <0.5ms |
| Layer 0 (full scan) | 5-20ms | <10ms |
| Input Prep (no embed) | 2-5ms | <3ms |
| Input Prep (with embed) | 50-100ms | <50ms |
| Image Processing (no stego) | 10-30ms | <20ms |
| Image Processing (full) | 100-500ms | <200ms |

---

## Quick Wins (< 1 hour each)

1. **Add `@lru_cache` to `calculate_phash`** - Done in image_processing/core.py
2. **Pre-compile all regex in layer0** - Already done in regex_engine.py
3. **Use `orjson` instead of `json`** - 2-3x faster JSON parsing
4. **Add response compression** - Reduce network latency for large results
