# LLM-Protect Pipeline Reorganization Summary

## Overview

The repository has been reorganized into a clean, modular structure following the flowchart architecture:

```
Layer 0 (Heuristics) → Input Prep → Image Processing → (Layer 1/2)
```

## New Structure

```
LLM-Protect/
├── contracts/           # Shared data contracts
│   ├── __init__.py
│   ├── manifest.py     # PipelineManifest - unified handoff object
│   └── shared.py       # Shared utilities (hash, embed, normalize)
│
├── pipeline/            # Orchestration layer
│   ├── __init__.py
│   └── main.py         # Pipeline class chaining all layers
│
├── input_prep/          # Input preparation module
│   ├── __init__.py
│   └── core.py         # Normalization, HMAC, embeddings, heuristics
│
├── image_processing/    # Image analysis module
│   ├── __init__.py
│   └── core.py         # Hash, pHash, EXIF, OCR, steganography
│
├── website/             # Web interface & API
│   ├── __init__.py
│   ├── serve.py        # Single FastAPI entrypoint
│   └── static/         # Frontend files
│
├── layer0/              # (Existing) Regex/heuristic scanning
└── security/            # (Existing) Advanced security analyzers
```

## Key Changes

### 1. Unified Manifest (`contracts/manifest.py`)
- `PipelineManifest`: Single object passed through all layers
- Each layer has its own result section: `layer0_result`, `input_prep_result`, `image_processing_result`
- Shared structures: `HashInfo`, `EmbeddingInfo`, `AttachmentInfo`, `FlagInfo`

### 2. Pipeline Orchestration (`pipeline/main.py`)
- `Pipeline` class chains Layer 0 → Input Prep → Image Processing
- Configurable layer enable/disable
- Short-circuit on rejection
- Comprehensive error handling with `fail_open` option
- Latency tracking per layer

### 3. Redundancy Elimination (`contracts/shared.py`)
- `ModelManager`: Singleton for lazy-loaded ML models
- `HMACManager`: Unified HMAC operations
- Shared hashing: `hash_sha256()`, `hash_file_sha256()`
- Cached embeddings with LRU cache
- Single `normalize_text()` implementation

### 4. Latency Optimizations
- Pre-compiled regex patterns in `input_prep/core.py`
- LRU cached embeddings (1000 entry cache)
- Lazy-loaded models (only load when first used)
- pHash caching with `@lru_cache`

### 5. Clean Website Integration (`website/serve.py`)
- Single API entrypoint for all operations
- **No business logic** - only calls pipeline APIs
- Endpoints: `/scan`, `/scan/detailed`, `/scan/layer0`, `/scan/with-media`
- Health checks: `/health`, `/ready`, `/live`

## Usage

### Programmatic
```python
from pipeline import run_pipeline

result = run_pipeline(
    text="User input here",
    external_chunks=["RAG result 1", "RAG result 2"]
)

print(f"Status: {result.layer0_result.status}")
print(f"Score: {result.overall_score}")
```

### API
```bash
curl -X POST http://localhost:8080/scan \
  -H "Content-Type: application/json" \
  -d '{"text": "Hello world"}'
```

### CLI
```bash
python -m pipeline.main "Text to scan" --json
```

## Files Created
- `contracts/__init__.py`, `manifest.py`, `shared.py`
- `pipeline/__init__.py`, `main.py`
- `input_prep/__init__.py`, `core.py`
- `image_processing/__init__.py`, `core.py`
- `website/__init__.py`, `serve.py`
- `IMPROVEMENTS.md` (actionable suggestions)

## What Was NOT Deleted
All original code remains intact:
- `layer0/` - Existing regex/heuristic system
- `Input Prep/` - Original input preparation
- `security/` - Advanced security analyzers
- `app/` - Original app structure

The new modules provide clean interfaces and can gradually replace imports.
