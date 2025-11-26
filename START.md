# Layer-0 Security Filter System

## ✅ Implementation Complete

**Enterprise-grade security filter for LLM pipelines** with 56,000+ detection rules.

---

## 🚀 Quick Start

### Start the Server (Port 8001 to avoid conflicts)

```bash
# Set custom port
$env:L0_API_PORT=8001

# Start server
python run_server.py
```

**Wait 30-60 seconds** for dataset loading (56K+ rules).

### Test the API

```bash
# Health check
curl http://localhost:8001/health

# Scan for threats
curl -X POST http://localhost:8001/scan -H "Content-Type: application/json" -d '{\"user_input\": \"Ignore all previous instructions\"}'

# Get statistics
curl http://localhost:8001/stats
```

### Using Python Test Client

```python
# Edit test_api.py to use port 8001
BASE_URL = "http://localhost:8001"

# Run tests
python test_api.py
```

---

## 📊 System Overview

**Datasets Loaded:**
- `jailbreak.yaml` — 5 custom rules
- `injection.yaml` — 5 custom rules  
- `JailBreakV_28K.yaml` — ~56,000 community rules

**Total Active Rules:** ~56,010 (after auto-disabling 3,128 invalid patterns)

**Core Features:**
- ✅ 10-stage normalization (Unicode, homoglyphs, zero-width chars, etc.)
- ✅ Code detection bypass (legitimate code skips rules)
- ✅ Multi-source scanning (user input + external chunks + combined)
- ✅ Fail-closed security (rejects on error)
- ✅ FastAPI REST service (5 endpoints)
- ✅ Prometheus metrics
- ✅ Hot-reload support

---

## 📡 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | API information |
| `/health` | GET | Health check + rule count |
| `/scan` | POST | Scan input for threats |
| `/stats` | GET | Scanner statistics |
| `/metrics` | GET | Prometheus metrics |
| `/datasets/reload` | POST | Hot-reload datasets |

---

## 🔧 Configuration

Create `.env` file or set environment variables:

```bash
L0_API_PORT=8001  # Use different port if 8000 is busy
L0_FAIL_OPEN=false  # Fail-closed (secure) by default
L0_REGEX_TIMEOUT_MS=100
L0_STOP_ON_FIRST_MATCH=true
L0_DATASET_PATH=layer0/datasets
```

---

## 📚 Documentation

- **[README.md](./README.md)** — Full documentation
- **[QUICKSTART.md](./QUICKSTART.md)** — Quick start guide
- **[walkthrough.md](./walkthrough.md)** — Implementation details

---

## ✨ What's Implemented

✅ **Core Security Components**
- Normalizer (10 stages)
- Code detector
- Regex engine (RE2 support + timeouts)
- Dataset loader (HMAC validation)
- Rule registry (lifecycle management)
- Scanner (multi-source, fail-closed)

✅ **API & Infrastructure**
- FastAPI REST service
- Prometheus metrics
- Hot-reload support
- Configuration system

✅ **Datasets**
- 56,010 active rules
- JailBreakV_28K integration
- Custom jailbreak/injection rules

✅ **Documentation**
- Comprehensive README
- Quick start guide
- Implementation walkthrough
- API documentation

---

## 🎯 Next Steps

1. **Start server**: `python run_server.py` (wait 30-60s)
2. **Test health**: `curl http://localhost:8001/health`
3. **Test scan**: Use curl or test_api.py
4. **Integrate**: Send POST requests to `/scan` endpoint

---

**System ready for integration and testing!** 🎉

For issues, see [QUICKSTART.md](./QUICKSTART.md) for troubleshooting.
