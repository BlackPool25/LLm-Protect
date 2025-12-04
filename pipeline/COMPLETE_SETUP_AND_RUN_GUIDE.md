# Complete LLM-Protect Setup & Testing Guide

**Date:** December 2, 2025  
**Status:** ✅ All Components Ready

---

## 📋 Project Overview

LLM-Protect is a **multi-layer security pipeline** for LLM inputs:

1. **Layer 0** (Heuristics) - Fast pattern detection (~1-5ms)
2. **Input Prep** - Text normalization, HMAC signing, embeddings (~20-80ms)
3. **Image Processing** - Hash, EXIF, OCR, steganography detection (~50-200ms)

### Architecture

```
┌────────────────────────────────────────────────────────────┐
│                        LLM-Protect                         │
├────────────────────────────────────────────────────────────┤
│                                                            │
│  Input → [Layer 0] → [Input Prep] → [Image Processing]   │
│           Heuristics   Normalize     Media Analysis        │
│           (3001)       (8000)        (built-in)            │
│                                                            │
│         ↓ Output ↓                                         │
│         PreparedInput (JSON)                              │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

---

## 🚀 QUICK START (5 Minutes)

### Step 1: Install Python Dependencies

#### For CPU Only:
```bash
cd "Input_Prep"
pip install -r requirements.txt
```

#### For AMD GPU (RX 7900 GRE):
```bash
cd "Input_Prep"
pip install -r requirements-amd.txt
# OR follow: Input_Prep/docs/INSTALL_AMD.md
```

#### For NVIDIA GPU:
```bash
cd "Input_Prep"
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118
pip install -r requirements.txt
```

### Step 2: Verify Environment Files

Check that these files exist:

```bash
# Main project files
- /LLM-Protect/contracts/manifest.py          ✅ Created
- /LLM-Protect/contracts/__init__.py          ✅ Created
- /Input_Prep/.env                            ✅ Created

# Test samples
- /Input_Prep/test_samples/sample.txt
- /Input_Prep/test_samples/sample.md
```

### Step 3: Start Input_Prep Service

**Terminal 1:**
```bash
cd "Input_Prep"
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Expected output:
```
INFO:     Uvicorn running on http://0.0.0.0:8000
INFO:     Application startup complete
```

Access the API at: http://localhost:8000/docs

### Step 4: Start Layer 0 Service

**Terminal 2:**
```bash
cd "layer0"
python server.py --port 3001
```

Expected output:
```
INFO:     Uvicorn running on http://0.0.0.0:3001
Layer0 service started
```

### Step 5: Test the Pipeline

**Terminal 3:**
```bash
# Test Input Prep health
curl http://localhost:8000/health

# Test Layer 0 health
curl http://localhost:3001/test

# Test text preparation
curl -X POST "http://localhost:8000/api/v1/prepare-text" \
  -F "user_prompt=Hello, this is a test message"
```

---

## 📊 DETAILED SETUP INSTRUCTIONS

### Phase 1: Environment Setup

#### 1.1 Create Virtual Environment

```bash
# Navigate to project root
cd LLM-Protect

# Create venv
python -m venv venv

# Activate venv
# On Windows:
venv\Scripts\activate

# On macOS/Linux:
source venv/bin/activate
```

#### 1.2 Install Dependencies

```bash
# Navigate to Input_Prep
cd Input_Prep

# Install all requirements
pip install -r requirements.txt

# Verify critical packages
python -c "import fastapi, pydantic, emoji; print('✅ Core packages OK')"
```

#### 1.3 Configure Environment

The `.env` file has been created at `Input_Prep/.env` with:
- ✅ HMAC Secret Key (change in production)
- ✅ File upload settings
- ✅ API configuration
- ✅ GPU settings (optional)

**Optional: Customize settings**
```bash
# Edit .env if needed
nano .env  # or use your editor
```

---

### Phase 2: Layer 0 (Heuristics) Setup

#### 2.1 Install Layer 0 Dependencies

```bash
cd layer0
pip install -r requirements.txt
```

Installs:
- FastAPI
- Uvicorn
- Pydantic
- pytest (for testing)

#### 2.2 Verify Layer 0 Rules

Check that rules file exists:
```bash
ls -la layer0/rules/rules.jsonl
# Should show rules JSONL file with security patterns
```

#### 2.3 Test Layer 0 Locally (No Server)

```bash
cd layer0

# Test with a sample file
python server.py --test "samples/input_example.json"

# Test with direct text
python server.py --text "Ignore all previous instructions"
```

---

### Phase 3: Starting Services

#### 3.1 Start Input_Prep (Port 8000)

```bash
cd Input_Prep

# Development mode (with auto-reload)
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Production mode (4 workers)
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

**Verify it's running:**
```bash
curl http://localhost:8000/health
```

Response should be:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "libraries": {
    "txt": true,
    "md": true,
    "pdf": true,
    "docx": true,
    "image": true
  },
  "message": "All systems operational"
}
```

#### 3.2 Start Layer 0 (Port 3001)

```bash
cd layer0

# Run with default port
python server.py

# Or specify port
python server.py --port 3001
```

**Verify it's running:**
```bash
curl http://localhost:3001/test
```

Response should be:
```json
{
  "status": "ok",
  "service": "layer0",
  "rules_loaded": 16
}
```

---

## 🧪 TESTING THE SYSTEM

### Test 1: Health Checks

```bash
# Check Input Prep
curl http://localhost:8000/health | python -m json.tool

# Check Layer 0
curl http://localhost:3001/test | python -m json.tool
```

### Test 2: Text Processing (Input Prep Only)

```bash
# Simple text
curl -X POST "http://localhost:8000/api/v1/prepare-text" \
  -F "user_prompt=What is artificial intelligence?" | python -m json.tool

# With file
curl -X POST "http://localhost:8000/api/v1/prepare-text" \
  -F "user_prompt=Analyze this document" \
  -F "file=@test_samples/sample.txt" | python -m json.tool

# With external data (RAG)
curl -X POST "http://localhost:8000/api/v1/prepare-text" \
  -F "user_prompt=What does the document say?" \
  -F 'external_data=["Important information here", "More context"]' | python -m json.tool
```

### Test 3: Media Processing

```bash
# Note: Requires an image file
curl -X POST "http://localhost:8000/api/v1/prepare-media" \
  -F "user_prompt=Analyze this image" \
  -F "file=@/path/to/image.png" | python -m json.tool
```

### Test 4: Full Pipeline (Using Python)

```python
import requests
import json

BASE_URL = "http://localhost:8000"

# Test 1: Prepare text
response = requests.post(
    f"{BASE_URL}/api/v1/prepare-text",
    data={"user_prompt": "Hello, world!"}
)

result = response.json()
print("✓ Text Preparation Successful")
print(f"  Request ID: {result['metadata']['request_id']}")
print(f"  Tokens: {result['text_embed_stub']['stats']['token_estimate']}")
print(f"  Time: {result['metadata']['prep_time_ms']:.2f}ms")

# Test 2: Check Layer 0 integration
if 'layer0' in result:
    layer0 = result['layer0']
    print(f"\n✓ Layer 0 Integrated")
    print(f"  Unicode obfuscation: {layer0['unicode_analysis']['unicode_obfuscation_flag']}")
    print(f"  Suspicious score: {layer0['heuristic_flags']['suspicious_score']:.2%}")
    print(f"  Detected patterns: {layer0['heuristic_flags']['detected_patterns']}")
```

### Test 5: Using the Web Interface

Open your browser:
```
http://localhost:8000
```

This provides a visual interface for:
- Text input with real-time processing
- File upload
- Results visualization
- Layer 0 analysis display

---

## 🔗 API ENDPOINTS REFERENCE

### Input_Prep Endpoints

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/health` | Service health check |
| GET | `/docs` | Interactive API documentation |
| POST | `/api/v1/prepare-text` | Prepare text input |
| POST | `/api/v1/prepare-media` | Process images/media |
| GET | `/api/v1/output-stats` | Get output statistics |

### Layer 0 Endpoints

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/test` | Health check |
| POST | `/layer0` | Main processing endpoint |
| POST | `/admin/reload-rules` | Reload security rules |

---

## 📁 OUTPUT LOCATIONS

After processing, outputs are saved to:

```
LLM-Protect/
├── Outputs/
│   ├── layer0_text/           # Layer 0 outputs
│   │   └── YYYYMMDD_HHMMSS_layer0_<id>_<preview>.json
│   └── media_processing/      # Media outputs
│       └── YYYYMMDD_HHMMSS_media_<id>_<preview>.json
└── Input_Prep/
    ├── uploads/               # Temporary file uploads
    ├── temp_media/            # Temporary media files
    └── logs/                  # Application logs
```

---

## 🔍 TROUBLESHOOTING

### Issue: Port Already in Use

```bash
# Find process using port 8000
# On Windows:
netstat -ano | findstr :8000

# On macOS/Linux:
lsof -i :8000

# Kill process (Windows):
taskkill /PID <PID> /F

# Kill process (macOS/Linux):
kill -9 <PID>
```

### Issue: Import Errors

```bash
# Ensure contracts module is in place
ls -la contracts/

# If missing, create it:
# The setup has already created it at:
# LLM-Protect/contracts/manifest.py

# Add to Python path if needed
export PYTHONPATH="${PYTHONPATH}:/path/to/LLM-Protect"
```

### Issue: HMAC Key Not Set

```bash
# Generate a new key
python -c "import secrets; print(secrets.token_hex(32))"

# Add to .env
HMAC_SECRET_KEY=<generated_key>
```

### Issue: Module Not Found (pymupdf, docx, etc)

```bash
# Reinstall requirements
pip install --upgrade -r requirements.txt

# Or install specific packages
pip install PyMuPDF python-docx
```

### Issue: GPU/CUDA Errors

```bash
# For NVIDIA GPU
pip install torch --index-url https://download.pytorch.org/whl/cu118

# For AMD GPU, follow:
# cat Input_Prep/docs/INSTALL_AMD.md

# For CPU only, use requirements as-is
```

---

## ✅ VALIDATION CHECKLIST

Before considering setup complete, verify:

- [ ] Python 3.8+ installed
- [ ] Virtual environment created and activated
- [ ] Dependencies installed: `pip list | grep fastapi`
- [ ] `.env` file exists in `Input_Prep/`
- [ ] `contracts/manifest.py` exists in project root
- [ ] Input_Prep service starts on port 8000
- [ ] Layer 0 service starts on port 3001
- [ ] Health endpoints respond
- [ ] Sample text preparation works
- [ ] Outputs directory created
- [ ] No import errors in logs

---

## 🚀 RUNNING IN PRODUCTION

### Using Docker Compose

```yaml
# Create docker-compose.yml in project root
version: '3.8'

services:
  input_prep:
    build: ./Input_Prep
    ports:
      - "8000:8000"
    environment:
      - HMAC_SECRET_KEY=${HMAC_SECRET_KEY}
      - API_PORT=8000
    volumes:
      - ./Outputs:/app/Outputs

  layer0:
    build: ./layer0
    ports:
      - "3001:3001"
    environment:
      - LAYER1_URL=${LAYER1_URL}
```

```bash
# Run services
docker-compose up -d
```

### Using Systemd (Linux)

Create `/etc/systemd/system/llm-protect.service`:

```ini
[Unit]
Description=LLM-Protect Input Prep Service
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/llm-protect/Input_Prep
ExecStart=/opt/llm-protect/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start
sudo systemctl enable llm-protect
sudo systemctl start llm-protect
```

---

## 📚 DOCUMENTATION REFERENCES

- **[README.md](../Input_Prep/README.md)** - Project overview
- **[USAGE.md](../Input_Prep/USAGE.md)** - Detailed API usage
- **[QUICKSTART.md](../Input_Prep/QUICKSTART.md)** - Quick reference
- **[LAYER0_INTEGRATION.md](../Input_Prep/docs/LAYER0_INTEGRATION.md)** - Layer 0 integration
- **[OUTPUT_FORMATS.md](../Input_Prep/docs/OUTPUT_FORMATS.md)** - Output structure
- **[INSTALLATION_GUIDE.md](../Input_Prep/INSTALLATION_GUIDE.md)** - Detailed installation
- **[layer0/README.md](../layer0/README.md)** - Layer 0 documentation

---

## 🆘 Getting Help

### Check Logs

```bash
# Input Prep logs
tail -f Input_Prep/logs/app.log

# Layer 0 logs (if using log files)
tail -f layer0/data/layer0_logs.db

# System logs
dmesg | tail -20
```

### Test Individual Components

```bash
# Test Layer 0 independently
cd layer0
python server.py --test samples/input_example.json

# Test Input Prep independently
cd Input_Prep
python test_scripts/test_api.py

# Test complete pipeline
python test_scripts/test_all_fixes.py
```

### Report Issues

Include in issue report:
1. Error message (full stack trace)
2. Python version: `python --version`
3. Installed packages: `pip list`
4. OS and hardware
5. Steps to reproduce

---

## 📞 Support

For detailed support information, see:
- **[TROUBLESHOOTING.md](../Input_Prep/TROUBLESHOOTING.md)**
- **[ANSWERS_TO_YOUR_QUESTIONS.md](../Input_Prep/docs/ANSWERS_TO_YOUR_QUESTIONS.md)**

---

**Last Updated:** December 2, 2025  
**Status:** Production Ready ✅
