# LLM-Protect Quick Reference Card

**Print this or keep it open while working!**

---

## 🚀 STARTUP COMMANDS

### Terminal 1 - Input Prep (Text Processing)
```bash
cd Input_Prep
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Terminal 2 - Layer 0 (Heuristics)
```bash
cd layer0
python server.py --port 3001
```

---

## ✅ HEALTH CHECKS

```bash
# Check Input Prep
curl http://localhost:8000/health

# Check Layer 0
curl http://localhost:3001/test

# Both should return HTTP 200
```

---

## 🧪 QUICK TESTS

### Simple Text
```bash
curl -X POST "http://localhost:8000/api/v1/prepare-text" \
  -F "user_prompt=Hello world"
```

### With External Data
```bash
curl -X POST "http://localhost:8000/api/v1/prepare-text" \
  -F "user_prompt=What about this?" \
  -F 'external_data=["Context 1", "Context 2"]'
```

### With File
```bash
curl -X POST "http://localhost:8000/api/v1/prepare-text" \
  -F "user_prompt=Analyze file" \
  -F "file=@Input_Prep/test_samples/sample.txt"
```

---

## 📍 KEY URLS

| Service | URL | Purpose |
|---------|-----|---------|
| Input Prep Web | http://localhost:8000 | Interactive interface |
| Input Prep API | http://localhost:8000/docs | API documentation |
| Layer 0 Health | http://localhost:3001/test | Health check |
| Outputs | `./Outputs/` | Saved processing results |

---

## 📂 KEY DIRECTORIES

```
LLM-Protect/
├── contracts/                 # Pipeline data structures ✅ CREATED
├── Input_Prep/               # Text processing service
│   ├── app/                  # Core application
│   ├── .env                  # Configuration ✅ CREATED
│   └── requirements.txt       # Dependencies
├── layer0/                   # Heuristics service
│   ├── server.py             # Main server
│   ├── rules/rules.jsonl     # Security rules
│   └── requirements.txt       # Dependencies
├── Outputs/                  # Processing results
│   ├── layer0_text/          # Text analysis outputs
│   └── media_processing/     # Image analysis outputs
└── test_pipeline.py          # Automated tests ✅ CREATED
```

---

## 🔧 TROUBLESHOOTING QUICK FIXES

### Port Already in Use
```bash
# Windows
netstat -ano | findstr :8000
taskkill /PID <PID> /F

# macOS/Linux
lsof -i :8000
kill -9 <PID>
```

### Import Errors
```bash
# Verify contracts exists
ls -la contracts/

# Reinstall dependencies
pip install -r requirements.txt
```

### HMAC Key Missing
```bash
# Generate new key
python -c "import secrets; print(secrets.token_hex(32))"

# Add to Input_Prep/.env
HMAC_SECRET_KEY=<generated_key>
```

### Module Not Found
```bash
# Check Python path
export PYTHONPATH="${PYTHONPATH}:/path/to/LLM-Protect"

# Or reinstall
pip install -e .
```

---

## 📊 EXPECTED PERFORMANCE

| Component | Time | Status |
|-----------|------|--------|
| Layer 0 | 1-5ms | ✅ Fast |
| Input Prep | 20-80ms | ✅ Fast |
| Image Processing | 50-200ms | ✅ Acceptable |
| Full Pipeline | 70-285ms | ✅ Good |

---

## 🧪 AUTOMATED TESTING

```bash
# Run all tests
python test_pipeline.py

# Tests include:
# - Connectivity (2 tests)
# - Text processing (5 tests)
# - Layer 0 integration (2 tests)
# - Output management (2 tests)
# - Performance (2 tests)
# - Unicode/HMAC (2 tests)
```

---

## 📝 EXPECTED OUTPUT STRUCTURE

```json
{
  "text_embed_stub": {
    "normalized_user": "...",
    "normalized_external": [...],
    "stats": {"token_estimate": N}
  },
  "layer0": {
    "unicode_analysis": {...},
    "heuristic_flags": {...}
  },
  "metadata": {
    "request_id": "uuid",
    "prep_time_ms": N
  }
}
```

---

## 🐛 COMMON ERRORS & FIXES

| Error | Cause | Fix |
|-------|-------|-----|
| Connection refused | Service not running | Start service in terminal |
| HMAC_SECRET_KEY error | .env missing | Copy `.env.example` to `.env` |
| Module not found: contracts | Missing contracts/ | Run setup (already done!) |
| Port 8000 in use | Another service | Kill process or use different port |
| Slow response | Network/system load | Check logs, reduce complexity |
| No outputs saved | Directory permissions | Create `Outputs/` manually |

---

## 📚 DOCUMENTATION LINKS

- **Full Setup:** `COMPLETE_SETUP_AND_RUN_GUIDE.md`
- **End-to-End Testing:** `END_TO_END_TESTING_GUIDE.md`
- **Project Summary:** `PROJECT_ANALYSIS_SUMMARY.md`
- **API Docs:** http://localhost:8000/docs (live)
- **Troubleshooting:** `Input_Prep/TROUBLESHOOTING.md`

---

## 🎯 5-MINUTE CHECKLIST

- [ ] Activate virtual environment
- [ ] Start Input Prep service (Terminal 1)
- [ ] Start Layer 0 service (Terminal 2)
- [ ] Health checks pass
- [ ] Run simple test
- [ ] Check outputs created
- [ ] Open http://localhost:8000

---

## 💾 BACKUP/RESTORE

```bash
# Backup outputs
cp -r Outputs Outputs.backup

# Backup database (Layer 0)
cp -r layer0/data layer0/data.backup

# Restore
cp -r Outputs.backup Outputs
```

---

## 🔐 SECURITY REMINDERS

- [ ] Change HMAC_SECRET_KEY in .env (not using default)
- [ ] Use HTTPS in production
- [ ] Restrict API access (firewall/reverse proxy)
- [ ] Rotate logs regularly
- [ ] Monitor error logs
- [ ] Update dependencies periodically

---

## 📞 QUICK SUPPORT

**Error in console?**
```bash
# 1. Check logs
tail -50 Input_Prep/logs/app.log

# 2. Verify services
curl http://localhost:8000/health
curl http://localhost:3001/test

# 3. Check config
cat Input_Prep/.env | grep HMAC

# 4. Test components
python test_pipeline.py
```

---

## ⏱️ PERFORMANCE OPTIMIZATION

```bash
# Enable caching
# Edit Input_Prep/.env:
# CACHE_EMBEDDINGS=true

# Use GPU (if available)
# Edit Input_Prep/.env:
# DEVICE=cuda

# Increase workers
uvicorn app.main:app --workers 4 --port 8000
```

---

## 🎓 NEXT STEPS AFTER SETUP

1. Review outputs in `Outputs/layer0_text/`
2. Check `Input_Prep/docs/OUTPUT_FORMATS.md`
3. Integrate with your application
4. Set up monitoring/alerting
5. Deploy to production

---

## 📋 FILE REFERENCE

### Created Files (You're Good!)
- ✅ `/contracts/manifest.py` - Pipeline structures
- ✅ `/contracts/__init__.py` - Package init
- ✅ `/Input_Prep/.env` - Configuration
- ✅ `/COMPLETE_SETUP_AND_RUN_GUIDE.md` - Full guide
- ✅ `/END_TO_END_TESTING_GUIDE.md` - Tests
- ✅ `/test_pipeline.py` - Automated tests
- ✅ `/PROJECT_ANALYSIS_SUMMARY.md` - Summary

### To Keep Handy
- `Input_Prep/README.md` - Architecture
- `layer0/README.md` - Layer 0 docs
- `Input_Prep/USAGE.md` - API usage
- `Input_Prep/QUICKSTART.md` - Quick ref

---

**Last Updated:** December 2, 2025  
**Bookmark this page!** 📌
