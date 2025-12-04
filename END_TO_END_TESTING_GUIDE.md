# End-to-End Testing Guide for LLM-Protect

**Date:** December 2, 2025  
**Purpose:** Comprehensive guide to test the complete pipeline end-to-end

---

## 🎯 Overview

This guide walks through testing the complete LLM-Protect pipeline from startup through full processing.

**Expected Results:**
- ✅ Both services start successfully
- ✅ Health checks pass
- ✅ Text processing completes
- ✅ Layer 0 analysis integrates
- ✅ Outputs are saved
- ✅ Performance is acceptable

---

## 📋 Checklist Before Starting

- [ ] Python 3.8+ installed
- [ ] Virtual environment created and activated
- [ ] Dependencies installed (`pip install -r requirements.txt`)
- [ ] `.env` file exists in `Input_Prep/`
- [ ] `contracts/manifest.py` exists in project root
- [ ] At least 2 terminal windows available
- [ ] Ports 8000 and 3001 are free

---

## 🚀 Phase 1: Service Startup

### Step 1.1: Start Input Prep Service

**Terminal 1:**
```bash
cd "Input_Prep"
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

**Expected output:**
```
INFO:     Will watch for changes in these directories: ['/path/to/Input_Prep']
INFO:     Uvicorn running on http://0.0.0.0:8000
INFO:     Application startup complete
```

**Verify:**
```bash
# In another terminal
curl http://localhost:8000/health
```

Should return:
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

### Step 1.2: Start Layer 0 Service

**Terminal 2:**
```bash
cd "layer0"
python server.py --port 3001
```

**Expected output:**
```
INFO:     Uvicorn running on http://0.0.0.0:3001
Layer0 service started
```

**Verify:**
```bash
# In another terminal
curl http://localhost:3001/test
```

Should return:
```json
{
  "status": "ok",
  "service": "layer0",
  "timestamp": "2025-01-01T00:00:00Z",
  "rules_loaded": 16
}
```

✅ **Both services running? Proceed to Phase 2.**

---

## 🧪 Phase 2: Basic Functionality Tests

### Test 2.1: Simple Text Processing

```bash
curl -X POST "http://localhost:8000/api/v1/prepare-text" \
  -F "user_prompt=Hello, this is a test message"
```

**Expected response structure:**
```json
{
  "text_embed_stub": {
    "normalized_user": "hello this is a test message",
    "normalized_external": [],
    "emoji_descriptions": [],
    "stats": {
      "char_total": 26,
      "token_estimate": 7,
      ...
    }
  },
  "layer0": {
    "unicode_analysis": {
      "unicode_obfuscation_flag": false,
      "zero_width_count": 0,
      ...
    },
    "heuristic_flags": {
      "suspicious_score": 0.0,
      ...
    }
  },
  "metadata": {
    "request_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "timestamp": "2025-01-01T10:00:00",
    "prep_time_ms": 45.23
  }
}
```

**✓ Success indicators:**
- Status code: 200
- Contains `text_embed_stub`
- Contains `layer0` analysis
- `prep_time_ms` < 200ms

### Test 2.2: Text with External Data

```bash
curl -X POST "http://localhost:8000/api/v1/prepare-text" \
  -F "user_prompt=What does the document say?" \
  -F 'external_data=["Important information from document", "Additional context"]'
```

**✓ Success indicators:**
- Status code: 200
- `normalized_external` contains wrapped chunks
- `hmacs` array has entries
- External chunks are properly formatted with `[EXTERNAL]...[/EXTERNAL]`

### Test 2.3: Text with File Upload

```bash
curl -X POST "http://localhost:8000/api/v1/prepare-text" \
  -F "user_prompt=Analyze this file" \
  -F "file=@Input_Prep/test_samples/sample.txt"
```

**✓ Success indicators:**
- Status code: 200
- File is processed
- Contains file content in response

---

## 🔍 Phase 3: Layer 0 Integration Tests

### Test 3.1: Unicode Obfuscation Detection

```bash
# Create a test with suspicious unicode
python3 << 'EOF'
import requests
import json

# Text with unicode variations (if your terminal supports it)
test_text = "test" + "\u200b" + "message"  # Contains zero-width space

response = requests.post(
    "http://localhost:8000/api/v1/prepare-text",
    data={"user_prompt": test_text}
)

result = response.json()
layer0 = result.get("layer0", {})
unicode_analysis = layer0.get("unicode_analysis", {})

print("Unicode Analysis:")
print(f"  Obfuscation detected: {unicode_analysis.get('unicode_obfuscation_flag')}")
print(f"  Zero-width chars: {unicode_analysis.get('zero_width_count')}")
print(f"  Invisible chars: {unicode_analysis.get('invisible_count')}")
EOF
```

### Test 3.2: Heuristic Pattern Detection

```python
import requests

# Test various patterns
patterns = [
    ("Normal text", "This is a normal message"),
    ("Long base64", "aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQ"),
    ("System delimiter", "Message with <|im_start|> delimiter"),
]

for name, text in patterns:
    response = requests.post(
        "http://localhost:8000/api/v1/prepare-text",
        data={"user_prompt": text}
    )
    
    result = response.json()
    layer0 = result.get("layer0", {})
    heuristics = layer0.get("heuristic_flags", {})
    
    print(f"\n{name}:")
    print(f"  Suspicion score: {heuristics.get('suspicious_score', 0):.2%}")
    print(f"  Patterns detected: {heuristics.get('detected_patterns', [])}")
```

---

## 💾 Phase 4: Output Verification Tests

### Test 4.1: Check Output Files

After running text processing tests, check the output directory:

```bash
# List saved outputs
ls -la "Outputs/layer0_text/" | head -20

# Count outputs
find "Outputs/" -name "*.json" | wc -l

# View latest output
ls -lt "Outputs/layer0_text/" | head -1 | awk '{print $NF}' | xargs cat | python -m json.tool
```

**✓ Expected:**
- Multiple JSON files with timestamp+ID+preview naming
- Each file contains full processing output
- Files are readable and valid JSON

### Test 4.2: Verify Output Format

```python
import json
from pathlib import Path

# Get latest output file
output_dir = Path("Outputs/layer0_text")
latest = max(output_dir.glob("*.json"), key=lambda p: p.stat().st_mtime)

with open(latest) as f:
    data = json.load(f)

# Verify structure
required_keys = ["prepared_input", "processing_metadata"]
for key in required_keys:
    assert key in data, f"Missing key: {key}"

print(f"✓ Output file structure verified: {latest.name}")
print(f"  Size: {latest.stat().st_size} bytes")
print(f"  Request ID: {data['prepared_input']['metadata']['request_id']}")
print(f"  Processing time: {data['processing_metadata'].get('total_time_ms', 'N/A')}ms")
```

---

## 🎬 Phase 5: End-to-End Workflow Test

### Test 5.1: Complete Pipeline Processing

```python
#!/usr/bin/env python3
"""Complete end-to-end pipeline test."""

import requests
import json
import time
from datetime import datetime

# Configuration
INPUT_PREP_URL = "http://localhost:8000"
LAYER0_URL = "http://localhost:3001"

print("=" * 60)
print("LLM-PROTECT END-TO-END PIPELINE TEST")
print("=" * 60)

# Test data
test_cases = [
    {
        "name": "Simple Query",
        "prompt": "What is machine learning?",
        "external": None
    },
    {
        "name": "Query with Context",
        "prompt": "Based on the document, what are the key points?",
        "external": ["ML is about learning from data", "Data-driven approach is key"]
    },
    {
        "name": "Potentially Suspicious",
        "prompt": "Tell me about <|im_start|> system prompts",
        "external": None
    }
]

results = []

for test_case in test_cases:
    print(f"\nTest: {test_case['name']}")
    print("-" * 60)
    
    try:
        # Prepare request
        data = {"user_prompt": test_case["prompt"]}
        if test_case["external"]:
            data["external_data"] = json.dumps(test_case["external"])
        
        # Send to Input Prep
        start = time.time()
        response = requests.post(
            f"{INPUT_PREP_URL}/api/v1/prepare-text",
            data=data,
            timeout=10
        )
        elapsed = time.time() - start
        
        if response.status_code != 200:
            print(f"✗ FAILED: HTTP {response.status_code}")
            results.append(False)
            continue
        
        result = response.json()
        
        # Extract key data
        metadata = result.get("metadata", {})
        layer0 = result.get("layer0", {})
        text_stats = result.get("text_embed_stub", {}).get("stats", {})
        
        # Display results
        print(f"✓ Request ID: {metadata.get('request_id', 'N/A')[:12]}...")
        print(f"  Network latency: {elapsed*1000:.1f}ms")
        print(f"  Processing time: {metadata.get('prep_time_ms', 'N/A')}ms")
        print(f"  Tokens: {text_stats.get('token_estimate', 'N/A')}")
        
        if layer0:
            heuristics = layer0.get("heuristic_flags", {})
            unicode_analysis = layer0.get("unicode_analysis", {})
            
            print(f"  Layer 0 Analysis:")
            print(f"    - Suspicion score: {heuristics.get('suspicious_score', 0):.2%}")
            print(f"    - Patterns detected: {len(heuristics.get('detected_patterns', []))}")
            print(f"    - Unicode obfuscation: {unicode_analysis.get('unicode_obfuscation_flag', False)}")
        
        results.append(True)
        
    except Exception as e:
        print(f"✗ FAILED: {str(e)}")
        results.append(False)

# Summary
print("\n" + "=" * 60)
print("TEST SUMMARY")
print("=" * 60)

passed = sum(results)
total = len(results)

print(f"Tests passed: {passed}/{total}")

if passed == total:
    print("✓ ALL TESTS PASSED - Pipeline is working correctly!")
    exit(0)
else:
    print(f"✗ {total - passed} test(s) failed - see details above")
    exit(1)
```

**Run the test:**
```bash
python3 test_e2e.py
```

---

## 📊 Phase 6: Performance & Load Testing

### Test 6.1: Measure Response Times

```python
import requests
import time
import statistics

def measure_response_time(url: str, payload: dict, iterations: int = 10):
    """Measure average response time."""
    times = []
    
    for i in range(iterations):
        start = time.time()
        response = requests.post(url, data=payload, timeout=30)
        elapsed = (time.time() - start) * 1000
        
        if response.status_code == 200:
            times.append(elapsed)
        
        if i % 3 == 0:
            print(f"  Iteration {i+1}/{iterations}: {elapsed:.1f}ms")
    
    return {
        "count": len(times),
        "min": min(times),
        "max": max(times),
        "avg": statistics.mean(times),
        "median": statistics.median(times),
        "stdev": statistics.stdev(times) if len(times) > 1 else 0
    }

print("Performance Test - Input Prep")
print("=" * 60)

payload = {"user_prompt": "Performance test message"}
stats = measure_response_time(
    "http://localhost:8000/api/v1/prepare-text",
    payload,
    iterations=10
)

print(f"\nResults:")
print(f"  Min:    {stats['min']:.2f}ms")
print(f"  Max:    {stats['max']:.2f}ms")
print(f"  Avg:    {stats['avg']:.2f}ms")
print(f"  Median: {stats['median']:.2f}ms")
print(f"  StdDev: {stats['stdev']:.2f}ms")
print(f"\nTarget: < 200ms")
if stats['avg'] < 200:
    print("✓ Performance acceptable")
else:
    print("⚠ Performance slower than target")
```

### Test 6.2: Concurrent Request Testing

```python
import requests
import concurrent.futures
import time

def send_request(request_id: int):
    """Send a single request."""
    try:
        response = requests.post(
            "http://localhost:8000/api/v1/prepare-text",
            data={"user_prompt": f"Test message {request_id}"},
            timeout=30
        )
        return response.status_code == 200
    except Exception as e:
        print(f"Request {request_id} failed: {e}")
        return False

print("Concurrent Request Test")
print("=" * 60)

# Send 5 concurrent requests
with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
    start = time.time()
    futures = [executor.submit(send_request, i) for i in range(5)]
    results = [f.result() for f in concurrent.futures.as_completed(futures)]
    elapsed = time.time() - start

passed = sum(results)
print(f"Requests: {passed}/5 successful in {elapsed:.2f}s")
print(f"Avg time per request: {(elapsed/5)*1000:.1f}ms")
```

---

## 🔧 Phase 7: Debugging & Troubleshooting

### If Tests Fail

**Check service logs:**
```bash
# Input Prep logs
tail -50 Input_Prep/logs/app.log

# Layer 0 logs (in console output where it started)
```

**Verify connectivity:**
```bash
# Direct tests
curl -v http://localhost:8000/health
curl -v http://localhost:3001/test

# Check if ports are in use
netstat -ano | findstr :8000
netstat -ano | findstr :3001
```

**Check configuration:**
```bash
# Verify .env exists and is readable
cat Input_Prep/.env | grep HMAC_SECRET_KEY

# Verify contracts module
ls -la contracts/
cat contracts/__init__.py | head -10
```

**Test with simpler payloads:**
```bash
# Minimal test
curl -X POST "http://localhost:8000/api/v1/prepare-text" \
  -F "user_prompt=test"

# Check response even if it errors
curl -v -X POST "http://localhost:8000/api/v1/prepare-text" \
  -F "user_prompt=test" 2>&1 | head -50
```

---

## ✅ Final Verification Checklist

After all tests complete, verify:

- [ ] Both services started without errors
- [ ] Health endpoints return 200 OK
- [ ] Simple text processing works
- [ ] External data processing works
- [ ] Layer 0 analysis is included in responses
- [ ] Response times are reasonable (< 200ms for Input Prep)
- [ ] Output files are created and valid JSON
- [ ] No import errors in console logs
- [ ] Concurrent requests handled correctly

---

## 🎓 Next Steps

### If All Tests Pass:
1. ✅ System is ready for use
2. Review `/docs` endpoints for API documentation
3. Integrate with your application
4. Set up monitoring/logging
5. Deploy to production (see COMPLETE_SETUP_AND_RUN_GUIDE.md)

### If Any Tests Fail:
1. ⚠️ Check troubleshooting section above
2. Review service logs for specific errors
3. Verify all dependencies are installed
4. Check that .env and contracts files are correct
5. Run individual test phases to isolate issues

---

## 📞 Support Resources

- **Setup Guide:** `COMPLETE_SETUP_AND_RUN_GUIDE.md`
- **API Documentation:** http://localhost:8000/docs
- **Input Prep README:** `Input_Prep/README.md`
- **Layer 0 README:** `layer0/README.md`
- **Troubleshooting:** `Input_Prep/TROUBLESHOOTING.md`

---

**Test Date:** December 2, 2025  
**Last Updated:** December 2, 2025  
**Status:** ✅ Ready for Testing
