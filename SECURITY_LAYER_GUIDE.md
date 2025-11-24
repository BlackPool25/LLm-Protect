# 🔒 Advanced Security Layer - Implementation Guide

## 📋 Overview

The Advanced Security Layer provides comprehensive threat detection for the LLM-Protect system, including:

- **Steganography Detection**: LSB analysis, frequency domain analysis, noise profiling
- **Unicode Threat Analysis**: Zero-width chars, bidi attacks, homoglyphs, emoji ciphers
- **Semantic Conflict Detection**: Cross-modal consistency verification
- **Behavioral Analysis**: Request pattern anomaly detection

## 🚀 Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure Environment

Copy `.env.template` to `.env` and configure:

```bash
cp .env.template .env
```

Edit `.env`:

```env
# Enable security features
ENABLE_STEGANOGRAPHY_DETECTION=true
ENABLE_ADVANCED_UNICODE_ANALYSIS=true
ENABLE_SEMANTIC_CONFLICT_DETECTION=true
ENABLE_BEHAVIORAL_ANALYSIS=true

# Set thresholds
THREAT_SCORE_THRESHOLD=0.75
MAX_SECURITY_ANALYSIS_TIME_MS=500
```

### 3. Test Security Layer

```bash
python test_security.py
```

## 📚 Architecture

### Directory Structure

```
security/
├── detectors/
│   ├── steganography.py      # Image steganography detection
│   └── unicode_analysis.py   # Unicode threat detection
├── analyzers/
│   ├── semantic_conflict.py  # Semantic consistency checks
│   └── behavioral.py         # Behavioral pattern analysis
├── models/
│   └── security_schemas.py   # Pydantic models for security reports
└── utils/
    ├── entropy_calculator.py # Statistical analysis utilities
    ├── pattern_matcher.py    # Pattern detection utilities
    └── cache_manager.py      # LRU cache with TTL
```

### Integration Points

The security layer integrates with existing services through:

```python
from app.services.security_integration import get_security_service

security_service = get_security_service()

# Analyze text
report = await security_service.analyze_text(
    text="user input",
    client_id="client123",
    metadata={"source": "api"}
)

# Analyze media
report = await security_service.analyze_media(
    media_data=image_bytes,
    text="caption",
    client_id="client123"
)
```

## 🔍 Security Features

### 1. Steganography Detection

**Techniques:**
- LSB (Least Significant Bit) analysis with chi-square tests
- Frequency domain analysis using gradient-based methods
- Noise profile analysis for unnatural patterns
- Color channel correlation checks

**Example:**

```python
from security.detectors.steganography import SteganographyDetector

detector = SteganographyDetector()
result = await detector.analyze(image_bytes)

print(f"Stego score: {result.overall_stego_score}")
print(f"Threat level: {result.threat_level}")
```

**Performance:**
- Target: <100ms per image
- CPU-friendly (no GPU required)
- Cached results for repeated analyses

### 2. Unicode Threat Analysis

**Detects:**
- Zero-width character encoding (steganography)
- Bidirectional override attacks (text spoofing)
- Homoglyph substitution (phishing)
- Emoji cipher patterns
- Unicode normalization exploits

**Example:**

```python
from security.detectors.unicode_analysis import UnicodeThreatAnalyzer

analyzer = UnicodeThreatAnalyzer()
result = await analyzer.analyze_text("suspicious text\u200B\u200C")

for threat in result.threat_vectors:
    print(f"{threat.type}: {threat.threat_score}")
```

**Attack Examples:**

```python
# Zero-width steganography
malicious = "Normal text\u200B\u200C\u200D\u200B"  # Hidden binary data

# Bidi override phishing
spoofed = "user@example.com\u202Emoc.elpmaxe@resu"

# Homoglyph domain
phishing = "pаypal.com"  # 'а' is Cyrillic, not Latin
```

### 3. Semantic Conflict Detection

**Checks:**
- Text internal contradictions
- Metadata-content mismatches
- File header vs claimed format
- Cross-modal consistency

**Example:**

```python
from security.analyzers.semantic_conflict import SemanticConflictDetector

detector = SemanticConflictDetector()
result = await detector.check_consistency(
    text="About cats",
    metadata={"title": "Dog Guide"}
)

print(f"Conflict score: {result.conflict_score}")
print(f"Conflicts: {result.detected_conflicts}")
```

### 4. Behavioral Analysis

**Monitors:**
- Request frequency patterns
- Pattern repetition (automated attacks)
- Temporal anomalies (bursts, regular intervals)
- Client-specific behavior profiles

**Example:**

```python
from security.analyzers.behavioral import BehavioralAnalyzer

analyzer = BehavioralAnalyzer()
profile = await analyzer.analyze(
    client_id="user123",
    request_data="request content",
    request_hash="hash123"
)

print(f"Anomaly score: {profile.anomaly_score}")
print(f"Frequency: {profile.request_frequency} req/s")
```

## 📊 Security Reports

### Report Structure

```python
class SecurityReport:
    # Individual scores
    steganography_score: float          # 0-1
    unicode_threat_score: float         # 0-1
    semantic_conflict_score: float      # 0-1
    behavioral_anomaly_score: float     # 0-1
    
    # Overall assessment
    overall_threat_score: float         # 0-1
    overall_threat_level: ThreatLevel   # NONE, LOW, MEDIUM, HIGH, CRITICAL
    
    # Details
    detected_anomalies: List[SecurityAnomaly]
    recommendations: List[SecurityRecommendation]
    
    # Performance
    analysis_time_ms: float
    analysis_enabled: Dict[str, bool]
    
    # Detailed sub-reports
    stego_analysis: Optional[StegoAnalysis]
    unicode_analysis: Optional[UnicodeThreatReport]
    conflict_analysis: Optional[ConflictAnalysis]
    behavioral_profile: Optional[BehavioralProfile]
```

### Example Report

```json
{
  "steganography_score": 0.15,
  "unicode_threat_score": 0.82,
  "semantic_conflict_score": 0.0,
  "behavioral_anomaly_score": 0.3,
  "overall_threat_score": 0.52,
  "overall_threat_level": "medium",
  "detected_anomalies": [
    {
      "type": "unicode_zero_width",
      "severity": "high",
      "description": "Found 15 zero-width characters (density: 2.3%)",
      "confidence": 0.85
    }
  ],
  "recommendations": [
    {
      "action": "Strip zero-width characters from input",
      "priority": "high",
      "reasoning": "Zero-width characters can hide malicious content"
    }
  ],
  "analysis_time_ms": 45.2
}
```

## ⚙️ Configuration

### Security Levels

**Standard Mode** (default):
- All basic detections enabled
- Moderate thresholds
- ~50ms additional latency

**Paranoid Mode**:
- All detections at maximum sensitivity
- Lower thresholds (more false positives)
- ~100ms additional latency

```env
SECURITY_LEVEL=paranoid
THREAT_SCORE_THRESHOLD=0.60  # Lower = more sensitive
```

### Performance Tuning

```env
# Maximum time for security analysis
MAX_SECURITY_ANALYSIS_TIME_MS=500

# Image analysis timeout
IMAGE_ANALYSIS_TIMEOUT=30

# Cache settings
ENABLE_SECURITY_CACHE=true
SECURITY_CACHE_TTL=3600        # 1 hour
SECURITY_CACHE_MAX_SIZE=10000  # Max entries
```

### Feature Toggles

```env
# Enable/disable specific analyses
ENABLE_STEGANOGRAPHY_DETECTION=true
ENABLE_ADVANCED_UNICODE_ANALYSIS=true
ENABLE_SEMANTIC_CONFLICT_DETECTION=true
ENABLE_BEHAVIORAL_ANALYSIS=true
```

## 🧪 Testing

### Run Tests

```bash
# Run all security tests
python -m pytest test_security.py -v

# Run specific test class
python -m pytest test_security.py::TestUnicodeThreatAnalysis -v

# Run attack simulations
python test_security.py
```

### Attack Simulation Examples

```python
from test_security import AttackScenarios

# Generate attack samples
zero_width = AttackScenarios.zero_width_steganography()
bidi = AttackScenarios.bidi_override_phishing()
homoglyph = AttackScenarios.homoglyph_domain()
emoji = AttackScenarios.emoji_encoding()

# Test against detectors
analyzer = UnicodeThreatAnalyzer()
result = await analyzer.analyze_text(zero_width)
```

## 📈 Performance Metrics

### Target Latencies

| Analysis Type | Target | Typical |
|--------------|--------|---------|
| Unicode Analysis | <20ms | 10-15ms |
| Steganography Detection | <100ms | 40-80ms |
| Semantic Conflict | <30ms | 15-25ms |
| Behavioral Analysis | <10ms | 2-5ms |
| **Total (All)** | **<150ms** | **70-120ms** |

### Cache Performance

- Hit Rate: 60-80% (typical)
- Memory Usage: ~100MB (10k entries)
- Eviction: LRU with TTL

## 🔐 Security Best Practices

### 1. Threshold Configuration

Start conservative and adjust based on false positive rates:

```python
# Conservative (fewer false positives)
THREAT_SCORE_THRESHOLD=0.80

# Moderate (balanced)
THREAT_SCORE_THRESHOLD=0.75

# Aggressive (catches more, more false positives)
THREAT_SCORE_THRESHOLD=0.60
```

### 2. Handling High-Threat Detections

```python
if report.overall_threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
    # Block request
    raise HTTPException(status_code=403, detail="Security threat detected")
elif report.overall_threat_level == ThreatLevel.MEDIUM:
    # Flag for review
    log_for_review(report)
    # Optionally continue with sanitization
```

### 3. Logging Suspicious Activity

```python
if report.overall_threat_score > 0.5:
    logger.warning(
        f"Security threat detected: {report.overall_threat_level}",
        extra={
            "client_id": client_id,
            "threat_score": report.overall_threat_score,
            "anomalies": [a.type for a in report.detected_anomalies],
            "recommendations": [r.action for r in report.recommendations]
        }
    )
```

## 🚧 Troubleshooting

### High Latency

```python
# Check cache stats
service = get_security_service()
stats = service.get_cache_stats()
print(f"Cache hit rate: {stats['hit_rate']:.1%}")

# Disable slower analyses
ENABLE_STEGANOGRAPHY_DETECTION=false  # Slowest
```

### False Positives

```python
# Adjust thresholds
THREAT_SCORE_THRESHOLD=0.85  # Higher = fewer false positives

# Review specific detector thresholds in code
# security/detectors/unicode_analysis.py:
self.zero_width_density_threshold = 0.02  # Increase from 0.01
```

### Memory Usage

```python
# Reduce cache size
SECURITY_CACHE_MAX_SIZE=5000  # Default: 10000

# Reduce TTL
SECURITY_CACHE_TTL=1800  # 30 minutes instead of 1 hour
```

## 🔄 Future Enhancements

Planned features for future releases:

1. **ML-Based Detection**
   - CLIP/BLIP for image-text alignment
   - Transformer-based semantic analysis
   - Neural steganography detection

2. **Threat Intelligence**
   - External threat feed integration
   - Perceptual hashing database
   - Known attack signature matching

3. **Advanced Features**
   - OCR for image text extraction
   - Multi-language homoglyph databases
   - Adversarial attack detection

## 📞 Support

For issues or questions:

1. Check existing test cases in `test_security.py`
2. Review configuration in `.env.template`
3. Enable debug logging: `DEBUG_SECURITY=true`

## 📄 License

Part of LLM-Protect system. See main project license.
