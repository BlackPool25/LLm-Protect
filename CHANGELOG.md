# Changelog

All notable changes to the Layer-0 Security Filter System will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-11-25

### Added
- Initial release of Layer-0 Security Filter System
- 10-stage normalization pipeline
- Code detection with bypass logic
- RE2-based regex engine with timeout enforcement
- Dataset loader with HMAC validation
- Rule registry with lifecycle management
- Multi-source scanner (52,892 active rules)
- FastAPI REST service with 6 endpoints
- Prometheus metrics integration
- Unified CLI tool (`l0.py`)
- Advanced CLI tester with ASCII visualization
- Comprehensive documentation (README, QUICKSTART, walkthrough)
- JailBreakV_28K dataset integration (52K+ rules)
- Custom jailbreak and injection rule datasets

### Security
- Fail-closed behavior by default
- Strict redaction policy (no raw matched text in logs)
- HMAC dataset integrity verification
- Audit token generation for traceability
- ReDoS protection with timeout enforcement

### Performance
- Sub-50ms scan latency for most inputs
- Concurrent chunk processing
- Prefilter optimization for fast rejection
- Compiled pattern caching

## [Unreleased]

### Planned
- Rate limiting for API endpoints
- API authentication
- Async scanner support
- Batch processing endpoint
- Formal pytest test suite
- Docker containerization
- CI/CD pipeline
