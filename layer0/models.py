"""
Data models for Layer-0 Security Filter System.

Pydantic schemas for input/output contracts and internal representations.
"""

from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class ScanStatus(str, Enum):
    """Scan result status."""

    CLEAN = "CLEAN"
    CLEAN_CODE = "CLEAN_CODE"
    REJECTED = "REJECTED"
    WARN = "WARN"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    ERROR = "ERROR"


class Severity(str, Enum):
    """Rule severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RuleState(str, Enum):
    """Rule lifecycle states."""

    DRAFT = "draft"
    TESTING = "testing"
    CANARY = "canary"
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    QUARANTINED = "quarantined"


class PreparedInput(BaseModel):
    """Input contract for scanning."""

    user_input: str = Field(..., description="Primary user input text")
    external_chunks: Optional[List[str]] = Field(
        default=None, description="External context chunks (e.g., RAG results)"
    )
    metadata: Optional[Dict[str, str]] = Field(
        default=None, description="Optional metadata for audit trail"
    )

    @field_validator("user_input")
    @classmethod
    def validate_user_input(cls, v: str) -> str:
        """Validate user input is not empty."""
        if not v or not v.strip():
            raise ValueError("user_input cannot be empty")
        return v

    @field_validator("external_chunks")
    @classmethod
    def validate_external_chunks(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        """Validate external chunks."""
        if v is not None:
            # Filter out empty chunks
            return [chunk for chunk in v if chunk and chunk.strip()]
        return v


class RuleMatch(BaseModel):
    """Internal representation of a rule match."""

    rule_id: str
    dataset: str
    severity: Severity
    matched_preview: str  # Redacted preview
    confidence: float = 1.0
    source: str  # "user_input", "external_chunks", "combined"


class ScanResult(BaseModel):
    """Output contract for scan results."""

    status: ScanStatus
    audit_token: str = Field(..., description="Audit token for traceability")
    rule_id: Optional[str] = Field(None, description="Matched rule ID (if any)")
    dataset: Optional[str] = Field(None, description="Dataset name (if matched)")
    severity: Optional[Severity] = Field(None, description="Rule severity (if matched)")
    processing_time_ms: float = Field(..., description="Total processing time in milliseconds")
    rule_set_version: str = Field(..., description="Active rule set version")
    scanner_version: str = Field(..., description="Scanner version")
    note: Optional[str] = Field(None, description="Optional human-readable note")
    ml_suspicion_score: Optional[float] = Field(
        None, description="ML suspicion score (0.0-1.0) if enabled"
    )


class Rule(BaseModel):
    """Rule definition."""

    id: str
    name: str
    description: str
    pattern: str
    severity: Severity
    state: RuleState = RuleState.ACTIVE
    enabled: bool = True
    impact_score: float = Field(1.0, ge=0.0, le=1.0)
    owner: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    positive_tests: List[str] = Field(default_factory=list)
    negative_tests: List[str] = Field(default_factory=list)


class DatasetMetadata(BaseModel):
    """Dataset metadata."""

    name: str
    version: str
    source: str
    last_updated: str
    total_rules: int
    dataset_build_id: str
    hmac_signature: Optional[str] = None


class Dataset(BaseModel):
    """Complete dataset with metadata and rules."""

    metadata: DatasetMetadata
    rules: List[Rule]
