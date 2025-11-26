"""
Configuration management for Layer-0 Security Filter System.

Environment-first configuration with secure defaults.
"""

from typing import List, Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Layer-0 Security Filter System configuration."""

    model_config = SettingsConfigDict(
        env_prefix="L0_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",  # Ignore extra env vars without L0_ prefix
    )

    # Regex Engine Settings
    regex_timeout_ms: int = Field(default=100, env="L0_REGEX_TIMEOUT_MS")
    regex_engine: str = Field(default="re2", env="L0_REGEX_ENGINE")  # "re2", "regex", or "re"

    # Scanner Settings
    stop_on_first_match: bool = Field(default=True, env="L0_STOP_ON_FIRST_MATCH")
    ensemble_scoring: bool = Field(default=False, env="L0_ENSEMBLE_SCORING")
    ensemble_threshold_reject: float = Field(default=0.95, env="L0_ENSEMBLE_THRESHOLD_REJECT")
    ensemble_threshold_warn: float = Field(default=0.7, env="L0_ENSEMBLE_THRESHOLD_WARN")

    # Prefilter Settings
    prefilter_keywords: str = Field(
        default="ignore,override,jailbreak,system,prompt,instructions",
        env="L0_PREFILTER_KEYWORDS"
    )
    prefilter_enabled: bool = Field(default=True, env="L0_PREFILTER_ENABLED")

    # Normalization Settings
    disable_normalization_steps: str = Field(default="", env="L0_DISABLE_NORMALIZATION_STEPS")
    normalization_enabled: bool = Field(default=True, env="L0_NORMALIZATION_ENABLED")

    # Code Detection Settings
    code_detection_enabled: bool = Field(default=True, env="L0_CODE_DETECTION_ENABLED")
    code_confidence_threshold: float = Field(default=0.7, env="L0_CODE_CONFIDENCE_THRESHOLD")

    # Dataset Settings
    dataset_hmac_secret: str = Field(default="change-me-in-production", env="L0_DATASET_HMAC_SECRET")
    dataset_path: str = Field(default="layer0/datasets", env="L0_DATASET_PATH")
    allowlisted_hashes: str = Field(default="", env="L0_ALLOWLISTED_HASHES")

    # Fail Policy
    fail_open: bool = Field(default=False, env="L0_FAIL_OPEN")  # Default: fail-closed (secure)

    # ML Suspicion (Optional)
    ml_suspicion_enabled: bool = Field(default=False, env="L0_ML_SUSPICION_ENABLED")

    # Metrics & Observability
    metrics_enabled: bool = Field(default=True, env="L0_METRICS_ENABLED")
    log_level: str = Field(default="INFO", env="L0_LOG_LEVEL")
    log_format: str = Field(default="json", env="L0_LOG_FORMAT")  # "json" or "text"

    # API Settings
    api_host: str = Field(default="0.0.0.0", env="L0_API_HOST")
    api_port: int = Field(default=8000, env="L0_API_PORT")
    api_workers: int = Field(default=4, env="L0_API_WORKERS")
    api_reload: bool = Field(default=False, env="L0_API_RELOAD")
    api_key: Optional[str] = Field(default=None, env="L0_API_KEY")  # Optional API key for authentication

    # Performance Settings
    max_input_length: int = Field(default=100_000, env="L0_MAX_INPUT_LENGTH")  # Characters
    max_chunks: int = Field(default=1000, env="L0_MAX_CHUNKS")
    chunk_processing_timeout_ms: int = Field(default=5000, env="L0_CHUNK_PROCESSING_TIMEOUT_MS")

    @property
    def prefilter_keywords_list(self) -> List[str]:
        """Get prefilter keywords as a list."""
        if not self.prefilter_keywords:
            return []
        return [kw.strip().lower() for kw in self.prefilter_keywords.split(",")]

    @property
    def disabled_normalization_steps(self) -> List[str]:
        """Get disabled normalization steps as a list."""
        if not self.disable_normalization_steps:
            return []
        return [step.strip() for step in self.disable_normalization_steps.split(",")]

    @property
    def allowlisted_hashes_list(self) -> List[str]:
        """Get allowlisted hashes as a list."""
        if not self.allowlisted_hashes:
            return []
        return [h.strip() for h in self.allowlisted_hashes.split(",")]


# Global settings instance
settings = Settings()
