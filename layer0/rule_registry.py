"""
Central rule registry with lifecycle management and hot-reload support.
"""

import hashlib
import logging
import threading
import time
from collections import defaultdict
from typing import Dict, List, Optional

from layer0.models import Dataset, Rule, RuleState, Severity
from layer0.prefilter import prefilter

logger = logging.getLogger(__name__)


class RuleRegistry:
    """Central rule registry with lifecycle management."""

    # Severity ordering (for sorting)
    SEVERITY_ORDER = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
    }

    def __init__(self) -> None:
        """Initialize rule registry."""
        self._lock = threading.RLock()
        self._datasets: Dict[str, Dataset] = {}
        self._rules: Dict[str, Rule] = {}
        self._version = "0.0.0"
        self._load_timestamp = 0.0

        # Analytics
        self._match_counts: Dict[str, int] = defaultdict(int)
        self._execution_times: Dict[str, List[float]] = defaultdict(list)

    def load_datasets(self, datasets: List[Dataset]) -> None:
        """
        Load datasets into registry (atomic operation).

        Args:
            datasets: List of validated datasets
        """
        with self._lock:
            new_rules: Dict[str, Rule] = {}
            new_datasets: Dict[str, Dataset] = {}

            for dataset in datasets:
                new_datasets[dataset.metadata.name] = dataset

                for rule in dataset.rules:
                    # Only load active rules
                    if rule.state == RuleState.ACTIVE and rule.enabled:
                        new_rules[rule.id] = rule

            # Atomic swap
            self._rules = new_rules
            self._datasets = new_datasets
            self._version = self._generate_version()
            self._load_timestamp = time.time()
            
            # Build prefilter from all active rules (optional, don't fail if it errors)
            try:
                logger.info(f"Building prefilter from {len(new_rules)} active rules...")
                start_time = time.perf_counter()
                prefilter.build_from_rules(list(new_rules.values()))
                elapsed_ms = (time.perf_counter() - start_time) * 1000
                logger.info(f"Prefilter built in {elapsed_ms:.1f}ms with {prefilter.keyword_count} keywords")
            except Exception as e:
                logger.warning(f"Failed to build prefilter (will continue without it): {e}")
                prefilter.enabled = False

            logger.info(
                f"Loaded {len(new_rules)} rules from {len(new_datasets)} datasets "
                f"(version: {self._version})"
            )

    def _generate_version(self) -> str:
        """Generate version string from dataset versions."""
        if not self._datasets:
            return "0.0.0"

        # Combine dataset versions and build IDs
        version_parts = []
        for dataset in self._datasets.values():
            version_parts.append(
                f"{dataset.metadata.name}:{dataset.metadata.version}"
            )

        # Create a short hash
        version_hash = hashlib.sha256(
            "|".join(sorted(version_parts)).encode()
        ).hexdigest()[:8]

        return f"ruleset-{version_hash}"

    def get_active_rules(self) -> List[Rule]:
        """
        Get all active rules sorted by severity.

        Returns:
            List of active rules
        """
        with self._lock:
            # Sort by severity (critical first)
            rules = list(self._rules.values())
            rules.sort(key=lambda r: self.SEVERITY_ORDER.get(r.severity, 99))
            return rules

    def get_rule(self, rule_id: str) -> Optional[Rule]:
        """
        Get rule by ID.

        Args:
            rule_id: Rule identifier

        Returns:
            Rule object or None if not found
        """
        with self._lock:
            return self._rules.get(rule_id)

    def record_match(self, rule_id: str, execution_time_ms: float) -> None:
        """
        Record a rule match for analytics.

        Args:
            rule_id: Rule identifier
            execution_time_ms: Execution time in milliseconds
        """
        with self._lock:
            self._match_counts[rule_id] += 1
            self._execution_times[rule_id].append(execution_time_ms)

            # Keep only last 1000 execution times
            if len(self._execution_times[rule_id]) > 1000:
                self._execution_times[rule_id] = self._execution_times[rule_id][-1000:]

    def get_stats(self) -> dict:
        """
        Get registry statistics.

        Returns:
            Dictionary of statistics
        """
        with self._lock:
            total_matches = sum(self._match_counts.values())

            # Calculate average execution times
            avg_execution_times = {}
            for rule_id, times in self._execution_times.items():
                if times:
                    avg_execution_times[rule_id] = sum(times) / len(times)

            # Top matched rules
            top_rules = sorted(
                self._match_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]

            return {
                "version": self._version,
                "load_timestamp": self._load_timestamp,
                "total_datasets": len(self._datasets),
                "total_rules": len(self._rules),
                "total_matches": total_matches,
                "top_matched_rules": [
                    {"rule_id": rule_id, "count": count}
                    for rule_id, count in top_rules
                ],
                "avg_execution_times": avg_execution_times,
            }

    def get_version(self) -> str:
        """Get current rule set version."""
        with self._lock:
            return self._version

    def get_dataset_count(self) -> int:
        """Get number of loaded datasets."""
        with self._lock:
            return len(self._datasets)

    def get_rule_count(self) -> int:
        """Get number of active rules."""
        with self._lock:
            return len(self._rules)


# Global rule registry instance
rule_registry = RuleRegistry()
