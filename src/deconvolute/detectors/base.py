from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class DetectionResult(BaseModel):
    """
    Base result model for all security detection operations.

    This generic model standardizes the output across different detection modules
    (Canaries, Scanners, etc.), making it easier to log and analyze threats uniformly.

    Attributes:
        threat_detected (bool): True if a threat or security violation was detected.
            False indicates the content is considered safe.
        timestamp (datetime): The UTC timestamp when the check was performed.
            Defaults to the current time.
        component (str): The name of the module that performed the check
            (e.g. 'Canary', 'YaraScanner').
        metadata (dict[str, Any]): A dictionary for arbitrary contextual data.
            Used for telemetry (e.g. latency, model versions, specific rule IDs).
    """

    threat_detected: bool = Field(
        ..., description="True if a threat or leak was detected. False if safe."
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp of the check.",
    )
    component: str = Field(
        ...,
        description="The module that produced this result (e.g. 'CanaryDetector').",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Contextual data (e.g. 'latency_ms', 'model_name').",
    )

    # Immutable instances
    model_config = ConfigDict(frozen=True)

    @property
    def safe(self) -> bool:
        """Helper for readable conditionals: if result.safe: ..."""
        return not self.threat_detected


class BaseDetector(ABC):
    """
    Abstract Base Class for all security detectors.
    """

    @abstractmethod
    def check(self, content: str, **kwargs) -> DetectionResult:
        """
        Analyzes the provided content for threats.

        Args:
            content: The text (prompt or response) to analyze.
            **kwargs: Additional context.

        Returns:
            DetectionResult: The assessment of the content.
        """
        pass

    @abstractmethod
    async def a_check(self, content: str, **kwargs) -> DetectionResult:
        """
        Async version of check.
        """
        pass
