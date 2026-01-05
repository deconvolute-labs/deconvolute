from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class DetectionResult(BaseModel):
    """
    Base result model for all security detection operations.

    This generic model standardizes the output across different detection modules
    (Canaries, Scanners, etc.), making it easier to log and analyze threats uniformly.

    Attributes:
        detected (bool): True if a threat or security violation was detected.
            False indicates the content is considered safe.
        timestamp (datetime): The UTC timestamp when the check was performed.
            Defaults to the current time.
        component (str): The name of the module that performed the check
            (e.g. 'Canary', 'YaraScanner').
        metadata (dict[str, Any]): A dictionary for arbitrary contextual data.
            Used for telemetry (e.g. latency, model versions, specific rule IDs).
    """

    detected: bool = Field(
        ..., description="True if a threat or leak was detected. False if safe."
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp of the check.",
    )
    component: str = Field(
        ...,
        description="The module that produced this result (e.g. 'Canary').",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Contextual data (e.g. 'latency_ms', 'model_name').",
    )

    # Immutable instances
    model_config = ConfigDict(frozen=True)

    @property
    def safe(self) -> bool:
        """
        Helper for readable conditionals: if result.safe: ...
        """
        return not self.detected


class CanaryResult(DetectionResult):
    """
    Result model specific to the Canary Jailbreak Detection module.

    Indicates whether the canary token mechanism detected a violation of the
    System Prompt instructions.

    Attributes:
        token_found (str | None): The specific canary token string found in the
            LLM output, if any.
            See the `Canary` class documentation for how this relates to
            detection based on the active scanning mode.
    """

    component: str = "Canary"

    token_found: str | None = Field(
        None, description="The actual token string found in the output (if any)."
    )
