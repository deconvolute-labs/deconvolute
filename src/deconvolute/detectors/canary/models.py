from pydantic import Field

from deconvolute.detectors.base import DetectionResult


class CanaryResult(DetectionResult):
    """
    Result model specific to the Canary Jailbreak Detection module.

    Attributes:
        token_found (str | None): The specific canary token string found in the
            LLM output, if any.
    """

    # Defaulting component name for convenience, though it can be overridden
    component: str = "CanaryDetector"

    token_found: str | None = Field(
        None, description="The actual token string found in the output (if any)."
    )
