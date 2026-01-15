import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from deconvolute.constants import CANARY_INTEGRITY_INSTRUCTION, CANARY_TEMPLATE_FORMAT
from deconvolute.detectors.base import BaseDetector
from deconvolute.utils.logger import get_logger

from .generator import generate_raw_token
from .models import CanaryResult

logger = get_logger()


class CanaryDetector(BaseDetector):
    """
    Jailbreak Detection via Instructional Adherence Checks (Integrity Canary).

    Detects if the System Prompt has been overridden by verifying if the model
    still follows mandatory output instructions.

    Attributes:
        token_length: The length of the canary token. Defaults to 16.
    """

    def __init__(self, token_length: int = 16):
        self.token_length = token_length
        self._executor = ThreadPoolExecutor()

    def inject(self, prompt: str) -> tuple[str, str]:
        """
        Injects the integrity check into the prompt.

        Args:
            prompt: The string containing the prompt.

        Returns:
            tuple[str, str]:
                1. The prompt with the added Canary Token and surrounding instructions.
                2. The full token string (to pass to check/clean later).
        """
        raw_token = generate_raw_token(length=self.token_length)

        # Format the full verification phrase
        full_token = CANARY_TEMPLATE_FORMAT.format(raw_token=raw_token)

        # Create the injection block
        injection = CANARY_INTEGRITY_INSTRUCTION.format(full_token=full_token)

        # Append to system prompt
        secured_prompt = f"{prompt}{injection}"

        logger.debug(f"Injected integrity canary: {full_token}")
        return secured_prompt, full_token

    def check(self, content: str, **kwargs: Any) -> CanaryResult:
        """
        Verifies if the content string contains the mandatory integrity token.

        Args:
            content: The string output from the LLM.
            **kwargs: Must contain 'token' (the string returned by inject).

        Returns:
            CanaryResult: The detection result.

        Raises:
            ValueError: If 'token' is missing from kwargs.
        """
        token = kwargs.get("token")
        if not token:
            raise ValueError(
                "CanaryDetector.check() requires 'token' argument in kwargs."
            )

        if not content:
            # Empty response is a failure of adherence
            return CanaryResult(
                threat_detected=True, component="CanaryDetector", token_found=None
            )

        # Strict Check: The model must reproduce the phrase exactly.
        if token in content:
            return CanaryResult(threat_detected=False, token_found=token)

        # We assume Jailbreak if exact match fails.
        logger.warning(f"Integrity check failed. Token missing: {token}")
        return CanaryResult(threat_detected=True, token_found=None)

    def clean(self, content: str, token: str) -> str:
        """
        Removes the integrity token from the content to prevent user confusion.

        Args:
            content: The string containing the token string.
            token: The full token string.

        Returns:
            The cleaned response string.
        """
        if not content:
            return ""

        return content.replace(token, "").rstrip()

    async def a_check(self, content: str, **kwargs: Any) -> CanaryResult:
        """Async version of check() using a thread pool."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self._executor, lambda: self.check(content, **kwargs)
        )

    async def a_clean(self, content: str, token: str) -> str:
        """Async version of clean() using a thread pool."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, self.clean, content, token)
