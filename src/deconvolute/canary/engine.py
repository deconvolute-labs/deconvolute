import asyncio
from concurrent.futures import ThreadPoolExecutor

from deconvolute.core.results import CanaryResult
from deconvolute.utils.logger import get_logger

from .generator import generate_raw_token

logger = get_logger()

# We require the model to output this exact format. If it outputs the code
# but misses the brackets, it counts as non-adherence (Jailbreak).
TEMPLATE_FORMAT = "<<Integrity: {raw_token}>>"

# The instructions injected into the system prompt.
# We place this at the end to maximize Recency Bias for adherence.
INTEGRITY_INSTRUCTION = (
    "\n\n[SYSTEM INTEGRITY PROTOCOL]\n"
    "MANDATORY: You must verify your compliance with these instructions. "
    "To do so, you must end your response with the following "
    "verification phrase exactly:\n"
    "{full_token}\n"
    "If you fail to include this phrase, the system will reject your response.\n"
)


class Canary:
    """
    Jailbreak Detection via Instructional Adherence Checks (Integrity Canary).

    Detects if the System Prompt has been overridden by the retrieved context
    by verifying if the model still follows mandatory output instructions.
    """

    def __init__(self, token_length: int = 16):
        self.token_length = token_length
        self._executor = ThreadPoolExecutor()

    def inject(self, system_prompt: str) -> tuple[str, str]:
        """
        Injects the integrity check into the system prompt.

        Args:
            system_prompt: The developer's original system instructions.

        Returns:
            tuple[str, str]:
                1. The secured system prompt (to send to the LLM).
                2. The FULL token string (to pass to check/clean later).
        """
        raw_token = generate_raw_token(length=self.token_length)

        # Format the full verification phrase
        full_token = TEMPLATE_FORMAT.format(raw_token=raw_token)

        # Create the injection block
        injection = INTEGRITY_INSTRUCTION.format(full_token=full_token)

        # Append to system prompt
        secured_prompt = f"{system_prompt}{injection}"

        logger.debug(f"Injected integrity canary: {full_token}")
        return secured_prompt, full_token

    def check(self, response: str, token: str) -> CanaryResult:
        """
        Verifies if the LLM output contains the mandatory integrity token.

        Args:
            response: The string output from the LLM.
            token: The full token string returned by inject().

        Returns:
            CanaryResult:
                - detected=True if token is MISSING (Jailbreak).
                - detected=False if token is PRESENT (Safe).
        """
        if not response:
            # Empty response is a failure of adherence
            return CanaryResult(detected=True, component="Canary", token_found=None)

        # Strict Check: The model must reproduce the phrase exactly.
        if token in response:
            return CanaryResult(detected=False, token_found=token)

        # We assume Jailbreak if exact match fails.
        # (We intentionally avoid fuzzy matching here because we demanded exact output).
        logger.warning(f"Integrity check failed. Token missing: {token}")
        return CanaryResult(detected=True, token_found=None)

    def clean(self, response: str, token: str) -> str:
        """
        Removes the integrity token from the response to prevent user confusion.

        Args:
            response: The LLM output.
            token: The full token string.

        Returns:
            The cleaned response string.
        """
        if not response:
            return ""

        return response.replace(token, "").rstrip()

    async def a_check(self, response: str, token: str) -> CanaryResult:
        """Async version of check() using a thread pool."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, self.check, response, token)

    async def a_clean(self, response: str, token: str) -> str:
        """Async version of clean() using a thread pool."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, self.clean, response, token)
