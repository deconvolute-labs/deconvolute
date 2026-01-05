import pytest

from deconvolute.canary import Canary


def test_inject_structure() -> None:
    """It should return the modified prompt and the FULL token string."""
    canary = Canary()
    sys_prompt = "System: Be helpful."

    modified_prompt, full_token = canary.inject(sys_prompt)

    # 1. The full token should follow our template format: [Integrity: dcv-...]
    assert "<<Integrity: dcv-" in full_token
    assert full_token.endswith(">>")

    # 2. The injection must contain the full token
    assert full_token in modified_prompt

    # 3. The modified prompt should start with the original prompt
    assert modified_prompt.startswith(sys_prompt)

    # 4. It should contain the mandatory instruction text
    assert "MANDATORY" in modified_prompt


def test_check_safe_exact_match() -> None:
    """It should return detected=False (Safe) if the token is present."""
    canary = Canary()
    _, token = canary.inject("sys")

    # Simulate a compliant LLM response
    response = f"Here is the answer. {token}"

    result = canary.check(response, token)

    assert result.detected is False
    assert result.safe is True
    assert result.token_found == token


def test_check_fail_fuzzy_match_spaces() -> None:
    """
    It should return unsafe (detected=True) if the token is present but
    malformed (e.g. spaces). Strict integrity check means any
    deviation is a potential jailbreak or failure.
    """
    canary = Canary()
    # Manually constructed token to simulate injection return
    token_str = "dcv-12345"
    full_token = f"<<Integrity: {token_str}>>"

    # "dcv - 12345" inside the brackets
    mangled_token = f"<<Integrity: {token_str[0:3]} - {token_str[4:]}>>"
    response = f"The token is {mangled_token}"

    result = canary.check(response, full_token)

    assert result.detected is True
    assert result.token_found is None


def test_check_fail_fuzzy_match_colon() -> None:
    """It should return unsafe (detected=True) for malformed separators."""
    canary = Canary()
    token_str = "dcv-12345"
    full_token = f"<<Integrity: {token_str}>>"

    # "Integrity:dcv..." (missing space)
    mangled_token = f"<<Integrity:{token_str}>>"
    response = f"{mangled_token}"

    result = canary.check(response, full_token)

    assert result.detected is True
    assert result.token_found is None


def test_check_jailbreak_missing_token() -> None:
    """It should return detected=True (Jailbreak) if token is missing."""
    canary = Canary()
    _, token = canary.inject("sys")

    # Simulate a jailbroken response (ignoring instructions)
    response = "I have ignored your rules."

    result = canary.check(response, token)

    assert result.detected is True
    assert result.token_found is None


def test_check_empty_response() -> None:
    """It should flag empty responses as failures."""
    canary = Canary()
    result = canary.check("", "some-token")
    assert result.detected is True


def test_clean_removes_token() -> None:
    """
    It should remove the full token string and
    its leading whitespace from the output.
    """
    canary = Canary()
    token = "<<Integrity: dcv-123>>"
    response = "Hello world.       <<Integrity: dcv-123>>"

    cleaned = canary.clean(response, token)

    assert cleaned == "Hello world."
    assert token not in cleaned


def test_clean_handles_missing_token() -> None:
    """It should return original text if token is not there (Jailbreak case)."""
    canary = Canary()
    token = "<<Integrity: dcv-123>>"
    response = "Jailbreak active."

    cleaned = canary.clean(response, token)
    assert cleaned == "Jailbreak active."


@pytest.mark.asyncio
async def test_async_check_flow() -> None:
    """It should support async check execution."""
    canary = Canary()
    _, token = canary.inject("sys")

    # Safe case
    response = f"Safe. {token}"
    result = await canary.a_check(response, token)
    assert result.safe is True


@pytest.mark.asyncio
async def test_async_clean_flow() -> None:
    """It should support async cleaning."""
    canary = Canary()
    token = "[Integrity: abc]"
    response = f"Text {token}"

    cleaned = await canary.a_clean(response, token)
    assert cleaned == "Text"
