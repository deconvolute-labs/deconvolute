import pytest

from deconvolute import Canary


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
    """It should return threat_detected=False (Safe) if the token is present."""
    canary = Canary()
    _, token = canary.inject("sys")

    # Simulate a compliant LLM response
    response = f"Here is the answer. {token}"

    result = canary.check(response, token=token)

    assert result.threat_detected is False

    assert result.safe is True
    assert result.token_found == token


def test_check_fail_fuzzy_match_spaces() -> None:
    """
    It should return unsafe (threat_detected=True) if the token is present but
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

    result = canary.check(response, token=full_token)

    assert result.threat_detected is True
    assert result.token_found is None


def test_check_fail_fuzzy_match_colon() -> None:
    """It should return unsafe (threat_detected=True) for malformed separators."""
    canary = Canary()
    token_str = "dcv-12345"
    full_token = f"<<Integrity: {token_str}>>"

    # "Integrity:dcv..." (missing space)
    mangled_token = f"<<Integrity:{token_str}>>"
    response = f"{mangled_token}"

    result = canary.check(response, token=full_token)

    assert result.threat_detected is True
    assert result.token_found is None


def test_check_jailbreak_missing_token() -> None:
    """It should return threat_detected=True (Jailbreak) if token is missing."""
    canary = Canary()
    _, token = canary.inject("sys")

    # Simulate a jailbroken response (ignoring instructions)
    response = "I have ignored your rules."

    result = canary.check(response, token=token)

    assert result.threat_detected is True

    assert result.token_found is None


def test_check_empty_response() -> None:
    """It should flag empty responses as failures."""
    canary = Canary()
    result = canary.check("", token="some-token")
    assert result.threat_detected is True


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


def test_inject_custom_length() -> None:
    """It should respect custom token_length passed in __init__."""
    custom_len = 32
    canary = Canary(token_length=custom_len)
    _, full_token = canary.inject("sys")

    # Format: <<Integrity: dcv-<random> >>
    algo_part = full_token.replace("<<Integrity: ", "").replace(">>", "")
    assert len(algo_part) == 4 + custom_len
    assert algo_part.startswith("dcv-")


def test_inject_empty_prompt() -> None:
    """It should handle empty system prompts gracefully."""
    canary = Canary()
    modified, token = canary.inject("")

    # It should just be the injection instruction
    assert token in modified
    assert "MANDATORY" in modified
    assert len(modified) > len(token)


def test_check_partial_match_fail() -> None:
    """It should fail if only a substring of the token is present."""
    canary = Canary()
    _, token = canary.inject("sys")
    # token e.g. "<<Integrity: dcv-1234...>>"

    partial = token[:-2]  # Check without closing brackets
    response = f"Here is {partial}"

    result = canary.check(response, token=token)
    assert result.threat_detected is True
    assert result.safe is False


def test_check_case_sensitivity() -> None:
    """It should be case sensitive (strict check)."""
    canary = Canary()
    _, token = canary.inject("sys")

    upper_token = token.upper()  # Hex parts might be already mixed case?
    # default implementation uses lower case hex.
    # If we upper case it, it should fail equality check.

    if token == upper_token:
        # If token has no letters (unlikely), validcheck.
        pass
    else:
        response = f"Here is {upper_token}"
        result = canary.check(response, token=token)
        assert result.threat_detected is True


def test_clean_no_op_empty() -> None:
    """Clean should return empty string for empty content."""
    canary = Canary()
    assert canary.clean("", "token") == ""


def test_check_missing_token_arg() -> None:
    """It should raise ValueError if 'token' kwarg is missing."""
    canary = Canary()
    with pytest.raises(ValueError, match="requires 'token' argument"):
        canary.check("Response with no token context")


@pytest.mark.asyncio
async def test_async_check_flow() -> None:
    """It should support async check execution."""
    canary = Canary()
    _, token = canary.inject("sys")

    # Safe case
    response = f"Safe. {token}"
    result = await canary.a_check(response, token=token)
    assert result.safe is True


@pytest.mark.asyncio
async def test_async_clean_flow() -> None:
    """It should support async cleaning."""
    canary = Canary()
    token = "[Integrity: abc]"
    response = f"Text {token}"

    cleaned = await canary.a_clean(response, token)
    assert cleaned == "Text"
