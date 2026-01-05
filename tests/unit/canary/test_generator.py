import string

import pytest

from deconvolute.canary.generator import generate_raw_token


def test_generate_defaults() -> None:
    """It should generate a token with default prefix 'dcv-' and length 16."""
    token = generate_raw_token()

    # "dcv-" (4 chars) + 16 random chars = 20 total
    assert len(token) == 20
    assert token.startswith("dcv-")


def test_generate_custom_length() -> None:
    """It should respect the length argument for the random part."""
    # 10 random hex chars + 4 prefix chars = 14
    token = generate_raw_token(length=10)
    assert len(token) == 14
    assert token.startswith("dcv-")


def test_generate_custom_prefix() -> None:
    """It should allow a custom namespace prefix."""
    token = generate_raw_token(prefix="test-")
    assert token.startswith("test-")


def test_validation_min_length() -> None:
    """It should raise ValueError if length is unsafe (< 8)."""
    with pytest.raises(ValueError, match="must be at least 8"):
        generate_raw_token(length=7)


def test_hex_alphabet_only() -> None:
    """It should only use hex digits (0-9, a-f) for the random part."""
    token = generate_raw_token(length=50)
    body = token.replace("dcv-", "")

    # Check that every character in the body is a valid hex digit
    allowed = string.hexdigits.lower()
    for char in body:
        assert char in allowed, f"Found invalid character: {char}"


def test_uniqueness() -> None:
    """
    It should return unique tokens on subsequent calls.
    Verifies that the collision probability is negligible for the default length.
    """
    # Generate 1000 tokens to ensure good statistical coverage
    count = 1000
    tokens = {generate_raw_token() for _ in range(count)}
    assert len(tokens) == count
