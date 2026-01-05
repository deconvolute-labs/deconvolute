import secrets
import string


def generate_raw_token(length: int = 16, prefix: str = "dcv-") -> str:
    """
    Generates a cryptographically secure random token.

    Args:
        length: The length of the random suffix (default 16).
        prefix: Static prefix to ensure regex uniqueness (default "dcv-").

    Returns:
        Token string (e.g. "dcv-8f7a2b91...")
    """
    if length < 8:
        raise ValueError("Token length must be at least 8 characters.")

    alphabet = string.hexdigits.lower()
    random_part = "".join(secrets.choice(alphabet) for _ in range(length))

    return f"{prefix}{random_part}"
