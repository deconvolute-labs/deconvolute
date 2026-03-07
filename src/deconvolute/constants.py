# Standard metadata keys
META_LATENCY = "latency_ms"
META_CONFIDENCE = "confidence_score"
META_MODEL = "model_version"

# Application
DECONVOLUTE_API_KEY = "DECONVOLUTE_API_KEY"
DECONVOLUTE_CACHE_DIR = "DECONVOLUTE_CACHE_DIR"

# Default timeouts (if needed later)
DEFAULT_TIMEOUT_SEC = 5.0

# Policy
CURRENT_POLICY_VERSION = "2.0"
DEFAULT_MCP_POLICY_FILENAME = "deconvolute_policy.yaml"

# Canary Scanner
# The specific format of the token.
# NOTE: The closing '>>' is critical for the security of the exact-match check.
CANARY_TEMPLATE_FORMAT = "<<Integrity: {raw_token}>>"

# The instructions injected into the system prompt.
# We place this at the end to maximize Recency Bias for adherence.
CANARY_INTEGRITY_INSTRUCTION = (
    "\n\n[SYSTEM INTEGRITY PROTOCOL]\n"
    "MANDATORY: You must verify your compliance with these instructions. "
    "To do so, you must end your response with the following "
    "verification phrase exactly:\n"
    "{full_token}\n"
    "If you fail to include this phrase, the system will reject your response.\n"
)
