DEFAULT_MCP_POLICY = """version: "2.0"

# GLOBAL SECURITY POSTURE
# -----------------------
# default_action: The fallback behavior if no rules match a tool call.
# Options: 
#  - "block": (Recommended) Zero Trust. Nothing runs unless explicitly allowed.
#  - "allow": Permissive. Everything runs unless explicitly blocked.
#  - "warn":  Audit mode. Everything runs but creates a warning log.
default_action: "block"

# EVALUATION STRATEGY: FIRST MATCH WINS
# -------------------------------------
# Rules are processed from top to bottom. The first matching rule found 
# determines the result. 
#
# BEST PRACTICE: 
# 1. Place specific blocks or narrow restrictions at the top.
# 2. Place broad permissions (like wildcards) at the bottom.
# 3. Use the default_action as your final safety net.

servers:
  # Example: A server with granular file access
  github-storage:
    version: ">=0.1.0", # Optionally add a server version
    tools:
      # PRIORITY 1: Explicitly prevent dangerous actions.
      # Even if we allow other tools later, this specific name is caught first.
      - name: "delete_repo"
        action: "block"
        reason: "Critical infrastructure protection: Deletion must be manual."

      # PRIORITY 2: Conditional access.
      # This tool is allowed ONLY if the arguments meet the Python expression.
      - name: "read_file"
        action: "allow"
        condition: "args.path.startswith('/public/')"
        reason: "Data Privacy: Only allow access to the public directory."

      # PRIORITY 3: Broad tool access.
      # The asterisk (*) matches any tool name not caught by the rules above.
      - name: "*"
        action: "allow"
        reason: "Allow standard non-destructive tools on this server."

  # Example: A server in 'Audit Mode'
  weather-service:
    tools:
      # This will log a warning to your audit trail but allow the agent to proceed.
      - name: "*"
        action: "warn"
        reason: "Log all external API usage for cost and rate-limit tracking."

  # Example: Tight restriction
  internal-database:
    tools:
      # Only one tool is allowed; everything else falls through to 
      # 'default_action: block'.
      - name: "query_readonly"
        action: "allow"
"""
