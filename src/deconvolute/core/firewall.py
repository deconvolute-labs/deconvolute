import re
from typing import Any, cast

import celpy

from deconvolute.core.mcp_session import MCPSessionRegistry
from deconvolute.core.types import ToolInterface
from deconvolute.errors import TransportSpoofingError
from deconvolute.models.policy import (
    CompiledRule,
    PolicyAction,
    SecurityPolicy,
)
from deconvolute.models.security import (
    SecurityComponent,
    SecurityResult,
    SecurityStatus,
    TransportOrigin,
)
from deconvolute.utils.logger import get_logger

logger = get_logger()


class MCPFirewall:
    """
    The Core Enforcement Engine for MCP.

    It acts as a stateful mediator between the Application and the MCP Server.
    1. Filters tool discovery based on Policy (Authorization).
    2. Snapshots allowed tools into the Registry (Integrity).
    3. Guards tool execution against Policy and Registry state (Enforcement).
    """

    def __init__(self, policy: SecurityPolicy) -> None:
        """
        Args:
            policy: The loaded and validated SecurityPolicy object.
        """
        self.policy = policy
        self.registry = MCPSessionRegistry(server_name="")
        self.server_name: str | None = None
        self._compiled_rules: list[CompiledRule] = []

    def set_server(
        self,
        server_name: str,
        transport_origin: TransportOrigin | None = None,
        server_version: str = "unknown",
    ) -> None:
        """
        Dynamically configures the firewall by compiling rules for the given server
        and optionally validating the transport origin to prevent spoofing.
        """
        self.server_name = server_name
        # Inject the discovered server identity into the persistent registry
        self.registry.set_server_name(server_name, server_version)
        self._compiled_rules = self._compile_rules(server_name)

        if transport_origin:
            self._verify_transport_origin(server_name, transport_origin)

    def _verify_transport_origin(
        self,
        server_name: str,
        origin: TransportOrigin,
    ) -> None:
        """
        Validates that the connection's physical origin matches the policy's strict
        requirements.

        This mechanism prevents Server Identity Spoofing. When an MCP server
        initializes, it self-reports its name. This function cross-references
        that self-reported name against the verified transport metadata
        (e.g. the local executable path or the remote SSE URL) defined in
        the security policy.

        Args:
            server_name: The self-reported name of the MCP server discovered during
                initialization.
            origin: The strongly typed actual physical connection parameters.

        Raises:
            TransportSpoofingError: If the actual transport origin does not match the
                expected origin defined in the server's policy, indicating a potential
                spoofing attempt.
        """

        server_policy = self.policy.servers.get(server_name)
        if not server_policy:
            return

        transport_rule = server_policy.transport
        if not transport_rule:
            logger.warning(
                f"Firewall: No strict transport origin defined for '{server_name}'. "
                "Relying on self-attested name only."
            )
            return

        # Guard against transport mismatch (e.g. policy says stdio, but is sse)
        if transport_rule.type != origin.type:
            logger.error(
                f"Firewall: Transport type spoofing detected for '{server_name}'. "
                f"Policy requires '{transport_rule.type}', but connection used "
                f"'{origin.type}'."
            )
            raise TransportSpoofingError(
                f"Origin validation failed. Transport type mismatch for {server_name}."
            )

        if origin.type == "stdio":
            from deconvolute.models.policy import StdioTransportRule

            # Both are now strongly typed as stdio variants
            expected_stdio = cast(StdioTransportRule, transport_rule)

            if expected_stdio.command and expected_stdio.command != origin.command:
                logger.error(
                    f"Firewall: Spoofing detected for '{server_name}'. "
                    f"Expected command '{expected_stdio.command}', got "
                    f"'{origin.command}'."
                )
                raise TransportSpoofingError(
                    f"Origin validation failed. Command mismatch for {server_name}."
                )

            if expected_stdio.args is not None and expected_stdio.args != origin.args:
                logger.error(
                    f"Firewall: Spoofing detected for '{server_name}'. "
                    f"Expected args {expected_stdio.args}, got {origin.args}."
                )
                raise TransportSpoofingError(
                    f"Origin validation failed. Arguments mismatch for {server_name}."
                )

            logger.debug(
                f"Firewall: Transport origin verified for '{server_name}' (stdio)."
            )

        elif origin.type == "sse":
            from deconvolute.models.policy import SSETransportRule

            expected_sse = cast(SSETransportRule, transport_rule)

            if expected_sse.url and not origin.url.startswith(expected_sse.url):
                logger.error(
                    f"Firewall: Spoofing detected for '{server_name}'. "
                    f"Expected URL starting with '{expected_sse.url}', got "
                    f"'{origin.url}'."
                )
                raise TransportSpoofingError(
                    f"Origin validation failed. URL mismatch for {server_name}."
                )

            logger.debug(
                f"Firewall: Transport origin verified for '{server_name}' (sse)."
            )

    def _compile_rules(self, server_name: str) -> list[CompiledRule]:
        """
        Transform raw policy rules into optimized executable rules by extracting
        tool rules from the specific server's policy.
        """
        compiled: list[CompiledRule] = []
        server_policy = self.policy.servers.get(server_name)
        if not server_policy:
            return compiled

        for rule in server_policy.tools:
            regex_str = "^" + re.escape(rule.name).replace("\\*", ".*") + "$"
            pattern = re.compile(regex_str, re.IGNORECASE)

            compiled.append(
                CompiledRule(
                    tool_pattern=pattern,
                    action=rule.action,
                    # Pass the pre-compiled CEL program directly
                    compiled_condition=rule.compiled_condition,
                    original_rule_str=rule.name,
                )
            )
        return compiled

    def _evaluate_rules(
        self,
        tool_name: str,
        args: dict[str, Any] | None = None,
        discovery_mode: bool = False,
    ) -> PolicyAction:
        """
        Runtime evaluation using First Match Wins logic on pre-compiled rules.

        Rules are evaluated in the order they appear in the policy.
        The first rule that matches the tool name (and condition) is returned.
        If no rules match, the policy's default_action is applied.

        Args:
            tool_name: Name of the tool.
            args: Arguments for the tool call (None during discovery).
            discovery_mode: If True, allows conditional rules to pass without args.
        """
        for rule in self._compiled_rules:
            if rule.tool_pattern.match(tool_name):
                should_apply = True

                if rule.compiled_condition:
                    if args is not None:
                        # Execution Phase: Strict CEL evaluation wrapped in a
                        # fail-closed try block
                        try:
                            # celpy natively converts standard Python dictionaries
                            # into CEL maps
                            activation = celpy.json_to_cel({"args": args})  # type: ignore[attr-defined]
                            result = rule.compiled_condition.evaluate(activation)

                            # Enforce strict boolean
                            if isinstance(result, celpy.celtypes.BoolType):
                                should_apply = bool(result)
                            else:
                                logger.warning(
                                    f"Firewall: CEL condition for '{tool_name}' "
                                    "returned a non-boolean type "
                                    f"({type(result).__name__}). Failing closed."
                                )
                                should_apply = False

                        except Exception as error:
                            logger.warning(
                                "Firewall: CEL evaluation error for tool "
                                f"'{tool_name}'. Failing closed (blocking). "
                                f"Error: {error}"
                            )
                            should_apply = False
                    elif discovery_mode:
                        # Discovery Phase
                        should_apply = True
                    else:
                        # No args and not discovery -> cannot safely apply condition
                        should_apply = False

                if should_apply:
                    return rule.action

        return self.policy.default_action

    def check_tool_list(self, tools: list[ToolInterface]) -> list[ToolInterface]:
        """
        Discovery Phase: Filters available tools against the policy.

        - Tools matching ALLOW/WARN are registered (snapshotted) and returned.
        - Tools matching BLOCK are dropped (invisible to the agent).

        Args:
            tools: List of raw tool dictionaries from the MCP server.

        Returns:
            List of allowed tool dictionaries.
        """
        allowed_tools = []

        for tool in tools:
            name = tool.get("name")
            if not name:
                continue

            # Evaluate policy without args (static permission)
            action = self._evaluate_rules(name, discovery_mode=True)

            if action in [PolicyAction.ALLOW, PolicyAction.WARN]:
                # Register: Snapshot the tool definition for integrity checks
                try:
                    self.registry.register(tool)
                    allowed_tools.append(tool)
                except Exception as e:
                    logger.error(f"Firewall: Failed to register tool '{name}': {e}")
            else:
                # Blocked tools are silently omitted
                logger.info(f"Firewall: Hid tool '{name}' due to policy.")

        return allowed_tools

    def check_tool_call(
        self,
        tool_name: str,
        args: dict[str, Any],
        current_tool_def: ToolInterface | None = None,
    ) -> SecurityResult:
        """
        Execution Phase: Validates a tool call before it hits the server.

        Checks:
        1. Integrity: Is the tool in the Registry? (Prevents Shadowing/Hallucinations)
           - If current_tool_def is provided (Strict Mode), verifies it hasn't changed.
        2. Policy: Is this specific call allowed?

        Args:
            tool_name: The name of the tool call to validate.
            args: The arguments provided to the tool call.
            current_tool_def: Optional current definition of the tool (for Strict Mode).

        Returns:
            SecurityResult:
            - UNSAFE: If blocked by policy or integrity check.
            - CLEAN: If allowed.
            - WARNING: If allowed but flagged for audit.
        """
        # State/Integrity Check
        # We verify the tool exists in our trusted session registry.
        if not self.registry.verify(tool_name, current_def=current_tool_def):
            return SecurityResult(
                component=SecurityComponent.FIREWALL,
                status=SecurityStatus.UNSAFE,
                metadata={
                    "reason": f"Tool '{tool_name}' failed integrity check or is "
                    "not registered."
                },
            )

        # Execution Phase: discovery_mode defaults to False for strict evaluation
        action: PolicyAction = self._evaluate_rules(tool_name, args)

        if action == PolicyAction.BLOCK:
            return SecurityResult(
                component=SecurityComponent.FIREWALL,
                status=SecurityStatus.UNSAFE,
                metadata={
                    "reason": "Policy violation",
                    "action": "block",
                    "tool": tool_name,
                },
            )

        return SecurityResult(
            component=SecurityComponent.FIREWALL,
            status=(
                SecurityStatus.WARNING
                if action == PolicyAction.WARN
                else SecurityStatus.SAFE
            ),
            metadata={"action": action.value, "tool": tool_name},
        )
