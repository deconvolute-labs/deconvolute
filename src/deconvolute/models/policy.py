from dataclasses import dataclass
from enum import StrEnum
from re import Pattern
from typing import Annotated, Any, Literal

import celpy
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, model_validator

# Initialize the CEL Environment Singleton once for the entire application
CEL_ENV = celpy.Environment()


class PolicyAction(StrEnum):
    """
    Defines the available enforcement actions.
    """

    ALLOW = "allow"  # Permit execution
    BLOCK = "block"  # Prevent execution
    WARN = "warn"  # Permit but log a warning


class ToolRule(BaseModel):
    """
    A single security rule defining how to handle specific tools.
    """

    name: str = Field(..., description="Tool name pattern (e.g. 'read_file')")

    action: PolicyAction = Field(..., description="The enforcement action to take.")

    condition: str | None = Field(
        None, description="CEL expression for argument validation."
    )

    reason: str | None = Field(None, description="Human-readable explanation for logs.")

    # Use a PrivateAttr to hold the compiled AST without breaking standard validation
    _compiled_condition: Any = PrivateAttr(default=None)

    model_config = ConfigDict(frozen=True)

    # Fail-fast compilation during validation
    @model_validator(mode="after")
    def compile_cel_condition(self) -> "ToolRule":
        if self.condition:
            try:
                ast = CEL_ENV.compile(self.condition)
                self._compiled_condition = CEL_ENV.program(ast)
            except (
                celpy.CELEvalError,  # type: ignore[attr-defined]
                celpy.CELParseError,  # type: ignore[attr-defined]
            ) as error:
                raise ValueError(
                    f"Failed to compile CEL condition '{self.condition}': {error}"
                ) from error
        return self

    @property
    def compiled_condition(self) -> Any:
        return self._compiled_condition


class StdioTransportRule(BaseModel):
    """
    Origin validation rules for local stdio connections.
    """

    type: Literal["stdio"]
    command: str | None = Field(
        None, description="The exact executable required (e.g. 'python')."
    )
    args: list[str] | None = Field(
        None, description="The exact arguments required to prevent execution hijacking."
    )
    model_config = ConfigDict(frozen=True)


class SSETransportRule(BaseModel):
    """
    Origin validation rules for remote SSE connections.
    """

    type: Literal["sse"]
    url: str | None = Field(
        None, description="The exact URL or base URL required for the connection."
    )
    model_config = ConfigDict(frozen=True)


TransportRule = Annotated[
    StdioTransportRule | SSETransportRule, Field(discriminator="type")
]


class ServerPolicy(BaseModel):
    """
    Policies applied to tools exposed by a specific server.
    """

    description: str | None = Field(
        default=None, description="Optional description of the server"
    )

    version: str | None = Field(
        default=None,
        description=(
            "Optional SemVer constraint for the server version "
            "(e.g. '>=1.2.0, <2.0.0')."
        ),
    )

    transport: TransportRule | None = Field(
        default=None, description="Optional strict transport origin validation."
    )

    tools: list[ToolRule] = Field(default_factory=list)

    model_config = ConfigDict(frozen=True)


class SecurityPolicy(BaseModel):
    """
    The compiled security policy configuration.
    """

    version: str

    default_action: PolicyAction = Field(
        default=PolicyAction.BLOCK, description="Fallback action if no rule matches."
    )

    servers: dict[str, ServerPolicy] = Field(default_factory=dict)

    model_config = ConfigDict(frozen=True)


@dataclass
class CompiledRule:
    """Internal executable representation of a policy rule."""

    tool_pattern: Pattern[str]
    action: PolicyAction
    compiled_condition: Any | None
    original_rule_str: str  # For logging
