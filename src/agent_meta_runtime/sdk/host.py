"""Public execution DTOs/protocols under development (ADR 032).

Consumer importability does not imply that a Runtime profile implements the
bound Host. Require public-wheel execution/recovery proofs before activation.
"""

from ..domain.context_projection import ProjectionManifest, Section, SourceRef
from ..domain.context_contract import ContextSnapshot, FrozenContextSource
from ..domain.host_contract import (
    CapabilityInvocation, ContextProjection, HarnessAdapter, HealthProbeInvocation, HealthStatus, InvocationResult,
    ModelInvocation, ProjectionInput, RenderedSection, TaskEnvelope, TaskRuntime,
    ProviderAdapter, ProviderRequestPlan, ProviderTerminalResponse,
    decode_model_response, decode_terminal_result, encode_model_response,
    encode_terminal_result, part_from_value, part_to_value,
)
from ..domain.loop import (
    ArtifactPart, JsonPart, ModelResponse, ProviderUsage, TerminalResult,
    TextPart, ToolCallPart, ToolResultPart, terminal_result, validate_response,
)
from ..domain.semantics import TaskBudget

__all__ = [
    "ContextSnapshot", "FrozenContextSource",
    "CapabilityInvocation", "ContextProjection", "HarnessAdapter", "InvocationResult",
    "HealthProbeInvocation", "HealthStatus",
    "ModelInvocation", "ProjectionInput", "RenderedSection", "TaskEnvelope", "TaskRuntime",
    "ProjectionManifest", "Section", "SourceRef", "ArtifactPart", "JsonPart", "ModelResponse",
    "ProviderUsage", "TerminalResult", "TextPart", "ToolCallPart", "ToolResultPart", "TaskBudget",
    "ProviderAdapter", "ProviderRequestPlan", "ProviderTerminalResponse",
    "decode_model_response", "decode_terminal_result", "encode_model_response", "encode_terminal_result",
    "part_from_value", "part_to_value", "terminal_result", "validate_response",
]
