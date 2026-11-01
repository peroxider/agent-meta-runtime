"""Execution-time DTOs and normalized value codecs (ADR 032).

These values carry immutable snapshots, never a live store or credential.
The bound Host must enforce authority/budget/recovery independently of types.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
from types import MappingProxyType
from typing import Awaitable, Callable, Mapping, Protocol

from .canonical import canonical_json, sha256_hex
from .context_projection import ProjectionManifest, SourceRef
from .context_contract import ContextSnapshot
from .errors import ErrorCode, StableError
from .harness import is_artifact_id
from .ids import validate_id
from .loop import (
    ArtifactPart, JsonPart, ModelResponse, ProviderUsage, TerminalResult,
    TextPart, ToolCallPart, ToolResultPart, validate_response,
)
from .semantics import TaskBudget


def _invalid(message: str) -> StableError:
    return StableError(code=ErrorCode.INVALID_RESULT, message=message)


def part_to_value(part) -> dict:
    if isinstance(part, TextPart):
        return {"kind": "text", "text": part.text}
    if isinstance(part, JsonPart):
        return {"kind": "json", "value": part.value}
    if isinstance(part, ArtifactPart):
        return {"kind": "artifact", "artifact_id": part.artifact_id}
    if isinstance(part, ToolCallPart):
        return {"kind": "tool_call", "call_id": part.call_id, "name": part.name, "arguments_json": part.arguments_json}
    if isinstance(part, ToolResultPart):
        return {"kind": "tool_result", "call_id": part.call_id, "status": part.status}
    raise _invalid("unknown normalized content part")


def part_from_value(value):
    if not isinstance(value, dict):
        raise _invalid("normalized content part must be an object")
    types = {
        "text": (TextPart, {"text"}), "json": (JsonPart, {"value"}),
        "artifact": (ArtifactPart, {"artifact_id"}),
        "tool_call": (ToolCallPart, {"call_id", "name", "arguments_json"}),
        "tool_result": (ToolResultPart, {"call_id", "status"}),
    }
    kind = value.get("kind")
    if not isinstance(kind, str) or kind not in types:
        raise _invalid("unknown normalized content kind")
    constructor, fields = types[kind]
    if set(value) != fields | {"kind"}:
        raise _invalid("normalized content fields differ from contract")
    try:
        return constructor(**{key: value[key] for key in fields})
    except (TypeError, ValueError) as exc:
        raise _invalid("invalid normalized content") from exc


def _read_object(raw: bytes, fields: set[str], schema: str) -> dict:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON field")
            result[key] = value
        return result

    try:
        if not isinstance(raw, bytes) or len(raw) > 16 * 1024 * 1024:
            raise ValueError("normalized result exceeds size limit")
        value = json.loads(raw, object_pairs_hook=unique)
        if not isinstance(value, dict) or set(value) != fields or value.get("schema") != schema:
            raise ValueError("normalized result schema/fields differ")
        if canonical_json(value) != raw:
            raise ValueError("normalized result must be canonical JSON")
        return value
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise _invalid("invalid normalized result encoding") from exc


def encode_model_response(response: ModelResponse) -> bytes:
    issues = validate_response(response)
    if issues:
        raise StableError(code=ErrorCode.INVALID_RESULT, message="invalid normalized model response", details={"issues": list(issues)})
    usage = response.usage
    body = {"schema": "model-response/v1", "parts": [part_to_value(part) for part in response.parts], "finish_reason": response.finish_reason, "usage": None if usage is None else {"input_tokens": usage.input_tokens, "output_tokens": usage.output_tokens, "cost_microunits": usage.cost_microunits}}
    try:
        raw = canonical_json(body)
    except (ValueError, UnicodeError) as exc:
        raise _invalid("invalid normalized model response encoding") from exc
    if len(raw) > 16 * 1024 * 1024:
        raise _invalid("normalized model response exceeds size limit")
    return raw


def decode_model_response(raw: bytes) -> ModelResponse:
    body = _read_object(raw, {"schema", "parts", "finish_reason", "usage"}, "model-response/v1")
    if not isinstance(body["parts"], list):
        raise _invalid("normalized parts must be an ordered array")
    usage = body["usage"]
    if usage is not None:
        if not isinstance(usage, dict) or set(usage) != {"input_tokens", "output_tokens", "cost_microunits"}:
            raise _invalid("normalized usage fields differ from contract")
        usage = ProviderUsage(**usage)
    response = ModelResponse(tuple(part_from_value(value) for value in body["parts"]), body["finish_reason"], usage)
    encode_model_response(response)  # use the same semantics for live and replay
    return response


def encode_terminal_result(result: TerminalResult) -> bytes:
    if not isinstance(result, TerminalResult) or type(result.result_truncated) is not bool:
        raise _invalid("invalid terminal result")
    response = ModelResponse(result.parts, "LENGTH" if result.result_truncated else "STOP")
    encode_model_response(response)
    if any(isinstance(part, (ToolCallPart, ToolResultPart)) for part in result.parts):
        raise _invalid("terminal result cannot contain tool history")
    return canonical_json({"schema": "terminal-result/v1", "parts": [part_to_value(part) for part in result.parts], "result_truncated": result.result_truncated})


def decode_terminal_result(raw: bytes) -> TerminalResult:
    body = _read_object(raw, {"schema", "parts", "result_truncated"}, "terminal-result/v1")
    if not isinstance(body["parts"], list):
        raise _invalid("normalized parts must be an ordered array")
    result = TerminalResult(tuple(part_from_value(value) for value in body["parts"]), body["result_truncated"])
    encode_terminal_result(result)
    return result


@dataclass(frozen=True, slots=True)
class TaskEnvelope:
    task_id: str
    realm_id: str
    actor_id: str
    root_action_id: str
    input_artifact_id: str
    input_content: bytes
    serving_composition_id: str
    serving_revision: int
    capability_surface_artifact_id: str
    capability_surface_content: bytes
    state_snapshot: tuple[tuple[str, str], ...]
    budget: TaskBudget
    accepted_meta_revision: int
    loop_policy_content: bytes
    deadline_at_us: int | None
    composition_content: bytes
    acceptance_view_artifact_id: str
    acceptance_view_content: bytes
    harness_manifest_content: bytes
    context: ContextSnapshot | None = None

    def __post_init__(self):
        if self.context is not None and not isinstance(self.context, ContextSnapshot):
            raise ValueError("Task context must be a frozen ContextSnapshot")
        for field in ("task_id", "realm_id", "actor_id", "root_action_id", "serving_composition_id"):
            validate_id(getattr(self, field))
        for field in ("input_content", "capability_surface_content", "loop_policy_content", "composition_content", "acceptance_view_content", "harness_manifest_content"):
            if not isinstance(getattr(self, field), bytes):
                raise ValueError("Task snapshot content must be immutable bytes")
        for field in ("input_artifact_id", "capability_surface_artifact_id", "acceptance_view_artifact_id"):
            if not is_artifact_id(getattr(self, field)):
                raise ValueError("Task snapshot artifact reference invalid")
        if self.input_artifact_id != "artifact://sha256/" + sha256_hex(self.input_content) or self.capability_surface_artifact_id != "artifact://sha256/" + sha256_hex(self.capability_surface_content):
            raise ValueError("Task snapshot content hash differs from ArtifactId")
        if self.acceptance_view_artifact_id != "artifact://sha256/" + sha256_hex(self.acceptance_view_content):
            raise ValueError("Task acceptance View hash differs from ArtifactId")
        if not isinstance(self.budget, TaskBudget):
            raise ValueError("Task snapshot requires a frozen TaskBudget")
        if type(self.serving_revision) is not int or self.serving_revision < 1 or type(self.accepted_meta_revision) is not int or self.accepted_meta_revision < 0:
            raise ValueError("Task snapshot revisions invalid")
        if self.deadline_at_us is not None and (type(self.deadline_at_us) is not int or self.deadline_at_us < 0):
            raise ValueError("Task deadline must be absolute UTC microseconds")
        pairs = tuple(tuple(pair) for pair in self.state_snapshot)
        if any(len(pair) != 2 or not all(isinstance(value, str) for value in pair) for pair in pairs) or tuple(sorted(set(pairs))) != pairs:
            raise ValueError("State snapshot must contain sorted unique bindings")
        if len({pair[0] for pair in pairs}) != len(pairs):
            raise ValueError("each State has exactly one frozen revision")
        object.__setattr__(self, "state_snapshot", pairs)


@dataclass(frozen=True, slots=True)
class RenderedSection:
    section_id: str
    renderer_artifact_id: str
    content: bytes
    token_count: int

    def __post_init__(self):
        if not isinstance(self.content, bytes) or not isinstance(self.section_id, str) or not self.section_id or not is_artifact_id(self.renderer_artifact_id):
            raise ValueError("rendered section content/identity invalid")
        if type(self.token_count) is not int or self.token_count < 0:
            raise ValueError("rendered section token count invalid")


@dataclass(frozen=True, slots=True)
class ProjectionInput:
    policy_artifact_id: str
    source_refs: tuple[SourceRef, ...]
    sections: tuple[RenderedSection, ...]
    redaction_policy_artifact_id: str
    tokenizer_id: str
    budget_tokens: int

    def __post_init__(self):
        object.__setattr__(self, "source_refs", tuple(self.source_refs))
        object.__setattr__(self, "sections", tuple(self.sections))
        if not self.source_refs or not all(isinstance(ref, SourceRef) for ref in self.source_refs):
            raise ValueError("projection requires immutable source references")
        if not self.sections or not all(isinstance(section, RenderedSection) for section in self.sections):
            raise ValueError("projection requires immutable rendered sections")
        if len({section.section_id for section in self.sections}) != len(self.sections):
            raise ValueError("duplicate rendered section id")
        if type(self.budget_tokens) is not int or self.budget_tokens < 0:
            raise ValueError("projection token budget invalid")
        if not is_artifact_id(self.policy_artifact_id) or not is_artifact_id(self.redaction_policy_artifact_id) or not isinstance(self.tokenizer_id, str) or not self.tokenizer_id:
            raise ValueError("projection provenance invalid")


@dataclass(frozen=True, slots=True)
class ContextProjection:
    manifest: ProjectionManifest
    rendered_artifact_id: str
    rendered_content: bytes

    def __post_init__(self):
        if not isinstance(self.manifest, ProjectionManifest) or not isinstance(self.rendered_content, bytes) or self.rendered_artifact_id != "artifact://sha256/" + sha256_hex(self.rendered_content):
            raise ValueError("projection rendered content hash invalid")


@dataclass(frozen=True, slots=True)
class ModelInvocation:
    task: TaskEnvelope
    request_id: str
    ordinal: int
    projection: ContextProjection
    history_content: bytes


@dataclass(frozen=True, slots=True)
class CapabilityInvocation:
    task: TaskEnvelope
    request_id: str
    call: ToolCallPart


@dataclass(frozen=True, slots=True)
class InvocationResult:
    content: bytes | None = None
    error_code: str | None = None

    def __post_init__(self):
        if (self.content is None) == (self.error_code is None):
            raise ValueError("InvocationResult has exactly one of content/error")
        if self.content is not None and not isinstance(self.content, bytes):
            raise ValueError("InvocationResult content must be immutable bytes")
        if self.error_code is not None and (not isinstance(self.error_code, str) or self.error_code not in ErrorCode.ALL):
            raise ValueError("unknown InvocationResult error code")


class TaskRuntime(Protocol):
    async def project_context(self, request: ProjectionInput) -> ContextProjection: ...
    async def invoke_model(self, projection: ContextProjection) -> ModelResponse: ...
    async def invoke_tool(self, call: ToolCallPart) -> InvocationResult: ...
    def check_cancelled(self) -> None: ...


@dataclass(frozen=True, slots=True)
class HealthProbeInvocation:
    """Task-free pure probe context; Runtime owns observation/commit fields."""

    request_id: str
    slot: str
    capability_id: str
    descriptor_revision: int
    operation_id: str
    deadline_at_us: int

    def __post_init__(self):
        validate_id(self.capability_id)
        if not self.capability_id.startswith("capability://"):
            raise ValueError("health probe requires a Capability identity")
        for name in ("request_id", "slot", "operation_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value or len(value) > 128:
                raise ValueError("health probe identity must be bounded and nonempty")
        if type(self.descriptor_revision) is not int or self.descriptor_revision < 1:
            raise ValueError("health probe descriptor revision invalid")
        if type(self.deadline_at_us) is not int or self.deadline_at_us <= 0:
            raise ValueError("health probe deadline invalid")


@dataclass(frozen=True, slots=True)
class HealthStatus:
    status: str
    reason_code: str

    def __post_init__(self):
        if not isinstance(self.status, str) or self.status not in ("READY", "DEGRADED", "UNHEALTHY"):
            raise ValueError("unknown health status")
        if not isinstance(self.reason_code, str) or re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", self.reason_code) is None:
            raise ValueError("health reason must be a bounded stable token")


@dataclass(frozen=True, slots=True)
class ProviderRequestPlan:
    """Public secretless plan; endpoint/credential selection belongs to Root."""
    profile_artifact_id: str
    body: bytes

    def __post_init__(self):
        if not is_artifact_id(self.profile_artifact_id) or type(self.body) is not bytes or not 0 < len(self.body) <= 1024 * 1024:
            raise ValueError("Provider plan requires a profile Artifact and bounded immutable bytes")
        try:
            document = json.loads(self.body)
            if not isinstance(document, dict) or canonical_json(document) != self.body:
                raise ValueError("Provider plan body must be a canonical JSON object")
            if set(document) - {"model", "messages", "max_tokens", "stream", "system", "tools", "tool_choice", "temperature", "top_p", "stop_sequences"}:
                raise ValueError("Provider plan fields are outside the terminal Messages contract")
            if (not {"model", "messages", "max_tokens", "stream"} <= set(document)
                    or not isinstance(document["model"], str) or re.fullmatch(r"[A-Za-z0-9_.:-]{1,200}", document["model"]) is None
                    or document["stream"] is not False or type(document["max_tokens"]) is not int
                    or not 0 < document["max_tokens"] <= 2**31-1
                    or not isinstance(document["messages"], list) or not 1 <= len(document["messages"]) <= 256):
                raise ValueError("Provider plan terminal request shape is invalid")
        except (ValueError, TypeError, UnicodeError, RecursionError):
            raise ValueError("invalid Provider plan body") from None


@dataclass(frozen=True, slots=True)
class ProviderTerminalResponse:
    """One complete bounded body; no headers, transport, credentials or handles."""
    profile_artifact_id: str
    content: bytes

    def __post_init__(self):
        if not is_artifact_id(self.profile_artifact_id) or type(self.content) is not bytes or not 0 < len(self.content) <= 1024 * 1024:
            raise ValueError("Provider terminal requires a profile Artifact and bounded immutable bytes")


@dataclass(frozen=True, slots=True)
class ProviderAdapter:
    """Synchronous plan/normalization callbacks; Runtime owns external effects."""
    prepare: Callable[[ModelInvocation], ProviderRequestPlan]
    normalize: Callable[[ProviderTerminalResponse], ModelResponse]

    def __post_init__(self):
        if not callable(self.prepare) or not callable(self.normalize):
            raise ValueError("Provider adapter requires plan and normalization callbacks")


@dataclass(frozen=True, slots=True)
class HarnessAdapter:
    run_task: Callable[[TaskEnvelope, TaskRuntime], Awaitable[TerminalResult]]
    invoke_model: Callable[[ModelInvocation], Awaitable[ModelResponse]] | None
    tools: Mapping[str, Callable[[CapabilityInvocation], Awaitable[InvocationResult]]]
    probe: Callable[[HealthProbeInvocation], Awaitable[HealthStatus]]
    provider: ProviderAdapter | None = None

    def __post_init__(self):
        model_valid = callable(self.invoke_model) if self.provider is None else type(self.provider) is ProviderAdapter and self.invoke_model is None
        if not callable(self.run_task) or not model_valid or not callable(self.probe) or not all(isinstance(key, str) and callable(value) for key, value in self.tools.items()):
            raise ValueError("Harness adapter requires callable operations")
        object.__setattr__(self, "tools", MappingProxyType(dict(self.tools)))
