"""Versioned Context mechanisms shared by external policies and Host verification.

No store, credentials or package execution is available here. Policy, schemas,
renderer and tokenizer declarations are immutable artifacts selected by the
external Harness. The default v1 ladder is the normative mechanism (§41.44.4).
"""

from dataclasses import dataclass
import json
import re
from types import MappingProxyType

from .canonical import canonical_json, sha256_hex
from .context_projection import BUDGET_LADDER, SECTION_DELIMITER, SourceRef, ladder_quotas
from .errors import ErrorCode, StableError
from .harness import is_artifact_id
from .host_schema import validate_host_value
from .context_tokenizer import (context_tokenizer_descriptor, measured_count, MAX_RENDERED_CONTEXT_BYTES, GLM53_TOKENIZER_ID)


SECTION_IDS = tuple(item[0] for item in BUDGET_LADDER)
_MIN_REDACT_KEYS = frozenset({"api_key", "apikey", "authorization", "credential", "password", "secret", "token", "private_key", "raw_response"})
_PATTERNS = {
    "bearer/v1": re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*"),
    "key-token/v1": re.compile(r"\b(?:sk|pk|api)[-_][A-Za-z0-9_-]{8,}\b"),
    "assignment/v1": re.compile(r"(?i)\b(?:api[_-]?key|token|password|secret)\s*[:=]\s*[^\s,;\"}]+"),
}


def _fail(message, code=ErrorCode.FAILED_PRECONDITION):
    return StableError(code=code, message=message)


def context_document(raw):
    def unique(pairs):
        result = {}
        for name, value in pairs:
            if name in result:
                raise ValueError("duplicate context field")
            result[name] = value
        return result
    try:
        if not isinstance(raw, bytes) or len(raw) > 4 * 1024 * 1024:
            raise ValueError("context resource exceeds ceiling")
        value = json.loads(raw, object_pairs_hook=unique)
        canonical_json(value)
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise _fail("invalid Context JSON resource", ErrorCode.INVALID_ARGUMENT) from exc


@dataclass(frozen=True, slots=True)
class FrozenContextSource:
    kind: str
    ref: str
    content: bytes

    def __post_init__(self):
        if self.kind not in {"constitution", "runtime", "fact"} or not isinstance(self.ref, str) or not self.ref or not isinstance(self.content, bytes):
            raise ValueError("invalid frozen context source")
        if self.ref.startswith("artifact://") and self.ref != "artifact://sha256/" + sha256_hex(self.content):
            raise ValueError("context source content differs from ArtifactId")

    def source_ref(self):
        return SourceRef(self.kind, self.ref, sha256_hex(self.content))


@dataclass(frozen=True, slots=True)
class ContextSnapshot:
    profile_artifact_id: str
    artifacts: tuple[tuple[str, bytes], ...]
    sources: tuple[FrozenContextSource, ...]
    facts_available: bool

    def __post_init__(self):
        artifacts, sources = tuple(tuple(item) for item in self.artifacts), tuple(self.sources)
        if not is_artifact_id(self.profile_artifact_id) or type(self.facts_available) is not bool:
            raise ValueError("invalid Context snapshot identity")
        if len(artifacts) > 256 or len(sources) > 514 or any(len(item) != 2 or not is_artifact_id(item[0]) or not isinstance(item[1], bytes) or item[0] != "artifact://sha256/" + sha256_hex(item[1]) for item in artifacts):
            raise ValueError("invalid Context artifact snapshot")
        if len({item[0] for item in artifacts}) != len(artifacts) or self.profile_artifact_id not in dict(artifacts):
            raise ValueError("Context artifact identities must be unique and complete")
        if not all(isinstance(source, FrozenContextSource) for source in sources) or len({(s.kind, s.ref) for s in sources}) != len(sources):
            raise ValueError("Context sources must be unique frozen values")
        if sum(len(item[1]) for item in artifacts) + sum(len(s.content) for s in sources) > 8 * 1024 * 1024:
            raise ValueError("Context snapshot exceeds ceiling")
        object.__setattr__(self, "artifacts", artifacts)
        object.__setattr__(self, "sources", sources)


def _shape(value, schema, fields):
    if not isinstance(value, dict) or set(value) != {"schema", *fields} or value.get("schema") != schema:
        raise _fail("Context resource schema or fields are unsupported")
    return value


def context_profile_references(raw):
    profile = _shape(context_document(raw), "context-profile/v1", {
        "policy_artifact_id", "redaction_policy_artifact_id", "tokenizer_artifact_id", "provider_profile_artifact_id", "renderer_artifact_ids"})
    renderers = profile["renderer_artifact_ids"]
    if not isinstance(renderers, dict) or set(renderers) != set(SECTION_IDS):
        raise _fail("Context profile requires all versioned section renderers")
    refs = [profile[key] for key in ("policy_artifact_id", "redaction_policy_artifact_id", "tokenizer_artifact_id", "provider_profile_artifact_id")]
    refs.extend(renderers.values())
    if not all(is_artifact_id(ref) for ref in refs):
        raise _fail("Context profile artifact reference is invalid")
    return profile, tuple(sorted(set(refs)))


def policy_schema_references(raw):
    policy = _shape(context_document(raw), "context-policy/v1", {"budget_tokens", "task_input_overflow", "truncate_field",
        "selected_operation_ids", "task_input_schema_artifact_id", "fact_schema_artifact_id", "runtime_schema_artifact_id", "fact_depth", "require_facts"})
    if type(policy["budget_tokens"]) is not int or not 256 <= policy["budget_tokens"] <= 1024 * 1024 or policy["fact_depth"] != 4 or type(policy["fact_depth"]) is not int or type(policy["require_facts"]) is not bool:
        raise _fail("Context policy budget or source bounds are unsupported")
    if policy["task_input_overflow"] not in {"REJECT", "TAIL_TRUNCATE"} or not isinstance(policy["truncate_field"], str):
        raise _fail("Context input truncation policy is unsupported")
    selected = policy["selected_operation_ids"]
    if not isinstance(selected, list) or not all(isinstance(name, str) and name for name in selected) or selected != sorted(set(selected)):
        raise _fail("Context selected operations must be sorted and unique")
    refs = tuple(policy[key] for key in ("task_input_schema_artifact_id", "fact_schema_artifact_id", "runtime_schema_artifact_id"))
    if not all(is_artifact_id(ref) for ref in refs):
        raise _fail("Context normalizer schemas must be artifacts")
    return policy, refs


def _normalize(schema, value, depth=0):
    if depth > 48:
        raise _fail("Context normalization nesting exceeds ceiling")
    if isinstance(schema, dict) and isinstance(value, dict):
        properties = schema.get("properties", {})
        additional = schema.get("additionalProperties", False)
        if not isinstance(properties, dict):
            raise _fail("Context normalizer properties are invalid")
        return {key: _normalize(properties[key] if key in properties else additional, item, depth + 1)
            for key, item in sorted(value.items()) if key in properties or isinstance(additional, dict)}
    if isinstance(schema, dict) and isinstance(value, list):
        return [_normalize(schema.get("items", False), item, depth + 1) for item in value]
    return value


def _redactor(document):
    redaction = _shape(document, "context-redaction-policy/v1", {"redact_keys", "patterns", "replacement"})
    keys, patterns = redaction["redact_keys"], redaction["patterns"]
    if not isinstance(keys, list) or not all(isinstance(key, str) for key in keys) or not _MIN_REDACT_KEYS <= set(keys) or not isinstance(patterns, list) or not all(isinstance(name, str) for name in patterns) or len(patterns)!=len(set(patterns)) or set(patterns) != set(_PATTERNS) or redaction["replacement"] != "[REDACTED]":
        raise _fail("Context redaction minimum policy is unavailable")
    hidden = {key.casefold() for key in keys}
    def redact(value, depth=0):
        if depth > 48:
            raise _fail("Context redaction nesting exceeds ceiling")
        if isinstance(value, dict):
            return {key: "[REDACTED]" if key.casefold() in hidden else redact(item, depth + 1) for key, item in sorted(value.items())}
        if isinstance(value, list):
            return [redact(item, depth + 1) for item in value]
        if isinstance(value, str):
            for name in sorted(patterns):
                value = _PATTERNS[name].sub("[REDACTED]", value)
        return value
    return redact


def _normalize_redact(schema, value, redact):
    value = _normalize(schema, value)
    try:
        validate_host_value(schema, value)
    except StableError as exc:
        raise _fail("Context source violates its declared normalizer schema", ErrorCode.INVALID_ARGUMENT) from exc
    return redact(value)


def _schema_redact(schema, redact):
    # Schema property names are structural declarations, not secret-bearing
    # data keys. Examples/defaults/descriptions still undergo redaction.
    if not isinstance(schema, dict):
        return schema
    result = {}
    for key, value in schema.items():
        if key in {"properties", "$defs", "definitions"} and isinstance(value, dict):
            result[key] = {name: _schema_redact(item, redact) for name, item in value.items()}
        elif key in {"items", "additionalProperties"}:
            result[key] = _schema_redact(value, redact)
        else:
            result[key] = redact(value)
    return result


def _fit_input(value, limit, policy, measure=len):
    full = canonical_json(value)
    if measure(full) <= limit:
        return full
    field = policy["truncate_field"]
    if policy["task_input_overflow"] != "TAIL_TRUNCATE" or not isinstance(value, dict) or not isinstance(value.get(field), str):
        raise _fail("Task input exceeds its Context quota and truncation is not permitted")
    text = value[field]
    lo, hi, fitted = 0, len(text), None
    while lo <= hi:
        middle = (lo + hi) // 2
        raw = canonical_json({**value, field: text[:middle]})
        if measure(raw) <= limit:
            fitted, lo = raw, middle + 1
        else:
            hi = middle - 1
    if fitted is None:
        raise _fail("Task input metadata cannot fit its Context quota")
    return fitted


def _fit_summary(value, limit, measure=len):
    value = json.loads(canonical_json(value))
    while measure(canonical_json(value)) > limit and value:
        bindings = value.get("state_bindings")
        if isinstance(bindings, dict) and bindings:
            del bindings[sorted(bindings)[-1]]
        else:
            del value[sorted(value)[-1]]
    raw = canonical_json(value)
    return raw if measure(raw) <= limit else b""


def build_projection_input(task, *, token_counter=None):
    """Compile the external policy over this exact immutable Task snapshot."""
    from .host_contract import ProjectionInput, RenderedSection
    snapshot = task.context
    if not isinstance(snapshot, ContextSnapshot):
        raise _fail("a versioned frozen Context profile is required")
    class Resources(dict):
        def __missing__(self, key):
            raise _fail("a frozen Context resource is unavailable")
    raw = Resources(snapshot.artifacts)
    profile, _ = context_profile_references(raw[snapshot.profile_artifact_id])
    policy, _ = policy_schema_references(raw[profile["policy_artifact_id"]])
    tokenizer = context_document(raw[profile["tokenizer_artifact_id"]])
    tokenizer_id = context_tokenizer_descriptor(tokenizer)
    provider = _shape(context_document(raw[profile["provider_profile_artifact_id"]]), "context-provider-profile/v1", {"provider_id", "tokenizer_id", "tokenizer_artifact_id"})
    if provider["tokenizer_id"] != tokenizer_id or provider["tokenizer_artifact_id"] != profile["tokenizer_artifact_id"] or not isinstance(provider["provider_id"], str) or not provider["provider_id"]:
        raise _fail("the Provider profile's exact tokenizer is unavailable")
    native = tokenizer_id != 'utf8-bytes/v1'
    if native and not callable(token_counter):
        raise _fail("the Root-owned native Context tokenizer is unavailable")
    count = (lambda content: measured_count(token_counter, content)) if native else len
    redact = _redactor(context_document(raw[profile["redaction_policy_artifact_id"]]))
    for section in SECTION_IDS:
        renderer = context_document(raw[profile["renderer_artifact_ids"][section]])
        expected = {"schema": "context-renderer/v2" if native else "context-renderer/v1",
            "renderer_id": "jcs-ladder-prefix-tokens/v1" if native else "jcs-ladder/v1", "section_id": section, "version": 2 if native else 1}
        if type(renderer) is not dict or type(renderer.get("version")) is not int or renderer != expected:
            raise _fail("a declared Context renderer is unavailable")
    sources = {kind: [source for source in snapshot.sources if source.kind == kind] for kind in ("constitution", "runtime", "fact")}
    if len(sources["constitution"]) != 1 or len(sources["runtime"]) != 1:
        raise _fail("Context requires exactly one frozen constitution and runtime summary")
    constitution = context_document(sources["constitution"][0].content)
    if not isinstance(constitution, dict) or constitution.get("schema") != "constitution/v1":
        raise _fail("Context constitution schema is unsupported")
    system = redact({key: constitution[key] for key in ("schema", "realm_id", "principles", "version") if key in constitution})
    input_value = _normalize_redact(context_document(raw[policy["task_input_schema_artifact_id"]]), context_document(task.input_content), redact)
    runtime_value = _normalize_redact(context_document(raw[policy["runtime_schema_artifact_id"]]), context_document(sources["runtime"][0].content), redact)
    if policy["require_facts"] and not snapshot.facts_available:
        raise _fail("Context Fact access is not authorized", ErrorCode.AUTHORITY_DENIED)
    fact_schema = context_document(raw[policy["fact_schema_artifact_id"]])
    facts = []
    for source in sources["fact"]:
        value = _normalize_redact(fact_schema, context_document(source.content), redact)
        if value.get("fact_id") != source.ref or type(value.get("causal_distance")) is not int or not 0 <= value["causal_distance"] <= 4 or type(value.get("seq")) is not int:
            raise _fail("invalid frozen Context Fact identity", ErrorCode.INTEGRITY_ERROR)
        facts.append(value)
    facts.sort(key=lambda fact: (fact["causal_distance"], -fact["seq"], fact["fact_id"]))
    surface = context_document(task.capability_surface_content)
    available = {operation["operation_id"]: operation for operation in surface["operations"]}
    operations = []
    for name in policy["selected_operation_ids"]:
        if name not in available:
            raise _fail("selected Context operation is absent from the frozen Surface", ErrorCode.AUTHORITY_DENIED)
        operation = available[name]
        item = {key: operation[key] for key in ("operation_id", "contract_version", "description", "effects", "idempotency", "retry_semantics", "required_permissions")}
        if 'resource_contract' in operation:
            item['resource_contract'] = operation['resource_contract']
        for direction in ("input", "output"):
            ref = "artifact://sha256/" + operation[direction + "_schema_hash"]
            item[direction + "_schema"] = _schema_redact(context_document(raw[ref]), redact)
        operations.append(item)
    bodies = {"system": canonical_json(system), "capability_schema": canonical_json(operations)}
    result, carry = [], 0
    for index, (section, quota) in enumerate(zip(SECTION_IDS, ladder_quotas(policy["budget_tokens"]))):
        capacity = quota + carry
        delimiter = len(SECTION_DELIMITER) if index and not native else 0
        limit = max(0, capacity - delimiter)
        if native:
            prefix = SECTION_DELIMITER.join(item.content for item in result)
            before = count(prefix)
            def measure(content):
                joined = prefix + SECTION_DELIMITER + content if index else content
                # BPE token counts need not add across section boundaries.
                # Negative increments are conservatively charged as zero.
                return max(0, count(joined) - before)
        else:
            measure = len
        if section in bodies:
            content = bodies[section]
            if measure(content) > limit:
                raise _fail("required Context section exceeds its quota")
        elif section == "task_input":
            content = _fit_input(input_value, limit, policy, measure)
        elif section == "state_summary":
            content = _fit_summary(runtime_value, limit, measure)
        else:
            selected = []
            for fact in facts:
                if measure(canonical_json([*selected, fact])) > limit:
                    break
                selected.append(fact)
            content = canonical_json(selected) if measure(canonical_json(selected)) <= limit else b""
        consumed = delimiter + measure(content)
        if consumed > capacity:
            raise _fail("Context delimiter exceeds its quota")
        carry = capacity - consumed
        result.append(RenderedSection(section, profile["renderer_artifact_ids"][section], content, count(content)))
    rendered = SECTION_DELIMITER.join(item.content for item in result)
    if len(rendered) > MAX_RENDERED_CONTEXT_BYTES or count(rendered) > policy['budget_tokens']:
        raise _fail("rendered Context exceeds its byte or token ceiling")
    refs = [source.source_ref() for source in snapshot.sources]
    refs.extend(SourceRef("artifact", ref, ref.rsplit("/", 1)[1]) for ref in raw)
    refs.extend((SourceRef("artifact", task.input_artifact_id, sha256_hex(task.input_content)),
        SourceRef("artifact", task.capability_surface_artifact_id, sha256_hex(task.capability_surface_content))))
    refs = tuple(sorted(set(refs), key=lambda ref: (ref.kind, ref.ref, ref.content_hash)))
    return ProjectionInput(profile["policy_artifact_id"], refs, tuple(result), profile["redaction_policy_artifact_id"], tokenizer["tokenizer_id"], policy["budget_tokens"])


def rendered_sections(projection):
    if projection.manifest.tokenizer_id not in ('utf8-bytes/v1', GLM53_TOKENIZER_ID):
        raise _fail('Context rendered tokenizer identity is unsupported')
    bodies = projection.rendered_content.split(SECTION_DELIMITER)
    if len(bodies) != len(projection.manifest.sections):
        raise _fail("Context rendered section framing differs from its manifest", ErrorCode.INTEGRITY_ERROR)
    result = {}
    for section, body in zip(projection.manifest.sections, bodies):
        if (section.output_artifact_id != "artifact://sha256/" + sha256_hex(body)
                or projection.manifest.tokenizer_id == 'utf8-bytes/v1' and section.token_count != len(body)):
            raise _fail("Context rendered section hash or count differs", ErrorCode.INTEGRITY_ERROR)
        result[section.section_id] = body
    return MappingProxyType(result)


def build_context_artifacts(*, input_schema, selected_operation_ids, provider_id,
                            budget_tokens=8192, input_overflow="REJECT", truncate_field="value", tokenizer_descriptor=None):
    """Author a generic v1 Context profile; caller chooses application schemas."""
    artifacts = {}
    def add(value):
        raw = canonical_json(value)
        reference = "artifact://sha256/" + sha256_hex(raw)
        artifacts[reference] = raw
        return reference
    payload_fields = {name: {"type": "string"} for name in (
        "reason_code", "old_status", "new_status", "status", "kind", "target", "capability_id", "composition_id",
        "state_revision_id", "input_artifact_id", "result_artifact_id", "value", "secret")}
    fact_schema = add({"type": "object", "required": ["schema", "fact_id", "seq", "causal_distance", "entity_id", "event_type", "payload"],
        "properties": {"schema": {"const": "context-fact/v1"}, "fact_id": {"type": "string"}, "seq": {"type": "integer"},
            "causal_distance": {"type": "integer", "minimum": 0, "maximum": 4}, "entity_id": {"type": "string"},
            "event_type": {"type": "string"}, "payload": {"type": "object", "properties": payload_fields, "additionalProperties": False}}, "additionalProperties": False})
    runtime_schema = add({"type": "object", "required": ["schema", "serving_revision", "composition_id", "state_bindings"],
        "properties": {"schema": {"const": "context-runtime-summary/v1"}, "serving_revision": {"type": "integer"},
            "composition_id": {"type": "string"}, "state_bindings": {"type": "object", "additionalProperties": {"type": "string"}}}, "additionalProperties": False})
    policy = add({"schema": "context-policy/v1", "budget_tokens": budget_tokens, "task_input_overflow": input_overflow,
        "truncate_field": truncate_field, "selected_operation_ids": sorted(selected_operation_ids),
        "task_input_schema_artifact_id": add(input_schema), "fact_schema_artifact_id": fact_schema,
        "runtime_schema_artifact_id": runtime_schema, "fact_depth": 4, "require_facts": False})
    descriptor = tokenizer_descriptor if tokenizer_descriptor is not None else {"schema": "context-tokenizer/v1", "tokenizer_id": "utf8-bytes/v1", "version": 1}
    tokenizer_id = context_tokenizer_descriptor(descriptor)
    tokenizer = add(descriptor)
    redaction = add({"schema": "context-redaction-policy/v1", "redact_keys": sorted(_MIN_REDACT_KEYS), "patterns": sorted(_PATTERNS), "replacement": "[REDACTED]"})
    native = tokenizer_id != 'utf8-bytes/v1'
    renderers = {section: add({"schema": "context-renderer/v2" if native else "context-renderer/v1",
        "renderer_id": "jcs-ladder-prefix-tokens/v1" if native else "jcs-ladder/v1", "section_id": section, "version": 2 if native else 1}) for section in SECTION_IDS}
    profile = add({"schema": "context-profile/v1", "policy_artifact_id": policy, "redaction_policy_artifact_id": redaction,
        "tokenizer_artifact_id": tokenizer, "provider_profile_artifact_id": add({"schema": "context-provider-profile/v1",
            "provider_id": provider_id, "tokenizer_id": tokenizer_id, "tokenizer_artifact_id": tokenizer}), "renderer_artifact_ids": renderers})
    policy_schema_references(artifacts[policy])
    return profile, MappingProxyType(artifacts)
