"""Bounded JSON Schema subset supported by the initial in-process Host.

Unsupported assertions fail closed; the profile never silently ignores a
schema constraint. Full schema/provider profiles can add explicit support.
"""

from .canonical import canonical_json
from .errors import ErrorCode, StableError


def validate_host_value(schema, value, *, depth=0):
    if depth > 48:
        raise StableError(code=ErrorCode.RESOURCE_EXHAUSTED, message="Host schema nesting exceeds ceiling")
    if type(schema) is bool:
        if not schema:
            raise StableError(code=ErrorCode.INVALID_RESULT, message="Host value is rejected by schema")
        return
    supported = {"type", "properties", "required", "additionalProperties", "items", "enum", "const",
        "minItems", "maxItems", "minLength", "maxLength", "minimum", "maximum", "title", "description", "$schema"}
    if not isinstance(schema, dict) or set(schema) - supported:
        raise StableError(code=ErrorCode.FEATURE_UNAVAILABLE, message="operation requires an unsupported schema assertion")
    kinds = {"object": lambda v: isinstance(v, dict), "array": lambda v: isinstance(v, list),
        "string": lambda v: isinstance(v, str), "integer": lambda v: type(v) is int,
        "number": lambda v: type(v) in (int, float), "boolean": lambda v: type(v) is bool, "null": lambda v: v is None}
    kind = schema.get("type")
    if kind is not None and (not isinstance(kind, str) or kind not in kinds):
        raise StableError(code=ErrorCode.FEATURE_UNAVAILABLE, message="operation schema type is unsupported")
    invalid = kind is not None and not kinds[kind](value)
    encoded = canonical_json(value)
    if "enum" in schema:
        invalid |= not isinstance(schema["enum"], list) or encoded not in [canonical_json(v) for v in schema["enum"]]
    if "const" in schema:
        invalid |= encoded != canonical_json(schema["const"])
    if isinstance(value, dict):
        properties, required, additional = schema.get("properties", {}), schema.get("required", []), schema.get("additionalProperties", True)
        if not isinstance(properties, dict) or not isinstance(required, list) or not all(isinstance(k, str) for k in required):
            raise StableError(code=ErrorCode.CONTRACT_INCOMPATIBLE, message="operation object schema is malformed")
        invalid |= bool(set(required) - set(value))
        for name, item in value.items():
            validate_host_value(properties[name] if name in properties else additional, item, depth=depth + 1)
    if isinstance(value, list):
        for item in value:
            validate_host_value(schema.get("items", True), item, depth=depth + 1)
    for lower, upper, measured in (("minItems", "maxItems", len(value) if isinstance(value, list) else None),
        ("minLength", "maxLength", len(value) if isinstance(value, str) else None),
        ("minimum", "maximum", value if type(value) in (int, float) else None)):
        for key, compare in ((lower, lambda a, b: a < b), (upper, lambda a, b: a > b)):
            if key in schema:
                bound = schema[key]
                if type(bound) not in (int, float):
                    raise StableError(code=ErrorCode.CONTRACT_INCOMPATIBLE, message="operation bound is malformed")
                if measured is not None:
                    invalid |= compare(measured, bound)
    if invalid:
        raise StableError(code=ErrorCode.INVALID_RESULT, message="Host value violates operation schema")
