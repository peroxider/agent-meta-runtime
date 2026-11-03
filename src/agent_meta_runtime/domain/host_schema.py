"""Bounded JSON Schema subset supported by the initial in-process Host.

Unsupported assertions fail closed; the profile never silently ignores a
schema constraint. Full schema/provider profiles can add explicit support.
"""

from .canonical import canonical_json
from .errors import ErrorCode, StableError


def validate_host_value(schema, value, *, depth=0, _enum_cache=None):
    if _enum_cache is None:
        _enum_cache = {}
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
    alternatives = kind if isinstance(kind, list) else [kind]
    if kind is not None and (not alternatives or not all(isinstance(item,str) and item in kinds for item in alternatives)
            or len(set(alternatives)) != len(alternatives)):
        raise StableError(code=ErrorCode.FEATURE_UNAVAILABLE, message="operation schema type is unsupported")
    invalid = kind is not None and not any(kinds[item](value) for item in alternatives)
    encoded = canonical_json(value)
    if "enum" in schema:
        if not isinstance(schema['enum'], list):
            invalid = True
        else:
            key = (id(schema), 'enum')
            if key not in _enum_cache:
                _enum_cache[key] = {canonical_json(v) for v in schema['enum']}
            invalid |= encoded not in _enum_cache[key]
    if "const" in schema:
        key = (id(schema), 'const')
        if key not in _enum_cache:
            _enum_cache[key] = canonical_json(schema['const'])
        invalid |= encoded != _enum_cache[key]
    if isinstance(value, dict):
        properties, required, additional = schema.get("properties", {}), schema.get("required", []), schema.get("additionalProperties", True)
        if not isinstance(properties, dict) or not isinstance(required, list) or not all(isinstance(k, str) for k in required):
            raise StableError(code=ErrorCode.CONTRACT_INCOMPATIBLE, message="operation object schema is malformed")
        invalid |= bool(set(required) - set(value))
        for name, item in value.items():
            validate_host_value(properties[name] if name in properties else additional, item, depth=depth + 1, _enum_cache=_enum_cache)
    if isinstance(value, list):
        for item in value:
            validate_host_value(schema.get("items", True), item, depth=depth + 1, _enum_cache=_enum_cache)
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
