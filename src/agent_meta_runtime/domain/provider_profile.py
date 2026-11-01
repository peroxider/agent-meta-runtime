"""Frozen Provider profile/price inputs and independent bounded wire usage.

Artifact data never selects Python code. The only current local tokenizer is
an explicitly controlled-test algorithm; real model tokenizer availability must
be established separately and cannot be inferred from a profile declaration.
"""

from dataclasses import dataclass
import json
import re

from .canonical import canonical_json, sha256_hex
from .errors import ErrorCode, StableError
from .harness import is_artifact_id
from .provider_accounting import amount
from .provider_transport import ProviderEgressPolicy, MAX_PROVIDER_BYTES

PARAMETERS = frozenset({"model", "messages", "max_tokens", "stream", "system", "tools", "tool_choice", "temperature", "top_p", "stop_sequences"})
REQUIRED_PARAMETERS = frozenset({"model", "messages", "max_tokens", "stream"})
_PROVIDER_HANDLE = re.compile(r"credential://(?:windows-dpapi|insecure-dev)/[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")


def valid_provider_handle(value):
    return isinstance(value,str) and _PROVIDER_HANDLE.fullmatch(value) is not None


def _text_blocks(value):
    return isinstance(value,str) or isinstance(value,list) and all(isinstance(block,dict)
        and set(block)=={'type','text'} and block['type']=='text' and isinstance(block['text'],str) for block in value)


def _message_content(value,role):
    if isinstance(value,str):
        return True
    if not isinstance(value,list):
        return False
    for block in value:
        if not isinstance(block,dict):
            return False
        kind=block.get('type')
        if kind=='text':
            if not _text_blocks([block]):
                return False
        elif kind=='tool_use' and role=='assistant':
            if (set(block)!={'type','id','name','input'} or not isinstance(block['input'],dict)
                    or any(not isinstance(block[key],str) or not 0<len(block[key])<=128 for key in ('id','name'))):
                return False
        elif kind=='tool_result' and role=='user':
            if (not {'type','tool_use_id','content'}<=set(block) or set(block)-{'type','tool_use_id','content','is_error'}
                    or not isinstance(block['tool_use_id'],str) or not 0<len(block['tool_use_id'])<=128
                    or not _text_blocks(block['content']) or 'is_error' in block and type(block['is_error']) is not bool):
                return False
        else:
            return False
    return True


def _messages_profile(value):
    if ('system' in value and not _text_blocks(value['system'])
            or any(not isinstance(message,dict) or set(message)!={'role','content'} or message['role'] not in ('user','assistant')
                or not _message_content(message['content'],message['role']) for message in value['messages'])):
        raise _fail('Provider messages require unsupported content/billing semantics',ErrorCode.FAILED_PRECONDITION)
    if 'tools' in value:
        tools=value['tools']
        if (not isinstance(tools,list) or len(tools)>64 or any(not isinstance(tool,dict)
                or not {'name','input_schema'}<=set(tool) or set(tool)-{'name','description','input_schema'}
                or not isinstance(tool['name'],str) or re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}',tool['name']) is None
                or not isinstance(tool['input_schema'],dict) or 'description' in tool and not isinstance(tool['description'],str) for tool in tools)):
            raise _fail('Provider tools require unsupported server-tool billing semantics',ErrorCode.FAILED_PRECONDITION)
    if 'tool_choice' in value:
        choice=value['tool_choice']
        if (not isinstance(choice,dict) or 'type' not in choice or set(choice)-{'type','name','disable_parallel_tool_use'}
                or choice['type'] not in ('auto','none','any','tool') or (choice['type']=='tool')!=('name' in choice)
                or 'name' in choice and not isinstance(choice['name'],str)
                or 'disable_parallel_tool_use' in choice and type(choice['disable_parallel_tool_use']) is not bool):
            raise _fail('Provider tool choice is outside the frozen profile')


def _fail(message, code=ErrorCode.INVALID_ARGUMENT):
    return StableError(code=code, message=message)


def document(raw, *, canonical=True):
    def nonfinite(_):
        raise ValueError("nonfinite number")
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("duplicate field")
            value[key] = item
        return value
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_PROVIDER_BYTES:
            raise ValueError("document size")
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite)
        if not isinstance(value, dict) or canonical and canonical_json(value) != raw:
            raise ValueError("document shape")
        pending, nodes = [(value, 0)], 0
        while pending:
            item, depth = pending.pop()
            nodes += 1
            if depth > 32 or nodes > 16384:
                raise ValueError("document complexity")
            if isinstance(item, dict):
                pending.extend((child, depth+1) for child in item.values())
            elif isinstance(item, list):
                pending.extend((child, depth+1) for child in item)
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise _fail("invalid bounded Provider document") from None


@dataclass(frozen=True, slots=True)
class ProviderPricing:
    currency: str
    pricing_version: str
    input_microunits_per_million_tokens: int
    output_microunits_per_million_tokens: int
    minimum_cost_microunits: int

    def __post_init__(self):
        if (not isinstance(self.currency,str) or re.fullmatch(r"[A-Z]{3,8}",self.currency) is None
                or not isinstance(self.pricing_version,str) or re.fullmatch(r"[A-Za-z0-9._:-]{1,128}",self.pricing_version) is None
                or any(not amount(value) for value in (self.input_microunits_per_million_tokens,
                    self.output_microunits_per_million_tokens,self.minimum_cost_microunits))):
            raise _fail("invalid frozen Provider price amounts")

    @classmethod
    def parse(cls, raw):
        value = document(raw)
        fields = {"schema", "currency", "pricing_version", "input_microunits_per_million_tokens", "output_microunits_per_million_tokens", "minimum_cost_microunits", "rounding"}
        if (set(value) != fields or value["schema"] != "provider-price/v1"
                or value["rounding"] != "CEIL_EACH_DIMENSION_MICROUNIT"
                or not isinstance(value["currency"], str) or re.fullmatch(r"[A-Z]{3,8}", value["currency"]) is None
                or not isinstance(value["pricing_version"], str) or re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", value["pricing_version"]) is None
                or any(not amount(value[key]) for key in ("input_microunits_per_million_tokens", "output_microunits_per_million_tokens", "minimum_cost_microunits"))):
            raise _fail("invalid frozen Provider price policy")
        return cls(**{key: value[key] for key in fields-{"schema", "rounding"}})

    def cost(self, input_tokens, output_tokens):
        if any(value is not None and not amount(value) for value in (input_tokens,output_tokens)):
            raise _fail("invalid Provider token usage", ErrorCode.INVALID_RESULT)
        if input_tokens is None or output_tokens is None:
            return None
        total = max(self.minimum_cost_microunits,
            (input_tokens*self.input_microunits_per_million_tokens+999999)//1000000
            + (output_tokens*self.output_microunits_per_million_tokens+999999)//1000000)
        if not amount(total):
            raise _fail("Provider cost exceeds accounting range", ErrorCode.RESOURCE_EXHAUSTED)
        return total


@dataclass(frozen=True, slots=True)
class ProviderProfile:
    artifact_id: str
    model_id: str
    parameter_allowlist: tuple[str, ...]
    context_window_tokens: int
    maximum_output_tokens: int
    maximum_request_bytes: int
    maximum_response_bytes: int
    timeout_us: int
    egress_policy_artifact_id: str
    tokenizer_artifact_id: str | None
    price_policy_artifact_id: str | None
    policy: ProviderEgressPolicy
    pricing: ProviderPricing | None
    tokenizer_algorithm: str | None
    tokenizer_id: str | None

    def count_input(self, body):
        if self.tokenizer_artifact_id is None or self.tokenizer_algorithm is None:
            raise _fail("exact Provider tokenizer is unavailable", ErrorCode.FAILED_PRECONDITION)
        if self.policy.profile != "CONTROLLED_TEST_ONLY" or self.tokenizer_algorithm != "CONTROLLED_TEST_UTF8_BYTES_V1" or self.tokenizer_id != "utf8-bytes/v1":
            raise _fail("exact Provider tokenizer implementation is unavailable", ErrorCode.FAILED_PRECONDITION)
        value = document(body)
        return len(canonical_json({key: value[key] for key in ("messages", "system", "tools", "tool_choice") if key in value}))

    def preflight(self, plan):
        if plan.profile_artifact_id != self.artifact_id:
            raise _fail("Provider plan profile differs from approved binding", ErrorCode.AUTHORITY_DENIED)
        value = document(plan.body)
        if (not REQUIRED_PARAMETERS <= set(value) or set(value)-set(self.parameter_allowlist)
                or value["model"] != self.model_id or value["stream"] is not False
                or type(value["max_tokens"]) is not int or not 0 < value["max_tokens"] <= self.maximum_output_tokens
                or not isinstance(value["messages"],list) or not 1 <= len(value["messages"]) <= 256
                or len(plan.body) > self.maximum_request_bytes):
            raise _fail("Provider request differs from frozen profile")
        _messages_profile(value)
        # This profile has no cache/reasoning/server-tool billing semantics.
        pending = [value]
        while pending:
            item = pending.pop()
            if isinstance(item, dict):
                if set(item) & {"cache_control", "thinking", "server_tool"}:
                    raise _fail("Provider request requires unsupported billing semantics", ErrorCode.FAILED_PRECONDITION)
                pending.extend(item.values())
            elif isinstance(item, list):
                pending.extend(item)
        tokens = self.count_input(plan.body)
        if tokens + value["max_tokens"] > self.context_window_tokens:
            raise _fail("Provider context window exhausted", ErrorCode.RESOURCE_EXHAUSTED)
        if self.pricing is None:
            raise _fail("firm maximum Provider cost is unavailable", ErrorCode.FAILED_PRECONDITION)
        return tokens, value["max_tokens"], self.pricing.cost(tokens, value["max_tokens"])

    def usage(self, raw):
        try:
            value = document(raw, canonical=False)
            if (value.get("model") != self.model_id
                    or set(value)-{'id','type','role','model','content','stop_reason','stop_sequence','usage'}
                    or 'content' in value and (not isinstance(value['content'],list)
                        or any(not isinstance(block,dict) or block.get('type') not in ('text','tool_use') for block in value['content']))):
                raise ValueError("response model")
            usage = value.get("usage")
            if usage is None:
                usage = {}
            fields = {"input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens"}
            if not isinstance(usage, dict) or set(usage)-fields:
                raise ValueError("usage dimensions")
            for key in ("cache_creation_input_tokens", "cache_read_input_tokens"):
                if key in usage and (type(usage[key]) is not int or usage[key] != 0):
                    raise ValueError("unsupported cache usage")
            counts = {key: usage.get(key) for key in ("input_tokens", "output_tokens")}
            if any(value is not None and not amount(value) for value in counts.values()):
                raise ValueError("usage amounts")
            return {**counts, "cost_microunits": self.pricing.cost(**counts) if self.pricing is not None else None}
        except (ValueError, TypeError, StableError):
            raise _fail("Provider response usage cannot be verified", ErrorCode.INVALID_RESULT) from None


def load_profile(reference, read_artifact):
    """Read only content-addressed data; return the complete verified closure."""
    contents = {}
    def read(ref):
        if not is_artifact_id(ref):
            raise _fail("invalid Provider profile Artifact reference")
        if ref not in contents:
            try:
                raw = read_artifact(ref)
            except StableError as exc:
                code=exc.code if exc.code in (ErrorCode.INTEGRITY_ERROR,ErrorCode.DATA_LOSS) else ErrorCode.FAILED_PRECONDITION
                raise _fail("Provider profile Artifact could not be verified",code) from None
            except (LookupError,OSError):
                raise _fail("Provider profile Artifact is unavailable",ErrorCode.FAILED_PRECONDITION) from None
            if type(raw) is not bytes or sha256_hex(raw) != ref.rsplit('/',1)[1]:
                raise _fail("Provider profile Artifact hash differs", ErrorCode.INTEGRITY_ERROR)
            contents[ref] = raw
        return contents[ref]
    value = document(read(reference))
    fields = {"schema", "protocol", "model_id", "parameter_allowlist", "context_window_tokens", "maximum_output_tokens",
        "maximum_request_bytes", "maximum_response_bytes", "timeout_us", "egress_policy_artifact_id",
        "tokenizer_artifact_id", "price_policy_artifact_id", "lookup_policy", "usage_mapping"}
    if (set(value) != fields or value["schema"] != "provider-profile/v1"
            or value["protocol"] != "anthropic-messages-terminal/v1" or value["usage_mapping"] != "anthropic-messages-usage/v1"
            or value["lookup_policy"] != "UNAVAILABLE_NO_RETRY"
            or not isinstance(value["model_id"], str) or re.fullmatch(r"[A-Za-z0-9_.:-]{1,200}", value["model_id"]) is None
            or not isinstance(value["parameter_allowlist"], list) or not all(isinstance(key,str) for key in value["parameter_allowlist"])
            or value["parameter_allowlist"] != sorted(set(value["parameter_allowlist"]))
            or not REQUIRED_PARAMETERS <= set(value["parameter_allowlist"]) <= PARAMETERS
            or any(not amount(value[key]) or value[key] == 0 for key in (
                "context_window_tokens", "maximum_output_tokens", "maximum_request_bytes", "maximum_response_bytes", "timeout_us"))
            or value["maximum_output_tokens"] > min(value["context_window_tokens"],2**31-1)
            or max(value["maximum_request_bytes"],value["maximum_response_bytes"]) > MAX_PROVIDER_BYTES
            or value["timeout_us"] > 300_000_000):
        raise _fail("invalid frozen Provider profile")
    policy = document(read(value["egress_policy_artifact_id"]))
    if set(policy) != {"schema", "scheme", "host", "port", "path", "networks", "profile"} or policy["schema"] != "provider-egress/v1" or policy["scheme"] != "https":
        raise _fail("invalid Provider egress policy")
    policy = ProviderEgressPolicy(**{key: policy[key] for key in policy if key not in ("schema","scheme")})
    pricing = ProviderPricing.parse(read(value["price_policy_artifact_id"])) if value["price_policy_artifact_id"] is not None else None
    tokenizer = document(read(value["tokenizer_artifact_id"])) if value["tokenizer_artifact_id"] is not None else None
    if tokenizer is not None and (set(tokenizer) != {"schema","model_id","algorithm","tokenizer_id"}
            or tokenizer["schema"] != "provider-tokenizer/v1" or tokenizer["model_id"] != value["model_id"]
            or any(not isinstance(tokenizer[key],str) or re.fullmatch(r"[A-Za-z0-9._:/-]{1,128}",tokenizer[key]) is None for key in ("algorithm","tokenizer_id"))):
        raise _fail("invalid Provider tokenizer descriptor")
    keys = fields - {"schema", "protocol", "lookup_policy", "usage_mapping"}
    data = {key:value[key] for key in keys}
    data["parameter_allowlist"] = tuple(data["parameter_allowlist"])
    profile = ProviderProfile(reference,**data,policy=policy,pricing=pricing,
        tokenizer_algorithm=tokenizer["algorithm"] if tokenizer else None,tokenizer_id=tokenizer["tokenizer_id"] if tokenizer else None)
    return profile, tuple(sorted(contents))
