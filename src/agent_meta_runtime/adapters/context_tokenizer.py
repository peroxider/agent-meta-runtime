"""Root-owned, pinned local native encoder. No URL/cache discovery or code load."""

from dataclasses import dataclass, field
from importlib import metadata

from ..domain.canonical import canonical_json, sha256_hex
from ..domain.context_tokenizer import (GLM53_TOKENIZER_ID, GLM53_VOCABULARY_SHA256,
    GLM53_VOCABULARY_BYTES, MAX_CONTEXT_TEXT_BYTES, glm53_context_tokenizer_descriptor)
from ..domain.errors import ErrorCode, StableError


@dataclass(frozen=True, slots=True)
class Glm53ContextTokenizer:
    _engine: object = field(repr=False, compare=False)

    @property
    def tokenizer_id(self):
        return GLM53_TOKENIZER_ID

    @property
    def descriptor_content(self):
        return canonical_json(glm53_context_tokenizer_descriptor())

    def count(self, content):
        if type(content) is not bytes or len(content) > MAX_CONTEXT_TEXT_BYTES:
            raise StableError(code=ErrorCode.FAILED_PRECONDITION, message="Context tokenizer text exceeds byte ceiling")
        try:
            return len(self._engine.encode(content.decode('utf-8'), add_special_tokens=False).ids)
        except Exception:
            raise StableError(code=ErrorCode.FAILED_PRECONDITION, message="native Context tokenizer encoding failed") from None


def load_glm53_context_tokenizer(raw):
    if (type(raw) is not bytes or len(raw) != GLM53_VOCABULARY_BYTES
            or sha256_hex(raw) != GLM53_VOCABULARY_SHA256):
        raise StableError(code=ErrorCode.INTEGRITY_ERROR, message="native Context tokenizer data differs from pinned identity")
    try:
        if metadata.version('tokenizers') != '0.23.3':
            raise ValueError('unavailable engine version')
        from tokenizers import Tokenizer
        engine = Tokenizer.from_str(raw.decode('utf-8'))
        if engine.padding is not None or engine.truncation is not None:
            raise ValueError('padding/truncation not permitted')
    except Exception:
        raise StableError(code=ErrorCode.FAILED_PRECONDITION, message="pinned native Context tokenizer engine is unavailable") from None
    return Glm53ContextTokenizer(engine)
