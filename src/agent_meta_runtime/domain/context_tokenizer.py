"""Closed Context tokenizer identity; data never selects executable code."""

from .errors import ErrorCode, StableError

GLM53_TOKENIZER_ID = "glm-5.3-flash/text/46a050b/tokenizers-0.23.3/v1"
GLM53_VOCABULARY_SHA256 = "19e773648cb4e65de8660ea6365e10acca112d42a854923df93db4a6f333a82d"
GLM53_VOCABULARY_BYTES = 20217442
MAX_CONTEXT_TEXT_BYTES = 8 * 1024 * 1024
MAX_RENDERED_CONTEXT_BYTES = 1024 * 1024


def glm53_context_tokenizer_descriptor():
    return {"schema": "context-tokenizer/v2", "tokenizer_id": GLM53_TOKENIZER_ID,
        "model_id": "glm-5.3-flash", "algorithm": "HF_JSON_TEXT_V1", "engine_version": "0.23.3",
        "vocabulary_sha256": GLM53_VOCABULARY_SHA256, "vocabulary_bytes": GLM53_VOCABULARY_BYTES}


def context_tokenizer_descriptor(value):
    if (type(value) is dict and value == {"schema": "context-tokenizer/v1", "tokenizer_id": "utf8-bytes/v1", "version": 1}
            and type(value.get('version')) is int):
        return "utf8-bytes/v1"
    expected = glm53_context_tokenizer_descriptor()
    if type(value) is dict and value == expected and type(value.get('vocabulary_bytes')) is int:
        return GLM53_TOKENIZER_ID
    raise StableError(code=ErrorCode.FAILED_PRECONDITION, message="exact tokenizer descriptor is unavailable")


def measured_count(counter, content):
    if type(content) is not bytes or len(content) > MAX_CONTEXT_TEXT_BYTES:
        raise StableError(code=ErrorCode.FAILED_PRECONDITION, message="Context tokenizer text exceeds byte ceiling")
    try:
        content.decode('utf-8', errors='strict')
        count = counter(content)
        if type(count) is not int or not 0 <= count <= MAX_CONTEXT_TEXT_BYTES:
            raise ValueError('invalid count')
        return count
    except StableError:
        raise
    except Exception:
        raise StableError(code=ErrorCode.FAILED_PRECONDITION, message="Context tokenizer could not count text") from None
