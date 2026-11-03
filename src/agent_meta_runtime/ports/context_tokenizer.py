"""Root-only exact text counter; no native object crosses the Task facade."""

from typing import Protocol


class ContextTokenizer(Protocol):
    @property
    def tokenizer_id(self) -> str: ...

    @property
    def descriptor_content(self) -> bytes: ...

    def count(self, content: bytes) -> int: ...
