"""Source-only Scratch candidate construction; no imports or heap serialization.

Root must authorize/retrieve the explicit inputs and journal the resulting
Artifacts. Building this private candidate grants no serving or execution right.
"""

from __future__ import annotations

import ast
import builtins
from dataclasses import dataclass, field
import keyword
import re
import symtable
import sys
import warnings

from .ampak import PackageMeta, build_manifest, encode_package
from .canonical import canonical_json, sha256_hex
from .context_contract import context_document
from .compatibility import EFFECT_REGISTRY, parse_semver_range
from .authority import PERMISSIONS
from .errors import ErrorCode, StableError
from .harness import is_artifact_id
from .harness_source import audit_harness_sources
from .scratch_export_lock import validate_export_lock
from .resource_contract import validate_resource_operation

MAX_SOURCE_BYTES = 1024 * 1024
MAX_TOTAL_SOURCE_BYTES = 4 * MAX_SOURCE_BYTES
MAX_AST_NODES = 50_000
SOURCE_MEDIA_TYPE = "text/x-python; canonical=lf-utf8-v1"
MODULE_NAME = "scratch_candidate"
_BUILTINS = frozenset(vars(builtins))
_DYNAMIC_GLOBALS = frozenset(
    {
        "__import__",
        "__builtins__",
        "eval",
        "exec",
        "compile",
        "globals",
        "locals",
        "vars",
    }
)
_DEFINITIONS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
_ANALYZER_ABI = (sys.implementation.name, sys.version_info[:2])


def _fail(reason, *, code=ErrorCode.INVALID_ARGUMENT, **details):
    bounded = {}
    truncated = False
    for key, value in details.items():
        if type(value) is str:
            bounded[key] = value[:256]
            truncated = truncated or len(value) > 256
        elif type(value) is list:
            bounded[key] = [item[:128] for item in value[:100]]
            truncated = (
                truncated
                or len(value) > 100
                or any(len(item) > 128 for item in value[:100])
            )
    if truncated:
        bounded["diagnostic_truncated"] = True
    raise StableError(
        code=code,
        message="Scratch source export was refused",
        details={"reason_code": reason, **bounded},
    ) from None


def canonical_scratch_source(text: str) -> bytes:
    if type(text) is not str:
        _fail("SOURCE_ENCODING")
    if len(text) > MAX_SOURCE_BYTES:
        _fail("SOURCE_SIZE", code=ErrorCode.RESOURCE_EXHAUSTED)
    try:
        raw = text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")
    except UnicodeError:
        _fail("SOURCE_ENCODING")
    if raw.startswith(b"\xef\xbb\xbf") or b"\0" in raw:
        _fail("SOURCE_ENCODING")
    if len(raw) > MAX_SOURCE_BYTES:
        _fail("SOURCE_SIZE", code=ErrorCode.RESOURCE_EXHAUSTED)
    return raw


@dataclass(frozen=True, slots=True)
class ExportArtifact:
    artifact_id: str
    content: bytes

    def __post_init__(self):
        if type(self.content) is not bytes or len(self.content) > 32 * MAX_SOURCE_BYTES:
            raise ValueError("export Artifact exceeds its byte ceiling")
        if (
            type(self.content) is not bytes
            or type(self.artifact_id) is not str
            or not is_artifact_id(self.artifact_id)
        ):
            raise ValueError("export input requires immutable Artifact bytes")
        if self.artifact_id != "artifact://sha256/" + sha256_hex(self.content):
            raise ValueError("export input differs from its Artifact identity")

    @classmethod
    def from_bytes(cls, content):
        return cls("artifact://sha256/" + sha256_hex(content), content)


@dataclass(frozen=True, slots=True)
class ScratchSource(ExportArtifact):
    def __post_init__(self):
        if type(self.content) is not bytes or len(self.content) > MAX_SOURCE_BYTES:
            raise ValueError("cell source exceeds its byte ceiling")
        ExportArtifact.__post_init__(self)
        try:
            if canonical_scratch_source(self.content.decode("utf-8")) != self.content:
                raise ValueError("cell source is not canonical LF UTF-8")
        except (UnicodeError, StableError) as error:
            raise ValueError("invalid cell source Artifact") from error

    @classmethod
    def from_text(cls, text):
        return cls.from_bytes(canonical_scratch_source(text))


@dataclass(frozen=True, slots=True)
class ScratchExport:
    package: ExportArtifact
    provenance: ExportArtifact
    inputs: tuple[ExportArtifact, ...]
    trust_class: str = field(init=False, default="trusted_candidate")


def _document(artifact):
    if type(artifact) is not ExportArtifact or len(artifact.content) > MAX_SOURCE_BYTES:
        _fail("INVALID_ARTIFACT")
    try:
        value = context_document(artifact.content)
        if type(value) is not dict or canonical_json(value) != artifact.content:
            raise ValueError("noncanonical document")
        return value
    except (StableError, ValueError, TypeError):
        _fail("INVALID_ARTIFACT")


def _contract(artifact):
    value = _document(artifact)
    fields = {
        "schema",
        "capability_id",
        "contract_version",
        "operations",
        "requires",
        "provides",
        "state",
        "execution_requirements",
        "runtime_constraints",
    }
    if set(value) != fields or value["schema"] != "capability-contract/v1":
        _fail("INVALID_CONTRACT")
    if (
        type(value["capability_id"]) is not str
        or not re.fullmatch(
            r"capability://[a-z][a-z0-9._-]{0,127}", value["capability_id"]
        )
        or type(value["contract_version"]) is not str
        or len(value["contract_version"]) > 128
    ):
        _fail("INVALID_CONTRACT")
    try:
        parse_semver_range("==" + value["contract_version"])
    except ValueError:
        _fail("INVALID_CONTRACT")
    if (
        type(value["operations"]) is not list
        or not 1 <= len(value["operations"]) <= 100
    ):
        _fail("INVALID_CONTRACT")
    operation_ids = set()
    for operation in value["operations"]:
        required = {
            "operation_id",
            "input_schema_artifact_id",
            "output_schema_artifact_id",
            "idempotency",
            "retry_semantics",
            "effects",
            "required_permissions",
        }
        if (
            type(operation) is not dict
            or not required <= set(operation)
            or set(operation) - required - {"resource_contract"}
        ):
            _fail("INVALID_CONTRACT")
        identity = operation["operation_id"]
        if (
            type(identity) is not str
            or not 1 <= len(identity) <= 128
            or identity in operation_ids
        ):
            _fail("INVALID_CONTRACT")
        operation_ids.add(identity)
        if (
            not all(
                is_artifact_id(operation[key])
                for key in ("input_schema_artifact_id", "output_schema_artifact_id")
            )
            or operation["idempotency"] not in ("PURE", "KEYED", "NONE")
            or operation["retry_semantics"] not in ("NEVER", "SAME_KEY_TRANSIENT")
            or any(
                type(operation[key]) is not list
                or not all(type(item) is str for item in operation[key])
                for key in ("effects", "required_permissions")
            )
        ):
            _fail("INVALID_CONTRACT")
        effects, permissions = operation["effects"], operation["required_permissions"]
        if (
            not effects
            or len(effects) > 32
            or len(permissions) > 64
            or len(effects) != len(set(effects))
            or len(permissions) != len(set(permissions))
            or not set(effects) <= EFFECT_REGISTRY
            or not set(permissions) <= PERMISSIONS
            or operation["idempotency"] == "PURE"
            and not set(effects) <= {"none", "state.read"}
            or operation["idempotency"] == "NONE"
            and operation["retry_semantics"] != "NEVER"
        ):
            _fail("INVALID_CONTRACT")
        try:
            validate_resource_operation(operation)
        except ValueError:
            _fail("INVALID_CONTRACT")
    if (
        type(value["requires"]) is not list
        or type(value["provides"]) is not list
        or any(
            type(value[key]) is not dict
            for key in ("state", "execution_requirements", "runtime_constraints")
        )
    ):
        _fail("INVALID_CONTRACT")
    for key, version_key in (("requires", "version_range"), ("provides", "version")):
        interfaces = set()
        if len(value[key]) > 100:
            _fail("INVALID_CONTRACT")
        for interface in value[key]:
            if (
                type(interface) is not dict
                or set(interface) != {"interface_id", version_key}
                or type(interface["interface_id"]) is not str
                or not 1 <= len(interface["interface_id"]) <= 128
                or interface["interface_id"] in interfaces
                or type(interface[version_key]) is not str
                or len(interface[version_key]) > 256
            ):
                _fail("INVALID_CONTRACT")
            interfaces.add(interface["interface_id"])
            try:
                parse_semver_range(
                    interface[version_key]
                    if key == "requires"
                    else "==" + interface[version_key]
                )
            except ValueError:
                _fail("INVALID_CONTRACT")
    state = value["state"]
    if set(state) - {"schema_artifact_id", "migration_artifact_ids"}:
        _fail("INVALID_CONTRACT")
    schema = state.get("schema_artifact_id")
    migrations = state.get("migration_artifact_ids", [])
    if (
        schema is not None
        and not is_artifact_id(schema)
        or type(migrations) is not list
        or not all(is_artifact_id(ref) for ref in migrations)
    ):
        _fail("INVALID_CONTRACT")
    return value


def _identifier(value):
    return (
        type(value) is str
        and len(value) <= 128
        and value.isidentifier()
        and not keyword.iskeyword(value)
    )


def _parse(source):
    try:
        with warnings.catch_warnings(record=True):
            tree = ast.parse(
                source, filename="<scratch-source>", feature_version=(3, 12)
            )
        count = sum(1 for _ in ast.walk(tree))
        if count > MAX_AST_NODES:
            _fail("SOURCE_COMPLEXITY", code=ErrorCode.RESOURCE_EXHAUSTED)
        return tree, count
    except (SyntaxError, ValueError, UnicodeError, RecursionError):
        _fail("SOURCE_SYNTAX")


def _segment(text, node):
    # get_source_segment honors UTF-8 column offsets and excludes another
    # statement after a semicolon. Decorators belong to the selected source.
    span = ast.copy_location(ast.Pass(), node)
    if isinstance(node, _DEFINITIONS) and node.decorator_list:
        # The expression may start after one or several opening parentheses,
        # even on another line. Its AST column is not the @ token's position.
        lines = text.splitlines(keepends=True)
        for index in range(node.decorator_list[0].lineno - 1, -1, -1):
            if (
                lines[index][node.col_offset : node.col_offset + 1] == "@"
                and not lines[index][: node.col_offset].strip()
            ):
                span.lineno, span.col_offset = index + 1, node.col_offset
                break
        else:
            _fail("SOURCE_SEGMENT")
    result = ast.get_source_segment(text, span)
    if result is None:
        _fail("SOURCE_SEGMENT")
    return result, span


def _symbols(source):
    """Analyze lexical scopes without PEP 709's inlined-comprehension flags.

    Generator expressions retain the same binding scope but are not inlined.
    This transformation is analysis-only; package files keep original source.
    """
    if _ANALYZER_ABI != ("cpython", (3, 12)):
        _fail("ANALYZER_UNAVAILABLE", code=ErrorCode.FEATURE_UNAVAILABLE)

    class ComprehensionScopes(ast.NodeTransformer):
        def visit_ListComp(self, node):
            self.generic_visit(node)
            return ast.copy_location(
                ast.GeneratorExp(elt=node.elt, generators=node.generators), node
            )

        visit_SetComp = visit_ListComp

        def visit_DictComp(self, node):
            self.generic_visit(node)
            return ast.copy_location(
                ast.GeneratorExp(
                    elt=ast.Tuple(elts=[node.key, node.value], ctx=ast.Load()),
                    generators=node.generators,
                ),
                node,
            )

    try:
        with warnings.catch_warnings(record=True):
            tree = ComprehensionScopes().visit(
                ast.parse(source, feature_version=(3, 12))
            )
            normalized = ast.unparse(ast.fix_missing_locations(tree))
            return symtable.symtable(normalized, "<scratch-source>", "exec")
    except (SyntaxError, ValueError, UnicodeError, RecursionError):
        _fail("SOURCE_SYNTAX")


def _module_writes(source):
    try:
        table = _symbols(source)
        return {
            symbol.get_name()
            for symbol in table.get_symbols()
            if symbol.is_assigned() or symbol.is_imported() or symbol.is_namespace()
        }
    except (SyntaxError, ValueError, RecursionError):
        _fail("SOURCE_SYNTAX")


def _imports(node, allowed):
    result = set()
    for current in ast.walk(node):
        if isinstance(current, ast.Import):
            modules = [alias.name for alias in current.names]
        elif isinstance(current, ast.ImportFrom):
            if current.level or any(alias.name == "*" for alias in current.names):
                _fail("OPAQUE_DEPENDENCY")
            modules = [current.module or ""]
        else:
            continue
        for module in modules:
            if module.split(".")[0] not in allowed:
                _fail("OPAQUE_DEPENDENCY", unlocked_import=module)
            result.add(module)
    return result


def _free_globals(source):
    try:
        root = _symbols(source)
        globals_used = set()
        pending = [root]
        while pending:
            table = pending.pop()
            for symbol in table.get_symbols():
                if symbol.is_referenced() and (table is root or symbol.is_global()):
                    globals_used.add(symbol.get_name())
            pending.extend(table.get_children())
        return globals_used
    except (SyntaxError, ValueError, RecursionError):
        _fail("SOURCE_SYNTAX")


def build_scratch_export(
    *,
    sources,
    export_names,
    contract,
    dependency_lock,
    entrypoint,
    dependency_artifacts=(),
    name="scratch-candidate",
    version="0.1.0",
):
    """Construct deterministic AMPAK1 bytes solely from explicit Artifact bytes.

    Source order is semantic. Selections are unique top-level definitions;
    other module statements are not copied. Dependencies are checked against
    actual wheel inputs, never the live kernel namespace or installed modules.
    """
    if (
        type(name) is not str
        or not 1 <= len(name) <= 128
        or type(version) is not str
        or not 1 <= len(version) <= 128
    ):
        _fail("INVALID_PACKAGE")
    try:
        parse_semver_range("==" + version)
    except ValueError:
        _fail("INVALID_PACKAGE")
    if (
        type(sources) is not tuple
        or not 1 <= len(sources) <= 64
        or any(type(source) is not ScratchSource for source in sources)
        or len({source.artifact_id for source in sources}) != len(sources)
    ):
        _fail("INVALID_SOURCES")
    if sum(len(source.content) for source in sources) > MAX_TOTAL_SOURCE_BYTES:
        _fail("SOURCE_SIZE", code=ErrorCode.RESOURCE_EXHAUSTED)
    if (
        type(export_names) is not tuple
        or not 1 <= len(export_names) <= 100
        or not all(_identifier(item) for item in export_names)
        or len(set(export_names)) != len(export_names)
    ):
        _fail("INVALID_SELECTION")
    if (
        type(entrypoint) is not str
        or entrypoint != MODULE_NAME + ":" + entrypoint.split(":")[-1]
        or entrypoint.split(":")[-1] not in export_names
    ):
        _fail("INVALID_ENTRYPOINT")
    selected = set(export_names)
    capability_contract = _contract(contract)
    lock = _document(dependency_lock)
    if type(dependency_artifacts) is not tuple or any(
        type(artifact) is not ExportArtifact for artifact in dependency_artifacts
    ):
        _fail("INVALID_DEPENDENCY_INPUTS")
    allowed = validate_export_lock(
        lock,
        tuple(
            (artifact.artifact_id, artifact.content)
            for artifact in dependency_artifacts
        ),
    )
    definitions, parsed, writes = {}, [], set()
    remaining = MAX_AST_NODES
    for source in sources:
        text = source.content.decode("utf-8")
        tree, count = _parse(text)
        remaining -= count
        if remaining < 0:
            _fail("SOURCE_COMPLEXITY", code=ErrorCode.RESOURCE_EXHAUSTED)
        writes.update(_module_writes(text))
        for node in tree.body:
            if isinstance(node, _DEFINITIONS) and node.name in selected:
                if node.name in definitions:
                    _fail("SELECTION_AMBIGUOUS", name=node.name)
                definitions[node.name] = node
        parsed.append((source, text, tree))
    if set(definitions) != selected:
        _fail("SELECTION_MISSING", names=sorted(selected - set(definitions)))
    pieces, origins, imports, module_imports = [], [], set(), set()
    for source, text, tree in parsed:
        for node in tree.body:
            chosen = isinstance(node, _DEFINITIONS) and node.name in selected
            if not chosen and not isinstance(node, (ast.Import, ast.ImportFrom)):
                continue
            if chosen and any(
                isinstance(child, ast.Lambda) for child in ast.walk(node)
            ):
                _fail("OPAQUE_DEPENDENCY", dependency_kind="lambda")
            imports.update(_imports(node, allowed))
            if not chosen:
                aliases = {
                    alias.asname
                    or (
                        alias.name.split(".")[0]
                        if isinstance(node, ast.Import)
                        else alias.name
                    )
                    for alias in node.names
                }
                if aliases & selected:
                    _fail("SELECTION_AMBIGUOUS", names=sorted(aliases & selected))
                module_imports.update(aliases)
            piece, span = _segment(text, node)
            pieces.append(piece)
            if chosen:
                origins.append(
                    {
                        "name": node.name,
                        "source_artifact_id": source.artifact_id,
                        "first_line": span.lineno,
                        "first_column": span.col_offset,
                        "last_line": span.end_lineno,
                        "last_column": span.end_col_offset,
                    }
                )
    generated = "\n\n".join(pieces) + "\n"
    if len(generated.encode("utf-8")) > MAX_SOURCE_BYTES:
        _fail("SOURCE_SIZE", code=ErrorCode.RESOURCE_EXHAUSTED)
    try:
        with warnings.catch_warnings(record=True):
            compile(
                generated, "<scratch-export>", "exec", dont_inherit=True, optimize=0
            )
    except (SyntaxError, ValueError, UnicodeError, RecursionError):
        _fail("SOURCE_SYNTAX")
    used = _free_globals(generated)
    hidden = (used & writes) - selected - module_imports
    free = used - selected - module_imports - _BUILTINS
    dynamic = (used - selected - module_imports) & _DYNAMIC_GLOBALS
    if hidden or free or dynamic:
        _fail("OPAQUE_DEPENDENCY", free_variables=sorted(hidden | free | dynamic))
    issues = audit_harness_sources(
        {MODULE_NAME + ".py": generated.encode("utf-8")},
        allow_literal_dynamic_imports=False,
    )
    if issues:
        _fail("OPAQUE_DEPENDENCY", source_issues=list(issues))
    files = {
        MODULE_NAME + ".py": generated.encode("utf-8"),
        "contract.json": contract.content,
        "dependency-lock.json": dependency_lock.content,
    }
    provenance = ExportArtifact.from_bytes(
        canonical_json(
            {
                "schema": "scratch-source-export-provenance/v1",
                "trust_class": "trusted_candidate",
                "source_artifact_ids": [source.artifact_id for source in sources],
                "selected_definitions": origins,
                "imports": sorted(imports),
                "entrypoint": entrypoint,
                "contract_artifact_id": contract.artifact_id,
                "dependency_lock_artifact_id": dependency_lock.artifact_id,
                "dependency_artifact_ids": sorted(
                    artifact.artifact_id for artifact in dependency_artifacts
                ),
                "python_abi": "cp312",
                "analyzer": "cpython-lexical-scopes/v1",
                "source_media_type": SOURCE_MEDIA_TYPE,
                "builtin_dependencies": sorted(
                    (used - selected - module_imports) & _BUILTINS
                ),
                "source_files": {
                    path: sha256_hex(raw) for path, raw in sorted(files.items())
                },
            }
        )
    )
    state = capability_contract["state"]
    meta = PackageMeta(
        name=name,
        version=version,
        artifact_kind="capability",
        entrypoint=entrypoint,
        contract_artifact_id=contract.artifact_id,
        dependency_lock_artifact_id=dependency_lock.artifact_id,
        state_schema_artifact_ids=(
            (state["schema_artifact_id"],) if state.get("schema_artifact_id") else ()
        ),
        migration_artifact_ids=tuple(
            sorted(set(state.get("migration_artifact_ids", [])))
        ),
        runtime_constraints={
            **capability_contract["runtime_constraints"],
            "python": ">=3.12 <3.13",
            "trust_class": "trusted_candidate",
            "source_export_profile": "scratch-source-export/v1",
        },
        platform_constraints={},
        build_provenance_artifact_id=provenance.artifact_id,
    )
    try:
        package = ExportArtifact.from_bytes(
            encode_package(build_manifest(meta, files), files)
        )
    except ValueError:
        _fail("INVALID_PACKAGE")
    inputs = (*sources, contract, dependency_lock, *dependency_artifacts)
    return ScratchExport(package, provenance, inputs)
