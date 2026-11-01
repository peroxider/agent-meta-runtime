"""Explicit AMPAK loading into isolated Python import namespaces.

This loader supports only operator-trusted in-process placement. Other
placements fail closed until a Backend worker implements the same Host SPI.
Install/Validate never invoke this loader; the execution composition root does.
"""

from __future__ import annotations

import importlib
import importlib.abc
import importlib.machinery
import inspect
import sys
import threading

from ..domain.ampak import decode_package
from ..domain.canonical import sha256_hex
from ..domain.errors import ErrorCode, StableError
from ..domain.host_contract import HarnessAdapter

_IMPORT_LOCK = threading.RLock()


class _ArtifactFinder(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    def __init__(self, namespace: str, artifact_id: str, files: dict[str, bytes]):
        self.namespace = namespace
        self.artifact_id = artifact_id
        self.files = files

    def find_spec(self, fullname, path=None, target=None):
        if fullname == self.namespace:
            return importlib.machinery.ModuleSpec(fullname, self, is_package=True)
        if not fullname.startswith(self.namespace + "."):
            return None
        relative = fullname[len(self.namespace) + 1:].replace(".", "/")
        package_path = relative + "/__init__.py"
        module_path = relative + ".py"
        if package_path in self.files:
            filename, package = package_path, True
        elif module_path in self.files:
            filename, package = module_path, False
        elif any(name.startswith(relative + "/") for name in self.files):
            return importlib.machinery.ModuleSpec(fullname, self, is_package=True)
        else:
            # Do not let another finder or sys.path resolve a missing member
            # of this installed package to unrelated local source.
            raise ModuleNotFoundError(fullname)
        spec = importlib.machinery.ModuleSpec(fullname, self, origin=f"ampak://{self.artifact_id.rsplit('/', 1)[1]}/{filename}", is_package=package)
        spec.loader_state = filename
        return spec

    def create_module(self, spec):
        return None  # importlib owns the normal ModuleType construction

    def exec_module(self, module):
        filename = module.__spec__.loader_state
        if filename is None:
            return  # artifact root or implicit namespace package
        module.__file__ = module.__spec__.origin
        code = compile(self.files[filename], module.__file__, "exec", dont_inherit=True)
        exec(code, module.__dict__)


class HarnessPackageLoader:
    """Own one version's code modules until all its Tasks/instances drain."""

    def __init__(self, artifact_id: str, content: bytes):
        if artifact_id != "artifact://sha256/" + sha256_hex(content):
            raise StableError(code=ErrorCode.INTEGRITY_ERROR, message="Harness code hash differs from ArtifactId")
        self.manifest, self._files = decode_package(content)
        self.artifact_id = artifact_id
        self.namespace = "_agent_meta_ampak_" + artifact_id.rsplit("/", 1)[1]
        self._finder = _ArtifactFinder(self.namespace, artifact_id, self._files)
        self._registered = False
        self._closed = False

    def instantiate(self, *, trust_class: str, placement: str) -> HarnessAdapter:
        """Create a task-free adapter for real reconcile/health/Task lifecycles.

        No synthetic Task or execution facade is supplied at module/factory time.
        The actual accepted envelope enters only through run_task/invocations.
        """
        if self._closed:
            raise StableError(code=ErrorCode.FAILED_PRECONDITION, message="Harness code installation has drained")
        if trust_class != "builtin_or_signed" or placement != "in_process":
            raise StableError(code=ErrorCode.FEATURE_UNAVAILABLE, message="this Host loader requires explicitly trusted in-process placement")
        module_name, separator, symbol = self.manifest.package.entrypoint.partition(":")
        if not separator or not symbol.isidentifier() or not module_name or not all(part.isidentifier() for part in module_name.split(".")):
            raise StableError(code=ErrorCode.CONTRACT_INCOMPATIBLE, message="Harness entrypoint is not a module:factory")
        with _IMPORT_LOCK:
            if not self._registered:
                if any(isinstance(finder, _ArtifactFinder) and finder.namespace == self.namespace for finder in sys.meta_path):
                    raise StableError(code=ErrorCode.ALREADY_RUNNING, message="code Artifact already has a live loader")
                sys.meta_path.insert(0, self._finder)
                self._registered = True
            try:
                module = importlib.import_module(self.namespace + "." + module_name)
                factory = getattr(module, symbol)
                if not callable(factory):
                    raise TypeError("entrypoint is not callable")
                adapter = factory()
                if not isinstance(adapter, HarnessAdapter):
                    if inspect.iscoroutine(adapter):
                        adapter.close()
                    raise TypeError("factory did not return HarnessAdapter")
                return adapter
            except (Exception, SystemExit) as exc:
                # Includes package-raised StableError: its message/details are
                # untrusted and must not bypass boundary error normalization.
                raise StableError(code=ErrorCode.INVALID_RESULT, message="Harness factory failed", details={"code_artifact_id": self.artifact_id}) from exc

    def close(self) -> None:
        """Caller must first drain active adapters; no hot unloading of Tasks."""
        with _IMPORT_LOCK:
            if self._registered:
                sys.meta_path.remove(self._finder)
                for name in list(sys.modules):
                    if name == self.namespace or name.startswith(self.namespace + "."):
                        del sys.modules[name]
                self._registered = False
            self._closed = True
