"""Read-only Python source boundary audit for external Harness packages.

This checks the supported import form, not arbitrary Python safety. Placement,
publisher trust and Backend enforcement remain separate requirements. In
particular this is not a sandbox against reflective trusted Python code.
"""

import ast


_PUBLIC_RUNTIME = ("agent_meta_runtime.sdk", "agent_meta_runtime.protocols.public")
_LOADERS = {"__import__", "builtins.__import__", "importlib.import_module"}
_SEARCH_PATHS = ("sys.path", "sys.meta_path", "sys.path_hooks", "sys.path_importer_cache")
MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_MODULE_BYTES = 1024 * 1024
MAX_AST_NODES = 200_000


def _runtime_private(name):
    return (name == "agent_meta_runtime" or name.startswith("agent_meta_runtime.")) and (
        not any(name == prefix or name.startswith(prefix + ".") for prefix in _PUBLIC_RUNTIME)
        or any(part.startswith("_") for part in name.split(".")))


def audit_harness_sources(files):
    """Stable path/line issues; never imports, executes or extracts code."""
    issues = set()
    modules = [(path, content) for path, content in sorted(files.items()) if path.endswith(".py")]
    if sum(len(content) for _, content in modules) > MAX_SOURCE_BYTES:
        return ("package.source_budget",)
    remaining_nodes = MAX_AST_NODES
    for path in files:
        if path == "agent_meta_runtime.py" or path.startswith("agent_meta_runtime/"):
            issues.add(f"package.source_vendored_runtime:{path}")
    for path, content in modules:
        if len(content) > MAX_MODULE_BYTES:
            issues.add(f"package.source_budget:{path}")
            continue
        try:
            tree = ast.parse(content, filename=path)
            nodes = list(ast.walk(tree))
        except (SyntaxError, ValueError, UnicodeError, RecursionError):
            issues.add(f"package.source_invalid:{path}")
            continue
        remaining_nodes -= len(nodes)
        if remaining_nodes < 0:
            issues.add("package.source_budget")
            break
        aliases = {}

        def bind(name, values):
            if isinstance(name, ast.Name):
                before = aliases.setdefault(name.id, set())
                previous = len(before)
                before.update(values)
                if len(before) > 32:
                    issues.add(f"package.source_budget:{path}")
                    aliases[name.id] = set(sorted(before)[:32])
                return len(before) != previous
            return False

        def names(node, depth=0):
            if depth > 24:
                return set()
            if isinstance(node, ast.Name):
                return aliases.get(node.id, {node.id})
            if isinstance(node, ast.Attribute):
                return {value + "." + node.attr for value in names(node.value, depth + 1)}
            if isinstance(node, ast.Subscript):
                return names(node.value, depth + 1)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "getattr" and len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str):
                return {value + "." + node.args[1].value for value in names(node.args[0], depth + 1)}
            if isinstance(node, ast.Call) and names(node.func, depth + 1) & _LOADERS and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                return {node.args[0].value}
            return set()

        for node in nodes:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    aliases.setdefault(alias.asname or alias.name.split(".")[0], set()).add(alias.name if alias.asname else alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                for alias in node.names:
                    aliases.setdefault(alias.asname or alias.name, set()).add((node.module or "") + "." + alias.name)
        # Retain every possible alias binding rather than allowing a later
        # assignment to erase a dangerous earlier import form.
        for _ in range(16):
            changed = False
            for node in nodes:
                if isinstance(node, (ast.Assign, ast.AnnAssign)):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    values = names(node.value) if node.value is not None else set()
                    for target in targets:
                        changed |= bind(target, values)
            if not changed:
                break

        def issue(reason, node):
            issues.add(f"package.source_{reason}:{path}:{node.lineno}")

        for node in nodes:
            if isinstance(node, ast.Import):
                if any(_runtime_private(alias.name) for alias in node.names):
                    issue("private_runtime_import", node)
            elif isinstance(node, ast.ImportFrom):
                if node.level == 0:
                    module = node.module or ""
                    if any(_runtime_private(module + "." + alias.name) for alias in node.names):
                        issue("private_runtime_import", node)
                    if module.startswith("agent_meta_runtime") and any(alias.name == "*" for alias in node.names):
                        issue("opaque_import", node)
                elif node.level > path.count("/"):
                    issue("relative_import_escape", node)
            if isinstance(node, ast.Attribute) and any(_runtime_private(value) for value in names(node)):
                issue("private_runtime_access", node)
            if isinstance(node, ast.Name) and node.id == "__builtins__":
                issue("opaque_import", node)
            if isinstance(node, ast.Call):
                called = names(node.func)
                if isinstance(node.func, ast.Name) and node.func.id == "getattr" and any(_runtime_private(value) for value in names(node)):
                    issue("private_runtime_access", node)
                if any(value.startswith(("importlib.util.", "importlib.machinery.", "runpy.")) for value in called):
                    issue("opaque_import", node)
                if called & {"eval", "exec", "compile", "builtins.eval", "builtins.exec", "builtins.compile", "globals", "locals", "vars"}:
                    issue("opaque_import", node)
                if called & _LOADERS:
                    argument = node.args[0] if node.args else next((item.value for item in node.keywords if item.arg == "name"), None)
                    if not isinstance(argument, ast.Constant) or not isinstance(argument.value, str) or argument.value.startswith("."):
                        issue("dynamic_import", node)
                    elif _runtime_private(argument.value):
                        issue("private_runtime_import", node)
                if any(value == "os.chdir" or value == "site.addsitedir" or any(value.startswith(prefix + ".") for prefix in _SEARCH_PATHS) for value in called):
                    issue("import_path_mutation", node)
                if isinstance(node.func, ast.Name) and node.func.id == "getattr" and node.args:
                    base = names(node.args[0])
                    if any(value.startswith(("importlib", "agent_meta_runtime", "builtins")) for value in base) and (len(node.args) < 2 or not isinstance(node.args[1], ast.Constant) or not isinstance(node.args[1].value, str)):
                        issue("opaque_import", node)
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Delete)):
                targets = node.targets if isinstance(node, (ast.Assign, ast.Delete)) else [node.target]
                if any(value == prefix or value.startswith(prefix + ".") for target in targets for value in names(target) for prefix in _SEARCH_PATHS):
                    issue("import_path_mutation", node)
    return tuple(sorted(issues))
