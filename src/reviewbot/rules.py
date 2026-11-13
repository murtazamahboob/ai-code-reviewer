"""Rule engine: AST + line-pattern detectors for Python source.

Fully offline and deterministic — no LLM, no network, no API key.
Every rule returns a Finding with the exact evidence line and a
concrete fix suggestion. Rules are grouped:

* SEC — security (eval, pickle, shell, secrets, SQL building, ...)
* BUG — correctness (mutable defaults, bare except, unreachable code, ...)
* QLT — maintainability (complexity, length, nesting, duplicates, ...)
"""
from __future__ import annotations

import ast
import hashlib
import re
from collections import Counter

from .findings import Finding

_SECRET_NAMES = ("password", "passwd", "api_key", "apikey", "secret", "token", "private_key")
_PLACEHOLDERS = {"", "xxx", "xxxx", "todo", "changeme", "your-api-key", "your_password"}
_SQL_WORDS = ("select ", "insert ", "update ", "delete ", "drop ", "where ")
_MAX_FUNC_LINES = 50
_MAX_PARAMS = 5
_MAX_NESTING = 4
_MAX_COMPLEXITY = 10
_MAX_LINE_LEN = 120


def _line(source_lines: list[str], lineno: int) -> str:
    if 1 <= lineno <= len(source_lines):
        return source_lines[lineno - 1].strip()
    return ""


def _is_sql_text(text: str) -> bool:
    lowered = text.lower()
    return any(word in lowered for word in _SQL_WORDS)


def _contains_sql(node: ast.AST) -> bool:
    """True when an expression builds a SQL string dynamically.

    A bare string constant (including a parameterised query such as
    "SELECT ... WHERE id = %s") is static and safe — only dynamic
    construction counts: f-strings, % / + formatting, and .format().
    """
    if isinstance(node, ast.Constant):
        return False
    if isinstance(node, ast.JoinedStr):  # f-string: check its literal parts
        try:
            return _is_sql_text(ast.unparse(node))
        except Exception:
            return any(_contains_sql(v) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)):
        try:
            return _is_sql_text(ast.unparse(node))
        except Exception:
            return False
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
            and node.func.attr == "format":
        base = node.func.value
        return isinstance(base, ast.Constant) and isinstance(base.value, str) \
            and _is_sql_text(base.value)
    return False


class _RuleVisitor(ast.NodeVisitor):
    def __init__(self, tree: ast.Module, source: str, filename: str):
        self.tree = tree
        self.source_lines = source.splitlines()
        self.filename = filename
        self.findings: list[Finding] = []
        # Pre-collect every loaded name: unused-variable checks run inside
        # visit_FunctionDef, i.e. before the full traversal has seen the
        # later loads, so the set must exist up front.
        self._used_names: set[str] = {
            n.id for n in ast.walk(tree)
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)
        }
        self._nesting = 0

    def add(self, rule, severity, category, title, message, node, suggestion):
        lineno = getattr(node, "lineno", 1)
        self.findings.append(
            Finding(
                rule=rule,
                severity=severity,
                category=category,
                title=title,
                message=message,
                file=self.filename,
                line=lineno,
                evidence=_line(self.source_lines, lineno),
                suggestion=suggestion,
            )
        )

    # -- generic bookkeeping -------------------------------------------------
    def visit_Name(self, node: ast.Name):
        if isinstance(node.ctx, ast.Load):
            self._used_names.add(node.id)
        self.generic_visit(node)

    def _enter_block(self, node):
        self._nesting += 1
        for stmt in getattr(node, "body", []):
            self.visit(stmt)
        for stmt in getattr(node, "orelse", []):
            self.visit(stmt)
        for stmt in getattr(node, "finalbody", []):
            self.visit(stmt)
        self._nesting -= 1

    # -- security ------------------------------------------------------------
    def visit_Call(self, node: ast.Call):
        func = node.func
        name = ""
        if isinstance(func, ast.Name):
            name = func.id
        elif isinstance(func, ast.Attribute):
            name = func.attr

        if name in ("eval", "exec"):
            self.add("SEC001", "critical", "security", "Dynamic code execution",
                     f"{name}() runs arbitrary code from a string — an attacker who "
                     "controls the input controls the process.",
                     node, f"Replace {name}() with an explicit parser (ast.literal_eval, "
                     "a dispatch dict, or a proper expression evaluator).")
        elif name in ("loads", "load") and isinstance(func, ast.Attribute):
            owner = func.value
            owner_name = owner.id if isinstance(owner, ast.Name) else ""
            if owner_name in ("pickle", "marshal", "shelve"):
                self.add("SEC002", "critical", "security", "Unsafe deserialization",
                         f"{owner_name}.{name}() can execute arbitrary code from untrusted data.",
                         node, "Use json.loads() for data, or sign/verify the payload "
                         "(e.g. hmac) before unpickling trusted data only.")
            elif owner_name == "yaml" and name == "load":
                has_loader = any(kw.arg == "Loader" for kw in node.keywords)
                if not has_loader:
                    self.add("SEC006", "high", "security", "Unsafe YAML loading",
                             "yaml.load() without a Loader can construct arbitrary objects.",
                             node, "Use yaml.safe_load() instead.")
        elif name in ("system", "popen") and isinstance(func, ast.Attribute):
            self.add("SEC003", "high", "security", "Shell command execution",
                     f"os.{name}() runs a shell command — shell metacharacters in "
                     "arguments become command injection.",
                     node, "Use subprocess.run([...], shell=False) with a list of arguments.")
        elif name == "Popen" and any(kw.arg == "shell" and isinstance(kw.value, ast.Constant)
                                     and kw.value.value is True for kw in node.keywords):
            self.add("SEC003", "high", "security", "Shell command execution",
                     "subprocess.Popen(..., shell=True) runs a shell command.",
                     node, "Drop shell=True and pass the command as a list.")
        elif name == "run" and any(kw.arg == "shell" and isinstance(kw.value, ast.Constant)
                                   and kw.value.value is True for kw in node.keywords):
            self.add("SEC003", "high", "security", "Shell command execution",
                     "subprocess.run(..., shell=True) runs a shell command.",
                     node, "Drop shell=True and pass the command as a list.")
        elif name == "execute":
            for arg in node.args:
                if _contains_sql(arg):
                    self.add("SEC005", "high", "security", "SQL built by string formatting",
                             "A SQL query is assembled from strings — user input can "
                             "break out of the query (SQL injection).",
                             node, "Use parameterised queries: cursor.execute("
                             "\"SELECT ... WHERE id = ?\", (value,)).")
                    break
        elif name in ("md5", "sha1") and isinstance(func, ast.Attribute):
            owner = func.value
            if isinstance(owner, ast.Name) and owner.id == "hashlib":
                self.add("SEC009", "medium", "security", "Weak hash algorithm",
                         f"hashlib.{name}() is broken for collision resistance and too "
                         "fast for password hashing.",
                         node, "Use hashlib.sha256() for checksums, or bcrypt/argon2 "
                         "for passwords.")
        elif name in ("random", "randint", "choice", "choices") and isinstance(func, ast.Attribute):
            owner = func.value
            if isinstance(owner, ast.Name) and owner.id == "random":
                # Only flag when the result feeds a security-looking name; the
                # assignment check in visit_Assign handles the context, so
                # this call alone is not flagged.
                pass
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        # Hardcoded secret: password = "hunter2" style assignments.
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            value = node.value.value
            for target in node.targets:
                if isinstance(target, ast.Name):
                    lowered = target.id.lower()
                    if any(secret in lowered for secret in _SECRET_NAMES):
                        if len(value) >= 8 and value.lower() not in _PLACEHOLDERS:
                            self.add("SEC004", "high", "security", "Hardcoded secret",
                                     f"Secret assigned to {target.id!r} is committed in source.",
                                     node, "Move the secret to an environment variable "
                                     "(os.environ[\"...\"]) or a secrets manager; rotate "
                                     "the exposed value.")
                # Insecure randomness feeding a token/password variable.
        if isinstance(node.value, ast.Call):
            func = node.value.func
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) \
                    and func.value.id == "random":
                for target in node.targets:
                    if isinstance(target, ast.Name) and any(
                            s in target.id.lower() for s in ("token", "password", "secret", "key")):
                        self.add("SEC007", "medium", "security",
                                 "Insecure randomness for a secret",
                                 f"{target.id!r} is generated with the non-cryptographic "
                                 "random module.",
                                 node, "Use the secrets module: secrets.token_urlsafe(32).")
        # requests.get(..., verify=False) / ssl unverified context
        self.generic_visit(node)

    def visit_keyword(self, node: ast.keyword):  # ast node class is lowercase `keyword`
        if node.arg == "verify" and isinstance(node.value, ast.Constant) and node.value.value is False:
            self.add("SEC008", "high", "security", "TLS verification disabled",
                     "verify=False disables TLS certificate checks — traffic can be "
                     "intercepted.",
                     node, "Remove verify=False (or pin the CA bundle with verify=<path>).")
        self.generic_visit(node)

    # -- bugs ------------------------------------------------------------------
    def visit_FunctionDef(self, node: ast.FunctionDef):
        # Mutable default argument.
        for default in node.args.defaults:
            if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                self.add("BUG001", "high", "bug", "Mutable default argument",
                         "A list/dict/set default is shared across every call — "
                         "mutations leak into later calls.",
                         node, "Use None as the default and create the container "
                         "inside the function: def f(items=None): items = items or [].")
        if len(node.args.args) > _MAX_PARAMS:
            self.add("QLT002", "low", "quality", "Too many parameters",
                     f"{node.name}() takes {len(node.args.args)} parameters "
                     f"(limit {_MAX_PARAMS}).",
                     node, "Group related parameters into a dataclass or config object.")
        end = getattr(node, "end_lineno", node.lineno) or node.lineno
        if end - node.lineno + 1 > _MAX_FUNC_LINES:
            self.add("QLT001", "low", "quality", "Function too long",
                     f"{node.name}() spans {end - node.lineno + 1} lines "
                     f"(limit {_MAX_FUNC_LINES}).",
                     node, "Extract a helper for one of its responsibilities.")
        complexity = _cyclomatic_complexity(node)
        if complexity > _MAX_COMPLEXITY:
            self.add("QLT004", "medium", "quality", "High cyclomatic complexity",
                     f"{node.name}() has cyclomatic complexity {complexity} "
                     f"(limit {_MAX_COMPLEXITY}).",
                     node, "Split the branching into small helpers or a lookup table.")
        self._check_unreachable(node)
        self._check_unused_variables(node)
        self.generic_visit(node)

    def _check_unreachable(self, node: ast.FunctionDef):
        for block in _all_blocks(node):
            seen_terminal = False
            for stmt in block:
                if seen_terminal:
                    self.add("BUG006", "medium", "bug", "Unreachable code",
                             "This statement can never run — a return/raise/break/continue "
                             "above it always exits first.",
                             stmt, "Delete the dead code, or move it before the "
                             "early exit.")
                    break
                if isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                    seen_terminal = True

    def _check_unused_variables(self, node: ast.FunctionDef):
        assigned: dict[str, ast.AST] = {}
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
                assigned.setdefault(child.id, child)
        for name, target in assigned.items():
            if name.startswith("_") or name in self._used_names:
                continue
            # Only flag plain local assignments inside this function.
            self.add("BUG008", "low", "bug", "Unused variable",
                     f"Variable {name!r} is assigned but never read.",
                     target, f"Remove {name!r}, or use it — dead assignments hide "
                     "real bugs (e.g. a result that was meant to be returned).")

    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        if node.type is None:
            self.add("BUG002", "high", "bug", "Bare except clause",
                     "A bare except: swallows KeyboardInterrupt and SystemExit too, "
                     "and hides the real error.",
                     node, "Catch the specific exception: except ValueError: ...")
        elif len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
            self.add("BUG003", "medium", "bug", "Silent exception handler",
                     "The exception is swallowed with pass — failures vanish silently.",
                     node, "Log the error, or re-raise if the caller should know.")
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare):
        for op, comparator in zip(node.ops, node.comparators):
            if isinstance(op, (ast.Eq, ast.NotEq)) and isinstance(comparator, ast.Constant) \
                    and comparator.value is None:
                self.add("BUG004", "medium", "bug", "Comparison with None using ==",
                         "Use `is None` / `is not None` — == can be overridden and "
                         "is slower and less clear.",
                         node, "Replace == None with is None (and != None with is not None).")
            if isinstance(op, (ast.Is, ast.IsNot)) and isinstance(comparator, ast.Constant) \
                    and isinstance(comparator.value, (int, str, float)) \
                    and not isinstance(comparator.value, bool):
                self.add("BUG005", "medium", "bug", "Identity check against a literal",
                         "is compares identity, not value — it works by accident for "
                         "small cached objects and breaks for others.",
                         node, "Use == for value comparison with literals.")
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert):
        self.add("BUG010", "low", "bug", "assert used for validation",
                 "assert statements are stripped with python -O, so they must not "
                 "guard real behaviour.",
                 node, "Raise a proper exception (ValueError, ...) for input "
                 "validation.")
        self.generic_visit(node)

    def visit_If(self, node: ast.If):
        if self._nesting > _MAX_NESTING:
            self.add("QLT003", "medium", "quality", "Deeply nested code",
                     f"Code nested {self._nesting} levels deep (limit {_MAX_NESTING}).",
                     node, "Return early (guard clauses) or extract a helper.")
        self._nesting += 1
        self.generic_visit(node)
        self._nesting -= 1

    def visit_For(self, node):
        self._visit_loop(node)

    def visit_While(self, node):
        self._visit_loop(node)

    def _visit_loop(self, node):
        if self._nesting > _MAX_NESTING:
            self.add("QLT003", "medium", "quality", "Deeply nested code",
                     f"Code nested {self._nesting} levels deep (limit {_MAX_NESTING}).",
                     node, "Return early (guard clauses) or extract a helper.")
        self._nesting += 1
        self.generic_visit(node)
        self._nesting -= 1


def _all_blocks(node: ast.AST):
    """Every statement list inside a node (function body, if/else, loops...)."""
    blocks = []
    for child in ast.walk(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.If,
                              ast.For, ast.While, ast.With, ast.Try)):
            blocks.append(child.body)
            if isinstance(child, ast.If):
                blocks.append(child.orelse)
            if isinstance(child, (ast.For, ast.While)):
                blocks.append(child.orelse)
            if isinstance(child, ast.Try):
                blocks.append(child.orelse)
                blocks.append(child.finalbody)
    return blocks


def _cyclomatic_complexity(func: ast.FunctionDef) -> int:
    complexity = 1
    for child in ast.walk(func):
        if isinstance(child, (ast.If, ast.For, ast.While, ast.ExceptHandler,
                              ast.With, ast.Assert)):
            complexity += 1
        elif isinstance(child, ast.BoolOp):
            complexity += max(0, len(child.values) - 1)
        elif isinstance(child, ast.comprehension):
            complexity += 1
    return complexity


def _line_findings(source: str, filename: str) -> list[Finding]:
    """Line-based rules (long lines, TODOs, print calls are AST-based)."""
    findings: list[Finding] = []
    for i, line in enumerate(source.splitlines(), start=1):
        if len(line) > _MAX_LINE_LEN:
            findings.append(Finding("QLT005", "low", "quality", "Line too long",
                                    f"Line is {len(line)} characters (limit {_MAX_LINE_LEN}).",
                                    filename, i, line.strip(),
                                    "Split the line, or extract the long expression."))
        if re.search(r"#\s*(TODO|FIXME|XXX)\b", line):
            findings.append(Finding("QLT006", "low", "quality", "TODO/FIXME marker",
                                    "An unfinished-work marker is committed in source.",
                                    filename, i, line.strip(),
                                    "Finish the work, or file it as a tracked issue "
                                    "and remove the marker."))
    return findings


def _print_findings(tree: ast.Module, source_lines: list[str], filename: str) -> list[Finding]:
    findings = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id == "print":
            findings.append(Finding("QLT007", "low", "quality", "print() in code",
                                    "print() output is unstructured and leaks into "
                                    "production logs.",
                                    filename, node.lineno,
                                    _line(source_lines, node.lineno),
                                    "Use the logging module instead."))
    return findings


def _duplicate_findings(tree: ast.Module, source_lines: list[str], filename: str) -> list[Finding]:
    seen: dict[str, str] = {}
    findings = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            body_dump = ast.dump(ast.Module(body=node.body, type_ignores=[]))
            digest = hashlib.sha256(body_dump.encode()).hexdigest()[:12]
            if digest in seen and len(node.body) >= 2:
                findings.append(Finding("QLT008", "medium", "quality",
                                        "Duplicated function body",
                                        f"{node.name}() has the same body as "
                                        f"{seen[digest]}() — a fix in one place will "
                                        "be missed in the other.",
                                        filename, node.lineno,
                                        _line(source_lines, node.lineno),
                                        "Extract the shared logic into one helper and "
                                        "call it from both places."))
            else:
                seen.setdefault(digest, node.name)
    return findings


def _unused_import_findings(tree: ast.Module, source_lines: list[str],
                            filename: str, used: set[str]) -> list[Finding]:
    findings = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = (alias.asname or alias.name).split(".")[0]
                if name not in used and name != "*":
                    findings.append(Finding("BUG007", "medium", "bug",
                                            "Unused import",
                                            f"Imported {alias.name!r} is never used.",
                                            filename, node.lineno,
                                            _line(source_lines, node.lineno),
                                            f"Remove the unused import of {alias.name!r}."))
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                name = alias.asname or alias.name
                if name not in used and name != "*":
                    findings.append(Finding("BUG007", "medium", "bug",
                                            "Unused import",
                                            f"Imported {alias.name!r} is never used.",
                                            filename, node.lineno,
                                            _line(source_lines, node.lineno),
                                            f"Remove the unused import of {alias.name!r}."))
    return findings


def review_source(source: str, filename: str = "<string>") -> list[Finding]:
    """Review one Python source string. Returns findings sorted by line."""
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [Finding("BUG000", "critical", "bug", "Syntax error",
                        f"File does not parse: {exc.msg}",
                        filename, exc.lineno or 1,
                        _line(source.splitlines(), exc.lineno or 1),
                        "Fix the syntax error — nothing else can be reviewed until it parses.")]
    visitor = _RuleVisitor(tree, source, filename)
    visitor.visit(tree)
    findings = list(visitor.findings)
    findings += _line_findings(source, filename)
    findings += _print_findings(tree, source.splitlines(), filename)
    findings += _duplicate_findings(tree, source.splitlines(), filename)
    findings += _unused_import_findings(tree, source.splitlines(), filename,
                                        visitor._used_names)
    # Nested functions can surface the same issue twice; keep one copy.
    seen: set[tuple] = set()
    unique: list[Finding] = []
    for f in findings:
        key = (f.rule, f.file, f.line, f.title)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    unique.sort(key=lambda f: (f.line, f.rule))
    return unique


def review_file(path) -> list[Finding]:
    from pathlib import Path
    path = Path(path)
    return review_source(path.read_text(encoding="utf-8"), filename=str(path))


def review_path(path) -> list[Finding]:
    """Review a file or a directory tree of .py files (skips venvs)."""
    from pathlib import Path
    path = Path(path)
    files = [path] if path.is_file() else sorted(
        p for p in path.rglob("*.py")
        if ".venv" not in p.parts and "__pycache__" not in p.parts
    )
    findings: list[Finding] = []
    for f in files:
        findings.extend(review_file(f))
    findings.sort(key=lambda x: (x.file, x.line, x.rule))
    return findings
