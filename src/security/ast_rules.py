"""
AST pattern rules
==================
Security rules that are properties of the code itself rather than of a data
flow: hardcoded secrets (SEC003), weak hashes (SEC004), bare except (SEC006),
mutable defaults (SEC007), assert-as-validation (SEC008), insecure randomness
in a security context (SEC011) and hardcoded network addresses (SEC012).

Each rule reports the line of the offending node (the old scanner reported the
function's ``def`` line for everything).
"""
from __future__ import annotations

import ast
import ipaddress
import os
import re
from typing import Callable, Dict, List, Optional, Tuple

from ..ir.lowering import collect_module_imports
from .rules import RULES

RawFinding = Dict[str, object]

_SECRET_NAME = re.compile(
    r"(?i)(^|_)(pass(word|wd|phrase)?|pwd|secret|token|api_?key|apikey|access_?key|"
    r"private_?key|auth_?key|credentials?|client_?secret|secret_?key|signing_?key)(s)?($|_)"
)
_NOT_SECRET_SUFFIX = re.compile(
    r"(?i)_(field|type|name|label|prompt|url|uri|path|file|len|length|regex|pattern|header|"
    r"param|env|var|key_name|id|policy|expiry|ttl|hint|min|max|count|column|attr)$"
)
_PLACEHOLDER = re.compile(
    r"(?i)^(<.*>|\$\{.*\}|\$\w+|%\(.*\)s|\{\{.*\}\}|\{.*\}|x+|\*+|\.+|changeme|change_me|"
    r"your[-_ ].*|example.*|dummy|test|testing|none|null|empty|todo|fixme|secret|password|"
    r"token|redacted|placeholder)$"
)
_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{2,}$")
_KNOWN_FORMATS: List[Tuple[str, re.Pattern]] = [
    ("AWS access key id", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("Stripe live key", re.compile(r"\b[sr]k_live_[0-9a-zA-Z]{16,}")),
    ("API secret key (sk-...)", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("private key block", re.compile(r"-----BEGIN ((RSA|EC|DSA|OPENSSH|ENCRYPTED) )?PRIVATE KEY-----")),
    ("credentials in URL", re.compile(r"\b[a-z][a-z0-9+.-]*://[^/\s:@'\"]+:[^/\s:@'\"]{3,}@[^\s'\"]+",
                                      re.IGNORECASE)),
]

_WEAK_HASHES = {"hashlib.md5": "MD5", "hashlib.sha1": "SHA-1", "Crypto.Hash.MD5.new": "MD5",
                "Crypto.Hash.SHA.new": "SHA-1", "Crypto.Hash.SHA1.new": "SHA-1",
                "cryptography.hazmat.primitives.hashes.MD5": "MD5",
                "cryptography.hazmat.primitives.hashes.SHA1": "SHA-1"}
_INSECURE_RANDOM = {"random.random", "random.randint", "random.choice", "random.choices",
                    "random.randrange", "random.shuffle", "random.sample", "random.getrandbits",
                    "random.uniform", "random.randbytes"}
_SECURITY_CONTEXT = re.compile(r"(?i)(token|passw|secret|nonce|salt|otp|session|csrf|auth|"
                               r"reset|api_?key|apikey|private|signature|sign|credential|key$|^key)")


def _mask(value: str) -> str:
    if len(value) <= 4:
        return "****"
    return value[:2] + "*" * min(8, len(value) - 4) + value[-2:]


def _is_test_file(filepath: str) -> bool:
    base = os.path.basename(filepath or "")
    return base.startswith("test_") or base.endswith("_test.py") or base == "conftest.py"


class _Rules(ast.NodeVisitor):
    def __init__(self, filepath: str, func_at: Callable[[int], str]):
        self.filepath = filepath
        self.func_at = func_at
        self.out: List[RawFinding] = []
        self.imports: Dict[str, str] = {}
        self.func_stack: List[str] = []
        self.docstring_nodes: set = set()

    # ── helpers ─────────────────────────────────────────────────────────

    def canonical(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Name):
            return self.imports.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = self.canonical(node.value)
            return f"{base}.{node.attr}" if base else None
        return None

    def add(self, rule_id: str, node: ast.AST, message: str, confidence: str,
            reasons: List[str], status: Optional[str] = None, suppression: str = "",
            code: str = "") -> None:
        line = getattr(node, "lineno", 0)
        self.out.append({
            "rule_id": rule_id, "line": line, "col": getattr(node, "col_offset", 0),
            "function": self.func_at(line), "message": message, "confidence": confidence,
            "confidence_reasons": reasons, "status": status, "suppression_reason": suppression,
            "code": code,
        })

    # ── traversal ───────────────────────────────────────────────────────

    def visit_Module(self, node):
        self.imports = collect_module_imports(node)
        self._mark_docstrings(node)
        self.generic_visit(node)

    def _mark_docstrings(self, node):
        for n in ast.walk(node):
            if isinstance(n, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                body = getattr(n, "body", [])
                if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                    self.docstring_nodes.add(id(body[0].value))

    def visit_FunctionDef(self, node):
        self._check_defaults(node)
        self._check_secret_defaults(node)
        self.func_stack.append(node.name)
        self.generic_visit(node)
        self.func_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    # ── SEC003 hardcoded secrets ───────────────────────────────────────

    def _secret_name(self, name: str) -> bool:
        return bool(_SECRET_NAME.search(name)) and not _NOT_SECRET_SUFFIX.search(name)

    def _secret_value(self, value) -> bool:
        if not isinstance(value, str) or len(value) < 4:
            return False
        v = value.strip()
        if _PLACEHOLDER.match(v) or _ENV_NAME.match(v) or len(set(v)) <= 2:
            return False
        if " " in v and len(v.split()) > 3:
            return False   # prose (prompts, messages)
        return True

    def _report_secret(self, node, name: str, value: str):
        self.add("SEC003", node,
                 f"Hardcoded secret assigned to '{name}' (value {_mask(value)}).",
                 "medium", ["secret identified from the variable name and a non-placeholder "
                            "string literal; the value itself is not verified"],
                 code=f"{name} = '{_mask(value)}'")

    def _target_name(self, t) -> Optional[str]:
        if isinstance(t, ast.Name):
            return t.id
        if isinstance(t, ast.Attribute):
            return t.attr
        if isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Constant) \
                and isinstance(t.slice.value, str):
            return t.slice.value
        return None

    def visit_Assign(self, node: ast.Assign):
        if isinstance(node.value, ast.Constant):
            for t in node.targets:
                name = self._target_name(t)
                if name and self._secret_name(name) and self._secret_value(node.value.value):
                    self._report_secret(node, name, node.value.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign):
        if isinstance(node.value, ast.Constant):
            name = self._target_name(node.target)
            if name and self._secret_name(name) and self._secret_value(node.value.value):
                self._report_secret(node, name, node.value.value)
        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict):
        for k, v in zip(node.keys, node.values):
            if isinstance(k, ast.Constant) and isinstance(k.value, str) and isinstance(v, ast.Constant) \
                    and self._secret_name(k.value) and self._secret_value(v.value):
                self._report_secret(v, k.value, v.value)
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare):
        if len(node.ops) == 1 and isinstance(node.ops[0], (ast.Eq, ast.NotEq)):
            left, right = node.left, node.comparators[0]
            for a, b in ((left, right), (right, left)):
                name = self._target_name(a)
                if name and self._secret_name(name) and isinstance(b, ast.Constant) \
                        and self._secret_value(b.value):
                    self.add("SEC003", node,
                             f"'{name}' is compared with a hardcoded literal "
                             f"({_mask(b.value)}) — embedded credential check.",
                             "medium", ["credential check identified from the variable name"])
                    break
        self.generic_visit(node)

    def _check_secret_defaults(self, node):
        args = node.args.posonlyargs + node.args.args
        defaults = [None] * (len(args) - len(node.args.defaults)) + list(node.args.defaults)
        pairs = list(zip(args, defaults)) + list(zip(node.args.kwonlyargs, node.args.kw_defaults))
        for arg, d in pairs:
            if isinstance(d, ast.Constant) and self._secret_name(arg.arg) and self._secret_value(d.value):
                self._report_secret(d, arg.arg, d.value)

    def visit_Constant(self, node: ast.Constant):
        if isinstance(node.value, str) and id(node) not in self.docstring_nodes:
            for label, pat in _KNOWN_FORMATS:
                if pat.search(node.value):
                    self.add("SEC003", node,
                             f"String literal contains a {label} ({_mask(node.value)}).",
                             "high", [f"value matches the {label} format"])
                    break
            self._check_ip(node)

    # ── SEC012 hardcoded IP ────────────────────────────────────────────

    def _check_ip(self, node: ast.Constant):
        text = node.value.strip()
        m = re.fullmatch(r"(?:[a-z]+://)?(\d{1,3}(?:\.\d{1,3}){3})(?::\d{1,5})?(?:/\S*)?", text)
        if not m:
            return
        try:
            ip = ipaddress.ip_address(m.group(1))
        except ValueError:
            return
        if ip.is_loopback or ip.is_unspecified or str(ip) == "255.255.255.255":
            return
        self.add("SEC012", node, f"Hardcoded IP address '{text}'.", "medium",
                 ["a literal IP may be legitimate configuration; deployment context unknown"])

    # ── calls: SEC004 / SEC011 ─────────────────────────────────────────

    def visit_Call(self, node: ast.Call):
        for kw in node.keywords:
            if kw.arg and isinstance(kw.value, ast.Constant) and self._secret_name(kw.arg) \
                    and self._secret_value(kw.value.value):
                self._report_secret(kw.value, kw.arg, kw.value.value)
        name = self.canonical(node.func) or ""
        weak = _WEAK_HASHES.get(name)
        if name == "hashlib.new" and node.args and isinstance(node.args[0], ast.Constant) \
                and str(node.args[0].value).lower().replace("-", "") in ("md5", "sha1"):
            weak = str(node.args[0].value).upper()
        if weak:
            nonsec = any(k.arg == "usedforsecurity" and isinstance(k.value, ast.Constant)
                         and k.value.value is False for k in node.keywords)
            fn = self.func_stack[-1] if self.func_stack else ""
            context_hint = bool(re.search(r"(?i)passw|token|sign|auth|secret|credential", fn))
            if nonsec:
                self.add("SEC004", node, f"Uses {weak} with usedforsecurity=False.", "high", [],
                         status="suppressed",
                         suppression="usedforsecurity=False declares a non-security use")
            else:
                conf = "high" if context_hint else "medium"
                reasons = ([f"enclosing function '{fn}' handles credentials/signatures"]
                           if context_hint else
                           ["whether the digest protects security-relevant data is not "
                            "determined (checksums/cache keys are acceptable uses)"])
                self.add("SEC004", node, f"Uses the weak hash {weak} ({name}).", conf, reasons)
        if name in _INSECURE_RANDOM:
            ctx = self._security_context_for(node)
            if ctx:
                self.add("SEC011", node,
                         f"{name}() is not cryptographically secure but is used for {ctx}.",
                         "medium", [f"security use inferred from the name {ctx!r}"])
        self.generic_visit(node)

    def _security_context_for(self, node: ast.AST) -> Optional[str]:
        fn = self.func_stack[-1] if self.func_stack else ""
        if fn and _SECURITY_CONTEXT.search(fn):
            return f"function '{fn}'"
        target = getattr(self, "_current_assign_target", None)
        if target and _SECURITY_CONTEXT.search(target):
            return f"variable '{target}'"
        return None

    def visit_Expr(self, node):
        self.generic_visit(node)

    def generic_visit(self, node):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names = [self._target_name(t) for t in targets]
            prev = getattr(self, "_current_assign_target", None)
            self._current_assign_target = next((n for n in names if n), None)
            super().generic_visit(node)
            self._current_assign_target = prev
            return
        super().generic_visit(node)

    # ── SEC006 bare except ─────────────────────────────────────────────

    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        if node.type is None:
            reraises = bool(node.body) and isinstance(node.body[-1], ast.Raise) \
                and node.body[-1].exc is None
            if reraises:
                self.add("SEC006", node, "Bare 'except:' that re-raises.", "high", [],
                         status="suppressed",
                         suppression="the handler ends with a bare 'raise', so no exception is "
                                     "swallowed")
            else:
                self.add("SEC006", node,
                         "Bare 'except:' also catches SystemExit and KeyboardInterrupt and hides "
                         "errors.", "high", [])
        self.generic_visit(node)

    # ── SEC007 mutable defaults ────────────────────────────────────────

    def _check_defaults(self, node):
        for d in list(node.args.defaults) + [d for d in node.args.kw_defaults if d is not None]:
            mutable = isinstance(d, (ast.List, ast.Dict, ast.Set)) or (
                isinstance(d, ast.Call) and isinstance(d.func, ast.Name)
                and d.func.id in ("list", "dict", "set") and not d.args)
            if mutable:
                self.add("SEC007", d,
                         f"Mutable default argument in {node.name}() is shared across calls.",
                         "high", [])

    # ── SEC008 assert ──────────────────────────────────────────────────

    def visit_Assert(self, node: ast.Assert):
        fn = self.func_stack[-1] if self.func_stack else ""
        if not _is_test_file(self.filepath) and not fn.startswith("test"):
            self.add("SEC008", node,
                     "assert used in non-test code; it is stripped when Python runs with -O.",
                     "medium", ["the assert may be a debugging aid rather than a security "
                                "check"])
        self.generic_visit(node)


def run_ast_rules(tree: ast.Module, filepath: str, func_at: Callable[[int], str]) -> List[RawFinding]:
    v = _Rules(filepath, func_at)
    v.visit(tree)
    for f in v.out:
        f.setdefault("rule", RULES[f["rule_id"]])
    return v.out
