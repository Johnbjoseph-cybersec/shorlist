"""Does a context_template parse? Syntax only, per file type; it does not compile or run.

| file                 | check                                                     |
|----------------------|-----------------------------------------------------------|
| *.py                 | ast.parse                                                 |
| *.go                 | gofmt -e (skipped when gofmt is not installed)            |
| *.java               | javac into a temp dir (skipped when javac is absent)      |
| *.sh                 | sh -n                                                     |
| *.js                 | node --check (skipped when node is not installed)         |
| *.c, *.h             | gcc -fsyntax-only; header not installed: delimiters only  |
| *.cpp                | g++ -fsyntax-only; header not installed: delimiters only  |
| *.rs                 | rustfmt (parses, resolves no crate); else delimiters only |
| *.cs                 | balanced braces and parentheses (no C# compiler is run)   |
| *.php                | php -l; without php: balanced braces and parentheses      |
| *.rb                 | ruby -c; without ruby: balanced braces and parentheses    |
| *.kt, *.swift        | balanced braces and parentheses (no compiler is run)      |
| swanctl.conf         | strongSwan: 'name {', '}' or 'key = value'; balanced      |
| httpd.conf           | Apache: 'Directive args' or balanced '<Section>' tags     |
| fortigate.conf       | FortiOS: config/edit/set/unset/next/end; balanced         |
| running-config       | Cisco IOS: '!' or a command; one-space indents; 'end'     |
| nginx.conf, *.conf   | balanced braces; every statement ends in ';', '{' or '}'  |
| sshd_config          | each line is 'Keyword value', Keyword alphabetic           |
| java.security        | each line is a comment or key=value                       |
| *.yaml, *.yml        | yaml.safe_load; the document must be a mapping            |
| *.json               | json.loads; the document must be an object or an array    |
| *.tf, *.hcl          | strings closed on their line; balanced (), [] and {}      |
| *.pem                | BEGIN/END labels match (RFC 7468); base64 body            |
| authorized_keys      | each line: [options] keytype base64 [comment]             |
| known_hosts          | each line: [@marker] hosts keytype base64 [comment]       |
| *.cnf (OpenSSL)      | each line: '[ section ]' or 'key = value'                 |

Java and Go are checked for syntax only: an import of a package the local toolchain does
not ship (e.g. crypto/mlkem before Go 1.24) does not fail gofmt; javac does resolve imports,
so it needs JDK 24 or newer for javax.crypto.KEM ML-KEM names (the class exists from JDK 21).
"""
from __future__ import annotations

import ast
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import yaml

OK, SKIP, FAIL = "ok", "skipped", "fail"


def _run(cmd: list[str], text: str, suffix: str, name: str | None = None) -> tuple[str, str]:
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / (name or f"t{suffix}")
        f.write_text(text)
        p = subprocess.run(cmd + [str(f)], capture_output=True, text=True, cwd=d)
        return (OK, "") if p.returncode == 0 else (FAIL, (p.stderr or p.stdout).strip()[:400])


def _nginx(text: str) -> tuple[str, str]:
    depth = 0
    for n, raw in enumerate(text.split("\n"), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        depth += line.count("{") - line.count("}")
        if depth < 0:
            return FAIL, f"line {n}: unbalanced '}}'"
        if not line.endswith((";", "{", "}")):
            return FAIL, f"line {n}: statement does not end in ';', '{{' or '}}'"
    return (OK, "") if depth == 0 else (FAIL, "unbalanced braces")


def _sshd(text: str) -> tuple[str, str]:
    for n, raw in enumerate(text.split("\n"), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not re.fullmatch(r"[A-Za-z]+\s+\S.*", line):
            return FAIL, f"line {n}: not 'Keyword value'"
    return OK, ""


def _properties(text: str) -> tuple[str, str]:
    for n, raw in enumerate(text.split("\n"), 1):
        line = raw.strip()
        if not line or line.startswith(("#", "!")):
            continue
        if not re.fullmatch(r"[A-Za-z0-9_.\-]+\s*[=:].*", line):
            return FAIL, f"line {n}: not key=value"
    return OK, ""


def _lines(text: str, comment: str):
    for n, raw in enumerate(text.split("\n"), 1):
        if raw.strip() and not raw.strip().startswith(comment):
            yield n, raw


def _csharp(text: str) -> tuple[str, str]:
    code = re.sub(r'"(?:\\.|[^"\\])*"', '""', re.sub(r"//[^\n]*", "", text))
    for o, c in ("{}", "()"):
        depth = 0
        for ch in code:
            depth += (ch == o) - (ch == c)
            if depth < 0:
                return FAIL, f"unbalanced '{c}'"
        if depth:
            return FAIL, f"unbalanced '{o}'"
    return OK, ""


def _delims(text: str) -> tuple[str, str]:
    """Balanced (), [] and {} outside comments, strings and char literals (C, C++, Rust)."""
    code = re.sub(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])\'', " ", text, flags=re.S)
    stack = []
    for ch in code:
        if ch in "([{":
            stack.append(")]}"["([{".index(ch)])
        elif ch in ")]}":
            if not stack or stack.pop() != ch:
                return FAIL, f"unbalanced '{ch}'"
    return (OK, "") if not stack else (FAIL, f"unclosed, expected '{stack[-1]}'")


def _cc(compiler: str, text: str, suffix: str) -> tuple[str, str]:
    """Compile for syntax; when a header is not installed, fall back to the delimiter check."""
    if not shutil.which(compiler):
        status, detail = _delims(text)
        return (SKIP, f"{compiler} not installed; delimiters balanced") if status == OK else (status, detail)
    status, detail = _run([compiler, "-fsyntax-only"], text, suffix)
    m = re.search(r"fatal error: ([^:\s]+): No such file", detail) if status == FAIL else None
    if m:
        status, detail = _delims(text)
        return (SKIP, f"{m.group(1)} not installed; delimiters balanced") if status == OK else (status, detail)
    return status, detail


def _swanctl(text: str) -> tuple[str, str]:
    depth = 0
    for n, raw in _lines(text, "#"):
        line = raw.strip()
        if line == "}":
            depth -= 1
        elif re.fullmatch(r"[A-Za-z0-9_.-]+\s*\{", line):
            depth += 1
        elif not re.fullmatch(r"[A-Za-z0-9_.-]+\s*=.*", line):
            return FAIL, f"line {n}: not 'name {{', '}}' or 'key = value'"
        if depth < 0:
            return FAIL, f"line {n}: unbalanced '}}'"
    return (OK, "") if depth == 0 else (FAIL, "unbalanced braces")


def _apache(text: str) -> tuple[str, str]:
    stack = []
    for n, raw in _lines(text, "#"):
        line = raw.strip()
        m = re.fullmatch(r"<(/?)([A-Za-z]+)[^>]*>", line)
        if m and m.group(1):
            if not stack or stack.pop() != m.group(2):
                return FAIL, f"line {n}: unbalanced </{m.group(2)}>"
        elif m:
            stack.append(m.group(2))
        elif not re.fullmatch(r"[A-Za-z][A-Za-z0-9]*(\s+\S.*)?", line):
            return FAIL, f"line {n}: not 'Directive args'"
    return (OK, "") if not stack else (FAIL, f"unclosed <{stack[-1]}>")


def _fortios(text: str) -> tuple[str, str]:
    depth = 0
    for n, raw in _lines(text, "#"):
        word = raw.split()[0]
        if word in ("config", "edit"):
            depth += 1
        elif word in ("end", "next"):
            depth -= 1
        elif word not in ("set", "unset"):
            return FAIL, f"line {n}: not a FortiOS CLI command"
        if depth < 0:
            return FAIL, f"line {n}: 'end' or 'next' without 'config' or 'edit'"
    return (OK, "") if depth == 0 else (FAIL, "unbalanced config/edit")


def _ios(text: str) -> tuple[str, str]:
    last = ""
    for n, raw in _lines(text, "!"):
        if not re.fullmatch(r"( *)[a-z][A-Za-z0-9_.:/ -]*", raw) or "\t" in raw:
            return FAIL, f"line {n}: not a Cisco IOS command line"
        last = raw.strip()
    return (OK, "") if last == "end" else (FAIL, "does not end with 'end'")


def _yaml(text: str) -> tuple[str, str]:
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as e:
        return FAIL, str(e).replace("\n", " ")[:400]
    return (OK, "") if isinstance(doc, dict) else (FAIL, "document is not a mapping")


def _json(text: str) -> tuple[str, str]:
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as e:
        return FAIL, f"line {e.lineno}: {e.msg}"
    return (OK, "") if isinstance(doc, (dict, list)) else (FAIL, "document is not an object or array")


def _hcl(text: str) -> tuple[str, str]:
    """HCL (Terraform, Vault): no parser is run. Strings must close on their line (heredocs are
    not supported); (), [] and {} must balance outside strings and comments."""
    code, i, n, line = [], 0, len(text), 1
    while i < n:
        ch = text[i]
        if ch == "\n":
            line += 1
        if ch == "#" or text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            if j < 0:
                return FAIL, f"line {line}: unclosed /* comment"
            line += text.count("\n", i, j)
            i = j + 2
            continue
        if text.startswith("<<", i):
            return FAIL, f"line {line}: heredoc not supported by this check"
        if ch == '"':
            i += 1
            while i < n and text[i] not in '"\n':
                i += 2 if text[i] == "\\" else 1
            if i >= n or text[i] != '"':
                return FAIL, f"line {line}: unclosed string"
            i += 1
            code.append('""')
            continue
        code.append(ch)
        i += 1
    return _delims("".join(code))


# RFC 7468: label = [ labelchar *( ["-" / SP] labelchar ) ], labelchar = %x21-2C / %x2E-7E
_LABEL = r"((?:[!-,.-~](?:[- ]?[!-,.-~])*)?)"
_PEM = re.compile(r"-----BEGIN " + _LABEL + r"-----\n([A-Za-z0-9+/=\n]*?)-----END " + _LABEL + r"-----")


def _pem(text: str) -> tuple[str, str]:
    """Each BEGIN line has an END line with the same label and a base64 body between them."""
    begins = text.count("-----BEGIN ")
    blocks = _PEM.findall(text)
    if not begins or len(blocks) != begins or text.count("-----END ") != begins:
        return FAIL, "BEGIN/END lines unpaired or body not base64"
    for b, body, e in blocks:
        if b != e:
            return FAIL, f"BEGIN {b} closed by END {e}"
        if not body.strip():
            return FAIL, f"empty body in {b}"
    return OK, ""


_KT = r"[a-z][a-z0-9@._+-]*"
_B64 = r"((?:[A-Za-z0-9+/]{4})+(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)"
_AUTHKEY = re.compile(r'(?:(?:[^\s"]|"(?:\\.|[^"\\])*")+\s+)?' + _KT + r"\s+" + _B64 + r"(\s+.*)?")
_KNOWNHOST = re.compile(r"(?:@(?:cert-authority|revoked)\s+)?\S+\s+" + _KT + r"\s+" + _B64 + r"(\s+.*)?")


def _keylines(text: str, pattern: re.Pattern, what: str) -> tuple[str, str]:
    for n, raw in _lines(text, "#"):
        if not pattern.fullmatch(raw.strip()):
            return FAIL, f"line {n}: not {what}"
    return OK, ""


def _cnf(text: str) -> tuple[str, str]:
    """OpenSSL config (openssl.cnf, ASN1_generate_nconf input): sections and key = value lines."""
    for n, raw in _lines(text, "#"):
        line = raw.strip()
        if not re.fullmatch(r"\[\s*[A-Za-z0-9_.$ -]+\s*\]|[A-Za-z0-9_.$-]+\s*=.*", line):
            return FAIL, f"line {n}: not '[ section ]' or 'key = value'"
    return OK, ""


def check(filename: str, text: str) -> tuple[str, str]:
    """Return (status, detail); status is ok, skipped or fail."""
    if filename.endswith(".py"):
        try:
            ast.parse(text, filename=filename)
            return OK, ""
        except SyntaxError as e:
            return FAIL, f"line {e.lineno}: {e.msg}"
    if filename.endswith(".go"):
        if not shutil.which("gofmt"):
            return SKIP, "gofmt not installed"
        return _run(["gofmt", "-e", "-l"], text, ".go")
    if filename.endswith(".java"):
        if not shutil.which("javac"):
            return SKIP, "javac not installed"
        with tempfile.TemporaryDirectory() as out:
            return _run(["javac", "-d", out], text, ".java", name=filename)
    if filename.endswith(".sh"):
        return _run(["sh", "-n"], text, ".sh")
    if filename.endswith(".js"):
        if not shutil.which("node"):
            return SKIP, "node not installed"
        return _run(["node", "--check"], text, ".js")
    if filename.endswith((".c", ".h")):
        return _cc("gcc", text, filename[filename.rindex("."):])
    if filename.endswith(".cpp"):
        return _cc("g++", text, ".cpp")
    if filename.endswith(".rs"):
        if not shutil.which("rustfmt"):
            status, detail = _delims(text)
            return (SKIP, "rustfmt not installed; delimiters balanced") if status == OK else (status, detail)
        return _run(["rustfmt", "--edition", "2021", "--emit", "stdout"], text, ".rs")
    if filename.endswith(".cs"):
        return _csharp(text)
    if filename == "swanctl.conf":
        return _swanctl(text)
    if filename == "httpd.conf":
        return _apache(text)
    if filename == "fortigate.conf":
        return _fortios(text)
    if filename == "running-config":
        return _ios(text)
    if filename == "sshd_config":
        return _sshd(text)
    if filename == "nginx.conf" or filename.endswith(".conf"):
        return _nginx(text)
    if filename == "java.security":
        return _properties(text)
    if filename.endswith((".php", ".rb")):
        tool = ["php", "-l"] if filename.endswith(".php") else ["ruby", "-c"]
        if not shutil.which(tool[0]):
            return _csharp(text)
        return _run(tool, text, filename[filename.rindex("."):])
    if filename.endswith((".kt", ".swift")):
        return _csharp(text)
    if filename.endswith((".yaml", ".yml")):
        return _yaml(text)
    if filename.endswith(".json"):
        return _json(text)
    if filename.endswith((".tf", ".hcl")):
        return _hcl(text)
    if filename.endswith(".pem"):
        return _pem(text)
    if filename == "authorized_keys":
        return _keylines(text, _AUTHKEY, "'[options] keytype base64 [comment]'")
    if filename == "known_hosts":
        return _keylines(text, _KNOWNHOST, "'[@marker] hosts keytype base64 [comment]'")
    if filename.endswith(".cnf"):
        return _cnf(text)
    return FAIL, f"no syntax check for {filename!r}; add one to parsecheck.py"
