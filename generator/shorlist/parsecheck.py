"""Does a context_template parse? Syntax only, per file type; it does not compile or run.

| file                 | check                                                     |
|----------------------|-----------------------------------------------------------|
| *.py                 | ast.parse                                                 |
| *.go                 | gofmt -e (skipped when gofmt is not installed)            |
| *.java               | javac into a temp dir (skipped when javac is absent)      |
| *.sh                 | sh -n                                                     |
| nginx.conf, *.conf   | balanced braces; every statement ends in ';', '{' or '}'  |
| sshd_config          | each line is 'Keyword value', Keyword alphabetic           |
| java.security        | each line is a comment or key=value                       |

Java and Go are checked for syntax only: an import of a package the local toolchain does
not ship (e.g. crypto/mlkem before Go 1.24) does not fail gofmt; javac does resolve imports,
so it needs JDK 24 or newer for javax.crypto.KEM ML-KEM names (the class exists from JDK 21).
"""
from __future__ import annotations

import ast
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

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
    if filename == "sshd_config":
        return _sshd(text)
    if filename == "nginx.conf" or filename.endswith(".conf"):
        return _nginx(text)
    if filename == "java.security":
        return _properties(text)
    return FAIL, f"no syntax check for {filename!r}; add one to parsecheck.py"
