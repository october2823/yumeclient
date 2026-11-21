"""The examples run end to end against a local httpbin stand-in, and every Python snippet
in the documentation at least compiles."""
from __future__ import annotations

import ast
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

import yumeclient
from httpbin_local import HTTPBin
from socks5udp import Socks5

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = sorted((ROOT / "examples").glob("*.py"))
# every Markdown page in both languages: docs/ and docs/ru/, README/USAGE/... and their .ru.md
DOCS = sorted([*(ROOT / "docs").rglob("*.md"), *ROOT.glob("*.md"), *(ROOT / "examples").glob("*.md"),
               *(ROOT / ".github").rglob("*.md")])


@pytest.fixture(scope="module")
def native():
    try:
        yumeclient.Session(timeout=5).close()
    except yumeclient.TLSClientError as exc:
        pytest.skip(f"native library unavailable: {exc}")


@pytest.fixture(scope="module")
def httpbin():
    srv = HTTPBin()
    yield srv
    srv.close()


@pytest.mark.parametrize("example", EXAMPLES, ids=lambda p: p.stem)
def test_example_runs(example, httpbin, native):
    env = {**os.environ, "HTTPBIN": httpbin.url, "PYTHONPATH": str(ROOT), "PYTHONIOENCODING": "utf-8"}
    proxy = None
    if example.stem == "proxies":
        proxy = Socks5()
        env["PROXY"] = proxy.url
    try:
        result = subprocess.run([sys.executable, str(example)], env=env, cwd=ROOT, capture_output=True,
                                text=True, encoding="utf-8", timeout=120)
    finally:
        if proxy:
            proxy.close()
    assert result.returncode == 0, result.stdout[-2000:] + result.stderr[-4000:]
    assert "Traceback" not in result.stderr, result.stderr[-4000:]
    assert result.stdout.strip()


def _snippets(path: Path):
    text = path.read_text(encoding="utf-8")
    for match in re.finditer(r"^```python\n(.*?)^```", text, re.S | re.M):
        line = text.count("\n", 0, match.start()) + 2
        yield line, match.group(1)


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: p.name)
def test_doc_snippets_compile(doc):
    if not doc.exists():
        pytest.skip(f"{doc.name} missing")
    for line, code in _snippets(doc):
        try:
            compile(code, f"{doc.name}:{line}", "exec", flags=ast.PyCF_ALLOW_TOP_LEVEL_AWAIT)
        except SyntaxError as exc:
            pytest.fail(f"{doc.name}:{line + (exc.lineno or 1) - 1}: {exc.msg}\n{code}")


def test_docs_link_to_existing_pages():
    for doc in DOCS:
        if not doc.exists():
            continue
        text = doc.read_text(encoding="utf-8")
        for target in re.findall(r"\]\(([^)#\s]+)(?:#[^)]*)?\)", text):
            repo = re.match(r"https://github\.com/october2823/yumeclient/(?:blob|tree)/main/(.*)", target)
            if repo:  # README: absolute links, so they work on PyPI too
                target = str(ROOT / repo.group(1))
            elif target.startswith(("http://", "https://", "mailto:")):
                continue
            path = doc.parent / target
            assert path.exists(), f"{doc.name} links to missing {target}"
