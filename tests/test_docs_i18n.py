"""The documentation exists in English and in Russian, and both versions have the same shape.

English lives at the standard paths (README.md, USAGE.md, docs/*.md, ...), Russian next to it
(README.ru.md, USAGE.ru.md, docs/ru/*.md, ...). A page changed in one language and not in the
other usually shows up here as a different number of headings, code blocks, table rows, list
items or links. Anchors (`page.md#section`) are checked in both languages."""
from __future__ import annotations

import io
import re
import tokenize
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
REPO_URL = re.compile(r"https://github\.com/october2823/yumeclient/(?:blob|tree)/main/(.*)")
CYRILLIC = re.compile(r"[А-Яа-яЁё]")
ROOT_PAGES = ("README", "USAGE", "CHANGELOG", "CONTRIBUTING", "SECURITY", "CODE_OF_CONDUCT", "ACCESSIBILITY")


def _pairs() -> list[tuple[Path, Path]]:
    names = {p.name for p in (ROOT / "docs").glob("*.md")} | {p.name for p in (ROOT / "docs" / "ru").glob("*.md")}
    pairs = [(ROOT / "docs" / n, ROOT / "docs" / "ru" / n) for n in sorted(names)]
    pairs += [(ROOT / f"{n}.md", ROOT / f"{n}.ru.md") for n in ROOT_PAGES]
    pairs.append((ROOT / "examples" / "README.md", ROOT / "examples" / "README.ru.md"))
    return pairs


PAIRS = _pairs()
ALL_DOCS = sorted({p for pair in PAIRS for p in pair} | set((ROOT / ".github").rglob("*.md")))


def _rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


class Page:
    """The parts of a Markdown page that must match between translations."""

    def __init__(self, path: Path):
        self.path = path
        self.lines = path.read_text(encoding="utf-8").splitlines()
        self.headings: list[tuple[int, str]] = []
        self.blocks: list[tuple[str, str]] = []
        self.prose: list[str] = []          # lines outside code blocks
        fence, lang, body = None, "", []
        for line in self.lines:
            stripped = line.strip()
            if fence is None:
                m = re.match(r"(`{3,})(\S*)", stripped)
                if m:
                    fence, lang, body = m.group(1), m.group(2), []
                    continue
                self.prose.append(line)
                h = re.match(r"(#{1,6})\s+(.*?)\s*$", line)
                if h:
                    self.headings.append((len(h.group(1)), h.group(2)))
            elif stripped == fence:
                self.blocks.append((lang, "\n".join(body) + "\n"))
                fence = None
            else:
                body.append(line)
        self.links = [m for line in self.prose for m in re.findall(r"\]\(([^)\s]+)\)", line)]
        self.table_rows = sum(1 for line in self.prose if line.lstrip().startswith("|"))
        self.list_items = sum(1 for line in self.prose if re.match(r"\s*(?:[-*]|\d+\.)\s", line))

    def anchors(self) -> set[str]:
        """GitHub heading ids: lower case, punctuation dropped, spaces become hyphens."""
        seen: dict[str, int] = {}
        out = set()
        for _level, text in self.headings:
            text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
            text = re.sub(r"<[^>]+>", "", text).replace("`", "").replace("*", "")
            slug = re.sub(r"[^\w\- ]", "", text.strip().lower()).replace(" ", "-")
            n = seen.get(slug, 0)
            seen[slug] = n + 1
            out.add(slug if n == 0 else f"{slug}-{n}")
        return out


def _switcher(page: Page) -> int:
    """Index of the language switcher line (the first non-empty line after the title)."""
    for i, line in enumerate(page.lines[1:], 1):
        if line.strip():
            return i
    return -1


def _target(page: Path, link: str) -> Path | None:
    repo = REPO_URL.match(link)
    if repo:
        return ROOT / repo.group(1)
    if re.match(r"[a-z]+:", link):
        return None
    return (page.parent / link).resolve()


def _python_tokens(code: str) -> list[tuple[int, str]]:
    toks = tokenize.generate_tokens(io.StringIO(code).readline)
    return [(t.type, t.string) for t in toks
            if t.type not in (tokenize.COMMENT, tokenize.NL, tokenize.NEWLINE, tokenize.ENDMARKER)]


def _shell_code(code: str) -> list[str]:
    return [line for line in (re.sub(r"(^|\s)#.*$", "", line).rstrip() for line in code.splitlines()) if line]


@pytest.mark.parametrize("en,ru", PAIRS, ids=lambda p: _rel(p) if isinstance(p, Path) else p)
def test_translation_has_same_shape(en: Path, ru: Path):
    assert en.exists(), f"{_rel(en)} missing (English version of {_rel(ru)})"
    assert ru.exists(), f"{_rel(ru)} missing (Russian version of {_rel(en)})"
    a, b = Page(en), Page(ru)
    where = f"{_rel(en)} vs {_rel(ru)}"
    assert [lvl for lvl, _ in a.headings] == [lvl for lvl, _ in b.headings], \
        f"{where}: headings differ\n{a.headings}\n{b.headings}"
    assert [lang for lang, _ in a.blocks] == [lang for lang, _ in b.blocks], f"{where}: code blocks differ"
    for i, ((lang, code_en), (_, code_ru)) in enumerate(zip(a.blocks, b.blocks)):
        label = f"{where}: code block {i + 1} ({lang or 'plain'})"
        if lang == "python":
            ta, tb = _python_tokens(code_en), _python_tokens(code_ru)
            assert len(ta) == len(tb), f"{label}: different code\n{code_en}\n{code_ru}"
            for x, y in zip(ta, tb):
                translated = x[0] == y[0] == tokenize.STRING and CYRILLIC.search(y[1])
                assert x == y or translated, f"{label}: {x[1]!r} != {y[1]!r}"
        elif lang in ("bash", "sh", "powershell", "console"):
            assert _shell_code(code_en) == _shell_code(code_ru), f"{label}: different commands"
        else:
            assert code_en.count("\n") == code_ru.count("\n"), f"{label}: different number of lines"
    assert a.table_rows == b.table_rows, f"{where}: table rows {a.table_rows} != {b.table_rows}"
    assert a.list_items == b.list_items, f"{where}: list items {a.list_items} != {b.list_items}"
    assert len(a.links) == len(b.links), f"{where}: links {len(a.links)} != {len(b.links)}"


@pytest.mark.parametrize("en,ru", PAIRS, ids=lambda p: _rel(p) if isinstance(p, Path) else p)
def test_language_switcher(en: Path, ru: Path):
    if not (en.exists() and ru.exists()):
        pytest.skip("pair incomplete")
    a, b = Page(en), Page(ru)
    line_en, line_ru = a.lines[_switcher(a)], b.lines[_switcher(b)]
    m = re.fullmatch(r"\*\*English\*\* \| \[Русский\]\((\S+)\)", line_en)
    assert m and _target(en, m.group(1)) == ru.resolve(), f"{_rel(en)}: switcher {line_en!r}"
    m = re.fullmatch(r"\[English\]\((\S+)\) \| \*\*Русский\*\*", line_ru)
    assert m and _target(ru, m.group(1)) == en.resolve(), f"{_rel(ru)}: switcher {line_ru!r}"


@pytest.mark.parametrize("en", [en for en, _ in PAIRS], ids=_rel)
def test_english_pages_have_no_russian(en: Path):
    if not en.exists():
        pytest.skip("missing")
    page = Page(en)
    skip = _switcher(page)
    bad = [f"{i + 1}: {line}" for i, line in enumerate(page.lines) if i != skip and CYRILLIC.search(line)]
    assert not bad, f"{_rel(en)} has untranslated text:\n" + "\n".join(bad[:20])


@pytest.mark.parametrize("doc", ALL_DOCS, ids=_rel)
def test_anchors_exist(doc: Path):
    if not doc.exists():
        pytest.skip("missing")
    page = Page(doc)
    for link in page.links:
        target, _, anchor = link.partition("#")
        if not anchor:
            continue
        path = doc.resolve() if not target else _target(doc, target)
        if path is None or path.suffix != ".md":
            continue
        assert path.exists(), f"{_rel(doc)} links to missing {link}"
        assert anchor in Page(path).anchors(), f"{_rel(doc)} links to missing anchor {link}"
