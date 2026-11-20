#!/usr/bin/env python3
"""Patched copies of upstream Go modules (native/third_party/<name>).

native/go.mod replaces these modules with the local copies. Every copy is the upstream
module at the version required in go.mod, without tests/examples, plus the changes in
native/third_party/patches/<name>.patch (unified diff, also the review record).

    python scripts/third_party.py check   # copies == upstream + patch, nothing else (CI)
    python scripts/third_party.py diff    # rewrite patches from the edited copies
    python scripts/third_party.py sync    # fresh copies from upstream + git apply patches
                                          # (after bumping a version in go.mod)
"""
from __future__ import annotations

import difflib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NATIVE = ROOT / "native"
THIRD = NATIVE / "third_party"
PATCHES = THIRD / "patches"
MODULES = {  # local name -> module path
    "fhttp": "github.com/bogdanfinn/fhttp",
    "tls-client": "github.com/bogdanfinn/tls-client",
    "utls": "github.com/bogdanfinn/utls",
}
SKIP_DIRS = {"testdata", "tests", "example", "examples", "_examples", ".github", "docs"}
KEEP_FILES = re.compile(r"(?i)^(go\.mod|go\.sum|license.*|copying.*|patents|notice.*)$")


def _version(module: str) -> str:
    text = (NATIVE / "go.mod").read_text(encoding="utf-8")
    m = re.search(rf"^\s*(?:require\s+)?{re.escape(module)}\s+(v\S+)", text, re.M)
    if not m: sys.exit(f"{module} not required in native/go.mod")
    return m.group(1)


def _pristine(module: str, version: str) -> Path:
    out = subprocess.run(["go", "mod", "download", "-json", f"{module}@{version}"], cwd=NATIVE,
                         capture_output=True, text=True, check=True).stdout
    return Path(json.loads(out)["Dir"])


def _files(base: Path) -> dict[str, Path]:
    found = {}
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith("."))
        for name in sorted(filenames):
            if name.endswith(".go") and not name.endswith("_test.go") or KEEP_FILES.match(name):
                path = Path(dirpath) / name
                found[path.relative_to(base).as_posix()] = path
    return found


def _stray(copy: Path) -> list[str]:
    """Files in a copy that the diff does not cover (a .syso, .s, .c or embedded file
    would be built or linked without showing up in the patch)."""
    covered = set(_files(copy))
    return sorted(p.relative_to(copy).as_posix() for p in copy.rglob("*")
                  if p.is_file() and p.relative_to(copy).as_posix() not in covered)


def _read(path: Path) -> list[str]:
    return path.read_bytes().decode("utf-8").replace("\r\n", "\n").splitlines(keepends=True)


def _diff(name: str, pristine: Path, copy: Path) -> str:
    upstream, local = _files(pristine), _files(copy)
    chunks = []
    for rel in sorted(set(upstream) | set(local)):
        a = _read(upstream[rel]) if rel in upstream else []
        b = _read(local[rel]) if rel in local else []
        if a == b and (rel in upstream) == (rel in local): continue  # an added empty file differs
        fromfile = f"a/{rel}" if rel in upstream else "/dev/null"
        tofile = f"b/{rel}" if rel in local else "/dev/null"
        lines = list(difflib.unified_diff(a, b, fromfile, tofile, n=3))
        mode = ("new file mode 100644\n" if rel not in upstream else
                "deleted file mode 100644\n" if rel not in local else "")
        chunks.append(f"diff --git a/{rel} b/{rel}\n{mode}" + "".join(
            line if line.endswith("\n") else line + "\n\\ No newline at end of file\n" for line in lines))
    return "".join(chunks)


def _copy(pristine: Path, dest: Path) -> None:
    if dest.exists(): shutil.rmtree(dest)
    for rel, src in _files(pristine).items():
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(src.read_bytes().replace(b"\r\n", b"\n"))


def main(argv: list[str]) -> int:
    command = argv[1] if len(argv) > 1 else "check"
    failed = False
    for name, module in MODULES.items():
        version = _version(module)
        pristine, copy, patch = _pristine(module, version), THIRD / name, PATCHES / f"{name}.patch"
        if command == "sync":
            # patched in a temporary copy: a patch that does not apply leaves the old copy
            fresh = THIRD / f".{name}.sync"
            _copy(pristine, fresh)
            try:
                if patch.exists() and patch.stat().st_size:
                    subprocess.run(["git", "apply", "--whitespace=nowarn",
                                    f"--directory={fresh.relative_to(ROOT).as_posix()}", str(patch)],
                                   cwd=ROOT, check=True)
            except BaseException:
                shutil.rmtree(fresh, ignore_errors=True)
                raise
            if copy.exists(): shutil.rmtree(copy)
            fresh.rename(copy)
            print(f"synced {name} {version}")
        elif command == "diff":
            PATCHES.mkdir(parents=True, exist_ok=True)
            text = _diff(name, pristine, copy)
            patch.write_text(f"# {module} {version}\n" + text if text else "", encoding="utf-8", newline="\n")
            print(f"{name}: {text.count(chr(10)) if text else 0} patch lines")
        elif command == "check":
            if not copy.is_dir():
                print(f"MISSING {copy}"); failed = True; continue
            text = _diff(name, pristine, copy)
            want = f"# {module} {version}\n" + text if text else ""
            have = patch.read_text(encoding="utf-8").replace("\r\n", "\n") if patch.exists() else ""
            stray = _stray(copy)
            if stray:
                print(f"UNEXPECTED {name}: files outside the compared set: {', '.join(stray[:10])}"); failed = True
            elif want != have:
                print(f"MISMATCH {name}: copy differs from upstream {version} + {patch.name}; "
                      "run `python scripts/third_party.py diff` and review"); failed = True
            else:
                print(f"OK {name} {version} ({len(_files(copy))} files, {text.count(chr(10))} patch lines)")
        else:
            sys.exit(__doc__)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
