"""Download real browser builds and record their HTTP/3 fingerprint with h3_capture.

  python scripts/h3_browsers.py chrome 103 104 ... [--cache DIR] [--out DIR]
  python scripts/h3_browsers.py firefox 102.0 120.0 ... [--cache DIR] [--out DIR]
  python scripts/h3_browsers.py opera 89.0.4447.38 ...

Chrome 113+ comes from Chrome for Testing, older milestones from Chromium snapshots at the
milestone's branch position (unbranded Chromium, same network stack). Windows x64 only.
Every capture records the exact build it came from.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import h3_capture  # noqa: E402

CFT = "https://googlechromelabs.github.io/chrome-for-testing/known-good-versions-with-downloads.json"
DASH = "https://chromiumdash.appspot.com/fetch_releases?channel=Stable&platform=Windows&num=1&milestone={}"
SNAP = "https://www.googleapis.com/storage/v1/b/chromium-browser-snapshots/o?prefix=Win_x64/{}&delimiter=/"
SNAP_FILE = "https://storage.googleapis.com/chromium-browser-snapshots/Win_x64/{}/chrome-win.zip"
FIREFOX = "https://archive.mozilla.org/pub/firefox/releases/{0}/win64/en-US/Firefox%20Setup%20{0}.exe"
OPERA = "https://get.geo.opera.com/pub/opera/desktop/{0}/win/Opera_{0}_Setup_x64.exe"
SEVENZIP = r"C:\Program Files\7-Zip\7z.exe"


def _json(url: str):
    with urllib.request.urlopen(url, timeout=60) as r:
        return json.load(r)


def _download(url: str, dest: Path) -> Path:
    if dest.exists() and dest.stat().st_size:
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    print(f"  download {url}", flush=True)
    with urllib.request.urlopen(url, timeout=600) as r, open(tmp, "wb") as f:
        while chunk := r.read(1 << 20):
            f.write(chunk)
    tmp.replace(dest)
    return dest


def _find(root: Path, name: str) -> Path:
    for p in root.rglob(name):
        return p
    raise FileNotFoundError(f"{name} not in {root}")


def chrome_build(milestone: int, cache: Path) -> tuple[Path, dict]:
    if milestone >= 113:
        versions = [v for v in _json(CFT)["versions"] if v["version"].split(".")[0] == str(milestone)
                    and any(d["platform"] == "win64" for d in v.get("downloads", {}).get("chrome", []))]
        v = versions[-1]
        url = next(d["url"] for d in v["downloads"]["chrome"] if d["platform"] == "win64")
        build = {"source": "chrome-for-testing", "version": v["version"], "url": url}
        target = cache / f"chrome-{v['version']}"
    else:
        rel = _json(DASH.format(milestone))[0]
        base = int(rel["chromium_main_branch_position"])
        pos = None
        for digits in (5, 4, 3):
            prefix = str(base)[:digits]
            listing = _json(SNAP.format(prefix))
            found = sorted(int(p.split("/")[1]) for p in listing.get("prefixes", []) if p.split("/")[1].isdigit())
            below = [p for p in found if p <= base]
            if below:
                pos = below[-1]
                break
        if pos is None:
            raise RuntimeError(f"no snapshot at or below {base}")
        url = SNAP_FILE.format(pos)
        build = {"source": "chromium-snapshot", "milestone_version": rel["version"],
                 "branch_position": base, "snapshot_position": pos, "url": url}
        target = cache / f"chromium-{milestone}-{pos}"
    if not target.exists():
        archive = _download(url, cache / "dl" / (target.name + ".zip"))
        with zipfile.ZipFile(archive) as z:
            z.extractall(target)
    return _find(target, "chrome.exe"), build


def firefox_build(version: str, cache: Path) -> tuple[Path, dict]:
    url = FIREFOX.format(version)
    target = cache / f"firefox-{version}"
    if not target.exists():
        archive = _download(url, cache / "dl" / f"firefox-{version}.exe")
        subprocess.run([SEVENZIP, "x", "-y", f"-o{target}", str(archive)], check=True, stdout=subprocess.DEVNULL)
    return _find(target, "firefox.exe"), {"source": "mozilla-archive", "version": version, "url": url}


def opera_build(version: str, cache: Path) -> tuple[Path, dict]:
    url = OPERA.format(version)
    target = cache / f"opera-{version}"
    if not target.exists():
        archive = _download(url, cache / "dl" / f"opera-{version}.exe")
        subprocess.run([SEVENZIP, "x", "-y", f"-o{target}", str(archive)], check=True, stdout=subprocess.DEVNULL)
    return _find(target, "opera.exe"), {"source": "opera-archive", "version": version, "url": url}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("browser", choices=["chrome", "firefox", "opera"])
    ap.add_argument("versions", nargs="+")
    ap.add_argument("--cache", default=os.environ.get("YC_BROWSER_CACHE", "browsers"))
    ap.add_argument("--out", default="h3_captures")
    ap.add_argument("--headless", default=None)
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("--chrome-flag", action="append", default=[],
                    help="extra Chromium switch, e.g. --enable-features=PostQuantumKyber")
    ap.add_argument("--tag", default="", help="suffix of the capture file names, e.g. pq")
    args = ap.parse_args()
    cache, out = Path(args.cache), Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for v in args.versions:
        try:
            if args.browser == "chrome":
                exe, build = chrome_build(int(v), cache)
                headless = args.headless or ("new" if int(v) >= 112 else "old")
            elif args.browser == "opera":
                exe, build = opera_build(v, cache)
                headless = args.headless or "old"
            else:
                exe, build = firefox_build(v, cache)
                headless = args.headless or "yes"
            for i in range(args.repeat):
                if args.browser == "firefox":
                    cap = h3_capture.capture_firefox(str(exe), headless != "none")
                else:
                    cap = h3_capture.capture_chrome(str(exe), headless, extra_args=args.chrome_flag)
                cap["build"] = build
                tag = f"_{args.tag}" if args.tag else ""
                name = f"{args.browser}_{v}{tag}" + (f"_{i}" if args.repeat > 1 else "") + ".json"
                (out / name).write_text(json.dumps(cap, indent=1, ensure_ascii=False), encoding="utf-8")
                fp = h3_capture.fingerprint(cap) if cap["connections"] else {}
                print(f"{name}: ok={cap['ok']} conns={len(cap['connections'])} ja4={fp.get('tls.ja4')} "
                      f"version={cap['client'].get('version')}", flush=True)
        except Exception as exc:  # noqa: BLE001 - keep going, report
            print(f"{args.browser} {v}: FAILED {exc!r}", flush=True)


if __name__ == "__main__":
    main()
