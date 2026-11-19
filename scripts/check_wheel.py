#!/usr/bin/env python3
"""Verify that every built wheel ships exactly one native library matching its platform tag.

Catches the 0.4.7 packaging defects:
  * a Windows PE image shipped as ``yumeclient.so`` next to ``yumeclient.dll``;
  * a thin arm64 dylib with LC_BUILD_VERSION minos 26.0 inside a wheel tagged
    ``macosx_26_0_universal2`` (uninstallable on macOS < 26, unloadable on Intel).

Usage: python scripts/check_wheel.py dist/*.whl
Exit code is non-zero when any wheel fails; one line per wheel is printed.
"""
from __future__ import annotations

import re
import struct
import sys
import zipfile
from pathlib import Path

NATIVE_SUFFIXES = (".dll", ".so", ".dylib")
ELF_MACHINES = {62: "x86_64", 183: "aarch64"}
PE_MACHINES = {0x8664: "x86_64", 0xAA64: "aarch64"}
MACHO_CPUS = {0x01000007: "x86_64", 0x0100000C: "arm64"}


class WheelError(Exception):
    pass


def _macho_thin(data: bytes, offset: int) -> tuple[str, tuple[int, int] | None]:
    magic, cpu = struct.unpack_from("<II", data, offset)
    if magic != 0xFEEDFACF:
        raise WheelError(f"unexpected Mach-O slice magic {magic:#x}")
    ncmds = struct.unpack_from("<I", data, offset + 16)[0]
    pos, minos = offset + 32, None
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", data, pos)
        if cmd == 0x32:  # LC_BUILD_VERSION: platform, minos
            value = struct.unpack_from("<I", data, pos + 12)[0]
            minos = (value >> 16, (value >> 8) & 0xFF)
        elif cmd == 0x24:  # LC_VERSION_MIN_MACOSX
            value = struct.unpack_from("<I", data, pos + 8)[0]
            minos = (value >> 16, (value >> 8) & 0xFF)
        pos += size
    return MACHO_CPUS.get(cpu, hex(cpu)), minos


def describe_binary(data: bytes) -> dict[str, object]:
    """Return {'format': 'PE'|'ELF'|'Mach-O', 'arches': [...], 'minos': (major, minor)|None}."""
    if data[:2] == b"MZ":
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe:pe + 4] != b"PE\0\0":
            raise WheelError("MZ header without PE signature")
        machine = struct.unpack_from("<H", data, pe + 4)[0]
        return {"format": "PE", "arches": [PE_MACHINES.get(machine, hex(machine))], "minos": None}
    if data[:4] == b"\x7fELF":
        machine = struct.unpack_from("<H", data, 18)[0]
        return {"format": "ELF", "arches": [ELF_MACHINES.get(machine, str(machine))], "minos": None}
    if data[:4] == b"\xca\xfe\xba\xbe":  # fat Mach-O (big-endian header)
        count = struct.unpack_from(">I", data, 4)[0]
        slices = [_macho_thin(data, struct.unpack_from(">IIIII", data, 8 + 20 * i)[2]) for i in range(count)]
        versions = [m for _, m in slices if m is not None]
        return {"format": "Mach-O", "arches": sorted(a for a, _ in slices), "minos": max(versions) if versions else None}
    if data[:4] == b"\xcf\xfa\xed\xfe":
        arch, minos = _macho_thin(data, 0)
        return {"format": "Mach-O", "arches": [arch], "minos": minos}
    raise WheelError(f"unknown binary magic {data[:4].hex()}")


def expected_for(platform_tag: str) -> tuple[str, str, list[str], tuple[int, int] | None]:
    """Map a wheel platform tag to (filename, format, arches, max minos)."""
    if platform_tag == "win_amd64":
        return "yumeclient.dll", "PE", ["x86_64"], None
    if platform_tag == "win_arm64":
        return "yumeclient.dll", "PE", ["aarch64"], None
    linux = re.fullmatch(r"(?:linux|manylinux\d+|manylinux_\d+_\d+|musllinux_\d+_\d+)_(x86_64|aarch64)", platform_tag)
    if linux:
        return "yumeclient.so", "ELF", [linux.group(1)], None
    mac = re.fullmatch(r"macosx_(\d+)_(\d+)_(universal2|arm64|x86_64)", platform_tag)
    if mac:
        arches = ["arm64", "x86_64"] if mac.group(3) == "universal2" else [mac.group(3)]
        return "yumeclient.dylib", "Mach-O", arches, (int(mac.group(1)), int(mac.group(2)))
    raise WheelError(f"unsupported platform tag {platform_tag}")


def check_wheel(path: Path) -> str:
    match = re.fullmatch(r"(?P<name>[^-]+)-(?P<ver>[^-]+)(-\d[^-]*)?-(?P<py>[^-]+)-(?P<abi>[^-]+)-(?P<plat>[^-]+)\.whl", path.name)
    if not match:
        raise WheelError("filename is not a wheel name")
    if (match["py"], match["abi"]) != ("py3", "none"):
        raise WheelError(f"expected py3-none (ctypes package, no CPython ABI), got {match['py']}-{match['abi']}")
    with zipfile.ZipFile(path) as archive:
        natives = [n for n in archive.namelist() if n.startswith("yumeclient/") and n.endswith(NATIVE_SUFFIXES)]
        if any(n.endswith(".h") for n in archive.namelist()):
            raise WheelError("cgo header shipped in wheel")
        results = []
        for platform_tag in match["plat"].split("."):
            filename, fmt, arches, max_minos = expected_for(platform_tag)
            if natives != [f"yumeclient/{filename}"]:
                raise WheelError(f"{platform_tag}: expected only yumeclient/{filename}, found {natives}")
            info = describe_binary(archive.read(natives[0]))
            if info["format"] != fmt or sorted(info["arches"]) != sorted(arches):
                raise WheelError(f"{platform_tag}: binary is {info['format']} {info['arches']}, expected {fmt} {arches}")
            if max_minos is not None and (info["minos"] is None or info["minos"] > max_minos):
                raise WheelError(f"{platform_tag}: dylib minos {info['minos']} is newer than the wheel tag {max_minos}")
            results.append(f"{platform_tag}={info['format']}/{'+'.join(info['arches'])}"
                           + (f"/minos {info['minos'][0]}.{info['minos'][1]}" if info["minos"] else ""))
    return ", ".join(results)


def main(argv: list[str]) -> int:
    paths = [Path(p) for p in argv]
    if not paths:
        print("usage: check_wheel.py WHEEL...", file=sys.stderr)
        return 2
    failed = 0
    for path in paths:
        try:
            print(f"OK   {path.name}: {check_wheel(path)}")
        except (WheelError, OSError, zipfile.BadZipFile, struct.error) as exc:
            failed += 1
            print(f"FAIL {path.name}: {exc}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
