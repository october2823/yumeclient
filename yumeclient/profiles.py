from __future__ import annotations

from typing import Final, Literal, TypeAlias
from difflib import get_close_matches
from urllib.parse import urlsplit

ALL_IDENTIFIERS: Final[tuple[str, ...]] = (
    "chrome_103", "chrome_104", "chrome_105", "chrome_106", "chrome_107", "chrome_108", "chrome_109", "chrome_110", "chrome_111", "chrome_112", "chrome_116_PSK", "chrome_116_PSK_PQ", "chrome_117", "chrome_120", "chrome_124", "chrome_130_PSK", "chrome_131", "chrome_131_PSK", "chrome_133", "chrome_133_PSK", "chrome_144", "chrome_144_PSK", "chrome_146", "chrome_146_PSK", "chrome_150", "chrome_150_PSK", "chrome_152", "chrome_152_PSK", "brave_146", "brave_146_PSK", "safari_15_6_1", "safari_16_0", "safari_ipad_15_6", "safari_ios_15_5", "safari_ios_15_6", "safari_ios_16_0", "safari_ios_17_0", "safari_ios_18_0", "safari_ios_18_5", "safari_ios_26_0", "firefox_102", "firefox_104", "firefox_105", "firefox_106", "firefox_108", "firefox_110", "firefox_117", "firefox_120", "firefox_123", "firefox_132", "firefox_133", "firefox_135", "firefox_146_PSK", "firefox_147", "firefox_147_PSK", "firefox_148", "opera_89", "opera_90", "opera_91", "zalando_android_mobile", "zalando_ios_mobile", "nike_ios_mobile", "nike_android_mobile", "cloudscraper", "mms_ios", "mms_ios_1", "mms_ios_2", "mms_ios_3", "mesh_ios", "mesh_ios_1", "mesh_ios_2", "mesh_android", "mesh_android_1", "mesh_android_2", "confirmed_ios", "confirmed_android", "okhttp4_android_7", "okhttp4_android_8", "okhttp4_android_9", "okhttp4_android_10", "okhttp4_android_11", "okhttp4_android_12", "okhttp4_android_13",
)
ClientIdentifier: TypeAlias = Literal[tuple(ALL_IDENTIFIERS)]

ClientOs: TypeAlias = Literal["windows", "android", "ios", "macos"]
ALL_CLIENT_OS: Final[tuple[str, ...]] = ("windows", "android", "ios", "macos")


class Profiles:
    LATEST_CHROME = "chrome_152"
    CHROME_152 = "chrome_152"
    CHROME_150 = "chrome_150"
    CHROME_144 = "chrome_144"
    FIREFOX_148 = "firefox_148"
    SAFARI_IOS_26_0 = "safari_ios_26_0"

for _name in ALL_IDENTIFIERS:
    setattr(Profiles, _name.upper(), _name)


def find(value: str) -> list[str]:
    value = value.lower()
    return [item for item in ALL_IDENTIFIERS if value in item.lower()]


def validate(value: str | None) -> str:
    if value is None or value == "":
        return Profiles.LATEST_CHROME
    if value in ALL_IDENTIFIERS:
        return value
    matches = get_close_matches(value, ALL_IDENTIFIERS, n=3, cutoff=0.35)
    raise ValueError(f"unknown client_identifier {value!r}; did you mean: {', '.join(matches)}")


def validate_os(value: str | ClientOs | None, identifier: str) -> ClientOs:
    """Resolve client OS; None derives a sensible default from the identifier family."""
    if value is None or value == "":
        if "_ios" in identifier or identifier.endswith("_ios") or "ipad" in identifier:
            return "ios"
        if "_android" in identifier:
            return "android"
        if identifier in ("safari_15_6_1", "safari_16_0"):
            return "macos"
        return "windows"
    normalized = str(value).lower()
    if normalized in ALL_CLIENT_OS:
        return normalized  # type: ignore[return-value]
    raise ValueError(f"unknown client_os {value!r}; expected one of: {', '.join(ALL_CLIENT_OS)}")


def _major(identifier: str, family: str) -> str:
    rest = identifier[len(family):].lstrip("_")
    parts = [piece for piece in rest.split("_") if piece.isdigit()]
    return parts[0] if parts else "120"


def _chrome_ua(identifier: str, os_name: str) -> str:
    major = _major(identifier, "chrome" if not identifier.startswith("brave") else "brave")
    if os_name == "ios":
        return f"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/{major}.0.0.0 Mobile/15E148 Safari/604.1"
    if os_name == "android":
        return f"Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.0.0 Mobile Safari/537.36"
    if os_name == "macos":
        return f"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36"
    return f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36"


def _chrome_headers(identifier: str, os_name: str) -> dict[str, str]:
    major = _major(identifier, "chrome" if not identifier.startswith("brave") else "brave")
    brand = f'"Chromium";v="{major}", "Not(A:Brand";v="24", "Google Chrome";v="{major}"'
    headers = {
        "sec-ch-ua": brand,
        "sec-ch-ua-mobile": "?1" if os_name == "android" else "?0",
        "sec-ch-ua-platform": {"windows": '"Windows"', "android": '"Android"', "macos": '"macOS"'}.get(os_name, '"Windows"'),
        "upgrade-insecure-requests": "1",
        "user-agent": _chrome_ua(identifier, os_name),
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "sec-fetch-site": "none",
        "sec-fetch-mode": "navigate",
        "sec-fetch-user": "?1",
        "sec-fetch-dest": "document",
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": "en-US,en;q=0.9",
    }
    if os_name == "ios":
        # Chrome on iOS is WebKit-based: no client hints, CriOS UA
        return {"user-agent": _chrome_ua(identifier, os_name),
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "accept-language": "en-US,en;q=0.9",
                "accept-encoding": "gzip, deflate, br"}
    if os_name == "android":
        headers["sec-ch-ua-mobile"] = "?1"
        headers.pop("sec-fetch-user", None)
        headers.pop("upgrade-insecure-requests", None)
    return headers


def _brave_headers(identifier: str, os_name: str) -> dict[str, str]:
    headers = _chrome_headers(identifier, os_name)
    major = _major(identifier, "brave")
    headers["sec-ch-ua"] = f'"Chromium";v="{major}", "Not(A:Brand";v="24", "Brave";v="{major}"'
    return headers


def _opera_headers(identifier: str, os_name: str) -> dict[str, str]:
    major = _major(identifier, "opera")
    headers = _chrome_headers(f"chrome_{major}", os_name)
    headers["sec-ch-ua"] = f'"Chromium";v="{major}", "Not(A:Brand";v="24", "Opera";v="{major}"'
    headers["user-agent"] = _chrome_ua(f"chrome_{major}", os_name) + f" OPR/{major}.0.0.0"
    return headers


def _firefox_ua(identifier: str, os_name: str) -> str:
    version = _major(identifier, "firefox")
    if os_name == "android":
        return f"Mozilla/5.0 (Android 10; Mobile; rv:{version}.0) Gecko/{version}.0 Firefox/{version}.0"
    if os_name == "ios":
        return f"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/{version}.0 Mobile/15E148 Safari/605.1.15"
    return f"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{version}.0) Gecko/20100101 Firefox/{version}.0"


def _firefox_headers(identifier: str, os_name: str) -> dict[str, str]:
    headers = {
        "user-agent": _firefox_ua(identifier, os_name),
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "accept-language": "en-US,en;q=0.5",
        "upgrade-insecure-requests": "1",
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "none",
        "sec-fetch-user": "?1",
        "accept-encoding": "gzip, deflate, br, zstd",
    }
    if os_name == "windows":
        headers["te"] = "trailers"
    return headers


def _safari_version(identifier: str) -> tuple[str, str]:
    """(ua_token, pretty) e.g. ('18_5', '18.5'); desktop safaris map to their own."""
    known = {"safari_15_6_1": ("15_6_1", "15.6.1"), "safari_16_0": ("16_0", "16.0"), "safari_ipad_15_6": ("15_6", "15.6")}
    if identifier in known: return known[identifier]
    digits = [piece for piece in identifier.split("_") if piece.isdigit()]
    if len(digits) >= 2: return ("_".join(digits[:2]), ".".join(digits[:2]))
    return ("17_5", "17.5")


def _safari_ua(identifier: str, os_name: str) -> str:
    ua_token, pretty = _safari_version(identifier)
    if os_name == "ios" or "_ios" in identifier or "ipad" in identifier:
        device = "iPad" if "ipad" in identifier else "iPhone"
        return f"Mozilla/5.0 ({device}; CPU {'iPad' if device == 'iPad' else 'iPhone'} OS {ua_token} like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{pretty} Mobile/15E148 Safari/604.1"
    if os_name == "windows":
        return f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{pretty} Safari/605.1.15"
    return f"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{pretty} Safari/605.1.15"


def _safari_headers(identifier: str, os_name: str) -> dict[str, str]:
    return {
        "user-agent": _safari_ua(identifier, os_name),
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "accept-language": "en-US,en;q=0.9",
        "accept-encoding": "gzip, deflate, br",
    }


def _okhttp_headers(identifier: str) -> dict[str, str]:
    return {"user-agent": "okhttp/4.12.0", "accept": "*/*", "accept-encoding": "gzip"}


def _ios_webview_ua() -> str:
    return "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148"


def _app_headers(identifier: str, os_name: str) -> dict[str, str]:
    if os_name == "ios":
        return {"user-agent": _ios_webview_ua(), "accept": "*/*", "accept-encoding": "gzip, deflate, br", "accept-language": "en-US,en;q=0.9"}
    return {"user-agent": "okhttp/4.12.0", "accept": "*/*", "accept-encoding": "gzip"}


def default_headers(identifier: str, os_name: str | None = None) -> dict[str, str]:
    """Browser-plausible baseline headers for a profile; any key can be overridden."""
    os_name = validate_os(os_name, identifier)
    if identifier.startswith("chrome_") or identifier == "cloudscraper":
        return _chrome_headers(identifier if identifier != "cloudscraper" else "chrome_131", os_name)
    if identifier.startswith("brave_"):
        return _brave_headers(identifier, os_name)
    if identifier.startswith("opera_"):
        return _opera_headers(identifier, os_name)
    if identifier.startswith("firefox_"):
        return _firefox_headers(identifier, os_name)
    if identifier.startswith(("safari_", "mms_")):
        return _safari_headers(identifier, os_name)
    if identifier.startswith("okhttp4"):
        return _okhttp_headers(identifier)
    return _app_headers(identifier, os_name)


def guess_os_from_url(url: str) -> str:
    """Heuristic helper used by docs/tests: http(s) URL -> host token (unused by core)."""
    return urlsplit(url).hostname or ""
