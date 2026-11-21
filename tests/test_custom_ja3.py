"""Custom JA3 sessions: what the JA3 string cannot carry.

fill_custom_with_chrome_defaults=True (default) takes extension contents and the HTTP/2 /
HTTP/3 parameters the caller did not pass from Profiles.LATEST_CHROME; False uses the
generic values. Before 0.7.0 the flag never reached the native layer, a JA3 with
compress_certificate (27) failed with "unknown ClientHelloID: Custom-ja3" after upstream
printed to stdout, and priority_frames / header_priority were dropped.
"""
from __future__ import annotations

import json
import ssl
import struct
import warnings
from pathlib import Path

import pytest

import yumeclient
from yumeclient import Profiles, Session, SessionConfigurationError

from test_protocol import H2Server
from test_wire import Sniffer, parse_hello

FIXTURES = Path(__file__).resolve().parent / "fixtures"
# Chrome's JA3 (extension order fixed), no other option given
CHROME_JA3 = ("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,"
              "0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17613-65037-21,4588-29-23-24,0")
GENERIC_SIGALGS = [0x0403, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601]
LEGACY_AKAMAI = "1:65536;2:0;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p"


@pytest.fixture(scope="module")
def sniffer():
    try:
        Session(timeout=5).close()
    except yumeclient.TLSClientError as exc:
        pytest.skip(f"native library unavailable: {exc}")
    s = Sniffer()
    yield s
    s.close()


@pytest.fixture()
def h2(sniffer):
    s = H2Server()
    yield s
    s.close()


def _hello(sniffer, **options):
    start = len(sniffer.hellos)
    with Session(verify=False, timeout=5, **options) as s:
        r = s.get(f"https://localhost:{sniffer.port}/x")
    assert r.status_code == 200
    return parse_hello(sniffer.hellos[start]), r


def _chrome_hello(sniffer):
    return _hello(sniffer, client_identifier=Profiles.LATEST_CHROME)[0]


def _alps(ext: bytes) -> list[str]:
    out, q = [], 2
    while q < len(ext):
        out.append(ext[q + 1:q + 1 + ext[q]].decode()); q += 1 + ext[q]
    return out


def test_chrome_fill_matches_the_chrome_profile(sniffer, capfd):
    custom, _ = _hello(sniffer, ja3_string=CHROME_JA3)
    chrome = _chrome_hello(sniffer)
    real = [v for v in chrome["sig"] if v & 0x0F0F != 0x0A0A]  # Chrome GREASEs signature algorithms too
    assert [v for v in custom["sig"] if v & 0x0F0F != 0x0A0A] == real and real[0] == 0x0904
    assert [v for v in custom["versions"] if v & 0x0F0F != 0x0A0A] == [0x0304, 0x0303]
    assert custom["alpn_list"] == chrome["alpn_list"] == ["h2", "http/1.1"]
    assert _alps(custom["exts"][17613]) == _alps(chrome["exts"][17613]) == ["h2"]
    assert custom["exts"][27] == chrome["exts"][27]  # compress_certificate: brotli
    assert [g for g, _ in custom["key_share"]] == [g for g, _ in chrome["key_share"] if g & 0x0F0F != 0x0A0A]
    ech = custom["exts"][65037]
    assert ech[:5] == chrome["exts"][65037][:5]  # outer, kdf, aead (config id and the rest are random)
    assert "attention" not in capfd.readouterr().out  # upstream printed this to stdout


def test_generic_values_without_chrome_fill(sniffer, capfd):
    custom, _ = _hello(sniffer, ja3_string=CHROME_JA3, fill_custom_with_chrome_defaults=False)
    assert custom["sig"] == GENERIC_SIGALGS
    assert custom["exts"][27] == b"\x02\x00\x02"  # brotli is the generic value too
    assert 17613 in custom["exts"]
    assert "attention" not in capfd.readouterr().out


def test_explicit_options_win_over_chrome(sniffer):
    custom, _ = _hello(sniffer, ja3_string=CHROME_JA3, supported_signature_algorithms=["0403", "0804"],
                       cert_compression_algos=["zlib"], alpn_protocols=["http/1.1"])
    assert custom["sig"] == [0x0403, 0x0804] and custom["alpn_list"] == ["http/1.1"]
    assert custom["exts"][27] == b"\x02\x00\x01"


def test_record_size_limit_gets_a_valid_value(sniffer):
    ja3 = "771,4865-4867-4866-49195-49199,0-23-65281-10-11-16-5-34-51-43-13-45-28,29-23-24,0"
    custom, _ = _hello(sniffer, ja3_string=ja3)
    assert custom["exts"][28] == struct.pack(">H", 0x4001)  # 0 is invalid (RFC 8449: >= 64)


def test_http2_parameters(h2):
    def akamai(**options):
        with Session(ja3_string=CHROME_JA3, verify=False, timeout=5, http_version="2", **options) as s:
            r = s.get(f"https://127.0.0.1:{h2.port}/a")
        assert r.used_protocol == "HTTP/2.0"
        return r.fingerprint["akamai_fingerprint"]

    with Session(client_identifier=Profiles.LATEST_CHROME, verify=False, timeout=5, http_version="2") as s:
        chrome = s.get(f"https://127.0.0.1:{h2.port}/a").fingerprint["akamai_fingerprint"]
    assert akamai() == chrome
    assert akamai(fill_custom_with_chrome_defaults=False) == LEGACY_AKAMAI
    assert akamai(h2_settings={"HEADER_TABLE_SIZE": 4096}, h2_settings_order=["HEADER_TABLE_SIZE"]
                  ).startswith("1:4096|15663105|")


def test_priority_frames_and_header_priority_reach_the_wire(h2):
    with Session(ja3_string=CHROME_JA3, verify=False, timeout=5, http_version="2",
                 header_priority={"streamDep": 0, "exclusive": False, "weight": 200},
                 priority_frames=[{"streamID": 3, "priorityParam": {"streamDep": 0, "exclusive": False, "weight": 100}}]
                 ) as s:
        r = s.get(f"https://127.0.0.1:{h2.port}/a")
    assert r.fingerprint["akamai_fingerprint"].split("|")[2] == "3:0:0:101"
    priority = [f for f in h2.frames if f[0] == 2]
    assert [(f[2], f[3]) for f in priority] == [(3, b"\x00\x00\x00\x00\x64")]
    headers = next(f for f in h2.frames if f[0] == 1)
    assert headers[1] & 0x20 and headers[3][:5] == b"\x00\x00\x00\x00\xc8"  # PRIORITY flag, dep 0, weight 200


def test_chrome_fill_header_priority(h2):
    with Session(ja3_string=CHROME_JA3, verify=False, timeout=5, http_version="2") as s:
        s.get(f"https://127.0.0.1:{h2.port}/a")
    headers = next(f for f in h2.frames if f[0] == 1)
    assert headers[1] & 0x20 and headers[3][:5] == b"\x80\x00\x00\x00\xff"  # exclusive, dep 0, weight 256


def test_http3_warning_depends_on_the_fill():
    with warnings.catch_warnings(record=True) as seen:
        warnings.simplefilter("always")
        Session(ja3_string=CHROME_JA3, http_version="3")._core._flags(None)
        assert not [w for w in seen if "HTTP/3" in str(w.message)]
        Session(ja3_string=CHROME_JA3, http_version="3", fill_custom_with_chrome_defaults=False)._core._flags(None)
        assert [w for w in seen if "HTTP/3" in str(w.message)]


@pytest.mark.parametrize("identifier", ["chrome_152", "chrome_146_PSK", "brave_146", "firefox_148", "chrome_133",
                                        "chrome_103", "edge_131", "opera_91", "firefox_102", "chrome_116_PSK_PQ"])
def test_profiles_with_http3_parameters_do_not_warn(identifier):
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        Session(client_identifier=identifier, http_version="3")._core._flags(None)


@pytest.mark.parametrize("identifier", ["safari_ios_18_0", "zalando_ios_mobile", "mesh_android"])
def test_profiles_without_http3_parameters_warn(identifier):
    with pytest.warns(UserWarning, match="HTTP/3"):
        Session(client_identifier=identifier, http_version="3")._core._flags(None)


@pytest.mark.parametrize("identifier", ["okhttp4_android_13", "okhttp4_conscrypt", "conscrypt_android_latest",
                                        "cloudscraper", "tor_145"])
def test_clients_without_http3_reject_it(identifier):
    with pytest.raises(SessionConfigurationError, match="never sends HTTP/3"):
        Session(client_identifier=identifier, http_version="3")
    with pytest.raises(SessionConfigurationError, match="never sends HTTP/3"):  # per-request check
        yumeclient._validateTransport(http_version="3", force_http1=False, disable_http3=False, proxy=None,
                                      client_identifier=identifier)


def test_chrome_157_capture_fixture_is_consistent():
    # Chrome 157 sends Chrome 144's HTTP/3 SETTINGS and the same TLS / HTTP/2 shape as
    # chrome_152
    data = json.loads((FIXTURES / "chrome_157_wire.json").read_text(encoding="utf-8"))
    assert data["http3"]["settings"][:4] == [[1, 65536], [6, 262144], [7, 100], [51, 1]]
    assert data["http2"]["frames"][:2] == ["SETTINGS 1:65536;2:0;4:6291456;6:262144", "WINDOW_UPDATE stream=0 inc=15663105"]
    profiles = json.loads((FIXTURES / "profiles.json").read_text(encoding="utf-8"))["profiles"]
    ours = profiles["chrome_152_PSK"]["ja4_r"].split("_")
    real = data["tls"]["ja4_r"].split("_")
    assert ours[1] == real[1] and ours[3] == real[3]  # ciphers and signature algorithms
    assert set(real[2].split(",")) - set(ours[2].split(",")) == {"0029"}  # pre_shared_key (resumed)


def test_numeric_key_share_and_version_ids(sniffer):
    # GREASE ids used to map to X25519MLKEM768 (a second 1216-byte share, handshake failure)
    # and 25497 (X25519Kyber768Draft00) to X25519MLKEM768
    ja3 = "771,4865-4866-4867-49195,0-23-65281-10-11-16-13-51-45-43,10794-4588-29-23,0"
    custom, _ = _hello(sniffer, ja3_string=ja3, key_share_curves=[0x2A2A, 4588, "29"],
                       supported_versions=[0x7A7A, 772, "1.2"])
    shares = custom["key_share"]
    assert [g for g, _ in shares[1:]] == [4588, 29] and shares[0][0] & 0x0F0F == 0x0A0A and shares[0][1] == 1
    assert custom["versions"][1:] == [0x0304, 0x0303] and custom["versions"][0] & 0x0F0F == 0x0A0A
    assert yumeclient._normalizeCurveName(25497) == "X25519Kyber768"
    assert yumeclient._normalizeCurveName(25) == "P521" and yumeclient._normalizeCurveName("0x11ec") == "X25519MLKEM768"


@pytest.mark.parametrize("option", [dict(key_share_curves=[4587]), dict(key_share_curves=["x25519"]),
                                    dict(supported_versions=[0x0305]), dict(cert_compression_algos=["gzip"])])
def test_unknown_list_values_are_rejected(option):
    # upstream's mapper skips names it does not know: the value vanished from the hello
    with pytest.raises(yumeclient.SessionConfigurationError):
        Session(ja3_string=CHROME_JA3, **option)


@pytest.mark.parametrize("curves, fill, shares", [
    ("23-24", True, [23, 24]),        # used to add an undeclared X25519 share: illegal_parameter
    ("23-24", False, [23, 24]),
    ("23-24-29", False, [23, 24, 29]),
    ("23-24-29", True, [29]),         # Chrome's shares, for the declared groups only
    ("4588-29-23", True, [4588, 29]),
    ("4588-29-23", False, [4588, 29]),
    # an ML-KEM answer used the first classic share's key (P-384): invalid server key share
    ("4588-24-29", False, [4588, 24, 29]),
    # no ML-KEM share without X25519 (uTLS: internal_error); an ML-KEM server then sends
    # HelloRetryRequest, which uTLS cannot answer (USAGE "Ограничения")
    ("4588-23-24", False, [23, 24]),
])
def test_key_shares_only_for_declared_groups(sniffer, curves, fill, shares):
    ja3 = f"771,4865-4866-4867-49195-49199,0-23-65281-10-11-35-16-13-51-45-43,{curves},0"
    start = len(sniffer.hellos)
    with Session(verify=False, timeout=5, ja3_string=ja3, fill_custom_with_chrome_defaults=fill) as s:
        try:
            ok = s.get(f"https://localhost:{sniffer.port}/x").status_code == 200
        except yumeclient.TLSError:
            ok = False
    hello = parse_hello(sniffer.hellos[start])
    assert [g for g, _ in hello["key_share"] if g & 0x0F0F != 0x0A0A] == shares
    # the test server (Python's OpenSSL) picks ML-KEM through HelloRetryRequest from 3.5 on
    mlkem_hrr = "4588" in curves.split("-") and "29" not in curves.split("-") and ssl.OPENSSL_VERSION_INFO >= (3, 5)
    assert ok == (not mlkem_hrr)


CHROME_152_JA3 = ("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,"
                  "11-13-27-51-51764-5-35-43-18-65037-65281-0-17613-10-23-45-16,4588-29-23-24,0")


def test_chrome_ja3_with_trust_anchors(sniffer):
    # Chrome 146+ sends trust_anchors (51764): its own JA3 used to fail on every handshake
    # ("unknown ClientHelloID: Custom-ja3"); filled from Chrome, the list is Chrome's
    custom, r = _hello(sniffer, ja3_string=CHROME_152_JA3)
    chrome = _chrome_hello(sniffer)
    assert custom["exts"][51764] == chrome["exts"][51764] and len(custom["exts"][51764]) > 2
    # random_tls_extension_order (default True) shuffles a custom JA3's extensions too
    assert sorted(r.fingerprint["ja3"].split(",")[2].split("-")) == sorted(CHROME_152_JA3.split(",")[2].split("-"))
    bare, _ = _hello(sniffer, ja3_string=CHROME_152_JA3, fill_custom_with_chrome_defaults=False)
    assert bare["exts"][51764] == b"\x00\x00"


@pytest.mark.parametrize("payload", [bytes.fromhex("0006050401020304"), "0006050401020304", "00:06:05:04:01:02:03:04"])
def test_trust_anchors_payload(sniffer, payload):
    custom, _ = _hello(sniffer, ja3_string=CHROME_152_JA3, trust_anchors_payload=payload)
    assert custom["exts"][51764] == bytes.fromhex("0006050401020304")


@pytest.mark.parametrize("ja3, payload", [
    (CHROME_JA3, "0000"),                    # no extension 51764 in the ja3
    (CHROME_152_JA3, "0005"),                # length does not match
    (CHROME_152_JA3, "zz"),                  # not hex
    (CHROME_152_JA3, 5),
])
def test_trust_anchors_payload_is_validated(ja3, payload):
    with pytest.raises(yumeclient.SessionConfigurationError):
        Session(ja3_string=ja3, trust_anchors_payload=payload)


def test_unbuildable_ja3_is_a_configuration_error():
    ja3 = "771,4865-4866-4867,0-23-65281-10-11-13-43-45-51-4242,29-23-24,0"
    with Session(ja3_string=ja3, timeout=5) as s:
        with pytest.raises(yumeclient.InvalidRequestError, match="4242"):
            s.get("https://127.0.0.1:9/")


def test_ja3_parsing_prints_nothing(sniffer, capfd):
    _hello(sniffer, ja3_string="771,4865-4866-4867-49195,0-23-65281-10-11-13-27-43-45-51,29-23-24,0",
           fill_custom_with_chrome_defaults=False)
    assert capfd.readouterr().out == ""


def test_ech_config_list_is_validated():
    # real ECH needs a serialized ECHConfigList, the ECH extension in the JA3 and TCP
    # (the QUIC hello has no ECH); the wire behaviour is covered by native/ech_test.go
    config = bytes([0xFE, 0x0D, 0x00, 0x02, 0x01, 0x02])
    good = len(config).to_bytes(2, "big") + config
    with Session(ja3_string=CHROME_152_JA3, ech_config_list=good):
        pass
    for kwargs, message in [
        ({"ech_config_list": config}, "ECHConfigList"),
        ({"ech_config_list": good, "ja3_string": CHROME_152_JA3.replace("-65037", "")}, "65037"),
        ({"ech_config_list": good, "http_version": "3"}, "TCP only"),
    ]:
        options = {"ja3_string": CHROME_152_JA3, **kwargs}
        with pytest.raises(SessionConfigurationError, match=message):
            Session(**options)


def test_http2_settings_by_name_or_id(h2):
    # any SETTINGS id can be sent (Firefox: 9 = NO_RFC7540_PRIORITIES); unknown names used
    # to be dropped from the frame without a word
    with Session(ja3_string=CHROME_JA3, verify=False, timeout=5, http_version="2",
                 h2_settings={"HEADER_TABLE_SIZE": 65536, "initial_window_size": 131072, "MAX_FRAME_SIZE": 16384,
                              "NO_RFC7540_PRIORITIES": 1, 0x4A4A: 7},
                 h2_settings_order=["HEADER_TABLE_SIZE", "INITIAL_WINDOW_SIZE", "MAX_FRAME_SIZE", "9", "0x4a4a"]) as s:
        r = s.get(f"https://127.0.0.1:{h2.port}/a")
    settings = next(f for f in h2.frames if f[0] == 4 and f[3])[3]
    sent = [struct.unpack(">HI", settings[i:i + 6]) for i in range(0, len(settings), 6)]
    assert sent == [(1, 65536), (4, 131072), (5, 16384), (9, 1), (0x4A4A, 7)]
    assert r.fingerprint["akamai_fingerprint"].startswith("1:65536;4:131072;5:16384;9:1;19018:7|")
    for bad in ({"MAX_CONCURENT_STREAMS": 1}, {"HEADER_TABLE_SIZE": -1}, {0: 1}):
        with pytest.raises(SessionConfigurationError):
            Session(ja3_string=CHROME_JA3, h2_settings=bad)


def test_signature_algorithms_accept_names_and_ids(sniffer):
    expected = "0403,0804"
    for algs in (["0x0403", "0x0804"], ["ECDSAWithP256AndSHA256", "PSSWithSHA256"], [1027, 2052], ["1027", "0804"]):
        custom, _ = _hello(sniffer, ja3_string=CHROME_JA3, supported_signature_algorithms=algs)
        assert custom["exts"][13][2:] == bytes.fromhex(expected.replace(",", "")), algs
    with pytest.raises(SessionConfigurationError, match="unknown signature algorithm"):
        Session(ja3_string=CHROME_JA3, supported_signature_algorithms=["ECDSA_P256"])


def test_pseudo_header_order_lists_all_four(h2):
    for order in ([":method", ":path", ":authority", ":scheme"], ["method", "path", "authority", "scheme"],
                  ["m", "p", "a", "s"]):
        with Session(ja3_string=CHROME_JA3, verify=False, timeout=5, http_version="2", pseudo_header_order=order) as s:
            r = s.get(f"https://127.0.0.1:{h2.port}/a")
        assert [h[0] for h in r.fingerprint["request_headers"][:4]] == [":method", ":path", ":authority", ":scheme"]
    # a partial or misspelled list used to send requests without :authority / :scheme
    for bad in ([":method", ":path"], ["method", "path", "host", "scheme"], ["m", "m", "a", "s"]):
        with pytest.raises(SessionConfigurationError, match="pseudo_header_order"):
            Session(ja3_string=CHROME_JA3, pseudo_header_order=bad)


def test_tls_extension_order_places_every_extension(sniffer):
    # ECH, the old ALPS id and NPN had wrong ids in the reorder table and ended up last
    ja3 = ("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,"
           "0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-65037-13172,4588-29-23-24,0")
    order = list(reversed([int(x) for x in ja3.split(",")[2].split("-")]))
    for shuffle in (False, True):  # an explicit order is never shuffled
        custom, _ = _hello(sniffer, ja3_string=ja3, tls_extension_order=order, random_tls_extension_order=shuffle)
        assert [e for e in custom["exts"] if e & 0x0F0F != 0x0A0A] == order


def test_http2_settings_keep_the_dict_order(h2):
    # without h2_settings_order the native map used to send them in random order
    settings = {"MAX_HEADER_LIST_SIZE": 262144, "INITIAL_WINDOW_SIZE": 6291456, "ENABLE_PUSH": 0,
                "HEADER_TABLE_SIZE": 65536, "MAX_FRAME_SIZE": 16384}
    for _ in range(5):
        with Session(ja3_string=CHROME_JA3, verify=False, timeout=5, http_version="2", h2_settings=settings) as s:
            r = s.get(f"https://127.0.0.1:{h2.port}/a")
        assert r.fingerprint["akamai_fingerprint"].split("|")[0] == "6:262144;4:6291456;2:0;1:65536;5:16384"


def test_connection_flow_requires_ja3():
    with pytest.raises(SessionConfigurationError, match="connection_flow require ja3_string"):
        Session(connection_flow=12517377)
