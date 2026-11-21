# Third-party notices

yumeclient's own code is under the MIT license ([LICENSE](LICENSE)). The native library is
built from patched copies of the following Go modules, kept in `native/third_party/` (the
changes are in `native/third_party/patches/`). Each copy keeps its original license.

| Module | Version | License | Copyright |
|---|---|---|---|
| [bogdanfinn/tls-client](https://github.com/bogdanfinn/tls-client) | v1.16.0 | BSD-style, 4 clauses — [UPSTREAM-LICENSE](UPSTREAM-LICENSE), `native/third_party/tls-client/LICENSE` | © 2023 Bogdan Finn |
| [bogdanfinn/fhttp](https://github.com/bogdanfinn/fhttp) (fork of Go `net/http`) | v0.6.9 | BSD 3-clause (Go), stated in each source file | © 2009 The Go Authors |
| [bogdanfinn/utls](https://github.com/bogdanfinn/utls) (fork of [refraction-networking/utls](https://github.com/refraction-networking/utls)) | v1.7.8-barnius | BSD 3-clause — `native/third_party/utls/LICENSE` | © 2009 The Go Authors |
| [bogdanfinn/quic-go-utls](https://github.com/bogdanfinn/quic-go-utls) (fork of [quic-go](https://github.com/quic-go/quic-go)) | v1.0.10-utls | MIT — `native/third_party/quic-go-utls/LICENSE` | © 2016 the quic-go authors & Google, Inc. |
| [quic-go/qpack](https://github.com/quic-go/qpack) | v0.6.0 | MIT — `native/third_party/qpack/LICENSE.md` | © 2019 Marten Seemann |

The tls-client license asks that advertising materials mentioning features or use of the
software display an acknowledgement: **this product includes software developed by Bogdan
Finn** (bogdanfinn/tls-client).

Other Go modules linked into the native library (for example `golang.org/x/net`,
`golang.org/x/crypto`, `github.com/andybalholm/brotli`, `github.com/klauspost/compress`)
are listed in `native/go.mod` and are used under their own licenses.

Browser fingerprints in `native/h3profiles.json` and `tests/fixtures/` are measurements of
how those browsers behave on the network; browser names are trademarks of their owners.
