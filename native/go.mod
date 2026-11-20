module github.com/kovak/yumeclient

go 1.24.1

require (
	github.com/bogdanfinn/fhttp v0.6.9
	github.com/bogdanfinn/tls-client v1.16.0
	github.com/bogdanfinn/utls v1.7.8-barnius
	golang.org/x/net v0.48.0
)

require (
	github.com/andybalholm/brotli v1.2.0 // indirect
	github.com/bdandy/go-errors v1.2.2 // indirect
	github.com/bdandy/go-socks4 v1.2.3 // indirect
	github.com/bogdanfinn/quic-go-utls v1.0.10-utls // indirect
	github.com/bogdanfinn/websocket v1.5.6-barnius // indirect
	github.com/cloudflare/circl v1.6.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/klauspost/compress v1.18.2 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/tam7t/hpkp v0.0.0-20160821193359-2b70b4024ed5 // indirect
	golang.org/x/crypto v0.46.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
	golang.org/x/text v0.32.0 // indirect
)

// patched copies, see scripts/third_party.py and native/third_party/patches
replace (
	github.com/bogdanfinn/fhttp => ./third_party/fhttp
	github.com/bogdanfinn/quic-go-utls => ./third_party/quic-go-utls
	github.com/bogdanfinn/tls-client => ./third_party/tls-client
	github.com/bogdanfinn/utls => ./third_party/utls
	github.com/quic-go/qpack => ./third_party/qpack
)
