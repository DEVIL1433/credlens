# Architecture

One codebase, pure standard-library Python, plus a Chaquopy Android shell.

## Components

- **`credlens.py`** — HTTP server on 127.0.0.1:8890 (loopback only),
  live-capture workers, scan worker, settings, and the snapshot builder.
  Serves `index.html` (desktop Deck) and `mobile.html` (Android UI).
- **`pcap.py`** — pcap/pcapng parser, TCP stream reassembly, HTTP and
  protocol extractors, NTLM handling, DHCP fingerprinting.
- **`rawcap.py`** — raw-socket capture (IPv4-complete) and adapter listing.
- **`scan.py`** — LAN/port-scan profiles (passive / standard / deep).
- **`toast.ps1`** — Windows toast notifications (parameterized, no shell
  injection from captured text).

## Capture engines

| Engine | Where | Notes |
|---|---|---|
| Raw sockets (SIO_RCVALL) | Windows, Linux | IPv4-complete; needs admin/root |
| tshark fields | Windows | IPv6-capable but lossy (HTTP forms only) |
| NPF frame stream | Windows hotspot | Full extraction parity |
| AF_PACKET | Linux | Loopback offered, never auto-picked |
| VPN relay | Android | IPv4 + IPv6, phone's own traffic |
| tcpdump stream | Android rooted hotspot | Client traffic under client IPs |

## Data flow

```
packets -> decode_frame -> live_packet -> events / requests / domains
   -> STATE.snapshot() -> /api/state -> dashboard / mobile UI
```

- **Events**: credential catches (kind, user, password/token, host, URL,
  source IP/MAC, raw request excerpt).
- **Requests**: HTTP and protocol requests (method, host, path, times).
- **Domains**: DNS + TLS-SNI sightings (domain, source, first/last seen,
  hit count, how seen).
- **Devices**: IPs/MACs with requests, leaks, vendor, and identity layers.

## API surface

`GET /api/state`, `GET /api/report`, `GET /api/pcap`,
`GET /api/interfaces`, `GET /api/scan/status`,
`POST /api/live`, `/api/stop`, `/api/clear`, `/api/load-pcap`,
`/api/label`, `/api/hotspot`, `/api/settings`, `/api/scan`,
`/api/scan/stop`.

State-changing POSTs require the `X-CredLens: 1` header, and all routes
reject forged Host headers. Unknown routes return 404.

## Visibility rule (read this before deploying)

On normal Wi-Fi a machine sees only its own traffic plus broadcasts.
CredLens gets its view from **position**: the device itself, a hotspot
it runs, or a router it owns. There is no ARP-spoofing, MITM poisoning,
or WPA2-PSK decryption anywhere in this codebase.
