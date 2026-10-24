# Platform notes and honest limits

## Windows

Everything works: raw + tshark engines, NPF hotspot frame capture,
toast pop-ups, dashboard, scan, reports, PCAP save, exe build.

```bash
python credlens.py
```

## Linux

Everything works except Windows-only pieces (tshark engine, NPF, toasts).
Loopback is offered as a capture adapter for local testing but is never
auto-picked; automatic selection stays on the real NIC.

```bash
sudo python3 credlens.py
```

## Android

- **VPN capture (any phone, no root):** watches the phone's own traffic,
  IPv4 and IPv6. Allow the one-time VPN prompt.
- **Hotspot watch (rooted phones only):** watches devices connected to
  the phone's hotspot, under their own addresses. Needs root + the
  bundled tcpdump. On an unrooted phone this is impossible for any app:
  client traffic bypasses apps at kernel level.
- **Not on Android, by design:** hotspot mode on unrooted phones,
  toast pop-ups, the tshark engine.
- **No downloadable session PCAP** in hotspot mode yet (live extraction
  only); PCAP download works for VPN sessions.

Install the APK from Releases, or build it yourself (see BUILDING.md).
The app's signing config is intentionally absent from this tree — use
your own keystore for release builds.
