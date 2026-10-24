# Changelog

## v1.6 — Mobile redesign (2026-10-24)

- Dedicated mobile UI (`mobile.html`) built to a 10-screen app design:
  dashboard, network graph, devices, websites, domains, credentials,
  live traffic, network scan, settings — bottom nav (Dashboard, Graph,
  Devices, More). Desktop dashboard untouched.
- Android app opens the mobile UI directly; splash screen shows the
  CREDLENS wordmark and tagline.
- Server gained a `/mobile.html` route under the same Host guard.

## v1.5 — Mobile layout (2026-10-24)

- Dashboard reshapes on narrow screens: one scrolling page, 44px touch
  targets, swipeable tab row. Desktop layout unchanged.
- Pinch-zoom off in the app; splash screen shows the Eye logo.
- Fixed a real update bug: the asset version stamp was stale, so updates
  could keep the old page. It now forces a fresh copy.

## v1.4 — Custom Android engine + Eye logo (2026-10-24)

- IPv6 VPN capture on any phone (no root): ULA addressing, extension-header
  walk, IPv6 pseudo-header checksums.
- Rooted hotspot watch (Tecno-class phones): bundled tcpdump built from
  source (libpcap 1.10.4 + tcpdump 4.99.4, statically linked) watches the
  tether interface; client logins land under the client device.
- Re-issue: the Eye logo as app icon, dashboard header, tab icon, and
  Windows exe icon.

## v1.3 — Cross-platform hardening (2026-10-24)

- Linux live capture proven (loopback adapter offered, AF_PACKET).
- Device labels (POST /api/label), MAC-keyed DHCP names, identity layers.
- Adapter-pick contract: an explicit pick is never silently substituted;
  pre-stop validation; watchdog retries forever and never fakes LIVE.

## v1.2 — First Android release (2026-10-21)

- VPN capture (IPv4), dashboard, scan, reports, PCAP save, toast pop-ups
  on Windows, NTLM hash grab, password-reuse alerts, session reports.
