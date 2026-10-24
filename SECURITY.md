# Security Policy

## What CredLens is for

CredLens watches **your own** network traffic on machines and networks
you own or are authorized to test. Do not point it at traffic or
credentials belonging to other people without their consent or lawful
authorization.

## Reporting a vulnerability

Open a GitHub issue with a minimal reproduction. Please do **not**
include real credentials, real captures, or other people's traffic in
the report — use the synthetic test fixture (`test.pcap`) or redacted
samples.

## Known trust boundaries (by design)

- The dashboard binds loopback only (127.0.0.1:8890) and rejects forged
  Host headers and cross-site state-changing POSTs.
- There is **no redaction** in the engine: real secrets surface in full
  on the machine running CredLens. Keep that machine to yourself.
- On Android, VPN capture sees the phone's own traffic. Hotspot watch
  on a rooted phone sees connected devices' traffic — only ever enable
  it on a hotspot you run yourself.
