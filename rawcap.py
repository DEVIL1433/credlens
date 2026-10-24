"""CredLens zero-dependency live capture backends (pure stdlib).

Windows : raw IPv4 socket + SIO_RCVALL (built into Windows — no Npcap,
          no Wireshark) (IPv4; IPv6 arrives via the tshark/Npcap engine).
Linux   : AF_PACKET raw socket (root / CAP_NET_RAW), Ethernet frames are
          unwrapped to IP packets so the engine sees one shape.

The callback receives (timestamp, ip_packet_bytes) — exactly what the
analysis engine consumes for PCAP files, so live and file analysis share
one code path.
"""
import os
import re
import socket
import subprocess
import threading
import time


def default_route_ip():
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect(("8.8.8.8", 80))
        ip = probe.getsockname()[0]
        probe.close()
        return ip
    except Exception:
        return None


def list_adapters():
    """[{id, ip, name, label, mac}] — id is the IPv4 address raw bind needs.
    Ranked: default-route adapter first, then Wi-Fi-named, then the rest."""
    adapters = []
    if os.name == "nt":
        try:
            out = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True,
                                 timeout=12, creationflags=getattr(
                                     subprocess, "CREATE_NO_WINDOW", 0)).stdout or ""
            cur = None  # line-walk: a non-indented line ending in ':' opens an adapter
            for ln in out.splitlines():
                if ln and not ln[0].isspace() and ln.rstrip().endswith(":"):
                    head = ln.rstrip().rstrip(":")
                    name = re.sub(r"^(Wireless LAN adapter|Ethernet adapter|"
                                  r"Unknown adapter|adapter)\s+", "", head,
                                  flags=re.I).strip() or head
                    cur = {"name": name, "ip": None, "mac": None}
                    adapters.append(cur)
                elif cur is not None:
                    m = re.search(r"IPv4 Address[^:]*:\s*([\d.]+)", ln)
                    if m:
                        cur["ip"] = m.group(1)
                    pm = re.search(r"Physical Address[^:]*:\s*([0-9A-Fa-f:-]+)", ln)
                    if pm:
                        cur["mac"] = pm.group(1).replace("-", ":").lower()
            adapters = [a for a in adapters if a["ip"]
                        and not a["ip"].startswith(("127.", "169.254."))]
            for a in adapters:
                a["id"] = a["ip"]
                a["label"] = f"{a['name']} — {a['ip']}"
        except Exception:
            pass
    else:
        try:
            out = subprocess.run(["ip", "-o", "-4", "addr", "show"],
                                 capture_output=True, text=True, timeout=10).stdout or ""
            for ln in out.splitlines():
                m = re.search(r"^\d+:\s+(\S+)\s+inet\s+([\d.]+)/", ln)
                if m and not m.group(2).startswith("127."):
                    adapters.append({"id": m.group(2), "ip": m.group(2),
                                     "name": m.group(1), "mac": None,
                                     "label": f"{m.group(1)} — {m.group(2)}"})
        except Exception:
            pass
    if os.name != "nt":
        # Linux loopback is a real capture position (AF_PACKET unwraps
        # its frames like Ethernet — verified) and the only way to watch
        # this machine's own local traffic. Offered LAST, never as the
        # auto pick: the default stays the real network adapter.
        adapters.append({"id": "127.0.0.1", "ip": "127.0.0.1", "name": "lo",
                         "mac": None,
                         "label": "Loopback (lo) — 127.0.0.1 · this machine only"})
    dip = default_route_ip()
    if not adapters and dip:
        adapters.append({"id": dip, "ip": dip, "name": "Network adapter",
                         "mac": None, "label": f"Network adapter — {dip}"})

    def rank(a):
        if a.get("name") == "lo":
            return 99           # loopback: listed last, never auto-picked
        n = a["name"].lower()
        virtual = any(v in n for v in ("tailscale", "vpn", "virtual",
                                       "loopback", "wintun", "tunnel"))
        physical = any(v in n for v in ("wi-fi", "wireless", "ethernet",
                                        "802.11", "wlan", "realtek", "intel"))
        score = 0
        if a["ip"] == dip:
            score -= 2          # the adapter carrying the default route
        if physical:
            score -= 1
        if virtual:
            score += 4          # tunnels carry encrypted traffic: useless
        return score

    adapters.sort(key=rank)
    return adapters


class RawCapture(threading.Thread):
    """Streams IP packets from one adapter to on_packet(ts, bytes)."""

    def __init__(self, adapter_ip, on_packet, on_error=None, iface_name=None):
        super().__init__(daemon=True)
        self.adapter_ip = adapter_ip
        self.iface_name = iface_name
        self.on_packet = on_packet
        self.on_error = on_error
        self.stop_flag = False
        self.packets = 0

    def stop(self):
        self.stop_flag = True

    # ------------------------------------------------------------ Windows
    def _run_windows(self):
        socks = []
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            s.bind((self.adapter_ip, 0))
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            s.settimeout(0.5)
            socks.append(s)
        except Exception as e:
            if self.on_error:
                self.on_error(e)
            return
        # NOTE (verified on Win11, 2026-10-21): an AF_INET6 raw socket can
        # be created and RCVALL-enabled when bound to a specific address,
        # but it delivers ZERO packets — Windows gives no usable IPv6 via
        # raw sockets. Built-in capture is IPv4-only by platform reality;
        # full IPv6 needs the tshark/Npcap engine (Settings choice).
        errs = 0
        while not self.stop_flag:
            for s in socks:
                try:
                    data, _ = s.recvfrom(65535)
                    if data:
                        errs = 0
                        self.packets += 1
                        self.on_packet(time.time(), data)
                except socket.timeout:
                    pass
                except Exception:
                    errs += 1
                    if errs > 50:   # socket is broken (adapter gone, IP
                        if self.on_error:   # changed): die loudly so the
                            self.on_error(OSError("raw capture socket failed"))
                        return              # watchdog can restart us
        for s in socks:
            try:
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except Exception:
                pass
            try:
                s.close()
            except Exception:
                pass

    # --------------------------------------------------------------- Linux
    def _run_linux(self):
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                              socket.htons(0x0003))
            if self.iface_name:
                s.bind((self.iface_name, 0))
            s.settimeout(0.5)
        except Exception as e:
            if self.on_error:
                self.on_error(e)
            return
        errs = 0
        while not self.stop_flag:
            try:
                frame, _ = s.recvfrom(65535)
                errs = 0
            except socket.timeout:
                continue
            except Exception:
                errs += 1
                if errs > 50:
                    if self.on_error:
                        self.on_error(OSError("packet socket failed"))
                    return
                continue
            if len(frame) < 14:
                continue
            eth = int.from_bytes(frame[12:14], "big")
            off = 14
            while eth in (0x8100, 0x88A8) and len(frame) >= off + 4:
                eth = int.from_bytes(frame[off + 2:off + 4], "big")
                off += 4
            if eth in (0x0800, 0x86DD):
                self.packets += 1
                self.on_packet(time.time(), frame[off:])
        try:
            s.close()
        except Exception:
            pass

    def run(self):
        if os.name == "nt":
            self._run_windows()
        else:
            self._run_linux()
