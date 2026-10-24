#!/usr/bin/env python3
"""CredLens — see credentials cross your network, with the page they leaked on.

Wireshark shows you everything and makes you dig. CredLens watches HTTP
traffic (live via tshark, or any .pcap you drop in) and surfaces only the
moments that matter: a username and password, the page that sent them,
the device that sent them, and the server IP they were sent to.

Usage:
    python3 credlens.py [--port 8890]
Then open http://127.0.0.1:8890

Live capture needs tshark (part of Wireshark) and capture privileges —
on Kali:  sudo python3 credlens.py   or run your user in the wireshark group.
PCAP analysis needs nothing but this file — drop in any Wireshark capture.
"""
import argparse
import os
import json
import re
import shutil
import struct
import subprocess
import sys
import queue
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pcap as engine
import rawcap
import scan as scanner

try:
    import socket as _sock0
    HOST_NAME = _sock0.gethostname()
except Exception:
    HOST_NAME = ""

STATE_LOCK = threading.Lock()


class State:
    def __init__(self):
        self.reset()
        self.mode = "idle"          # idle | pcap | live
        self.live_info = ""
        self.engine = ""            # "" | raw | tshark
        self.capture_error = ""     # set when a capture worker dies silently

    def reset(self):
        self.events = []
        self.requests = []          # diary of every HTTP request seen
        self.devices = {}           # ip -> device dict
        self.sites = {}             # host -> site dict
        self.names = {}             # ip -> harvested device name
        self.mac_names = {}         # mac -> name (follows the hardware)
        self.fingerprints = {}      # mac -> OS family (DHCP option 55)
        self.domains = {}           # (src_ip, domain) -> sighting aggregate
        self.stats = {"packets": 0, "http_requests": 0}
        self.aux_seen = set()   # (kind, src, host, secret) already surfaced

    def add_domain(self, ts, src_ip, domain, via, dst_ip, qtype=""):
        """Record a domain sighting (DNS query or TLS SNI), aggregated."""
        if not domain or "." not in domain:
            return
        if domain.endswith((".in-addr.arpa", ".ip6.arpa", ".local")):
            return                  # reverse lookups / mDNS noise, not visits
        key = (src_ip, domain)
        d = self.domains.get(key)
        if d is None:
            if len(self.domains) >= 1000:
                oldest = min(self.domains,
                             key=lambda k: self.domains[k]["last"])
                self.domains.pop(oldest, None)
            d = self.domains[key] = {"src_ip": src_ip, "domain": domain,
                                     "via": set(), "dst_ip": dst_ip,
                                     "count": 0, "first": ts, "last": ts,
                                     "qtypes": set()}
        d["via"].add(via)
        if qtype:
            d["qtypes"].add(qtype)
        d["count"] += 1
        d["last"] = max(d["last"], ts)
        d["dst_ip"] = dst_ip or d["dst_ip"]

    def aux_mark(self, key):
        """True if this aux secret is new (and records it). Bounded."""
        if key in self.aux_seen:
            return False
        if len(self.aux_seen) > 5000:
            self.aux_seen.clear()
        self.aux_seen.add(key)
        return True

    def _device(self, ip, mac=None):
        if ip not in self.devices and len(self.devices) >= 512:
            self.devices.pop(next(iter(self.devices)), None)
        d = self.devices.setdefault(ip, {
            "ip": ip, "mac": mac, "vendor": engine.mac_vendor(mac),
            "leaks": 0, "requests": 0, "via": None})
        if mac and not d.get("mac"):
            d["mac"] = mac
            d["vendor"] = engine.mac_vendor(mac)
        return d

    def _site(self, host, server_ip):
        if host not in self.sites and len(self.sites) >= 512:
            self.sites.pop(next(iter(self.sites)), None)
        return self.sites.setdefault(host, {
            "host": host, "server_ip": server_ip, "pages": set(),
            "leaks": 0, "requests": 0})

    def add_request(self, rec):
        self.requests.append(rec)
        self.requests = self.requests[-200:]
        d = self._device(rec["src_ip"], rec.get("src_mac"))
        d["requests"] += 1
        d["via"] = "traffic"
        st = self._site(rec["host"], rec["dst_ip"])
        if len(st["pages"]) < 200:
            st["pages"].add(rec["path"])
        st["requests"] += 1

    def add_event(self, ev):
        self.events.append(ev)
        if self.mode == "live":
            try:
                TOAST_Q.put_nowait(ev)
            except Exception:
                pass
        if len(self.events) > 2000:
            self.events = self.events[-2000:]
        d = self._device(ev["src_ip"], ev.get("src_mac"))
        d["leaks"] += 1
        d["via"] = "traffic"
        self._site(ev["host"], ev["dst_ip"])["leaks"] += 1

    def load_analysis(self, result):
        self.reset()
        self.names = {d["ip"]: d["name"] for d in result["devices"] if d.get("name")}
        self.stats = result["stats"]
        for d in result["devices"]:
            self.devices[d["ip"]] = {"ip": d["ip"], "mac": d["mac"],
                                     "vendor": d["vendor"], "leaks": d["leaks"],
                                     "os": d.get("os"),
                                     "requests": d.get("requests", 0)}
        for s in result["sites"]:
            self.sites[s["host"]] = {"host": s["host"], "server_ip": s["server_ip"],
                                     "pages": set(s["pages"]), "leaks": s["leaks"],
                                     "requests": s.get("requests", 0)}
        self.events = result["events"]
        self.requests = result.get("requests", [])
        for s in result.get("domains", []):
            self.add_domain(s["ts"], s["src_ip"], s["domain"], s["via"],
                            s["dst_ip"], s.get("qtype", ""))

    def snapshot(self):
        hints = {}
        for r in self.requests:
            hint = _hint_for(r.get("host"))
            if hint:
                hints.setdefault(r["src_ip"], hint)
        for dm in self.domains.values():
            hint = _hint_for(dm.get("domain"))
            if hint:
                hints.setdefault(dm["src_ip"], hint)
        labels = load_settings().get("labels") or {}
        models = {}
        for r in self.requests:
            if r["src_ip"] not in models:
                mdl = _ua_model(r.get("ua"))
                if mdl:
                    models[r["src_ip"]] = mdl
        families = {}
        for dm in self.domains.values():
            if dm["src_ip"] not in families:
                fam = _family_for(dm.get("domain"))
                if fam:
                    families[dm["src_ip"]] = fam
        devs = []
        for d in self.devices.values():
            mac = (d.get("mac") or "").lower()
            devs.append({**d,
                         "name": self.names.get(d["ip"])
                                 or self.mac_names.get(mac),
                         "label": labels.get(mac),
                         "ua_model": models.get(d["ip"]),
                         "family": families.get(d["ip"]),
                         "os": self.fingerprints.get(mac) or d.get("os"),
                         "hint": hints.get(d["ip"])})
        sites = []
        for s in self.sites.values():
            sites.append({**s, "pages": sorted(s["pages"])})
        devs.sort(key=lambda d: (-d["leaks"], -d["requests"], d["ip"]))
        sites.sort(key=lambda s2: (-s2["leaks"], -s2["requests"], s2["host"]))
        by_pw = {}
        for ev in self.events:
            pw = ev.get("password") or ""
            if len(pw) < 4 or ev["kind"] in ("cookie", "apikey", "bearer"):
                continue
            by_pw.setdefault(pw, set()).add(ev["host"])
        reuse = sorted(({"password": pw, "hosts": sorted(hs), "sites": len(hs)}
                        for pw, hs in by_pw.items() if len(hs) >= 2),
                       key=lambda r: -r["sites"])
        doms = sorted(self.domains.values(), key=lambda d: -d["last"])[:200]
        return {"events": self.events[-500:], "requests": self.requests[-200:],
                "reuse": reuse,
                "domains": [{"ts": d["last"], "first": d["first"],
                             "src_ip": d["src_ip"], "domain": d["domain"],
                             "via": sorted(d["via"]), "dst_ip": d["dst_ip"],
                             "count": d["count"],
                             "qtypes": sorted(d["qtypes"])} for d in doms],
                "domain_count": len({d["domain"] for d in self.domains.values()}),
                "pcap_bytes": REC["bytes"] if REC["on"] else (
                    os.path.getsize(REC["path"]) if os.path.exists(REC["path"]) else 0),
                "devices": devs, "sites": sites,
                "stats": {**self.stats, "credentials": len(self.events)},
                "mode": self.mode, "live_info": self.live_info,
                "engine": self.engine,
                "engine_pref": PREF["engine"],
                "npf_note": NPF_NOTE["msg"],
                "capture_error": self.capture_error,
                "tshark": bool(find_tshark())}


_TS_CACHE = {"t": 0.0, "v": None}


def find_tshark():
    if time.time() - _TS_CACHE["t"] < 30 and _TS_CACHE["v"] is not None:
        return _TS_CACHE["v"]
    w = _find_tshark_uncached()
    _TS_CACHE.update({"t": time.time(), "v": w})
    return w


def _find_tshark_uncached():
    w = shutil.which("tshark")
    if w:
        return w
    for cand in (r"C:\Program Files\Wireshark\tshark.exe",
                 r"C:\Program Files (x86)\Wireshark\tshark.exe",
                 r"D:\Wireshark\tshark.exe", r"D:\Program Files\Wireshark\tshark.exe"):
        if os.path.exists(cand):
            return cand
    return None


def list_interfaces():
    """[(id, label)] from tshark -D, Wi-Fi first."""
    ts = find_tshark()
    if not ts:
        return []
    try:
        out = subprocess.run([ts, "-D"], capture_output=True, text=True, timeout=15,
                             creationflags=getattr(
                                 subprocess, "CREATE_NO_WINDOW", 0)).stdout
    except Exception:
        return []
    ifaces = []
    for ln in out.splitlines():
        ln = ln.strip()
        if ". " in ln:
            _num, rest = ln.split(". ", 1)
            dev = rest.split(" (")[0].strip()
            m = re.search(r"\((.+)\)\s*$", rest)
            label = m.group(1) if m else rest.strip()
            ifaces.append({"id": dev, "label": label})
    def wifi_rank(it):
        n = it["label"].lower()
        if "wi-fi" in n or "wifi" in n or "wireless" in n or "802.11" in n:
            return 0
        if "loopback" in n:
            return 2
        return 1
    return sorted(ifaces, key=wifi_rank)


STATE = State()

# Android (Chaquopy APK): the Java VpnService owns capture. The web UI's
# Live button selects the synthetic "vpn" adapter; Java polls vpn_wanted()
# and starts/stops the TUN; packets arrive via feed_external_packet().
ANDROID = bool(os.environ.get("CREDLENS_ANDROID"))
VPN_REQ = {"want": False}

TOAST_Q = queue.Queue(maxsize=200)

SETTINGS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "credlens-settings.json")


PREF = {"engine": "raw", "hotspot_auto": False}
SETTINGS_LOCK = threading.Lock()


_SETTINGS_CACHE = {"t": 0.0, "data": None}


def load_settings():
    # 1 s cache: snapshot() reaches this via hotspot_status() on every
    # /api/state poll while holding STATE_LOCK — a disk read + JSON parse
    # per poll stalls the capture threads behind filesystem I/O
    if _SETTINGS_CACHE["data"] is not None and time.time() - _SETTINGS_CACHE["t"] < 1:
        return dict(_SETTINGS_CACHE["data"])
    try:
        with open(SETTINGS_PATH) as fh:
            data = json.load(fh)
    except Exception:
        data = {}
    _SETTINGS_CACHE.update({"t": time.time(), "data": data})
    return dict(data)


def _write_settings(data):
    """Atomic (temp + rename) settings write; keeps PREF in sync."""
    try:
        tmp = SETTINGS_PATH + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(data, fh)
        os.replace(tmp, SETTINGS_PATH)
        _SETTINGS_CACHE.update({"t": time.time(), "data": dict(data)})
        if data.get("engine"):
            PREF["engine"] = data["engine"]
        if "hotspot_auto" in data:
            PREF["hotspot_auto"] = bool(data["hotspot_auto"])
    except Exception:
        pass


def save_live_setting(iface, engine_pref=None):
    with SETTINGS_LOCK:
        data = load_settings()
        data["live_iface"] = iface
        if engine_pref:
            data["engine"] = engine_pref
        _write_settings(data)


def set_hotspot_auto(on):
    with SETTINGS_LOCK:
        data = load_settings()
        data["hotspot_auto"] = bool(on)
        _write_settings(data)


def _set_setting(key, value):
    with SETTINGS_LOCK:
        data = load_settings()
        data[key] = value
        _write_settings(data)


def set_engine_pref(eng):
    with SETTINGS_LOCK:
        data = load_settings()
        data["engine"] = eng
        _write_settings(data)


def clear_live_setting():
    """Forget the auto-resume adapter ONLY — the engine preference is a
    deliberate user choice and survives Stop/Clear."""
    with SETTINGS_LOCK:
        data = load_settings()
        data.pop("live_iface", None)
        if data:
            _write_settings(data)
        else:
            try:
                os.remove(SETTINGS_PATH)
            except Exception:
                pass


_NAME_TRIED = {}


def _nbns_name(ip):
    """Ask a Windows machine its NetBIOS name (UDP 137 node-status query)."""
    import socket as _s
    try:
        q = (b"\x81\x3c\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
             b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01")
        sk = _s.socket(_s.AF_INET, _s.SOCK_DGRAM)
        sk.settimeout(1.2)
        sk.sendto(q, (ip, 137))
        data, _ = sk.recvfrom(4096)
        sk.close()
        off = 12
        if off < len(data) and data[off] == 0x20:      # skip question section
            off += 34 + 4
        if data[off:off + 2] == b"\xc0\x0c":          # answer: compressed name ptr
            off += 2
        off += 2 + 2 + 4                               # type, class, ttl
        rdlen = int.from_bytes(data[off:off + 2], "big")
        off += 2
        if off >= len(data):
            return None
        count = data[off]
        off += 1
        for _ in range(count):
            entry = data[off:off + 18]
            if len(entry) < 18:
                break
            raw, suffix, flags = entry[:15], entry[15], int.from_bytes(entry[16:18], "big")
            if suffix == 0x00 and not (flags & 0x8000):     # unique workstation name
                name = raw.decode("ascii", "replace").strip()
                if name:
                    return name
            off += 18
    except Exception:
        return None
    return None


def _dns_read_name(data, off):
    """Read a (possibly compressed) DNS name at `off` in `data`."""
    out = []
    next_off = None
    guard = 0
    while off < len(data) and guard < 128:
        guard += 1
        ln = data[off]
        if ln == 0:
            if next_off is None:
                next_off = off + 1
            break
        if ln & 0xC0 == 0xC0:
            if next_off is None:
                next_off = off + 2
            off = int.from_bytes(data[off:off + 2], "big") & 0x3FFF
            continue
        out.append(data[off + 1:off + 1 + ln].decode("utf-8", "replace"))
        off += 1 + ln
    return ".".join(out), (next_off if next_off is not None else off)


def _build_ptr_query(ip):
    """A reverse (PTR) question for ip, with the mDNS QU bit set so the
    answer comes back unicast to our own port."""
    labels = b"".join(bytes([len(p)]) + p.encode() for p in ip.split(".")[::-1])
    return (b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" + labels
            + b"\x07in-addr\x04arpa\x00\x00\x0c\x80\x01")


def _parse_name_answers(data, ip):
    """First real device name in a DNS-style answer packet for `ip`:
    a PTR target (Pixel-8.local -> Pixel-8) or an A record whose name
    is the device and whose address is the device."""
    try:
        qd = int.from_bytes(data[4:6], "big")
        an = int.from_bytes(data[6:8], "big")
        off = 12
        for _ in range(qd):
            _qn, off = _dns_read_name(data, off)
            off += 4
        ipb = bytes(int(p) for p in ip.split(".")) if ip.count(".") == 3 else b""
        for _ in range(an):
            nm, off = _dns_read_name(data, off)
            if off + 10 > len(data):
                return None
            rtype = int.from_bytes(data[off:off + 2], "big")
            rdlen = int.from_bytes(data[off + 8:off + 10], "big")
            off += 10
            if off + rdlen > len(data):
                return None
            if rtype == 12:                        # PTR
                target, _ = _dns_read_name(data, off)
                if target:
                    return target.replace(".local", "").split(".")[0]
            elif rtype == 1 and data[off:off + rdlen] == ipb and nm:
                return nm.replace(".local", "").split(".")[0]
            off += rdlen
    except Exception:
        return None
    return None


def _iface_for(ip):
    """The local address that reaches `ip`. Name questions must leave
    by the door the device is behind: the multicast question used to
    leave by the default route (Wi-Fi), so hotspot devices never
    heard it and never answered."""
    try:
        if ip.startswith("192.168.137."):
            return HOTSPOT_IP
        ips = [a.get("ip") for a in adapters() if a.get("ip")]
        pref = ".".join(ip.split(".")[:3]) + "."
        for a in ips:
            if a and a.startswith(pref):
                return a
        net = connected_network()
        if net and net.get("ip"):
            return net["ip"]
        return ips[0] if ips else None
    except Exception:
        return None


def _reverse_query(ip, group, port):
    """Ask the whole link, from the right interface, 'who is ip?' —
    mDNS (5353) and LLMNR (5355) responders answer with the device's
    own name. That is dynamic detection: the name comes from the
    device, never from a list."""
    import socket as _s
    try:
        sk = _s.socket(_s.AF_INET, _s.SOCK_DGRAM)
        sk.setsockopt(_s.SOL_SOCKET, _s.SO_REUSEADDR, 1)
        iface = _iface_for(ip)
        if iface:
            try:
                sk.setsockopt(_s.IPPROTO_IP, _s.IP_MULTICAST_IF,
                              _s.inet_aton(iface))
            except Exception:
                pass
            sk.bind((iface, 0))
        sk.settimeout(1.6)
        sk.sendto(_build_ptr_query(ip), (group, port))
        deadline = time.time() + 1.6
        found = None
        while time.time() < deadline and not found:
            try:
                data, _ = sk.recvfrom(4096)
            except Exception:
                break
            found = _parse_name_answers(data, ip)
        sk.close()
        return found
    except Exception:
        return None


def _mdns_name(ip):
    """Reverse mDNS lookup — phones & IoT answer this."""
    return _reverse_query(ip, "224.0.0.251", 5353)


def _llmnr_name(ip):
    """Reverse LLMNR lookup — Windows and many Android builds answer."""
    return _reverse_query(ip, "224.0.0.252", 5355)


def _resolve_name(ip):
    for fn in (_nbns_name, _mdns_name, _llmnr_name):
        name = fn(ip)
        if name and engine.plausible_hostname(name):
            return name
    try:
        import socket as _s
        old = _s.getdefaulttimeout()
        _s.setdefaulttimeout(1.5)       # bound the reverse lookup…
        try:
            nm = _s.gethostbyaddr(ip)[0].split(".")[0]
            return nm if engine.plausible_hostname(nm) else None
        finally:
            _s.setdefaulttimeout(old)   # …without leaking the timeout
    except Exception:                   # process-wide to every later socket
        return None


def discovery_worker(gen=None):
    """Register every device on the LAN (from the ARP table) as a map node,
    even when its web traffic is not visible from this machine."""
    if gen is None:
        gen = LIVE_PROC["gen"]
    while not LIVE_PROC["stop"] and LIVE_PROC["gen"] == gen:
        try:
            found = {}
            if os.name == "nt":
                out = subprocess.run(["arp", "-a"], capture_output=True, text=True,
                                     timeout=15, creationflags=getattr(
                                         subprocess, "CREATE_NO_WINDOW", 0)).stdout or ""
                for m in re.finditer(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})", out):
                    found[m.group(1)] = m.group(2).replace("-", ":").lower()
            else:
                out = subprocess.run(["ip", "neigh"], capture_output=True, text=True,
                                     timeout=10).stdout or ""
                for m in re.finditer(r"(\d+\.\d+\.\d+\.\d+).*?lladdr\s+([0-9a-fA-F:]+)", out):
                    found[m.group(1)] = m.group(2).lower()
            for ip in list(found):
                mac = found[ip]
                if mac == "ff:ff:ff:ff:ff:ff" or ip.endswith(".255") \
                        or ip.startswith(("224.", "239.", "255.")):
                    del found[ip]
            try:                                    # this machine names itself
                probe = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
                probe.connect(("8.8.8.8", 80))
                my_ip = probe.getsockname()[0]
                probe.close()
                # name EVERY local address with the hostname: on a
                # multi-adapter machine the route probe lands on one
                # address only, and the others kept whatever the wire
                # harvest shouted first (DESKTOP got WORKGROUP on the
                # Wi-Fi address while its IPv6 twin was named right)
                own_ips = {my_ip}
                try:
                    for info in _sock.getaddrinfo(HOST_NAME, None):
                        own_ips.add(info[4][0])
                except Exception:
                    pass
                try:
                    for a in adapters():
                        if a.get("ip"):
                            own_ips.add(a["ip"])
                except Exception:
                    pass
                with STATE_LOCK:
                    for ip in own_ips:
                        STATE.names[ip] = HOST_NAME
                    _me = STATE._device(my_ip)
                    if not _me.get("via"):
                        _me["via"] = "self"
            except Exception:
                pass
            now = time.time()
            todo = []
            with STATE_LOCK:
                for ip, mac in found.items():
                    d = STATE._device(ip, mac)
                    if not d.get("via"):
                        d["via"] = "lan"
                known = list(found) + [ip for ip in STATE.devices if ip not in found]
                for ip in known:
                    if not engine.plausible_hostname(STATE.names.get(ip)) \
                            and now - _NAME_TRIED.get(ip, 0) > 600:
                        todo.append(ip)
            for ip in todo[:6]:                     # bounded per pass
                _NAME_TRIED[ip] = now
                name = _resolve_name(ip)
                if name:
                    with STATE_LOCK:
                        STATE.names[ip] = name
        except Exception:
            pass
        for _ in range(30):
            if LIVE_PROC["stop"] or LIVE_PROC["gen"] != gen:
                break
            time.sleep(1)


RAW = {"cap": None}
LAST_PKT = {"t": 0.0}
FLOWS = {}
FLOCK = threading.Lock()
OWN_MACS = {}
_ADAPTER_CACHE = {"t": 0, "list": []}


def adapters():
    if ANDROID:
        return [{"id": "vpn", "ip": "10.0.0.2",
                 "name": "This phone (VPN)", "mac": None}]
    if time.time() - _ADAPTER_CACHE["t"] > 15:
        _ADAPTER_CACHE["list"] = rawcap.list_adapters()
        _ADAPTER_CACHE["t"] = time.time()
    return _ADAPTER_CACHE["list"]


def _reassemble(segs):
    out = bytearray()
    covered = 0
    for seq, _ts, pl in sorted(segs, key=lambda x: x[0]):
        if seq >= covered:
            out += pl
            covered = seq + len(pl)
        elif seq + len(pl) > covered:
            out += pl[covered - seq:]
            covered = seq + len(pl)
    return bytes(out)


REC = {"fh": None, "bytes": 0, "on": False,
       "path": os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "session.pcap")}
_PKT_N = {"n": 0}


def _rng_covered(ranges, a, b):
    return any(a >= x and b <= y for x, y in ranges)


def _rng_add(ranges, a, b):
    ranges.append((a, b))
    ranges.sort()
    merged = []
    for x, y in ranges:
        if merged and x <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], y))
        else:
            merged.append((x, y))
    return merged[-8:]



def start_recording():
    try:
        fh = open(REC["path"], "wb", buffering=1024 * 1024)
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
        REC.update({"fh": fh, "bytes": 24, "on": True, "flushed": 0})
    except Exception:
        REC.update({"fh": None, "bytes": 0, "on": False})


def record_packet(ts, data):
    if not REC["on"]:
        return
    try:
        REC["fh"].write(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6),
                                    len(data), len(data)))
        REC["fh"].write(data)
        REC["bytes"] += 16 + len(data)
        if REC["bytes"] - REC.get("flushed", 0) > 262144:
            REC["fh"].flush()
            REC["flushed"] = REC["bytes"]
        if REC["bytes"] > 512 * 1024 * 1024:
            stop_recording()
    except Exception:
        stop_recording()


def stop_recording():
    try:
        if REC["fh"]:
            REC["fh"].close()
    except Exception:
        pass
    REC.update({"fh": None, "on": False})


_CAPTIVE_HINTS = (("captive.apple.com", "Apple device"),
                  ("connectivitycheck.gstatic.com", "Android device"),
                  ("msftconnecttest.com", "Windows device"))


_FAMILY_DOMAINS = (
    ("palmplaystore.com", "Transsion"),
    ("samsungapps.com", "Samsung"),
    ("galaxystore.com", "Samsung"),
    ("appgallery.huawei.com", "Huawei"),
    ("hicloud.com", "Huawei"),
    ("heytap.com", "Oppo/Realme"),
    ("oppomobile.com", "Oppo"),
    ("market.xiaomi.com", "Xiaomi"),
    ("miui.com", "Xiaomi"),
    ("honor.com", "Honor"),
)


def _family_for(domain):
    """The maker behind a service domain the device itself called —
    vendor infrastructure names the family (palmplaystore = Transsion,
    the Tecno/Infinix store) from the device's own traffic."""
    d = (domain or "").lower()
    for suffix, family in _FAMILY_DOMAINS:
        if d == suffix or d.endswith("." + suffix):
            return family
    return None


_UA_MODEL = None


def _ua_model(ua):
    """The model a device announces to every HTTP site, from its
    User-Agent: 'Android 13; Pixel 8 Pro)' -> 'Pixel 8 Pro',
    '(iPhone; ...' -> 'iPhone'. Generic/decoy agents yield None."""
    global _UA_MODEL
    if _UA_MODEL is None:
        import re as _re
        _UA_MODEL = _re.compile(r"Android\s+[^;]*;\s*([^;)]+?)(?:\s+Build/|\))")
    if not ua:
        return None
    if "(iPhone;" in ua:
        return "iPhone"
    if "(iPad;" in ua:
        return "iPad"
    m = _UA_MODEL.search(ua)
    if m:
        model = m.group(1).strip()
        if model and model.lower() not in ("k", "linux"):
            return model
    return None


def _hint_for(host):
    """What kind of device is it, from its own traffic? A device that
    will not say its name still checks its maker's captive-portal
    address when it joins — that check names the maker honestly."""
    h = (host or "").lower().split(":")[0]
    for pat, label in _CAPTIVE_HINTS:
        if h == pat or h.endswith("." + pat):
            return label
    return None


def _toast_text(ev):
    """(title, text) for a catch toast — always naming WHAT was caught.
    A session-cookie catch once popped as 'frmLogin @ site' and read
    like a typed username/password pair; it was the site's login token,
    and the toast must say so."""
    kind = ev.get("kind", "")
    host = ev.get("host", "")
    if kind == "cookie":
        return ("CredLens: session cookie caught",
                f"{ev.get('user') or 'cookie'} @ {host}")
    if kind in ("bearer", "apikey"):
        return ("CredLens: token caught", f"{kind} @ {host}")
    if kind == "hash":
        return ("CredLens: password hash caught",
                f"{ev.get('user') or 'hash'} @ {host}")
    return ("CredLens: credential caught",
            f"{ev.get('user') or 'password'} @ {host}")


def toast_worker():
    """One Windows toast per burst of caught credentials (live mode)."""
    if os.name != "nt":
        return
    ps1 = os.path.join(os.path.dirname(os.path.abspath(__file__)), "toast.ps1")
    last = 0.0
    while True:
        ev = TOAST_Q.get()
        now = time.time()
        if now - last < 8:
            time.sleep(8 - (now - last))
        last = time.time()
        extra = 0
        while True:
            try:
                TOAST_Q.get_nowait()
                extra += 1
            except Exception:
                break
        title, text = _toast_text(ev)
        if extra:
            text += f"  (+{extra} more)"
        try:
            subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy",
                            "Bypass", "-File", ps1,
                            title, text],
                           timeout=15, creationflags=getattr(
                               subprocess, "CREATE_NO_WINDOW", 0))
        except Exception:
            pass


def build_report():
    st = STATE
    import datetime as _dt
    lines = []
    lines.append("CREDLENS SESSION REPORT")
    lines.append("Generated: " + _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    eng = {"raw": "built-in engine", "tshark": "tshark/Npcap"}.get(
        st.engine, st.engine or "-")
    lines.append(f"Mode: {st.mode}" + (f" ({eng})" if st.mode == "live" else "")
                 + (f" on {st.live_info}" if st.live_info else ""))
    lines.append(f"Packets seen: {st.stats['packets']} | "
                 f"HTTP requests: {st.stats['http_requests']}")
    lines.append("")
    lines.append("SUMMARY")
    lines.append(f"Devices: {len(st.devices)} | Websites: {len(st.sites)} | "
                 f"Credential events: {len(st.events)}")
    lines.append("")
    by_pw = {}
    for ev in st.events:
        pw = ev.get("password") or ""
        if len(pw) >= 4 and ev["kind"] not in ("cookie", "apikey", "bearer"):
            by_pw.setdefault(pw, set()).add(ev["host"])
    reuse = [(pw, sorted(hs)) for pw, hs in by_pw.items() if len(hs) >= 2]
    lines.append("PASSWORD REUSE")
    if reuse:
        for pw, hs in sorted(reuse, key=lambda r: -len(r[1])):
            lines.append(f'- "{pw}" on {len(hs)} websites: {", ".join(hs)}')
    else:
        lines.append("None found.")
    lines.append("")
    lines.append("CREDENTIAL EVENTS")
    if st.events:
        for ev in st.events:
            t = _dt.datetime.fromtimestamp(ev["ts"]).strftime("%H:%M:%S")
            nm = st.names.get(ev["src_ip"], "")
            lines.append(
                f"[{t}] {ev['kind'].upper()} {ev.get('user') or '-'} / "
                f"{ev.get('password') or '-'} @ {ev['host']}{ev.get('path', '')} "
                f"from {nm + ' ' if nm else ''}{ev['src_ip']} -> {ev['dst_ip']}")
    else:
        lines.append("None captured.")
    lines.append("")
    lines.append("DEVICES")
    for d in st.devices.values():
        nm = st.names.get(d["ip"], "") or "Unknown device"
        lines.append(f"- {nm} | {d['ip']} | requests {d['requests']} | leaks {d['leaks']}")
    lines.append("")
    lines.append("WEBSITES")
    for sv in st.sites.values():
        lines.append(f"- {sv['host']} | server {sv['server_ip']} | "
                     f"requests {sv['requests']} | leaks {sv['leaks']}")
    return "\n".join(lines) + "\n"


def vpn_wanted():
    """Polled by the Android shell: True while VPN capture should run."""
    return bool(VPN_REQ["want"])


def feed_external_packet(ts, data):
    """Packets from the Android VpnService (raw IP, linktype 101)."""
    if STATE.mode != "live" or STATE.engine != "vpn":
        with STATE_LOCK:
            STATE.mode = "live"
            STATE.engine = "vpn"
            STATE.live_info = "This phone (VPN)"
    live_packet(ts, bytes(data))


# ------------------------------------------------- Android rooted hotspot
# On a rooted phone the hotspot's clients can be watched the same way
# the Windows NPF stream watches them: tcpdump on the tether interface,
# its pcap stream parsed by the same engine. The binary is either the
# static build bundled in the APK (extracted by the Java shell, path
# handed over via set_tcpdump_path) or a system tcpdump under su.
TCPDUMP_PATH = {"path": ""}
_ANDROID_HS_CACHE = {"t": 0.0, "iface": None}


def set_tcpdump_path(path):
    """Called by the Android shell after extracting the bundled binary."""
    TCPDUMP_PATH["path"] = path or ""


def _eth_ip(frame):
    """Ethernet frame -> IP packet bytes, or None (shared by the NPF
    stream worker and the Android hotspot worker)."""
    if len(frame) < 14:
        return None
    et = struct.unpack(">H", frame[12:14])[0]
    off = 14
    if et == 0x8100 and len(frame) >= 18:
        et = struct.unpack(">H", frame[16:18])[0]
        off = 18
    if et in (0x0800, 0x86DD):
        return frame[off:]
    return None


def android_run_su(cmd, timeout=15):
    """Run a command as root. Returns (rc, stdout); (None, '') when
    su is missing, denied, or the command cannot run."""
    try:
        r = subprocess.run(["su", "-c", cmd], capture_output=True,
                           text=True, timeout=timeout)
        return r.returncode, r.stdout or ""
    except Exception:
        return None, ""


def android_root_ok():
    rc, out = android_run_su("id")
    return rc == 0 and "uid=0" in out


def android_tether_iface(text=None):
    """(iface, ip) of the hotspot interface, or None. Parses `ip -o
    addr show` output; takes text so Lab W can test it without a phone.
    The hotspot interface is the one serving a .1 gateway address
    (Android's default is 192.168.43.1); cellular (rmnet/ccmni) and
    loopback are excluded, and a plain Wi-Fi client lease scores too
    high to qualify."""
    if text is None:
        rc, text = android_run_su("ip -o addr show")
        if rc != 0 or not text:
            return None
    best = None
    for ln in text.splitlines():
        m = re.search(r"^\d+:\s+(\S+)\s+inet\s+([\d.]+)/\d+", ln)
        if not m:
            continue
        name, ip = m.group(1), m.group(2)
        if name == "lo" or ip.startswith("127."):
            continue
        if name.startswith(("rmnet", "ccmni", "wwan")):
            continue
        score = 0
        if name in ("ap0", "softap", "wlan1", "tether"):
            score -= 3
        if ip == "192.168.43.1":
            score -= 3
        if ip.endswith(".1"):
            score -= 1
        if name.startswith("wlan"):
            score += 1
        if best is None or score < best[0]:
            best = (score, name, ip)
    if best is None or best[0] > 0:
        return None
    return best[1], best[2]


def android_hotspot_cached():
    """Tether interface, cached 15 s — state polls hotspot_status()
    every poll, and every poll must not fork su."""
    if time.time() - _ANDROID_HS_CACHE["t"] > 15:
        _ANDROID_HS_CACHE["iface"] = android_tether_iface()
        _ANDROID_HS_CACHE["t"] = time.time()
    return _ANDROID_HS_CACHE["iface"]


def android_hotspot_worker(iface):
    """tcpdump (as root) on the tether interface -> engine, mirroring
    the Windows NPF stream worker. `exec` makes tcpdump replace su so
    terminating the process kills the capture itself, not a wrapper."""
    tcpdump = TCPDUMP_PATH["path"]
    if not (tcpdump and os.path.isfile(tcpdump)):
        tcpdump = "tcpdump"
    try:
        proc = subprocess.Popen(
            ["su", "-c", "exec %s -i %s -y EN10MB -l -n -w - -U"
             % (tcpdump, iface)],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except Exception as e:
        with STATE_LOCK:
            STATE.capture_error = f"hotspot capture failed: {e}"
        return
    LIVE_PROC["proc"] = proc
    if LIVE_PROC["stop"]:
        try:
            proc.terminate()
        except Exception:
            pass
        return
    try:
        for ts, frame in _iter_pcap_stream(proc.stdout,
                                           lambda: LIVE_PROC["stop"]):
            ipb = _eth_ip(frame)
            if ipb:
                try:
                    live_packet(ts, ipb)
                except Exception:
                    pass
    except Exception as e:
        with STATE_LOCK:
            STATE.capture_error = f"hotspot stream error: {e}"
    finally:
        try:
            proc.terminate()
        except Exception:
            pass


def android_hotspot_start():
    """Start rooted hotspot capture. Returns (ok, error). Manual-only:
    the mode is not auto-resumed on restart (the tether interface may
    not exist then)."""
    if not ANDROID:
        return False, "not an Android build"
    if not android_root_ok():
        return False, "phone is not rooted, or root was denied"
    t = android_tether_iface()
    if not t:
        return False, "no hotspot interface found — turn the hotspot on first"
    iface, _tip = t
    stop_all()
    with STATE_LOCK:
        STATE.reset()
        STATE.mode = "live"
        STATE.engine = "hotspot"
        STATE.live_info = f"Hotspot ({iface})"
    LIVE_PROC["stop"] = False
    threading.Thread(target=android_hotspot_worker, args=(iface,),
                     daemon=True).start()
    return True, ""


def live_packet(ts, data):
    """One raw IP packet from the built-in capture -> the same extractors
    PCAP mode uses (full parity: JSON, multipart, chunked, cookies, all
    plaintext protocols — no tshark field loss)."""
    record_packet(ts, data)
    pkt = engine.decode_frame(101, data)
    if not pkt:
        return
    kind, sport, dport, payload, seq, flags = engine.decode_transport(pkt)
    if kind is None:
        return
    src, dst = pkt["src"], pkt["dst"]
    LAST_PKT["t"] = ts
    with STATE_LOCK:
        STATE.stats["packets"] += 1
    if kind == "udp":
        if dport == 53 or sport == 53:
            _q = engine.parse_dns_query(payload)
            if _q:
                with STATE_LOCK:
                    STATE.add_domain(ts, src, _q[0], "dns", dst, _q[1])
        if sport in (67, 68, 137, 5353, 1900) or dport in (67, 68, 137, 5353, 1900):
            try:
                names = engine.harvest_names([dict(
                    pkt, kind=kind, sport=sport, dport=dport, payload=payload)])
            except Exception:
                names = {}
            with STATE_LOCK:
                for ip2, nm in names.items():
                    if engine.plausible_hostname(nm) and not \
                            engine.plausible_hostname(STATE.names.get(ip2)):
                        STATE.names[ip2] = nm
                for mac2, nm2 in engine.harvest_mac_names(
                        [dict(pkt, kind="udp", sport=sport, dport=dport,
                              payload=payload)]).items():
                    STATE.mac_names[mac2] = nm2
                for mac3, os3 in engine.harvest_dhcp_fingerprints(
                        [dict(pkt, kind="udp", sport=sport, dport=dport,
                              payload=payload)]).items():
                    STATE.fingerprints[mac3] = os3
                # a device announcing itself to the whole network is a
                # discovered device, even if none of its traffic is for us
                if src != "0.0.0.0" and (dst.endswith(".255") or dst.startswith(
                        ("224.", "239.", "255."))):
                    _bd = STATE._device(src)
                    if not _bd.get("via"):
                        _bd["via"] = "lan"
        return
    if kind != "tcp":
        return
    if (flags & 0x02) and not (flags & 0x10):
        # bare SYN: a new incarnation of this tuple — drop any stale flow
        with FLOCK:
            FLOWS.pop((src, sport, dst, dport), None)
    if not payload:
        return
    mac = pkt.get("src_mac") or OWN_MACS.get(src)
    if dport in engine.PROTO_PORTS:
        ckey, is_client, proto = (src, sport, dst, dport), True, True
    elif sport in engine.PROTO_PORTS:
        ckey, is_client, proto = (dst, dport, src, sport), False, True
    else:
        ckey, is_client, proto = (src, sport, dst, dport), True, False
    seq = seq or 0
    seg_end = seq + len(payload)
    pending_domain = None
    with FLOCK:
        if not proto and (dst, dport, src, sport) in FLOWS:
            ckey, is_client = (dst, dport, src, sport), False
        fl = FLOWS.get(ckey)
        if fl is None:
            fl = FLOWS[ckey] = {"csegs": [], "ssegs": [], "reqinfo": {},
                                "evs": set(), "last": ts,
                                "meta": (ts, mac), "host": None,
                                "proto": proto, "c_rng": [], "s_rng": []}
        fl["last"] = ts
        rng_key = "c_rng" if is_client else "s_rng"
        if _rng_covered(fl[rng_key], seq, seg_end):
            return            # pure retransmission: nothing new to parse
        (fl["csegs"] if is_client else fl["ssegs"]).append((seq, ts, payload))
        fl[rng_key] = _rng_add(fl[rng_key], seq, seg_end)
        for kk in ("csegs", "ssegs"):
            if len(fl[kk]) > 600:
                fl[kk] = fl[kk][-300:]
        cstream = _reassemble(fl["csegs"])
        sstream = _reassemble(fl["ssegs"])
        _PKT_N["n"] += 1
        if _PKT_N["n"] % 2048 == 0:      # idle sweep regardless of table size
            for kold in [k for k, v in FLOWS.items() if ts - v["last"] > 300]:
                FLOWS.pop(kold, None)
        if len(FLOWS) > 4000:
            for kold in [k for k, v in FLOWS.items() if ts - v["last"] > 600]:
                FLOWS.pop(kold, None)
            if len(FLOWS) > 4000:   # hard cap: evict least-recently-active
                excess = sorted(FLOWS.items(),
                                key=lambda kv: kv[1]["last"])[:len(FLOWS) - 4000]
                for kold, _v in excess:
                    FLOWS.pop(kold, None)
        if not fl.get("sni_done"):
            for _stream, _flag in ((cstream, "sni_c"), (sstream, "sni_s")):
                if fl.get(_flag) or not _stream:
                    continue
                _host, _complete = engine.sni_status(_stream[:16384])
                if _complete:
                    fl[_flag] = True
                if _host:
                    fl["sni_done"] = True
                    pending_domain = (_host, ckey[0], ckey[2])
                    break
            if fl.get("sni_c") and fl.get("sni_s"):
                fl["sni_done"] = True
    if pending_domain:
        with STATE_LOCK:
            STATE.add_domain(ts, pending_domain[1], pending_domain[0],
                             "sni", pending_domain[2])
    if fl["proto"]:
        if not is_client:
            return
        ts0, mac0 = fl["meta"]
        for ev in engine.extract_protocol_events(
                cstream, sstream, ckey[3], ckey[0], ckey[2], mac0, ts0):
            k = (ev["kind"], ev["src_ip"], ev["dst_ip"], ev["user"], ev["password"])
            if k in fl["evs"]:
                continue
            fl["evs"].add(k)
            with STATE_LOCK:
                STATE.add_event(ev)
        return
    if not is_client:
        _ch = engine.find_ntlm_challenge(sstream)
        if _ch:
            fl["ntlm_chal"] = _ch
        if fl.get("host"):
            for ev in engine.extract_response_events(
                    sstream, ckey[0], ckey[2], fl["host"], fl["meta"][1], ts):
                kk = (ev["kind"], ev["src_ip"], ev["host"], ev["password"])
                with STATE_LOCK:
                    if not STATE.aux_mark(kk):
                        continue
                    STATE.add_event(ev)
        return
    pass_count = {}
    for req in engine.parse_http_requests(cstream):
        rid = hash((req["method"], req["uri"], bytes(req["body"]),
                    req["headers"].get("authorization", "")))
        idx = pass_count.get(rid, 0)
        pass_count[rid] = idx + 1
        info = fl["reqinfo"].get(rid)
        if info is not None and idx < info["n"]:
            continue          # this occurrence was handled in an earlier pass
        split = urllib.parse.urlsplit(req["uri"] or "/")
        rec = {"ts": ts, "method": req["method"],
               "host": req["headers"].get("host", ckey[2]),
               "path": split.path or "/", "src_ip": ckey[0], "dst_ip": ckey[2],
               "src_mac": mac, "form_keys": req.get("fields", [])[:8],
               "ua": req["headers"].get("user-agent", ""),
               "ctype": req["headers"].get("content-type", ""),
               "captured": False}
        if info is not None:
            # same request genuinely submitted again on this connection:
            # the diary shows it, the credential feed does not repeat it
            rec["captured"] = info["captured"]
            info["n"] += 1
            with STATE_LOCK:
                STATE.stats["http_requests"] += 1
                STATE.add_request(rec)
            continue
        if fl.get("host") is None:
            fl["host"] = req["headers"].get("host", ckey[2])
        evs = engine.extract_http_events(req, ckey[0], ckey[2], mac, ts)
        _ns = fl.setdefault("ntlm_seen", set())
        for ev in engine.extract_ntlm(req, ckey[0], ckey[2], mac, ts,
                                      fl.get("ntlm_chal")):
            kk = (ev["kind"], ev["src_ip"], ev["host"], ev["user"], ev["password"])
            if kk not in _ns:
                _ns.add(kk)
                evs.append(ev)
        rec["captured"] = bool(evs)
        fl["reqinfo"][rid] = {"n": 1, "captured": bool(evs)}
        with STATE_LOCK:
            STATE.stats["http_requests"] += 1
            STATE.add_request(rec)
            for ev in evs:
                if ev["kind"] in ("cookie", "apikey", "bearer"):
                    kk = (ev["kind"], ev["src_ip"], ev["host"], ev["password"])
                    if not STATE.aux_mark(kk):
                        continue
                STATE.add_event(ev)


def start_live(selection, engine_pref=None):
    with CAPTURE_LOCK:
        return _start_live_locked(selection, engine_pref)


def _start_live_locked(selection, engine_pref=None):
    """Engine preference 'raw' (default): zero-dependency built-in capture,
    tshark only as fallback. Preference 'tshark': Npcap engine first — it
    is the only path with full IPv6 on Windows."""
    if ANDROID:
        stop_all()
        VPN_REQ["want"] = True
        with STATE_LOCK:
            STATE.reset()
            STATE.mode = "live"
            STATE.engine = "vpn"
            STATE.live_info = "This phone (VPN)"
        save_live_setting("vpn")
        return True
    pref = engine_pref or load_settings().get("engine") or "raw"
    # Validate the pick BEFORE stop_all(): a rejected start must never
    # kill a healthy running capture. (A mode-button click carrying an
    # id the current engine doesn't know once wiped a live hotspot
    # session this way and left the app idle.)
    if selection and selection.startswith("\\Device\\NPF_"):
        known = ({it["id"] for it in list_interfaces()}
                 if find_tshark() else set())
        if selection not in known:
            with STATE_LOCK:
                STATE.capture_error = "the selected adapter is not available"
            return False
    elif selection and selection != "auto":
        if pref == "tshark" and find_tshark():
            if selection not in {it["id"] for it in list_interfaces()}:
                ad = next((a for a in adapters()
                           if a["id"] == selection), None)
                mapped = npf_id_for_adapter(ad) if ad else None
                if not mapped:
                    with STATE_LOCK:
                        STATE.capture_error = ("the selected adapter is "
                                               "not available")
                    return False
                # same physical adapter, in the id form this engine
                # uses — a translation, not a substitution
                selection = mapped
        elif selection not in {a["id"] for a in adapters()}:
            with STATE_LOCK:
                STATE.capture_error = "the selected adapter is not available"
            return False
    stop_all()
    if selection and selection.startswith("\\Device\\NPF_"):
        # an explicit Npcap device (the saved adapter after a restart,
        # the hotspot pick) streams frames — never reinterpret it as a
        # raw-socket target and never fall back to "first adapter luck"
        hs = hotspot_adapter()
        hs_ip = None
        if hs and find_tshark() and npf_id_for_adapter(hs) == selection:
            hs_ip = hs["ip"]            # it IS the hotspot adapter:
        return start_live_npf(selection, hs_ip=hs_ip)   # mark it so
    if pref == "tshark" and find_tshark():
        ifaces = list_interfaces()
        if ifaces:
            chosen = next((it for it in ifaces if it["id"] == selection),
                          None)
            if chosen is None:
                # an explicit pick is a contract: never substitute a
                # different adapter and save it as the user's preference
                # (one stray start silently re-homed capture to Wi-Fi
                # that way) — fail honestly; the watchdog retries
                if selection and selection != "auto":
                    with STATE_LOCK:
                        STATE.capture_error = ("the selected adapter is "
                                               "not available")
                    return False
                chosen = ifaces[0]
            start_live_tshark(chosen["id"])
            with STATE_LOCK:
                STATE.engine = "tshark"
            save_live_setting(chosen["id"], engine_pref="tshark")
            return True
    ads = adapters()
    target = None
    if selection and selection != "auto":
        for a in ads:
            if a["id"] == selection:
                target = a
                break
    if target is None and ads:
        if selection and selection != "auto":
            with STATE_LOCK:
                STATE.capture_error = "the selected adapter is not available"
            return False
        target = ads[0]
    raw_err = None
    if target is not None:
        err = {}
        cap = rawcap.RawCapture(
            target["ip"], live_packet, lambda e: err.update({"e": e}),
            iface_name=target["name"] if os.name != "nt" else None)
        cap.start()
        cap.join(1.2)
        if not cap.is_alive():
            raw_err = err.get("e")      # surfaced if the fallback fails too
        if cap.is_alive():
            RAW["cap"] = cap
            start_recording()
            LIVE_PROC["stop"] = False
            OWN_MACS.clear()
            for a in ads:
                if a.get("mac"):
                    OWN_MACS[a["ip"]] = a["mac"]
            with STATE_LOCK:
                STATE.reset()
                STATE.mode = "live"
                STATE.engine = "raw"
                STATE.live_info = target["name"]
            threading.Thread(target=discovery_worker, args=(LIVE_PROC["gen"],), daemon=True).start()
            save_live_setting(target["id"], engine_pref="raw")
            return True
    if find_tshark():
        ifaces = list_interfaces()
        if ifaces:
            # engine fallback (raw failed): stay on the SAME adapter via
            # its Npcap twin; only an "auto" start may take the first
            # tshark interface. A fallback NEVER saves its substitution
            # as the user's live target
            fb = npf_id_for_adapter(target) if target is not None else None
            if fb is None and (not selection or selection == "auto"):
                fb = ifaces[0]["id"]
            if fb:
                start_live_tshark(fb)
                with STATE_LOCK:
                    STATE.engine = "tshark"
                return True
    with STATE_LOCK:
        STATE.live_info = ("Live capture needs Administrator rights for raw "
                           "sockets, and no tshark fallback is installed."
                           + (f" Raw capture reported: {raw_err}" if raw_err else ""))
    return False


def start_live_tshark(iface):
    """Start (or restart) the tshark worker on iface. Returns True on spawn."""
    LIVE_PROC["stop"] = False
    label = iface                       # UI shows the friendly adapter name,
    try:                                # never the raw \\Device\\NPF_{...} path
        for it in list_interfaces():
            if it["id"] == iface:
                label = it["label"]
                break
        else:
            if "NPF" in iface or iface.startswith("\\Device"):
                label = "Network adapter"
    except Exception:
        pass
    with STATE_LOCK:
        STATE.reset()
        STATE.mode = "live"
        STATE.live_info = label
    start_recording()               # fields mode records like every engine
    threading.Thread(target=npf_stream_worker, args=(iface,),
                     kwargs={"recorder_only": True}, daemon=True).start()
    threading.Thread(target=live_worker, args=(iface,), daemon=True).start()
    threading.Thread(target=proto_worker, args=(iface,), daemon=True).start()
    threading.Thread(target=discovery_worker, args=(LIVE_PROC["gen"],), daemon=True).start()
    return True

LIVE_PROC = {"proc": None, "proto_proc": None, "rec_proc": None,
             "stop": False, "gen": 0}

# Hotspot capture via Npcap: Windows ICS NAT rewrites a hotspot client's
# source address to this machine's own BEFORE the raw-socket layer, so the
# built-in engine attributes every client packet to the laptop. Npcap sits
# at the adapter, below NAT, and sees the client's real address. When the
# hotspot is the capture target we therefore stream FRAMES from tshark
# (-w -) into the same live_packet pipeline — full extraction parity.
NPF_HS = {"ip": None}
NPF_NOTE = {"msg": "", "t": 0.0}    # sticky: why the last npf stream ended
_NPF_CACHE = {"t": 0.0, "map": {}}


def _npf_map():
    """MAC -> \\Device\\NPF_{GUID}, from Get-NetAdapter (cached 60 s)."""
    if time.time() - _NPF_CACHE["t"] < 60 and _NPF_CACHE["map"]:
        return _NPF_CACHE["map"]
    m = {}
    if os.name == "nt":
        try:
            ps = ("Get-NetAdapter | Select-Object MacAddress,InterfaceGuid | "
                  "ConvertTo-Json -Compress")
            out = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                                 capture_output=True, text=True, timeout=10,
                                 creationflags=getattr(
                                     subprocess, "CREATE_NO_WINDOW", 0)).stdout or ""
            rows = json.loads(out) if out.strip() else []
            if isinstance(rows, dict):
                rows = [rows]
            for row in rows:
                mac = (row.get("MacAddress") or "").replace("-", ":").lower()
                guid = (row.get("InterfaceGuid") or "").strip("{}").upper()
                if mac and guid:
                    m[mac] = "\\Device\\NPF_{%s}" % guid
        except Exception:
            pass
    _NPF_CACHE.update({"t": time.time(), "map": m})
    return m


def npf_id_for_adapter(adapter):
    """The tshark/Npcap device id for an adapters() entry, or None."""
    if not adapter:
        return None
    ids = {it["id"].lower(): it["id"] for it in list_interfaces()}
    if not ids:
        return None
    mac = (adapter.get("mac") or "").lower()
    if mac:
        cand = _npf_map().get(mac)
        if cand and cand.lower() in ids:
            return ids[cand.lower()]
    name = (adapter.get("name") or "").lower()
    for it in list_interfaces():
        if it["label"].lower() == name:
            return it["id"]
    return None


def _iter_pcap_stream(stream, stopfn):
    """Yield (ts, ethernet_frame) from a classic-pcap byte stream."""
    def read_exact(n):
        buf = b""
        while len(buf) < n:
            chunk = stream.read(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf
    hdr = read_exact(24)
    # tshark -F pcap writes NANOSECOND pcap (magic a1b23c4d) — accept all
    # four classic-pcap magics; the first deployed reader knew only the
    # microsecond pair and bailed instantly on the real stream
    magics = {b"\xd4\xc3\xb2\xa1": ("<IIII", 1e6),    # micro, little-endian
              b"\xa1\xb2\xc3\xd4": (">IIII", 1e6),    # micro, big-endian
              b"\x4d\x3c\xb2\xa1": ("<IIII", 1e9),    # nano, little-endian
              b"\xa1\xb2\x3c\x4d": (">IIII", 1e9)}    # nano, big-endian
    if not hdr or hdr[:4] not in magics:
        return
    fmt, div = magics[hdr[:4]]
    while not stopfn():
        rh = read_exact(16)
        if not rh:
            return
        ts_s, ts_u, incl, _orig = struct.unpack(fmt, rh)
        if incl > 262144:
            return
        frame = read_exact(incl)
        if frame is None:
            return
        yield ts_s + ts_u / div, frame


def npf_stream_worker(iface, recorder_only=False):
    try:
        proc = subprocess.Popen(
            [find_tshark(), "-i", iface, "-l", "-n", "-F", "pcap", "-w", "-"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except Exception as e:
        if not recorder_only:
            with STATE_LOCK:
                STATE.capture_error = f"npcap stream failed: {e}"
        return
    LIVE_PROC["rec_proc" if recorder_only else "proc"] = proc
    if LIVE_PROC["stop"]:
        try:
            proc.terminate()
        except Exception:
            pass
        return
    try:
        for ts, frame in _iter_pcap_stream(proc.stdout, lambda: LIVE_PROC["stop"]):
            if len(frame) < 14:
                continue
            et = struct.unpack(">H", frame[12:14])[0]
            off = 14
            if et == 0x8100 and len(frame) >= 18:
                et = struct.unpack(">H", frame[16:18])[0]
                off = 18
            if et in (0x0800, 0x86DD):
                try:
                    if recorder_only:
                        # fields mode's companion: frames for the session
                        # recording only — extraction stays with the
                        # fields workers (no double-counted events)
                        record_packet(ts, frame[off:])
                    else:
                        live_packet(ts, frame[off:])
                except Exception:
                    pass            # one bad packet must not kill capture
        if not LIVE_PROC["stop"] and not recorder_only:
            NPF_NOTE.update({"msg": "stream ended, tshark exit %s"
                                    % proc.poll(), "t": time.time()})
            with STATE_LOCK:
                STATE.capture_error = ("npcap stream ended (tshark exit %s)"
                                       % proc.poll())
    except Exception as e:
        if not recorder_only:
            NPF_NOTE.update({"msg": f"stream error: {e}", "t": time.time()})
            with STATE_LOCK:
                STATE.capture_error = f"npcap stream error: {e}"
    finally:
        try:
            proc.terminate()
        except Exception:
            pass


def start_live_npf(iface, hs_ip=None):
    """Live capture from a Npcap device, frames decoded by live_packet."""
    label = iface
    for it in list_interfaces():
        if it["id"] == iface:
            label = it["label"]
            break
    with STATE_LOCK:
        STATE.reset()
        STATE.mode = "live"
        STATE.engine = "tshark"
        STATE.live_info = label
    NPF_HS["ip"] = hs_ip
    start_recording()
    LIVE_PROC["stop"] = False
    threading.Thread(target=npf_stream_worker, args=(iface,),
                     daemon=True).start()
    threading.Thread(target=discovery_worker, args=(LIVE_PROC["gen"],),
                     daemon=True).start()
    # record WHERE capture is, never the user's engine preference —
    # saving engine="tshark" here once poisoned the watchdog into
    # fields-mode restarts (and overwrote the user's raw preference)
    save_live_setting(iface)
    _set_setting("hotspot_npf", iface)
    return True

def detect_lan():
    """This machine's current network: {ip, mask, cidr, gateway} (best effort)."""
    import ipaddress as _ipa
    info = {"ip": None, "mask": None, "cidr": None, "gateway": None}
    try:
        import socket as _s
        probe = _s.socket(_s.AF_INET, _s.SOCK_DGRAM)
        probe.connect(("8.8.8.8", 80))
        info["ip"] = probe.getsockname()[0]
        probe.close()
    except Exception:
        pass
    if not info["ip"]:
        return info
    try:
        if os.name == "nt":
            out = subprocess.run(["ipconfig"], capture_output=True, text=True,
                                 timeout=10, creationflags=getattr(
                                     subprocess, "CREATE_NO_WINDOW", 0)).stdout or ""
            blocks = re.split(r"\r?\n\r?\n", out)
            blk = next((b for b in blocks if info["ip"] in b), out)
            m = re.search(r"Subnet Mask[^:]*:\s*([\d.]+)", blk)
            if m:
                info["mask"] = m.group(1)
            gi = blk.find("Default Gateway")
            if gi >= 0:
                g = re.search(r"(\d+\.\d+\.\d+\.\d+)", blk[gi:gi + 200])
                if g:
                    info["gateway"] = g.group(1)
        else:
            out = subprocess.run(["ip", "-o", "-4", "addr", "show"],
                                 capture_output=True, text=True, timeout=10).stdout or ""
            for ln in out.splitlines():
                m = re.search(r"inet\s+([\d.]+)/(\d+)", ln)
                if m and m.group(1) == info["ip"]:
                    info["mask"] = str(_ipa.IPv4Address(
                        (0xFFFFFFFF << (32 - int(m.group(2)))) & 0xFFFFFFFF))
            rt = subprocess.run(["ip", "route"], capture_output=True, text=True,
                                timeout=10).stdout or ""
            g = re.search(r"default via\s+([\d.]+)", rt)
            if g:
                info["gateway"] = g.group(1)
    except Exception:
        pass
    try:
        if info["mask"]:
            info["cidr"] = str(_ipa.ip_network(
                f"{info['ip']}/{info['mask']}", strict=False))
        else:
            info["cidr"] = info["ip"] + "/24"
    except Exception:
        info["cidr"] = info["ip"] + "/24"
    return info


SCAN_PROC = {"running": False, "phase": "", "report": "", "summary": None,
             "error": "", "stop": False}


_NET_CACHE = {"t": 0.0, "v": None}


def connected_network():
    """Identity of the network this machine is currently joined to:
    {ssid, ip, gateway, gateway_mac, cidr}. Re-detected as the machine
    moves between networks (cached 5 s). Best-effort; blanks when a fact
    cannot be read on this platform."""
    if time.time() - _NET_CACHE["t"] < 5 and _NET_CACHE["v"] is not None:
        return _NET_CACHE["v"]
    lan = detect_lan()
    info = {"ssid": "", "ip": lan.get("ip") or "",
            "gateway": lan.get("gateway") or "", "gateway_mac": "",
            "cidr": lan.get("cidr") or ""}
    try:
        if os.name == "nt":
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            out = subprocess.run(["netsh", "wlan", "show", "interfaces"],
                                 capture_output=True, text=True, timeout=6,
                                 creationflags=flags).stdout or ""
            m = re.search(r"^\s*SSID\s*:\s*(.+)$", out, re.M)
            if m:
                info["ssid"] = m.group(1).strip()
            if not info["ssid"]:
                ps = ("(Get-NetConnectionProfile | Where-Object "
                      "{$_.IPv4Connectivity -ne 'Disconnected'} | "
                      "Select-Object -First 1).Name")
                out = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                                     capture_output=True, text=True, timeout=6,
                                     creationflags=flags).stdout or ""
                info["ssid"] = out.strip()
            if info["gateway"]:
                out = subprocess.run(["arp", "-a", info["gateway"]],
                                     capture_output=True, text=True, timeout=6,
                                     creationflags=flags).stdout or ""
                m = re.search(r"([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})", out)
                if m:
                    info["gateway_mac"] = m.group(1).lower().replace("-", ":")
    except Exception:
        pass
    _NET_CACHE.update({"t": time.time(), "v": info})
    return info


def scan_worker(target, profile, exclude, label_override=None):
    SCAN_PROC.update({"running": True, "phase": "starting…", "report": "",
                      "summary": None, "error": "", "stop": False})
    try:
        with STATE_LOCK:
            known = list(STATE.devices)
            names = dict(STATE.names)
        report, summary = scanner.run_scan(
            target, profile, exclude,
            progress=lambda m: SCAN_PROC.update({"phase": m}),
            stop=lambda: SCAN_PROC["stop"],
            known_hosts=known, names=names, label_override=label_override)
        SCAN_PROC.update({"report": report, "summary": summary,
                          "phase": "done"})
    except Exception as e:
        SCAN_PROC.update({"error": str(e), "phase": "failed"})
    finally:
        SCAN_PROC["running"] = False


# --------------------------------------------------------------- live (tshark)
def live_worker(iface):
    cmd = [find_tshark(), "-i", iface, "-l", "-n", "-Y", "http.request",
           "-T", "fields", "-E", "separator=\t", "-E", "occurrence=a", "-E", "aggregator=|",
           "-e", "frame.time_epoch", "-e", "eth.src", "-e", "ip.src", "-e", "ip.dst",
           "-e", "ipv6.src", "-e", "ipv6.dst",
           "-e", "http.request.method", "-e", "http.host", "-e", "http.request.uri",
           "-e", "http.authorization", "-e", "urlencoded-form.key", "-e", "urlencoded-form.value",
           "-e", "http.content_type", "-e", "http.cookie"]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                text=True, bufsize=1,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except Exception as e:
        with STATE_LOCK:
            STATE.live_info = f"tshark failed to start: {e}"
            STATE.mode = "idle"
        return
    LIVE_PROC["proc"] = proc
    if LIVE_PROC["stop"]:      # stop raced the spawn — don't orphan the child
        try:
            proc.terminate()
        except Exception:
            pass
        return
    for line in proc.stdout:
        if LIVE_PROC["stop"]:
            break
        f = line.rstrip("\n").split("\t")
        if len(f) < 10:
            continue
        try:
            ts = float(f[0] or time.time())
        except ValueError:
            ts = time.time()
        one = lambda v: (v or "").split("|")[0]
        mac = one(f[1])
        src = one(f[2]) or (one(f[4]) if len(f) > 4 else "")
        dst = one(f[3]) or (one(f[5]) if len(f) > 5 else "")
        method, host, uri, auth = one(f[6]), one(f[7]), f[8], one(f[9])
        keys = f[10].split("|") if len(f) > 10 and f[10] else []
        vals = f[11].split("|") if len(f) > 11 and f[11] else []
        ctype = f[12] if len(f) > 12 else ""
        cookie = one(f[13]) if len(f) > 13 else ""
        body = urllib.parse.urlencode(list(zip(keys, vals))).encode()
        headers = {"host": host}
        # the extractor only parses form bodies when Content-Type says so —
        # tshark hands us dissected fields, so the header must be rebuilt here
        if keys:
            headers["content-type"] = ctype or "application/x-www-form-urlencoded"
        if auth:
            headers["authorization"] = auth
        if cookie:
            headers["cookie"] = cookie
        req = {"method": method or "GET", "uri": uri or "/", "headers": headers,
               "body": body, "raw": f"{method} {uri} HTTP/1.1\nHost: {host}\n(live via tshark)"}
        evs = engine.extract_http_events(req, src, dst, mac, ts)
        split = urllib.parse.urlsplit(uri or "/")
        rec = {"ts": ts, "method": method or "GET", "host": host,
               "path": split.path or "/", "src_ip": src, "dst_ip": dst,
               "src_mac": mac, "form_keys": keys[:8], "ctype": ctype,
               "captured": bool(evs)}
        with STATE_LOCK:
            STATE.stats["packets"] += 1
            STATE.stats["http_requests"] += 1
            STATE.add_request(rec)
            for ev in evs:
                if ev["kind"] in ("cookie", "apikey", "bearer"):
                    k = (ev["kind"], ev["src_ip"], ev["host"], ev["password"])
                    if not STATE.aux_mark(k):
                        continue
                STATE.add_event(ev)
    if not LIVE_PROC["stop"]:
        with STATE_LOCK:
            STATE.capture_error = "tshark capture ended unexpectedly"


def proto_worker(iface):
    """Second tshark feed: raw TCP payloads on the plaintext-protocol ports,
    parsed by the same stream extractors as PCAP mode."""
    cmd = [find_tshark(), "-i", iface, "-l", "-n",
           "-Y", "tcp.port in {21, 23, 25, 110, 143, 587, 1883}",
           "-T", "fields", "-E", "separator=\t", "-E", "occurrence=a", "-E", "aggregator=|",
           "-e", "frame.time_epoch", "-e", "eth.src", "-e", "ip.src", "-e", "ip.dst",
           "-e", "ipv6.src", "-e", "ipv6.dst", "-e", "tcp.srcport", "-e", "tcp.dstport",
           "-e", "tcp.payload"]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                text=True, bufsize=1,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except Exception:
        with STATE_LOCK:
            STATE.capture_error = "protocol capture failed to start (tshark)"
        return
    LIVE_PROC["proto_proc"] = proc
    if LIVE_PROC["stop"]:      # stop raced the spawn — don't orphan the child
        try:
            proc.terminate()
        except Exception:
            pass
        return
    cbuf, sbuf, meta, emitted = {}, {}, {}, set()
    for line in proc.stdout:
        if LIVE_PROC["stop"]:
            break
        f = line.rstrip("\n").split("\t")
        if len(f) < 9:
            continue
        one = lambda v: (v or "").split("|")[0]
        try:
            ts = float(f[0] or time.time())
        except Exception:
            ts = time.time()
        mac = one(f[1])
        src = one(f[2]) or one(f[4])
        dst = one(f[3]) or one(f[5])
        try:
            sport, dport = int(one(f[6]) or 0), int(one(f[7]) or 0)
        except Exception:
            continue
        chunks = []
        for part in (f[8] or "").split("|"):
            part = part.strip()
            if part:
                try:
                    chunks.append(bytes.fromhex(part.replace(":", "")))
                except Exception:
                    pass
        if not chunks or not src or not dst:
            continue
        if dport in engine.PROTO_PORTS:
            key, is_client = (src, sport, dst, dport), True
        elif sport in engine.PROTO_PORTS:
            key, is_client = (dst, dport, src, sport), False
        else:
            continue
        data = b"".join(chunks)
        with STATE_LOCK:
            STATE.stats["packets"] += 1
        if is_client:
            cbuf[key] = (cbuf.get(key, b"") + data)[-65536:]
            meta.setdefault(key, (ts, mac))
        else:
            sbuf[key] = (sbuf.get(key, b"") + data)[-65536:]
            continue
        if len(cbuf) + len(sbuf) > 1024:
            # long fields-mode sessions meet endless short connections —
            # the per-connection buffers must not grow for the process
            # life. NEVER evict the connection being processed right now:
            # a long-lived flow keeps its original dict position, so it
            # sits near the front and its meta would vanish mid-parse
            for buf in (cbuf, sbuf):
                for old in list(buf)[:256]:
                    if old == key:
                        continue
                    buf.pop(old, None)
                    meta.pop(old, None)
        ts0, mac0 = meta.get(key, (ts, mac))
        evs = engine.extract_protocol_events(cbuf[key], sbuf.get(key, b""),
                                             key[3], key[0], key[2], mac0, ts0)
        for ev in evs:
            k = (ev["kind"], ev["src_ip"], ev["dst_ip"], ev["user"], ev["password"])
            if k in emitted:
                continue
            emitted.add(k)
            with STATE_LOCK:
                STATE.add_event(ev)
    if not LIVE_PROC["stop"]:
        with STATE_LOCK:
            STATE.capture_error = "protocol capture ended unexpectedly"


CAPTURE_LOCK = threading.RLock()
SCAN_LOCK = threading.Lock()


def stop_all():
    with CAPTURE_LOCK:
        _stop_all_locked()


def _stop_all_locked():
    VPN_REQ["want"] = False
    NPF_HS["ip"] = None
    stop_recording()
    LIVE_PROC["stop"] = True
    LIVE_PROC["gen"] += 1
    if RAW.get("cap"):
        try:
            RAW["cap"].stop()
        except Exception:
            pass
        RAW["cap"] = None
    with FLOCK:
        FLOWS.clear()
    if LIVE_PROC["proc"]:
        try:
            LIVE_PROC["proc"].terminate()
        except Exception:
            pass
    LIVE_PROC["proc"] = None
    if LIVE_PROC.get("proto_proc"):
        try:
            LIVE_PROC["proto_proc"].terminate()
        except Exception:
            pass
    LIVE_PROC["proto_proc"] = None
    if LIVE_PROC.get("rec_proc"):
        try:
            LIVE_PROC["rec_proc"].terminate()
        except Exception:
            pass
    LIVE_PROC["rec_proc"] = None


# -------------------------------------------------------------------- server
# Local-only hardening: the dashboard must never be reachable under a foreign
# Host name (DNS-rebinding), and state-changing POSTs must carry our header
# (a cross-site form/fetch from any web page cannot set it -> CSRF dead).
ALLOWED_HOST = re.compile(r"^(127\.0\.0\.1|localhost|\[::1\])(:\d+)?$", re.I)
MAX_JSON_BODY = 1 * 1024 * 1024
MAX_PCAP_BODY = 256 * 1024 * 1024


def _json_obj(body):
    """A POST body as a JSON object — anything else (a list, a scalar,
    invalid JSON) becomes {} so handlers can .get() without dying.
    A malformed body must earn a clean 400, never a dropped connection."""
    try:
        req = json.loads(body or b"{}")
    except Exception:
        return {}
    return req if isinstance(req, dict) else {}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _host_ok(self):
        host = (self.headers.get("Host") or "").strip()
        return bool(ALLOWED_HOST.match(host))

    def _guard(self, post=False):
        if not self._host_ok():
            self.close_connection = True
            self._json({"ok": False, "error": "forbidden host"}, 403)
            return False
        if post and self.headers.get("X-CredLens") != "1":
            self.close_connection = True
            self._json({"ok": False, "error": "missing X-CredLens header"}, 403)
            return False
        return True

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _report(self):
        with STATE_LOCK:
            text = build_report()
        self._json({"ok": True, "report": text})

    def _pcap(self):
        if REC["on"] and REC["fh"]:
            try:
                REC["fh"].flush()
            except Exception:
                pass
        path = REC["path"]
        if not os.path.exists(path) or os.path.getsize(path) <= 24:
            return self._json({"ok": False, "error": "no recording yet"}, 404)
        # no Content-Length on purpose: the file is still growing while
        # recording — a stat'ed length would truncate the download
        # mid-packet. HTTP/1.0 close delimits the body instead.
        self.close_connection = True
        self.send_response(200)
        self.send_header("Content-Type", "application/vnd.tcpdump.pcap")
        self.send_header("Content-Disposition",
                         "attachment; filename=credlens-session.pcap")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        with open(path, "rb") as fh:
            shutil.copyfileobj(fh, self.wfile, 1024 * 1024)

    def do_GET(self):
        if not self._guard():
            return
        if self.path in ("/", "/index.html", "/mobile.html"):
            page = "mobile.html" if self.path == "/mobile.html" else "index.html"
            try:
                body = open(os.path.join(getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__))), page), "rb").read()
            except Exception as e:
                self._json({"ok": False, "error": f"{page} unreadable: {e}"}, 500)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                             "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                             "connect-src 'self'; frame-ancestors 'none'")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/api/interfaces":
            ads = adapters()
            self._json({"interfaces": ads if ads else list_interfaces(),
                        "tshark": bool(find_tshark()),
                        "engine": "raw" if ads else "tshark"})
        elif self.path == "/api/scan/status":
            self._json({"running": SCAN_PROC["running"], "phase": SCAN_PROC["phase"],
                        "report": SCAN_PROC["report"], "summary": SCAN_PROC["summary"],
                        "error": SCAN_PROC["error"]})
        elif self.path == "/api/report":
            self._report()
        elif self.path == "/api/pcap":
            self._pcap()
        elif self.path == "/api/state":
            with STATE_LOCK:
                snap = STATE.snapshot()
            # hotspot_status() may shell out to PowerShell for the WinRT
            # tethering probe (seconds, worst case) — it must never run
            # while STATE_LOCK is held, or every capture thread stalls
            # behind it on every poll
            snap["hotspot"] = hotspot_status()
            snap["network"] = connected_network()
            snap["host"] = {"name": HOST_NAME}
            self._json(snap)
        else:
            self.send_error(404)

    def do_POST(self):
        if not self._guard(post=True):
            return
        cap = MAX_PCAP_BODY if self.path == "/api/load-pcap" else MAX_JSON_BODY
        try:
            ln = int(self.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            ln = -1
        if ln < 0 or ln > cap:
            self.close_connection = True
            self._json({"ok": False, "error": "request body too large"}, 413)
            return
        body = self.rfile.read(ln) if ln else b""
        if self.path == "/api/load-pcap":
            # analyze FIRST: a corrupt upload must not kill a running
            # capture or leave the UI claiming LIVE over a dead engine
            try:
                result = engine.analyze_pcap(body)
            except Exception as e:
                self._json({"ok": False, "error": str(e)}, 400)
                return
            # stop+load under CAPTURE_LOCK: the watchdog holds the same
            # lock across its keep -> restart -> restore, so the two can
            # never interleave into a stale restore over this analysis
            with CAPTURE_LOCK:
                stop_all()
                with STATE_LOCK:
                    STATE.load_analysis(result)
                    STATE.mode = "pcap"
                    STATE.engine = ""
                    STATE.capture_error = ""
            self._json({"ok": True, "events": len(result["events"]),
                        "packets": result["stats"]["packets"]})
        elif self.path == "/api/hotspot":
            req = _json_obj(body)
            act = req.get("action", "")
            if not isinstance(act, str):
                act = ""
            if act == "open-settings":
                if os.name == "nt":
                    try:
                        os.startfile("ms-settings:network-mobilehotspot")
                    except Exception as e:
                        return self._json({"ok": False, "error": str(e)}, 500)
                self._json({"ok": True})
            elif act == "auto":
                set_hotspot_auto(bool(req.get("on")))
                self._json({"ok": True, "hotspot": hotspot_status()})
            elif act in ("use", "leave"):
                if ANDROID:
                    if act == "use":
                        ok, err = android_hotspot_start()
                        if not ok:
                            self._json({"ok": False, "error": err}, 400)
                        else:
                            self._json({"ok": True,
                                        "hotspot": hotspot_status()})
                    else:
                        stop_all()
                        self._json({"ok": True, "hotspot": hotspot_status()})
                    return
                # a manual mode pick beats automation: turn auto-switch
                # OFF so the app never fights the user's explicit choice
                # (it can be re-enabled from the Settings checkbox)
                ok = hotspot_switch(act == "use")
                if ok:
                    set_hotspot_auto(False)
                self._json({"ok": ok, "hotspot": hotspot_status()})
            else:
                self._json({"ok": False, "error": "unknown action"}, 400)
        elif self.path == "/api/label":
            req = _json_obj(body)
            mac = req.get("mac")
            mac = mac.strip().lower() if isinstance(mac, str) else ""
            name = req.get("name", "")
            if not isinstance(name, str):
                self._json({"ok": False, "error": "bad name"}, 400)
                return
            name = "".join(c for c in name if ord(c) >= 32).strip()[:40]
            if not re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", mac):
                self._json({"ok": False, "error": "bad mac"}, 400)
                return
            data = load_settings()
            labels = dict(data.get("labels") or {})
            if name:
                labels[mac] = name
            else:
                labels.pop(mac, None)
            data["labels"] = labels
            _write_settings(data)
            self._json({"ok": True, "labels": labels})
        elif self.path == "/api/settings":
            try:
                eng = json.loads(body or b"{}").get("engine", "")
            except Exception:
                eng = ""
            if eng not in ("raw", "tshark"):
                self._json({"ok": False, "error": "unknown engine"}, 400)
                return
            set_engine_pref(eng)
            if STATE.mode == "live":
                start_live(load_settings().get("live_iface", "auto"),
                           engine_pref=eng)
            self._json({"ok": True, "engine": STATE.engine})
        elif self.path == "/api/scan":
            if SCAN_PROC["running"]:
                self._json({"ok": False, "error": "a scan is already running"}, 409)
                return
            req = _json_obj(body)
            target = req.get("target")
            target = target.strip() if isinstance(target, str) else ""
            label_override = None
            if req.get("lan"):
                lan = detect_lan()
                if not lan.get("cidr"):
                    self._json({"ok": False,
                                "error": "could not detect the local network"}, 400)
                    return
                target = lan["cidr"]
                label_override = (f"LAN {lan['cidr']} (auto-detected; "
                                  f"this device {lan['ip']})")
            if not target:
                self._json({"ok": False, "error": "no target given"}, 400)
                return
            profile = req.get("profile", "standard")
            if profile not in ("passive", "standard", "deep"):
                self._json({"ok": False, "error": "unknown profile"}, 400)
                return
            exclude = req.get("exclude", "")
            if not isinstance(exclude, str):
                exclude = ""
            with SCAN_LOCK:      # re-check + claim atomically at spawn
                if SCAN_PROC["running"]:
                    self._json({"ok": False,
                                "error": "a scan is already running"}, 409)
                    return
                SCAN_PROC["running"] = True
            threading.Thread(target=scan_worker, daemon=True,
                             args=(target, profile, exclude,
                                   label_override)).start()
            self._json({"ok": True, "target": target})
        elif self.path == "/api/scan/stop":
            SCAN_PROC["stop"] = True
            self._json({"ok": True})
        elif self.path == "/api/live":
            # validate BEFORE touching the running capture — start_live
            # stops the old engine itself once the request is known-good
            try:
                iface = json.loads(body or b"{}").get("iface", "").strip()
            except Exception:
                iface = ""
            valid = {"", "auto"}
            valid |= {a["id"] for a in adapters()}
            valid |= {it["id"] for it in list_interfaces()}
            if iface not in valid:
                # never let request data reach a capture command line unchecked
                self._json({"ok": False, "error": "unknown interface"}, 400)
                return
            try:
                eng = json.loads(body or b"{}").get("engine", "")
            except Exception:
                eng = ""
            if eng not in ("", "raw", "tshark"):
                self._json({"ok": False, "error": "unknown engine"}, 400)
                return
            if start_live(iface or "auto", engine_pref=eng or None):
                self._json({"ok": True})
            else:
                with STATE_LOCK:
                    msg = STATE.live_info
                self._json({"ok": False, "error": msg}, 400)
        elif self.path == "/api/stop":
            clear_live_setting()
            stop_all()
            with STATE_LOCK:
                STATE.mode = "idle"
                STATE.live_info = ""
                STATE.engine = ""
            self._json({"ok": True})
        elif self.path == "/api/clear":
            clear_live_setting()
            stop_all()
            with STATE_LOCK:
                STATE.reset()
                STATE.mode = "idle"
                STATE.live_info = ""
                STATE.engine = ""
            self._json({"ok": True})
        else:
            self.send_error(404)


WATCH_FAILS = {"n": 0}


def _capture_dead():
    if STATE.engine == "raw":
        cap = RAW.get("cap")
        if cap is None or not cap.is_alive():
            return True
        if time.time() - LAST_PKT["t"] > 150:
            cur = rawcap.default_route_ip()
            return bool(cur and cap.adapter_ip and cur != cap.adapter_ip)
        return False
    if STATE.engine == "tshark":
        # npf frame-stream mode runs a single process (protocols are
        # decoded from its frames) — proto_proc only exists in fields mode
        keys = ("proc",) if NPF_HS.get("ip") else ("proc", "proto_proc")
        for key in keys:
            pr = LIVE_PROC.get(key)
            if pr is None or pr.poll() is not None:
                return True
        return False
    return False


HOTSPOT_IP = "192.168.137.1"


def hotspot_adapter():
    """The Windows Mobile Hotspot (Wi-Fi Direct) adapter, if it exists."""
    for a in adapters():
        if a.get("ip") == HOTSPOT_IP or (
                "wi-fi direct" in (a.get("name") or "").lower()
                and (a.get("ip") or "").startswith("192.168.137.")):
            return a
    return None


def _current_iface():
    if NPF_HS.get("ip"):
        return NPF_HS["ip"]
    cap = RAW.get("cap")
    if cap is not None and getattr(cap, "ip", None):
        return cap.ip
    return load_settings().get("live_iface")


_HS_ON = {"t": 0.0, "v": None}


def hotspot_on():
    """Windows Mobile Hotspot really ON? True/False from the tethering
    API the Settings toggle itself uses; None when unreadable (caller
    must not switch on None). Every cheaper signal lies on this class of
    machine: the Wi-Fi Direct adapter keeps its 192.168.137.1 address,
    'Up' status and even static ARP entries with the hotspot OFF, which
    once sent the auto-switch into a 40-second ping-pong that kept
    wiping the session state."""
    if os.name != "nt":
        return None
    if time.time() - _HS_ON["t"] < 8 and _HS_ON["v"] is not None:
        return _HS_ON["v"]
    v = None
    try:
        ps = ("Add-Type -AssemblyName System.Runtime.WindowsRuntime; "
              "$p=[Windows.Networking.Connectivity.NetworkInformation,"
              "Windows.Networking,ContentType=WindowsRuntime]::"
              "GetInternetConnectionProfile(); "
              "$m=[Windows.Networking.NetworkOperators."
              "NetworkOperatorTetheringManager,Windows.Networking,"
              "ContentType=WindowsRuntime]::CreateFromConnectionProfile($p); "
              "$m.TetheringOperationalState.ToString()")
        out = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                             capture_output=True, text=True, timeout=12,
                             creationflags=getattr(
                                 subprocess, "CREATE_NO_WINDOW", 0)).stdout or ""
        out = out.strip()
        if out == "On":
            v = True
        elif out == "Off":
            v = False
    except Exception:
        pass
    if v is not None:
        _HS_ON.update({"t": time.time(), "v": v})
    return v


def hotspot_status():
    if ANDROID:
        t = android_hotspot_cached()
        return {"present": bool(t),
                "on": STATE.mode == "live" and STATE.engine == "hotspot",
                "active": STATE.mode == "live" and STATE.engine == "hotspot",
                "auto": False,
                "ip": (t or (None, None))[1]}
    hs = hotspot_adapter()
    cur = _current_iface()
    return {"present": bool(hs),
            "on": hotspot_on(),
            "active": bool(hs) and STATE.mode == "live"
                      and cur == (hs or {}).get("ip"),
            "auto": bool(PREF.get("hotspot_auto")),
            "ip": (hs or {}).get("ip")}


def hotspot_switch(to_hotspot):
    """Move live capture between the Wi-Fi adapter and the hotspot."""
    if STATE.mode != "live":
        return False
    if to_hotspot:
        hs = hotspot_adapter()
        if not hs:
            return False
        cur = load_settings().get("live_iface")
        if cur and cur != hs["ip"] and "NPF_" not in cur:
            _set_setting("wifi_iface", cur)
        # Npcap sees hotspot clients BEFORE Windows NAT rewrites their
        # addresses to this machine's own — prefer the frame stream so
        # client traffic is attributed to the client, not the laptop.
        npf = npf_id_for_adapter(hs) if find_tshark() else None
        if npf:
            stop_all()
            return start_live_npf(npf, hs["ip"])
        NPF_NOTE.update({"msg": "hotspot npf device unresolved",
                         "t": time.time()})
        return start_live(hs["id"], engine_pref=PREF["engine"])
    back = load_settings().get("wifi_iface") or "auto"
    if "NPF_" in back:
        back = "auto"
    return start_live(back, engine_pref=PREF["engine"])


def _hotspot_autoswitch():
    if not PREF.get("hotspot_auto") or STATE.mode != "live":
        return
    on = hotspot_on()
    if on is None:
        return                      # never switch on a guess
    hs = hotspot_adapter()
    cur = _current_iface()
    if on:
        if hs and cur != hs["ip"]:
            hotspot_switch(True)
    elif cur and (cur.startswith("192.168.137.")
                  or cur == load_settings().get("hotspot_npf")):
        hotspot_switch(False)


def watchdog_tick():
    """One resilience pass: if the capture died (worker exit, adapter
    drop, IP change after a Wi-Fi roam), restart it and keep everything
    captured so far. After 5 failed restarts, stop claiming LIVE."""
    if STATE.engine not in ("raw", "tshark"):
        return False
    _hotspot_autoswitch()
    if STATE.mode != "live" or not STATE.engine:
        return False
    rp = LIVE_PROC.get("rec_proc")
    if (rp is not None and STATE.engine == "tshark"
            and rp.poll() is not None):
        # the fields-mode companion recorder died quietly — restart it;
        # extraction was never affected, only the session recording froze
        LIVE_PROC["rec_proc"] = None
        rec_iface = load_settings().get("live_iface") or ""
        if rec_iface:
            threading.Thread(target=npf_stream_worker, args=(rec_iface,),
                             kwargs={"recorder_only": True},
                             daemon=True).start()
    if not _capture_dead() and not STATE.capture_error:
        WATCH_FAILS["n"] = 0
        return False
    # CAPTURE_LOCK across keep -> restart -> restore: a PCAP upload
    # landing mid-restart takes the same lock for its stop+load, so the
    # restore can never rebind stale collections over a fresh analysis
    with CAPTURE_LOCK:
        with STATE_LOCK:
            keep = (STATE.events, STATE.requests, STATE.devices, STATE.sites,
                    STATE.names, STATE.stats, STATE.aux_seen, STATE.domains)
        sel = load_settings().get("live_iface", "auto")
        pref = load_settings().get("engine", "raw")
        if start_live(sel, engine_pref=pref):
            with STATE_LOCK:
                # start_live reset the state — anything captured during
                # the restart window landed in the fresh collections;
                # merge it into the restored ones instead of discarding
                fresh = (STATE.events, STATE.requests, STATE.devices,
                         STATE.sites, STATE.names, STATE.stats,
                         STATE.aux_seen, STATE.domains)
                (STATE.events, STATE.requests, STATE.devices, STATE.sites,
                 STATE.names, STATE.stats, STATE.aux_seen,
                 STATE.domains) = keep
                for e in fresh[0]:
                    if e not in STATE.events:
                        STATE.events.append(e)
                for r in fresh[1]:
                    if r not in STATE.requests:
                        STATE.requests.append(r)
                for new_coll, keep_coll in ((fresh[2], STATE.devices),
                                            (fresh[3], STATE.sites)):
                    for k, v in new_coll.items():
                        if k not in keep_coll:
                            keep_coll[k] = v
                            continue
                        # same entry on both sides: sum its counters,
                        # union its page set — never lose window growth
                        for f in ("requests", "leaks"):
                            if isinstance(v.get(f), (int, float)):
                                keep_coll[k][f] = (keep_coll[k].get(f, 0)
                                                   + v[f])
                        kp, vp = keep_coll[k].get("pages"), v.get("pages")
                        if isinstance(kp, set) and isinstance(vp, (set, list)):
                            kp |= set(vp)
                for k, v in fresh[4].items():
                    STATE.names.setdefault(k, v)
                for k, v in fresh[7].items():
                    if k not in STATE.domains:
                        STATE.domains[k] = v
                        continue
                    d = STATE.domains[k]
                    d["count"] = d.get("count", 0) + v.get("count", 0)
                    d["last"] = max(d.get("last", 0), v.get("last", 0))
                    if v.get("first"):
                        d["first"] = min(d.get("first") or v["first"],
                                          v["first"])
                    for f in ("via", "qtypes"):
                        if isinstance(d.get(f), set) and isinstance(
                                v.get(f), (set, list)):
                            d[f] |= set(v[f])
                for k, v in fresh[5].items():
                    if isinstance(v, (int, float)):
                        STATE.stats[k] = STATE.stats.get(k, 0) + v
                STATE.aux_seen |= fresh[6]
                STATE.capture_error = ""
            WATCH_FAILS["n"] = 0
            return True
    WATCH_FAILS["n"] += 1
    with STATE_LOCK:
        # never give up on the saved target: adapters come back (the
        # hotspot is toggled, Wi-Fi roams) and capture must resume on
        # its own. Dying to idle after 5 strikes once left the app
        # silently dead through a whole afternoon of testing — keep
        # retrying every tick, and say so honestly in the status line
        if STATE.mode == "live":
            STATE.live_info = ("capture interrupted — retrying "
                               f"(attempt {WATCH_FAILS['n']})")
    return False


def watchdog_worker():
    while True:
        time.sleep(30)
        try:
            watchdog_tick()
        except Exception:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8890)
    ap.add_argument("--pcap", help="analyze this capture file at startup")
    args = ap.parse_args()
    if args.pcap:
        try:
            with open(args.pcap, "rb") as fh:
                STATE.load_analysis(engine.analyze_pcap(fh.read()))
            STATE.mode = "pcap"
        except Exception as e:
            print(f"could not load --pcap file: {e} (starting idle instead)")
    try:
        with open(SETTINGS_PATH) as fh:
            saved = json.load(fh)
        if saved.get("live_iface"):
            start_live(saved["live_iface"])
            print("auto-resumed live capture:", STATE.engine, "engine")
    except Exception:
        pass
    threading.Thread(target=watchdog_worker, daemon=True).start()
    threading.Thread(target=toast_worker, daemon=True).start()
    _boot = load_settings()
    if _boot.get("engine"):
        PREF["engine"] = _boot["engine"]
    PREF["hotspot_auto"] = bool(_boot.get("hotspot_auto"))
    print(f"CredLens running at http://127.0.0.1:{args.port}  (Ctrl+C to stop)")
    if getattr(sys, "frozen", False):
        import webbrowser
        threading.Timer(1.0, lambda: webbrowser.open(f"http://127.0.0.1:{args.port}")).start()
    print("capture: built-in raw engine (zero dependency);",
          "tshark fallback:", find_tshark() or "not installed")
    ThreadingHTTPServer(("127.0.0.1", args.port), H).serve_forever()


if __name__ == "__main__":
    main()
