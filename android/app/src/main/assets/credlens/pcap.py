"""CredLens capture engine — pure-stdlib PCAP reader + HTTP credential extractor.

Parses classic pcap files (Ethernet / Linux cooked / raw IP), reassembles
client->server TCP streams, parses HTTP requests, and extracts credentials:
  * urlencoded form posts (username/password field heuristics)
  * credentials in GET query strings
  * HTTP Basic Auth (base64-decoded)
Also harvests device names from DHCP (option 12), mDNS (.local) and NetBIOS
broadcasts, and MAC vendors from a small built-in OUI table.
"""
import base64
import gzip
import re
import struct
import zlib
import urllib.parse

USER_KEYS = re.compile(r"(user|uname|email|login|userid|usr|account|mail|phone|mobile|(?:^|_)log$)", re.I)
PASS_KEYS = re.compile(r"(pass|pwd|pw|passwd|password|secret)", re.I)

OUI = {
    "5C3C27": "Samsung", "8C7712": "Samsung", "A04BDA": "Samsung", "34C3A0": "Samsung",
    "ACDE48": "Apple", "F099BF": "Apple", "A45E60": "Apple", "3C0754": "Apple",
    "3CFDfe": "Intel", "3CFDFE": "Intel", "8C1645": "Intel", "8086F2": "Intel",
    "64CC2E": "Xiaomi", "7811DC": "Xiaomi", "F8A2D6": "Xiaomi",
    "B827EB": "Raspberry Pi", "DC A632".replace(" ", ""): "Raspberry Pi",
    "00155D": "Microsoft (Hyper-V)", "005056": "VMware", "000C29": "VMware",
    "7C2F80": "TP-Link", "50C7BF": "TP-Link", "8416F9": "TP-Link",
    "F4F26D": "ASUS", "1C872C": "Dell", "F8B156": "Dell", "18DBF2": "Dell",
}


def mac_vendor(mac):
    if not mac:
        return "Unknown vendor"
    key = mac.replace(":", "").replace("-", "").upper()[:6]
    return OUI.get(key, "Unknown vendor")


def fmt_mac(raw):
    return ":".join(f"{b:02x}" for b in raw)


# ---------------------------------------------------------------- pcap reader
def read_pcap(data):
    """Yield (ts, linktype, frame_bytes) from classic pcap bytes."""
    if len(data) < 24:
        return
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian, ns = "<", False
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian, ns = ">", False
    elif magic == b"\x4d\x3c\xb2\xa1":
        endian, ns = "<", True
    elif magic == b"\xa1\xb2\x3c\x4d":
        endian, ns = ">", True
    else:
        raise ValueError("not a pcap or pcapng capture file")
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    off = 24
    while off + 16 <= len(data):
        ts_s, ts_f, incl, _orig = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        if incl <= 0 or off + incl > len(data):
            break
        frame = data[off:off + incl]
        off += incl
        yield ts_s + ts_f / (1e9 if ns else 1e6), linktype, frame


# ------------------------------------------------------------- packet decode
def decode_frame(linktype, frame):
    """Return dict(ip_version, src, dst, proto, payload, src_mac, dst_mac) or None."""
    src_mac = dst_mac = None
    if linktype == 1:  # Ethernet (incl. pktmon's prefixed / 802.11-translated frames)
        if frame[:4] == b"\x08\x01\x00\x80":
            frame = frame[4:]
        if len(frame) >= 14:
            eth0 = struct.unpack(">H", frame[12:14])[0]
            if eth0 not in (0x0800, 0x86DD, 0x8100, 0x88A8):
                snap = frame.find(b"\xaa\xaa\x03\x00\x00\x00", 0, 48)
                if snap >= 0 and snap + 8 <= len(frame):
                    et = struct.unpack(">H", frame[snap + 6:snap + 8])[0]
                    if et in (0x0800, 0x86DD):
                        return decode_frame(101, frame[snap + 8:])
        if len(frame) < 14:
            return None
        dst_mac, src_mac = fmt_mac(frame[0:6]), fmt_mac(frame[6:12])
        eth = struct.unpack(">H", frame[12:14])[0]
        off = 14
        while eth in (0x8100, 0x88A8):  # VLAN tags
            if len(frame) < off + 4:
                return None
            eth = struct.unpack(">H", frame[off + 2:off + 4])[0]
            off += 4
        payload = frame[off:]
        if eth == 0x0800:
            ver = 4
        elif eth == 0x86DD:
            ver = 6
        else:
            return None
    elif linktype == 113:  # Linux cooked
        if len(frame) < 16:
            return None
        eth = struct.unpack(">H", frame[14:16])[0]
        payload = frame[16:]
        ver = 4 if eth == 0x0800 else 6 if eth == 0x86DD else None
        if ver is None:
            return None
    elif linktype in (0, 101):  # BSD loopback / raw IP
        payload = frame[4:] if linktype == 0 else frame
        if not payload:
            return None
        ver = payload[0] >> 4
        if ver not in (4, 6):
            return None
    else:
        return None

    if ver == 4:
        if len(payload) < 20:
            return None
        ihl = (payload[0] & 0x0F) * 4
        proto = payload[9]
        src = ".".join(str(b) for b in payload[12:16])
        dst = ".".join(str(b) for b in payload[16:20])
        body = payload[ihl:]
        frag = struct.unpack(">H", payload[6:8])[0]
        if frag & 0x1FFF or frag & 0x2000:  # fragmented: v1 skips
            return None
    else:
        if len(payload) < 40:
            return None
        proto = payload[6]
        import ipaddress
        src = str(ipaddress.IPv6Address(payload[8:24]))
        dst = str(ipaddress.IPv6Address(payload[24:40]))
        body = payload[40:]
    return {"src": src, "dst": dst, "proto": proto, "payload": body,
            "src_mac": src_mac, "dst_mac": dst_mac}


def decode_transport(pkt):
    """Return (kind, sport, dport, payload, seq) kind in tcp/udp."""
    body = pkt["payload"]
    if pkt["proto"] == 6 and len(body) >= 20:
        sport, dport, seq = struct.unpack(">HHI", body[:8])
        doff = (body[12] >> 4) * 4
        flags = body[13] & 0x3F if len(body) > 13 else 0
        return "tcp", sport, dport, body[doff:], seq, flags
    if pkt["proto"] == 17 and len(body) >= 8:
        sport, dport = struct.unpack(">HH", body[:4])
        return "udp", sport, dport, body[8:], None, 0
    return None, None, None, b"", None, 0


# ------------------------------------------------------------ name harvesting
def dns_name(msg, off):
    """Decode a (possibly compressed) DNS name starting at off."""
    labels, jumped, hops = [], False, 0
    end = off
    while off < len(msg) and hops < 20:
        hops += 1
        ln = msg[off]
        if ln == 0:
            if not jumped:
                end = off + 1
            break
        if ln & 0xC0 == 0xC0:
            if off + 1 >= len(msg):
                break
            ptr = ((ln & 0x3F) << 8) | msg[off + 1]
            if not jumped:
                end = off + 2
            off, jumped = ptr, True
            continue
        off += 1
        labels.append(msg[off:off + ln].decode("utf-8", "replace"))
        off += ln
    return ".".join(labels), end


def plausible_hostname(nm):
    """A harvested name worth trusting: printable, no service junk.
    Windows browser traffic announces a group name whose raw bytes are
    control characters around __MSBROWSE__ — that garbage once became
    the laptop's own display name and, first-writer-wins, stuck."""
    if not nm or len(nm) > 63 or "MSBROWSE" in nm:
        return False
    if nm.strip().upper() in ("WORKGROUP", "MSHOME"):
        return False    # generic Windows group names, never a device
    return all(32 < ord(c) < 127 for c in nm)


def harvest_names(packets):
    """packets: decoded packet dicts w/ transport info. Return ip -> device name."""
    names = {}
    for p in packets:
        if p["kind"] != "udp":
            continue
        data = p["payload"]
        # DHCP: ports 67/68, hostname option 12
        if p["sport"] in (67, 68) or p["dport"] in (67, 68):
            try:
                if len(data) > 240 and data[236:240] == b"\x63\x82\x53\x63":
                    opts = data[240:]
                    i = 0
                    ciaddr = ".".join(str(b) for b in data[12:16])
                    while i < len(opts):
                        code = opts[i]
                        if code == 255:
                            break
                        if code == 0:      # pad: single byte, no length
                            i += 1
                            continue
                        ln = opts[i + 1]
                        if code == 12:
                            host = opts[i + 2:i + 2 + ln].decode("utf-8", "replace").strip()
                            # key by the address the server assigned
                            # (yiaddr, in the ACK) — in DISCOVER/REQUEST
                            # both ciaddr and the frame source are
                            # 0.0.0.0, which used to throw the name away
                            yiaddr = ".".join(str(b) for b in data[16:20])
                            ip = ciaddr if ciaddr != "0.0.0.0" else (
                                yiaddr if yiaddr != "0.0.0.0" else p["src"])
                            if host and ip != "0.0.0.0" and plausible_hostname(host):
                                names[ip] = host
                        i += 2 + ln
            except Exception:
                pass
        # mDNS: port 5353 — answers carry A records named <device>.local
        if p["sport"] == 5353 or p["dport"] == 5353:
            try:
                if len(data) > 12:
                    qd, an = struct.unpack(">HH", data[4:8])
                    off = 12
                    for _ in range(qd):
                        _, off = dns_name(data, off)
                        off += 4
                    for _ in range(an):
                        nm, off = dns_name(data, off)
                        if off + 10 > len(data):
                            break
                        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
                        off += 10
                        rdata = data[off:off + rdlen]
                        off += rdlen
                        if rtype == 1 and rdlen == 4 and nm.endswith(".local"):
                            ip = ".".join(str(b) for b in rdata)
                            names[ip] = nm[:-6]
            except Exception:
                pass
        # NetBIOS name service: port 137 — query name of the sender
        if p["dport"] == 137 and len(data) > 12:
            try:
                qd = struct.unpack(">H", data[4:6])[0]
                if qd:
                    raw, _ = dns_name(data, 12)
                    enc = raw.split(".")[0]
                    dec = ""
                    for i in range(0, len(enc) - 1, 2):
                        dec += chr(((ord(enc[i]) - 0x41) << 4) | (ord(enc[i + 1]) - 0x41))
                    # the last decoded byte is the NetBIOS suffix and
                    # the name before it is space-padded — drop the
                    # suffix, then strip (the old strip-then-rstrip
                    # order could reach neither)
                    nm = dec[:-1].strip() if dec else ""
                    if plausible_hostname(nm) and p["src"] not in names:
                        names[p["src"]] = nm
            except Exception:
                pass
    return names


def harvest_mac_names(packets):
    """Device names keyed by hardware (MAC), from DHCP client packets:
    the hostname option belongs to the CLIENT and rides with its MAC
    (chaddr). Keying by IP alone loses the name whenever the lease
    changes — one phone held three IPs in a single evening."""
    out = {}
    for p in packets:
        if p["kind"] != "udp":
            continue
        if p["sport"] not in (67, 68) and p["dport"] not in (67, 68):
            continue
        data = p["payload"]
        try:
            if len(data) > 240 and data[236:240] == b"\x63\x82\x53\x63":
                mac = fmt_mac(data[28:34])
                opts = data[240:]
                i = 0
                while i < len(opts):
                    code = opts[i]
                    if code == 255:
                        break
                    if code == 0:
                        i += 1
                        continue
                    ln = opts[i + 1]
                    if code == 12:
                        host = opts[i + 2:i + 2 + ln].decode(
                            "utf-8", "replace").strip()
                        if plausible_hostname(host) \
                                and mac != "00:00:00:00:00:00":
                            out[mac] = host
                    i += 2 + ln
        except Exception:
            pass
    return out


# DHCP option-55 (parameter request list) sequences are per-OS
# fingerprints — the join packet identifies its OS family even when
# its hostname field is blank. Scored by longest ordered overlap.
_DHCP_FP = (
    ("Android", (1, 3, 6, 15, 26, 28, 51, 58, 59, 43)),
    ("Android", (1, 3, 6, 15, 26, 28, 51, 58, 59)),
    ("iOS", (1, 3, 6, 15, 119, 252)),
    ("Windows", (1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252)),
    ("Linux", (1, 28, 2, 3, 15, 6, 119, 12, 44, 47, 26, 121, 42)),
)


def dhcp_os_for(prl):
    """OS family for a DHCP parameter-request list, or None."""
    if not prl:
        return None
    seq = tuple(prl)
    best, best_score = None, 0
    for os_name, ref in _DHCP_FP:
        common = len(set(seq) & set(ref))
        ordered = 0
        it = iter(seq)
        for want in ref:
            for got in it:
                if got == want:
                    ordered += 1
                    break
        score = common + ordered
        if score > best_score:
            best, best_score = os_name, score
    return best if best_score >= 8 else None


def harvest_dhcp_fingerprints(packets):
    """mac -> OS family, from DHCP client packets (option 55)."""
    out = {}
    for p in packets:
        if p["kind"] != "udp":
            continue
        if p["sport"] not in (67, 68) and p["dport"] not in (67, 68):
            continue
        data = p["payload"]
        try:
            if len(data) > 240 and data[236:240] == b"\x63\x82\x53\x63":
                mac = fmt_mac(data[28:34])
                opts = data[240:]
                i = 0
                while i < len(opts):
                    code = opts[i]
                    if code == 255:
                        break
                    if code == 0:
                        i += 1
                        continue
                    ln = opts[i + 1]
                    if code == 55:
                        os_name = dhcp_os_for(list(opts[i + 2:i + 2 + ln]))
                        if os_name and mac != "00:00:00:00:00:00":
                            out[mac] = os_name
                    i += 2 + ln
        except Exception:
            pass
    return out


# ------------------------------------------------- domain sightings (DNS/SNI)
QTYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
               16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 257: "CAA"}


def parse_dns_query(msg):
    """(domain, qtype) from a DNS query message (UDP payload), else None.
    Responses (QR=1) and malformed messages return None."""
    try:
        if len(msg) < 13:
            return None
        flags, qd = struct.unpack(">HH", msg[2:6])
        if flags & 0x8000 or qd < 1:
            return None
        name, off = dns_name(msg, 12)
        if not name or off + 4 > len(msg):
            return None
        qtype = struct.unpack(">H", msg[off:off + 2])[0]
        return name.lower(), QTYPE_NAMES.get(qtype, str(qtype))
    except Exception:
        return None


def sni_status(head):
    """(hostname_or_None, complete) for a TLS ClientHello starting head.
    complete=False means the record has not fully arrived yet and more
    bytes could change the answer; complete=True is a definitive verdict
    (hostname found, or provably not a ClientHello / no SNI present)."""
    try:
        if len(head) < 5:
            return None, False
        if head[0] != 22:                       # not a TLS handshake record
            return None, True
        rec_len = struct.unpack(">H", head[3:5])[0]
        if rec_len == 0 or rec_len > 18432:
            return None, True
        if len(head) < 5 + rec_len:
            return None, False                  # record still arriving
        body = head[5:5 + rec_len]
        if len(body) < 4 or body[0] != 1:       # not a ClientHello
            return None, True
        pos = 4 + 2 + 32                        # hs hdr + version + random
        if pos >= len(body):
            return None, True
        sid_len = body[pos]
        pos += 1 + sid_len
        if pos + 2 > len(body):
            return None, True
        cs_len = struct.unpack(">H", body[pos:pos + 2])[0]
        pos += 2 + cs_len
        if pos >= len(body):
            return None, True
        comp_len = body[pos]
        pos += 1 + comp_len
        if pos + 2 > len(body):
            return None, True                   # no extensions block
        ext_total = struct.unpack(">H", body[pos:pos + 2])[0]
        pos += 2
        ext_end = min(len(body), pos + ext_total)
        while pos + 4 <= ext_end:
            etype, elen = struct.unpack(">HH", body[pos:pos + 4])
            edata = body[pos + 4:pos + 4 + elen]
            if len(edata) < elen:
                break
            if etype == 0 and len(edata) >= 5:  # server_name
                list_end = min(len(edata), 2 + struct.unpack(">H", edata[0:2])[0])
                p = 2
                while p + 3 <= list_end:
                    ntype = edata[p]
                    nlen = struct.unpack(">H", edata[p + 1:p + 3])[0]
                    name = edata[p + 3:p + 3 + nlen]
                    if len(name) < nlen:
                        break
                    if ntype == 0 and name:
                        return name.decode("utf-8", "replace").lower(), True
                    p += 3 + nlen
                return None, True
            pos += 4 + elen
        return None, True
    except Exception:
        return None, True


def parse_sni(head):
    """Hostname from a complete TLS ClientHello at head, else None."""
    return sni_status(head)[0]


# -------------------------------------------------------------- HTTP parsing
def _decode_chunked(body):
    """-> (decoded_bytes, wire_bytes_consumed)."""
    out = b""
    i = 0
    while i < len(body):
        j = body.find(b"\r\n", i)
        if j < 0:
            return out, i
        try:
            size = int(body[i:j].split(b";")[0].strip(), 16)
        except ValueError:
            return out, i
        if size == 0:
            end = body.find(b"\r\n\r\n", j)
            if end >= 0:
                return out, end + 4
            tail = body.find(b"\r\n", j + 2)
            return out, (tail + 2) if tail >= 0 else len(body)
        out += body[j + 2:j + 2 + size]
        i = j + 2 + size + 2
    return out, i


def parse_http_requests(stream):
    """Scan a client->server byte stream for HTTP requests. Yield dicts."""
    reqs = []
    pos = 0
    methods = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ")
    while pos < len(stream):
        nxt = None
        for m in methods:
            k = stream.find(m, pos)
            if k >= 0 and (nxt is None or k < nxt[0]):
                nxt = (k, m)
        if not nxt:
            break
        start = nxt[0]
        hdr_end = stream.find(b"\r\n\r\n", start)
        term = 4
        if hdr_end < 0:
            hdr_end = stream.find(b"\n\n", start)   # LF-only embedded stacks
            term = 2
        if hdr_end < 0:
            break
        head = stream[start:hdr_end].decode("iso-8859-1", "replace")
        lines = head.replace("\r\n", "\n").split("\n")
        parts = lines[0].split(" ")
        if len(parts) < 2:
            pos = start + 4
            continue
        method, uri = parts[0], parts[1]
        headers = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        body_off = hdr_end + term
        body = b""
        if "chunked" in headers.get("transfer-encoding", "").lower():
            body, wire = _decode_chunked(stream[body_off:])
            pos = body_off + wire
        elif "content-length" in headers:
            try:
                cl = int(headers["content-length"])
            except ValueError:
                cl = 0
            body = stream[body_off:body_off + cl]
            pos = body_off + cl
        else:
            pos = body_off
        reqs.append({"method": method, "uri": uri, "headers": headers, "body": body,
                     "off": start,
                     "raw": stream[start:body_off + len(body)].decode("iso-8859-1", "replace")})
    return reqs


def extract_credentials(req, src_ip, dst_ip, src_mac, ts):
    """Return an event dict if the request carries credentials, else None."""
    headers = req["headers"]
    enc = headers.get("content-encoding", "")
    if req["body"] and ("gzip" in enc or "deflate" in enc):
        try:
            raw = gzip.decompress(req["body"]) if "gzip" in enc \
                else zlib.decompress(req["body"])
        except Exception:
            try:
                raw = zlib.decompress(req["body"], -15)
            except Exception:
                raw = None
        if raw is not None:
            req = {**req, "body": raw}
    host = headers.get("host", dst_ip)
    url = "http://" + host + req["uri"] if req["uri"].startswith("/") else req["uri"]
    pairs = []
    ctype = headers.get("content-type", "")
    body_txt = req["body"].decode("utf-8", "replace") if req["body"] else ""
    if "application/x-www-form-urlencoded" in ctype and req["body"]:
        pairs += urllib.parse.parse_qsl(body_txt, keep_blank_values=True)
    elif "multipart/form-data" in ctype and req["body"]:
        for m in re.finditer(r'name="([^"]+)"\r\n\r\n(.*?)\r\n--', body_txt, re.S):
            pairs.append((m.group(1), m.group(2).strip()))
    elif ("json" in ctype or body_txt.lstrip().startswith("{")) and req["body"]:
        for m in re.finditer(r'"([^"]+)"\s*:\s*"([^"]*)"', body_txt):
            pairs.append((m.group(1), m.group(2)))
    q = urllib.parse.urlsplit(req["uri"]).query
    if q:
        pairs += urllib.parse.parse_qsl(q, keep_blank_values=True)

    user = pw = ufield = pfield = None
    for k, v in pairs:
        if pw is None and PASS_KEYS.search(k) and v:
            pw, pfield = v, k
        elif user is None and USER_KEYS.search(k) and v:
            user, ufield = v, k
    kind = None
    if pw is not None:
        kind = "form" if req["method"] in ("POST", "PUT") else "get"
    auth = headers.get("authorization", "")
    if auth.lower().startswith("basic "):
        try:
            dec = base64.b64decode(auth[6:].strip()).decode("utf-8", "replace")
            if ":" in dec:
                user, pw = dec.split(":", 1)
                ufield, pfield, kind = "Authorization", "Authorization", "basic"
        except Exception:
            pass
    if pw is None:
        return None
    split = urllib.parse.urlsplit(url)
    return {
        "ts": ts, "method": req["method"], "host": split.netloc or host,
        "path": split.path or "/", "url": url, "kind": kind,
        "user": user, "password": pw, "user_field": ufield, "pass_field": pfield,
        "src_ip": src_ip, "dst_ip": dst_ip, "src_mac": src_mac,
        "raw": req["raw"][:1500],
    }



SESSION_COOKIE = re.compile(r"(sess|auth|token|sid|jwt|login)", re.I)
APIKEY_NAME = re.compile(r"(api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|secret[_-]?key)", re.I)


def _aux_event(req, kind, user, password, field, src_ip, dst_ip, src_mac, ts):
    headers = req["headers"]
    host = headers.get("host", dst_ip)
    url = "http://" + host + req["uri"] if req["uri"].startswith("/") else req["uri"]
    split = urllib.parse.urlsplit(url)
    return {"ts": ts, "method": req["method"], "host": split.netloc or host,
            "path": split.path or "/", "url": url, "kind": kind,
            "user": user, "password": password, "user_field": field, "pass_field": field,
            "src_ip": src_ip, "dst_ip": dst_ip, "src_mac": src_mac,
            "raw": req["raw"][:1500]}


def extract_http_events(req, src_ip, dst_ip, src_mac, ts):
    """All leak events in one HTTP request: the credential event (if any)
    plus exposed session cookies, bearer tokens and API keys."""
    events = []
    ev = extract_credentials(req, src_ip, dst_ip, src_mac, ts)
    if ev:
        events.append(ev)
    headers = req["headers"]
    auth = headers.get("authorization", "")
    if auth.lower().startswith("bearer ") and len(auth[7:].strip()) >= 10:
        events.append(_aux_event(req, "bearer", "(bearer token)", auth[7:].strip(),
                                 "Authorization", src_ip, dst_ip, src_mac, ts))
    cookie = headers.get("cookie", "")
    if cookie:
        for pair in cookie.split(";"):
            if "=" in pair:
                name, val = pair.split("=", 1)
                name, val = name.strip(), val.strip()
                if val and SESSION_COOKIE.search(name):
                    events.append(_aux_event(req, "cookie", name, val[:300],
                                             "Cookie", src_ip, dst_ip, src_mac, ts))
                    break
    key_found = False
    for hn in ("x-api-key", "api-key", "x-auth-token"):
        v = headers.get(hn)
        if v and len(v.strip()) >= 8:
            events.append(_aux_event(req, "apikey", hn, v.strip(), hn,
                                     src_ip, dst_ip, src_mac, ts))
            key_found = True
            break
    if not key_found:
        q = urllib.parse.urlsplit(req["uri"]).query
        for k, v in urllib.parse.parse_qsl(q, keep_blank_values=True):
            if v and len(v) >= 8 and APIKEY_NAME.search(k):
                events.append(_aux_event(req, "apikey", k, v, k,
                                         src_ip, dst_ip, src_mac, ts))
                break
    return events


# ------------------------------------------- plaintext protocol extractors
PROTO_PORTS = {21: "ftp", 110: "pop3", 143: "imap", 25: "smtp",
               587: "smtp", 2525: "smtp", 23: "telnet", 1883: "mqtt"}


def _proto_event(proto, user, pw, raw, src, dst, mac, ts):
    return {"ts": ts, "method": proto.upper(), "host": dst, "path": "",
            "url": f"{proto}://{dst}", "kind": proto,
            "user": user, "password": pw, "user_field": "USER", "pass_field": "PASS",
            "src_ip": src, "dst_ip": dst, "src_mac": mac, "raw": raw[:1500]}


def _lines(data):
    txt = data.decode("iso-8859-1", "replace")
    return [ln.strip() for ln in re.split(r"\r\n|\r|\n", txt) if ln.strip()]


def _b64(s):
    try:
        return base64.b64decode(s.strip()).decode("utf-8", "replace")
    except Exception:
        return None


def _userpass_events(lines, proto, src, dst, mac, ts):
    """FTP & POP3: USER x / PASS y line pairs."""
    user = None
    for ln in lines:
        up = ln.upper()
        if up.startswith("USER ") and user is None:
            user = ln[5:].strip()
        elif up.startswith("PASS ") and user is not None:
            pw = ln[5:].strip()
            if pw:
                return [_proto_event(proto, user, pw, f"USER {user}\nPASS {pw}",
                                     src, dst, mac, ts)]
    return []


def _imap_events(lines, src, dst, mac, ts):
    for ln in lines:
        m = re.match(r'^\S+\s+LOGIN\s+(?:"([^"]*)"|(\S+))\s+(?:"([^"]*)"|(\S+))', ln, re.I)
        if m:
            user = m.group(1) or m.group(2)
            pw = m.group(3) or m.group(4)
            if pw:
                return [_proto_event("imap", user, pw, ln, src, dst, mac, ts)]
        m = re.match(r'^\S+\s+AUTHENTICATE\s+PLAIN\s+(\S+)', ln, re.I)
        if m:
            dec = _b64(m.group(1))
            if dec:
                parts = dec.split("\x00")
                if len(parts) >= 3 and parts[-1]:
                    return [_proto_event("imap", parts[-2], parts[-1], ln, src, dst, mac, ts)]
    return []


def _smtp_events(lines, src, dst, mac, ts):
    user = None
    stage = 0
    for ln in lines:
        m = re.match(r'^AUTH\s+PLAIN\s+(\S+)', ln, re.I)
        if m:
            dec = _b64(m.group(1))
            if dec:
                parts = dec.split("\x00")
                if len(parts) >= 3 and parts[-1]:
                    return [_proto_event("smtp", parts[-2], parts[-1], ln, src, dst, mac, ts)]
            continue
        m = re.match(r'^AUTH\s+LOGIN(?:\s+(\S+))?$', ln, re.I)
        if m:
            if m.group(1):
                user = _b64(m.group(1))
                stage = 2
            else:
                stage = 1
            continue
        if stage == 1:
            user = _b64(ln)
            stage = 2
            continue
        if stage == 2:
            pw = _b64(ln)
            if user and pw:
                return [_proto_event("smtp", user, pw, "AUTH LOGIN (base64)", src, dst, mac, ts)]
            stage = 0
    return []


def _mqtt_events(data, src, dst, mac, ts):
    """Parse an MQTT CONNECT packet: username/password ride in the payload."""
    try:
        if len(data) < 2 or data[0] != 0x10:
            return []
        i, mult, rlen = 1, 1, 0
        while True:
            b = data[i]
            rlen += (b & 0x7F) * mult
            i += 1
            if not (b & 0x80):
                break
            mult *= 128
            if i > 5:
                return []
        if len(data) < i + rlen:
            return []                       # incomplete — caller may retry with more

        def rd_str(p):
            ln = struct.unpack(">H", data[p:p + 2])[0]
            return data[p + 2:p + 2 + ln], p + 2 + ln

        def skip_props(p):
            # MQTT v5 property block: a varint LENGTH followed by that
            # many bytes — skipping only the varint desyncs the parse
            # whenever properties are present (the common v5 case)
            start = p
            while data[p] & 0x80:
                p += 1
            p += 1
            ln, mult = 0, 1
            for b in data[start:p]:
                ln += (b & 0x7F) * mult
                mult *= 128
            return p + ln

        p = i
        _name, p = rd_str(p)
        level = data[p]; p += 1
        flags = data[p]; p += 1
        p += 2                              # keepalive
        if level == 5:
            p = skip_props(p)               # connect properties
        _cid, p = rd_str(p)
        if flags & 0x04:                    # will present
            if level == 5:
                p = skip_props(p)           # will properties
            _t, p = rd_str(p)
            wlen = struct.unpack(">H", data[p:p + 2])[0]
            p += 2 + wlen
        user = pw = None
        if flags & 0x80:
            ub, p = rd_str(p)
            user = ub.decode("utf-8", "replace")
        if flags & 0x40:
            pb, p = rd_str(p)
            pw = pb.decode("utf-8", "replace")
        if pw:
            return [_proto_event("mqtt", user, pw, "MQTT CONNECT (username/password)",
                                 src, dst, mac, ts)]
    except Exception:
        return []
    return []


def _telnet_events(cdata, sdata, src, dst, mac, ts):
    """Telnet: the first two typed lines after the login/password prompts."""
    stxt = sdata.decode("iso-8859-1", "replace").lower() if sdata else ""
    if "password" not in stxt and "login" not in stxt and "username" not in stxt:
        return []   # no prompt evidence -> no finding (proof-first)
    out = bytearray()
    i = 0
    while i < len(cdata):                   # strip IAC negotiation sequences
        b = cdata[i]
        if b == 0xFF:
            if i + 1 < len(cdata) and cdata[i + 1] == 0xFF:
                out.append(0xFF)
                i += 2
                continue
            i += 3
            continue
        out.append(b)
        i += 1
    lines = []
    for raw in re.split(rb"\r\n|\r\x00|\r|\n", bytes(out)):
        ln = raw.decode("iso-8859-1", "replace").strip()
        if ln and all(32 <= ord(c) < 127 for c in ln):
            lines.append(ln)
    if len(lines) >= 2 and len(lines[0]) <= 64 and len(lines[1]) <= 128:
        return [_proto_event("telnet", lines[0], lines[1], "telnet login (typed at prompts)",
                             src, dst, mac, ts)]
    return []


def _skip_chunked(data, pos):
    while True:
        eol = data.find(b"\r\n", pos)
        if eol < 0:
            return None
        try:
            size = int(data[pos:eol].split(b";")[0].strip(), 16)
        except Exception:
            return None
        pos = eol + 2
        if size == 0:
            end = data.find(b"\r\n\r\n", pos)
            if end >= 0:
                return end + 4
            return pos + 2 if data[pos:pos + 2] == b"\r\n" else None
        pos += size + 2
        if pos > len(data):
            return None


# ---------------------------------------------------------------------------
# NTLM hash grab: pair the server challenge (type 2) with the client's
# response (type 3) on the same connection and emit a hashcat-ready line.
_NTLM_CHAL_RE = re.compile(
    rb"(?:WWW-Authenticate|Proxy-Authenticate):\s*NTLM\s+([A-Za-z0-9+/=]+)",
    re.I)


def _ntlm_msg(b64):
    try:
        raw = base64.b64decode(b64)
    except Exception:
        return None
    if len(raw) < 12 or not raw.startswith(b"NTLMSSP\x00"):
        return None
    return raw


def find_ntlm_challenge(stream):
    """The 8-byte server challenge from an NTLM type-2 message, or None."""
    if not stream:
        return None
    for m in _NTLM_CHAL_RE.finditer(stream):
        raw = _ntlm_msg(m.group(1))
        if raw and len(raw) >= 32 and struct.unpack("<I", raw[8:12])[0] == 2:
            return raw[24:32]
    return None


def _ntlm_field(raw, off):
    ln, _mx, bo = struct.unpack("<HHI", raw[off:off + 8])
    return raw[bo:bo + ln] if 0 <= bo and bo + ln <= len(raw) else b""


def parse_ntlm_type3(b64):
    raw = _ntlm_msg(b64)
    if not raw or len(raw) < 64 or struct.unpack("<I", raw[8:12])[0] != 3:
        return None
    flags = struct.unpack("<I", raw[60:64])[0]
    dec = (lambda b: b.decode("utf-16-le", "replace") if flags & 1
           else b.decode("latin-1", "replace"))
    return {"lm": _ntlm_field(raw, 12), "nt": _ntlm_field(raw, 20),
            "domain": dec(_ntlm_field(raw, 28)).strip("\x00"),
            "user": dec(_ntlm_field(raw, 36)).strip("\x00")}


def extract_ntlm(req, src_ip, dst_ip, src_mac, ts, challenge):
    """One 'hash' event when a request carries an NTLM type-3 response and
    the server challenge for this connection is known. The password field
    holds the full hashcat line (mode 5600 for v2, 5500 for v1)."""
    if not challenge:
        return []
    auth = req["headers"].get("authorization") or \
        req["headers"].get("proxy-authorization") or ""
    if not auth.lower().startswith("ntlm "):
        return []
    t3 = parse_ntlm_type3(auth.split(None, 1)[1].strip())
    if not t3 or not t3["user"]:
        return []
    chal = challenge.hex()
    if len(t3["nt"]) > 24:
        line = (f"{t3['user']}::{t3['domain']}:{chal}:"
                f"{t3['nt'][:16].hex()}:{t3['nt'][16:].hex()}")
        label = "NetNTLMv2 - hashcat 5600"
    elif len(t3["nt"]) == 24 and len(t3["lm"]) == 24:
        line = (f"{t3['user']}::{t3['domain']}:{t3['lm'].hex()}:"
                f"{t3['nt'].hex()}:{chal}")
        label = "NetNTLMv1 - hashcat 5500"
    else:
        return []
    headers = req["headers"]
    host = headers.get("host", dst_ip)
    url = "http://" + host + req["uri"] if req["uri"].startswith("/") else req["uri"]
    split = urllib.parse.urlsplit(url)
    return [{"ts": ts, "method": req["method"], "host": split.netloc or host,
             "path": split.path or "/", "url": url, "kind": "hash",
             "user": t3["user"], "password": line,
             "user_field": "NTLM user", "pass_field": label,
             "src_ip": src_ip, "dst_ip": dst_ip, "src_mac": src_mac,
             "raw": req["raw"][:1500]}]


def extract_response_events(sdata, client_ip, server_ip, host, src_mac, ts):
    """Session cookies a server SETS over plaintext HTTP (Set-Cookie) — the
    leak exists the moment it is issued, before the browser re-sends it."""
    out = []
    pos = 0
    while True:
        i = sdata.find(b"HTTP/1.", pos)
        if i < 0:
            break
        if i > 0 and sdata[i - 1:i] != b"\n":
            pos = i + 1
            continue
        hend = sdata.find(b"\r\n\r\n", i)
        if hend < 0:
            break
        head = sdata[i:hend].decode("iso-8859-1", "replace")
        headers = {}
        cookies = []
        for ln in head.split("\r\n")[1:]:
            if ":" not in ln:
                continue
            k, v = ln.split(":", 1)
            k, v = k.strip().lower(), v.strip()
            if k == "set-cookie":
                cookies.append(v)
            else:
                headers[k] = v
        for c in cookies:
            pair = c.split(";", 1)[0]
            if "=" not in pair:
                continue
            name, val = pair.split("=", 1)
            name, val = name.strip(), val.strip()
            if len(val) >= 6 and SESSION_COOKIE.search(name):
                out.append({"ts": ts, "method": "HTTP", "host": host,
                            "path": "", "url": f"http://{host}/",
                            "kind": "cookie", "user": name,
                            "password": val[:300], "user_field": "Set-Cookie",
                            "pass_field": "Set-Cookie",
                            "src_ip": client_ip, "dst_ip": server_ip,
                            "src_mac": src_mac,
                            "raw": f"Set-Cookie: {name}={val[:60]} (HTTP response)"})
        body_start = hend + 4
        if "chunked" in headers.get("transfer-encoding", "").lower():
            nxt = _skip_chunked(sdata, body_start)
            if nxt is None:
                break
            pos = nxt
        elif headers.get("content-length", "").isdigit():
            pos = body_start + int(headers["content-length"])
        else:
            break  # close-delimited body: next response not findable reliably
    return out


def extract_protocol_events(cdata, sdata, dport, src, dst, mac, ts):
    """Credential events from one plaintext-protocol connection.
    cdata = client->server bytes, sdata = server->client bytes."""
    proto = PROTO_PORTS.get(dport)
    if not proto:
        return []
    if proto == "mqtt":
        return _mqtt_events(cdata, src, dst, mac, ts)
    if proto == "telnet":
        return _telnet_events(cdata, sdata, src, dst, mac, ts)
    lines = _lines(cdata)
    if proto in ("ftp", "pop3"):
        return _userpass_events(lines, proto, src, dst, mac, ts)
    if proto == "imap":
        return _imap_events(lines, src, dst, mac, ts)
    if proto == "smtp":
        return _smtp_events(lines, src, dst, mac, ts)
    return []


# --------------------------------------------------------------- top analyzer
def analyze_pcap(data):
    """Full pipeline: pcap/pcapng bytes -> {events, devices, sites, stats}."""
    udp_recs = []   # only what harvest_names reads — not the whole capture
    flows = {}  # (src,sport,dst,dport) -> list of (seq, ts, payload, src_mac)
    stats = {"packets": 0, "http_requests": 0}
    reader = read_pcapng(data) if data[:4] == b"\x0a\x0d\x0d\x0a" else read_pcap(data)
    for ts, linktype, frame in reader:
        pkt = decode_frame(linktype, frame)
        if not pkt:
            continue
        stats["packets"] += 1
        kind, sport, dport, payload, seq, _fl = decode_transport(pkt)
        if kind is None:
            continue
        if kind == "udp":
            udp_recs.append(dict(pkt, kind=kind, sport=sport, dport=dport,
                                 payload=payload, ts=ts))
        if kind == "tcp" and payload:
            key = (pkt["src"], sport, pkt["dst"], dport)
            flows.setdefault(key, []).append((seq or 0, ts, payload, pkt["src_mac"]))

    names = harvest_names(udp_recs)

    # domain sightings: DNS queries (UDP) — who looked up what
    sightings = []
    for p in udp_recs:
        if p["dport"] == 53 or p["sport"] == 53:
            q = parse_dns_query(p["payload"])
            if q:
                sightings.append({"ts": p["ts"], "src_ip": p["src"],
                                  "domain": q[0], "via": "dns",
                                  "dst_ip": p["dst"], "qtype": q[1]})

    events = []
    requests_seen = []
    devices = {}
    sites = {}
    streams = {}
    for key, segs in flows.items():
        segs.sort(key=lambda s: s[0])
        parts, marks, covered_end, joined = [], [], None, 0
        for seq, seg_ts, payload, _mac in segs:
            seg_end = seq + len(payload)          # end BEFORE any trimming
            if covered_end is not None and seg_end <= covered_end:
                continue  # duplicate / retransmission (pktmon multi-point)
            if covered_end is not None and seq < covered_end:
                payload = payload[covered_end - seq:]
            marks.append((joined, seg_ts))
            parts.append(payload)
            joined += len(payload)
            covered_end = seg_end if covered_end is None \
                else max(covered_end, seg_end)
        streams[key] = (b"".join(parts), segs[0][1], segs[0][3], marks)

    seen_aux, seen_proto = set(), set()
    for (src, sport, dst, dport), (stream, ts0, src_mac, marks) in streams.items():
        sstream0 = streams.get((dst, dport, src, sport), (b"", 0, None, None))[0]
        ntlm_chal = find_ntlm_challenge(sstream0)
        for req in parse_http_requests(stream):
            stats["http_requests"] += 1
            ts_req = ts0
            for off, mts in marks:
                if off <= req.get("off", 0):
                    ts_req = mts
                else:
                    break
            evs = extract_http_events(req, src, dst, src_mac, ts_req)
            fresh = []
            for ev in evs:
                if ev["kind"] in ("cookie", "apikey", "bearer"):
                    k = (ev["kind"], ev["src_ip"], ev["host"], ev["password"])
                    if k in seen_aux:
                        continue
                    seen_aux.add(k)
                fresh.append(ev)
            for ev in extract_ntlm(req, src, dst, src_mac, ts_req, ntlm_chal):
                k = (ev["kind"], ev["src_ip"], ev["host"], ev["user"], ev["password"])
                if k in seen_proto:
                    continue
                seen_proto.add(k)
                fresh.append(ev)
            host_r = req["headers"].get("host", dst)
            keys_seen = [k for k, _v in urllib.parse.parse_qsl(
                req["body"].decode("utf-8", "replace"), keep_blank_values=True)][:8] if req["body"] else []
            requests_seen.append({"ts": ts_req, "method": req["method"], "host": host_r,
                                  "path": urllib.parse.urlsplit(req["uri"]).path or "/",
                                  "src_ip": src, "dst_ip": dst, "src_mac": src_mac,
                                  "form_keys": keys_seen,
                                  "ua": req["headers"].get("user-agent", ""),
                                  "ctype": req["headers"].get("content-type", ""),
                                  "captured": bool(fresh)})
            events.extend(fresh)
        if dport not in PROTO_PORTS:
            reqs_here = [r for r in requests_seen if r["src_ip"] == src
                         and r["dst_ip"] == dst]
            sstream = streams.get((dst, dport, src, sport), (b"", 0, None, None))[0]
            if sstream and reqs_here:
                for ev in extract_response_events(
                        sstream, src, dst, reqs_here[0]["host"], src_mac, ts0):
                    k = (ev["kind"], ev["src_ip"], ev["host"], ev["password"])
                    if k in seen_aux:
                        continue
                    seen_aux.add(k)
                    events.append(ev)
        # domain sightings: TLS SNI (any port) + DNS carried over TCP 53
        _sni = parse_sni(stream[:16384])
        if _sni:
            sightings.append({"ts": ts0, "src_ip": src, "domain": _sni,
                              "via": "sni", "dst_ip": dst, "qtype": ""})
        if dport == 53:
            _off = 0
            while _off + 2 <= len(stream):
                _mlen = struct.unpack(">H", stream[_off:_off + 2])[0]
                _msg = stream[_off + 2:_off + 2 + _mlen]
                if len(_msg) < _mlen:
                    break
                _q = parse_dns_query(_msg)
                if _q:
                    sightings.append({"ts": ts0, "src_ip": src,
                                      "domain": _q[0], "via": "dns",
                                      "dst_ip": dst, "qtype": _q[1]})
                _off += 2 + _mlen
        if dport in PROTO_PORTS:
            sstream = streams.get((dst, dport, src, sport), (b"", 0, None, None))[0]
            for ev in extract_protocol_events(stream, sstream, dport, src, dst, src_mac, ts0):
                k = (ev["kind"], ev["src_ip"], ev["dst_ip"], ev["user"], ev["password"])
                if k in seen_proto:
                    continue
                seen_proto.add(k)
                events.append(ev)
    events.sort(key=lambda e: e["ts"])
    requests_seen.sort(key=lambda r: r["ts"])
    sightings.sort(key=lambda s: s["ts"])

    # Parity with live mode: a device that only makes encrypted
    # connections (no HTTP, no events) still EXISTS — seed talkers from
    # flow sources and UDP sightings so PCAP mode shows them too.
    for (src, _sp, _dst, _dp), segs in flows.items():
        devices.setdefault(src, {
            "ip": src, "mac": segs[0][3],
            "vendor": mac_vendor(segs[0][3]),
            "name": names.get(src), "leaks": 0, "requests": 0})
    for p in udp_recs:
        devices.setdefault(p["src"], {
            "ip": p["src"], "mac": p.get("src_mac"),
            "vendor": mac_vendor(p.get("src_mac")),
            "name": names.get(p["src"]), "leaks": 0, "requests": 0})
    for r in requests_seen:
        d = devices.setdefault(r["src_ip"], {
            "ip": r["src_ip"], "mac": r.get("src_mac"),
            "vendor": mac_vendor(r.get("src_mac")),
            "name": names.get(r["src_ip"]), "leaks": 0, "requests": 0})
        if r.get("src_mac") and not d["mac"]:
            d["mac"] = r["src_mac"]
            d["vendor"] = mac_vendor(r["src_mac"])
        d["requests"] += 1
        st = sites.setdefault(r["host"], {
            "host": r["host"], "server_ip": r["dst_ip"],
            "pages": set(), "leaks": 0, "requests": 0})
        st["pages"].add(r["path"])
        st["requests"] += 1
    for ev in events:
        d = devices.setdefault(ev["src_ip"], {
            "ip": ev["src_ip"], "mac": ev["src_mac"],
            "vendor": mac_vendor(ev["src_mac"]),
            "name": names.get(ev["src_ip"]), "leaks": 0, "requests": 0})
        if ev["src_mac"]:
            d["mac"] = ev["src_mac"]
            d["vendor"] = mac_vendor(ev["src_mac"])
        d["leaks"] += 1
        s = sites.setdefault(ev["host"], {
            "host": ev["host"], "server_ip": ev["dst_ip"],
            "pages": set(), "leaks": 0, "requests": 0})
        if ev["path"]:
            s["pages"].add(ev["path"])
        s["leaks"] += 1
    for s in sites.values():
        s["pages"] = sorted(s["pages"])
    _mac_names = harvest_mac_names(udp_recs)
    _mac_os = harvest_dhcp_fingerprints(udp_recs)
    for _d in devices.values():
        if not _d.get("name") and _d.get("mac") in _mac_names:
            _d["name"] = _mac_names[_d["mac"]]
        if _d.get("mac") in _mac_os:
            _d["os"] = _mac_os[_d["mac"]]
    return {"events": events, "devices": list(devices.values()),
            "sites": list(sites.values()), "stats": stats,
            "requests": requests_seen, "domains": sightings}


# ------------------------------------------------------------ pcapng reader
def read_pcapng(data):
    """Yield (ts_seconds, linktype, frame) from pcapng bytes."""
    off = 0
    endian = "<"
    interfaces = []  # (linktype, tsresol_power, tsoffset)
    while off + 12 <= len(data):
        btype, blen = struct.unpack(endian + "II", data[off:off + 8])
        if blen < 12 or off + blen > len(data):
            break
        body = data[off + 8:off + blen - 4]
        if btype == 0x0A0D0D0A:  # section header
            bom = struct.unpack("<I", body[0:4])[0]
            endian = "<" if bom == 0x1A2B3C4D else ">"
            btype, blen = struct.unpack(endian + "II", data[off:off + 8])
            body = data[off + 8:off + blen - 4]
            interfaces = []
        elif btype == 0x00000001 and len(body) >= 8:  # interface description
            linktype = struct.unpack(endian + "H", body[0:2])[0]
            tsresol, tsoff = 6, 0
            opts = body[8:]
            i = 0
            while i + 4 <= len(opts):
                code, ln = struct.unpack(endian + "HH", opts[i:i + 4])
                if code == 0:
                    break
                val = opts[i + 4:i + 4 + ln]
                if code == 9 and ln >= 1:
                    tsresol = val[0] & 0x7F
                elif code == 14 and ln >= 8:
                    tsoff = struct.unpack(endian + "q", val[:8])[0]
                i += 4 + ((ln + 3) // 4) * 4
            interfaces.append((linktype, tsresol, tsoff))
        elif btype == 0x00000006 and len(body) >= 20:  # enhanced packet
            iid, tsh, tsl, caplen, _plen = struct.unpack(endian + "IIIII", body[:20])
            frame = body[20:20 + caplen]
            if iid < len(interfaces):
                linktype, tsresol, tsoff = interfaces[iid]
                raw_ts = (tsh << 32) | tsl
                ts = raw_ts / (10 ** tsresol) + tsoff
                yield ts, linktype, frame
        elif btype == 0x00000003 and len(body) >= 4:  # simple packet
            plen = struct.unpack(endian + "I", body[:4])[0]
            if interfaces:
                yield 0.0, interfaces[0][0], body[4:4 + plen]
        off += blen
