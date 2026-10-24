"""CredLens Scan — network vulnerability scanner (pure stdlib).

Methodical, evidence-driven: a check becomes a finding only when the scan
observed it directly. Everything not proven lands in the report's COVERAGE
section with the reason. Non-destructive by policy: anonymous-access checks
only (FTP / MQTT / Redis / SNMP-public), never password guessing, never DoS.

Profiles:
  passive  — DNS + certificate-transparency only, no target connections
  standard — top ports, banners, service/TLS/web checks, SNMP probe
  deep     — ports 1-1024 + extras, extended web probes, TLS floor tests
"""
import datetime
import ipaddress
import re
import socket
import ssl
import struct
import threading
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 111: "RPCbind", 135: "MS-RPC", 139: "NetBIOS", 143: "IMAP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 587: "SMTP submission",
    873: "rsync", 993: "IMAPS", 995: "POP3S", 1723: "PPTP", 1883: "MQTT",
    2049: "NFS", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8000: "HTTP-alt", 8080: "HTTP-alt",
    8443: "HTTPS-alt", 8888: "HTTP-alt", 9090: "HTTP-alt",
    9200: "Elasticsearch", 27017: "MongoDB",
}

STD_PORTS = sorted({21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389,
                    443, 445, 587, 873, 993, 995, 1723, 1883, 2049, 3306,
                    3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888, 9090,
                    9200, 27017})
WEB_PORTS = {80, 443, 8000, 8080, 8443, 8888, 9090}
TLS_PORTS = {443, 8443, 993, 995}
DB_PORTS = {3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL", 27017: "MongoDB"}


class Finding:
    def __init__(self, sev, title, asset, category, cvss, confidence,
                 evidence, repro, impact, fix):
        self.sev, self.title, self.asset = sev, title, asset
        self.category, self.cvss, self.confidence = category, cvss, confidence
        self.evidence, self.repro, self.impact, self.fix = evidence, repro, impact, fix

    def key(self):
        return (self.title, self.asset)


# ------------------------------------------------------------ target parsing
def parse_target(raw):
    """Return dict(kind, hosts=[ips], hostname, domain, url_parts, label)."""
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("empty target")
    hostname = None
    url_parts = None
    host_part = raw
    if "://" in raw:
        url_parts = urllib.parse.urlsplit(raw)
        hostname = url_parts.hostname
        host_part = hostname or ""
    elif "/" in raw and not _is_cidr(raw):
        host_part = raw.split("/")[0]
        hostname = host_part
    if _is_cidr(host_part):
        net = ipaddress.ip_network(host_part, strict=False)
        if net.num_addresses > 256:
            raise ValueError("range too large — /24 (256 hosts) is the max per scan")
        hosts = [str(ip) for ip in net.hosts()] or [str(net.network_address)]
        return {"kind": "cidr", "hosts": hosts, "hostname": None,
                "domain": None, "url_parts": url_parts, "label": raw}
    try:
        ip = ipaddress.ip_address(host_part)
        return {"kind": "ip", "hosts": [str(ip)], "hostname": None,
                "domain": None, "url_parts": url_parts, "label": raw}
    except ValueError:
        pass
    hostname = host_part
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
        ips = sorted({i[4][0] for i in infos})
    except Exception as e:
        raise ValueError(f"cannot resolve {hostname}: {e}")
    if not ips:
        raise ValueError(f"cannot resolve {hostname}")
    return {"kind": "host", "hosts": ips, "hostname": hostname,
            "domain": hostname, "url_parts": url_parts, "label": raw}


def _is_cidr(s):
    try:
        return "/" in s and bool(ipaddress.ip_network(s, strict=False))
    except Exception:
        return False


# ---------------------------------------------------------------- DNS client
def _dns_name_encode(name):
    out = b""
    for part in name.rstrip(".").split("."):
        out += bytes([len(part)]) + part.encode()
    return out + b"\x00"


def _dns_name_decode(msg, off):
    labels, jumped, end = [], False, off
    hops = 0
    while off < len(msg) and hops < 24:
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


def dns_query(name, qtype, server="1.1.1.1", timeout=4):
    """Minimal DNS client. Returns list of (type, value) answers."""
    tid = 0xC10D
    q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    q += _dns_name_encode(name) + struct.pack(">HH", qtype, 1)
    sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sk.settimeout(timeout)
    try:
        sk.sendto(q, (server, 53))
        data, _ = sk.recvfrom(8192)
    except Exception:
        return []
    finally:
        sk.close()
    if len(data) < 12:
        return []
    _id, _fl, qd, an, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
    if _id != tid:
        return []                   # not our answer — stray or spoofed
    off = 12
    answers = []
    try:
        for _ in range(qd):
            _, off = _dns_name_decode(data, off)
            off += 4
        for _ in range(an):
            _, off = _dns_name_decode(data, off)
            if off + 10 > len(data):
                break
            rtype, _cls, _ttl, rdlen = struct.unpack(
                ">HHIH", data[off:off + 10])
            off += 10
            rdata_off = off
            rdata = data[off:off + rdlen]
            off += rdlen
            if rtype == 1 and rdlen == 4:
                answers.append((1, ".".join(str(b) for b in rdata)))
            elif rtype == 2:
                answers.append((2, _dns_name_decode(data, rdata_off)[0]))
            elif rtype == 5:
                answers.append((5, _dns_name_decode(data, rdata_off)[0]))
            elif rtype == 16:
                txt, i = "", 0
                while i < len(rdata):
                    ln = rdata[i]
                    txt += rdata[i + 1:i + 1 + ln].decode("utf-8", "replace")
                    i += 1 + ln
                answers.append((16, txt))
            elif rtype == 15 and rdlen > 2:
                answers.append((15, _dns_name_decode(data, rdata_off + 2)[0]))
    except Exception:
        pass                    # malformed/spoofed answer: keep what parsed
    return answers


def dns_axfr(domain, ns_host, timeout=6):
    """Try a zone transfer. Returns record count if allowed, else None."""
    try:
        ns_ip = socket.getaddrinfo(ns_host, 53, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    except Exception:
        return None
    q = struct.pack(">HHHHHH", 0xA17C, 0x0000, 1, 0, 0, 0)
    q += _dns_name_encode(domain) + struct.pack(">HH", 252, 1)
    try:
        sk = socket.create_connection((ns_ip, 53), timeout=timeout)
        sk.sendall(struct.pack(">H", len(q)) + q)
        total_answers = 0
        for _ in range(12):
            hdr = sk.recv(2)
            if len(hdr) < 2:
                break
            ln = struct.unpack(">H", hdr)[0]
            msg = b""
            while len(msg) < ln:
                chunk = sk.recv(ln - len(msg))
                if not chunk:
                    break
                msg += chunk
            if len(msg) < 12:
                break
            an = struct.unpack(">H", msg[6:8])[0]
            total_answers += an
            if an == 0:
                break
        sk.close()
        return total_answers if total_answers >= 3 else None
    except Exception:
        return None


# ------------------------------------------------------------- port scanning
def scan_ports(ip, ports, timeout=0.7, workers=48, stop=None):
    open_ports = []

    def probe(port):
        if stop and stop():
            return
        try:
            sk = socket.create_connection((ip, port), timeout=timeout)
            sk.close()
            open_ports.append(port)
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(probe, ports))
    return sorted(open_ports)


def grab_banner(ip, port, timeout=1.6):
    """Best-effort service banner. Returns text or ''."""
    try:
        sk = socket.create_connection((ip, port), timeout=timeout)
        sk.settimeout(timeout)
        data = b""
        try:
            data = sk.recv(512)
        except socket.timeout:
            pass
        if not data:
            probe = (b"GET / HTTP/1.0\r\nHost: x\r\n\r\n" if port in WEB_PORTS
                     else b"\r\n")
            try:
                sk.sendall(probe)
                data = sk.recv(512)
            except Exception:
                pass
        sk.close()
        return data.decode("iso-8859-1", "replace").strip()
    except Exception:
        return ""


def _sock(ip, port, timeout=3):
    sk = socket.create_connection((ip, port), timeout=timeout)
    sk.settimeout(timeout)
    return sk


# ------------------------------------------------------- banner version rules
# (needle, sev, cvss, title, fix) — banner-derived, confidence medium at best:
# a banner can lie, so these never claim high confidence.
BANNER_RULES = [
    ("vsftpd 2.3.4", "critical", 9.8,
     "vsftpd 2.3.4 backdoor-vulnerable FTP server (CVE-2011-2523)",
     "Upgrade vsftpd immediately — 2.3.4 shipped with a malicious backdoor."),
    ("Apache/2.4.49", "high", 7.5,
     "Apache 2.4.49 path traversal / RCE (CVE-2021-41773)",
     "Upgrade Apache httpd to 2.4.51 or later."),
    ("Apache/2.2.", "medium", 5.3,
     "Apache 2.2.x end-of-life web server",
     "Upgrade to a supported Apache httpd release (2.4.x)."),
    ("Apache/2.4.50", "high", 7.5,
     "Apache 2.4.50 incomplete CVE-2021-41773 fix (CVE-2021-42013)",
     "Upgrade Apache httpd to 2.4.51 or later."),
    ("PHP/5.", "medium", 5.3,
     "PHP 5.x end-of-life runtime exposed in banner",
     "Upgrade PHP to a supported release and suppress version banners."),
    ("Microsoft-IIS/6.0", "high", 7.5,
     "Microsoft IIS 6.0 end-of-life web server",
     "Migrate off IIS 6.0 — unsupported since 2015."),
    ("Microsoft-IIS/7.5", "low", 3.7,
     "Microsoft IIS 7.5 end-of-life web server",
     "Plan migration to a supported IIS/Windows Server release."),
    ("OpenSSH_5.", "low", 3.7,
     "OpenSSH 5.x (very old) in banner",
     "Upgrade OpenSSH to a current release."),
    ("OpenSSH_6.", "low", 3.7,
     "OpenSSH 6.x (old) in banner",
     "Upgrade OpenSSH to a current release."),
]


def check_banner_rules(findings, banner, asset, ip, port):
    if not banner:
        return
    for needle, sev, cvss, title, fix in BANNER_RULES:
        if needle.lower() in banner.lower():
            findings.append(Finding(
                sev, title, asset, "C Service", cvss, "med",
                f"Service on {ip}:{port} banner: {banner.splitlines()[0][:120]!r} contains {needle!r}.",
                f"Connect to {ip} port {port} and read the banner (e.g. `nc {ip} {port}`).",
                "Known-vulnerable or unsupported software is remotely identifiable and targetable.",
                fix))


# ------------------------------------------------------------ service checks
def check_ftp(findings, ip, port, banner):
    asset = f"{ip}:{port} (FTP)"
    try:
        sk = _sock(ip, port, 3)
        sk.recv(256)
        sk.sendall(b"USER anonymous\r\n")
        r1 = sk.recv(256).decode("iso-8859-1", "replace").strip()
        logged = r1.startswith("230")
        if not logged and r1.startswith("331"):
            sk.sendall(b"PASS anonymous@credlens\r\n")
            r2 = sk.recv(256).decode("iso-8859-1", "replace").strip()
            logged = r2.startswith("230")
        sk.close()
        if logged:
            findings.append(Finding(
                "medium", "FTP allows anonymous login", asset, "C Service", 5.3, "high",
                f"USER anonymous accepted; server response confirmed login (230). Banner: {banner.splitlines()[0][:80]!r}",
                f"`ftp {ip}` → login as 'anonymous' with any password.",
                "Anyone on the network can browse/download whatever the anonymous account can reach; a classic staging point for malware and data theft.",
                "Disable anonymous FTP. If file transfer is needed, use SFTP/FTPS with named accounts."))
    except Exception:
        pass


def check_mqtt(findings, ip, port):
    asset = f"{ip}:{port} (MQTT)"
    try:
        vh = b"\x00\x04MQTT\x04\x02\x00\x3c"
        payload = b"\x00\x0acredlens-1"
        body = vh + payload
        sk = _sock(ip, port, 3)
        sk.sendall(bytes([0x10, len(body)]) + body)
        resp = sk.recv(64)
        sk.close()
        if len(resp) >= 4 and resp[0] == 0x20 and resp[3] == 0x00:
            findings.append(Finding(
                "high", "MQTT broker accepts anonymous connections", asset, "P IoT/OT", 7.5, "high",
                "CONNECT with no credentials returned CONNACK 0x00 (connection accepted).",
                f"Connect any MQTT client to {ip}:{port} with no username/password (e.g. `mosquitto_sub -h {ip} -t '#'`).",
                "Anyone reachable can subscribe to every topic (sensor data, commands) and publish messages — for an IoT broker that can mean reading telemetry or controlling devices.",
                "Require username/password or client certificates on the broker; bind it away from untrusted networks."))
    except Exception:
        pass


def check_redis(findings, ip, port):
    asset = f"{ip}:{port} (Redis)"
    try:
        sk = _sock(ip, port, 3)
        sk.sendall(b"PING\r\n")
        resp = sk.recv(128).decode("iso-8859-1", "replace").strip()
        sk.close()
        if resp.startswith("+PONG"):
            findings.append(Finding(
                "high", "Redis answers without authentication", asset, "C Service", 7.5, "high",
                "Sent PING with no AUTH; server replied +PONG.",
                f"`redis-cli -h {ip} ping` — no password needed.",
                "An unauthenticated Redis usually allows full read/write of its data and, in common misconfigurations, leads to file write / RCE.",
                "Set requirepass, bind to localhost or a private interface, and firewall 6379."))
    except Exception:
        pass


def check_elasticsearch(findings, ip, port, host_header):
    asset = f"{ip}:{port} (Elasticsearch)"
    r = http_fetch(ip, port, False, "/", host_header=host_header)
    if r and r[0] == 200 and b'"cluster_name"' in r[2]:
        findings.append(Finding(
            "high", "Elasticsearch REST API open without authentication", asset,
            "C Service", 7.5, "high",
            "GET / returned the cluster info document (cluster_name present) with no credentials.",
            f"`curl http://{ip}:{port}/` and `curl http://{ip}:{port}/_cat/indices`.",
            "Indices can typically be listed and read in full — a frequent source of large data breaches.",
            "Enable Elasticsearch security (authentication), bind to a private interface, firewall 9200."))
    elif r:
        findings.append(Finding(
            "medium", "Elasticsearch port reachable on the network", asset,
            "A Network", 5.3, "med",
            f"Port {port} is open and answers HTTP (status {r[0]}).",
            f"`curl -i http://{ip}:{port}/`.",
            "Database/search services should not be broadly reachable; exposure invites probing and exploitation.",
            "Restrict 9200 to application hosts only."))


def _ber_tlv(tag, val):
    ln = len(val)
    if ln < 128:
        return bytes([tag, ln]) + val
    return bytes([tag, 0x81, ln]) + val


def _ber_int(n):
    b = b"\x00" if n == 0 else n.to_bytes((n.bit_length() + 7) // 8, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return _ber_tlv(0x02, b)


def _ber_oid(arcs):
    out = bytes([40 * arcs[0] + arcs[1]])
    for a in arcs[2:]:
        stack = [a & 0x7F]
        a >>= 7
        while a:
            stack.append(0x80 | (a & 0x7F))
            a >>= 7
        out += bytes(reversed(stack))
    return _ber_tlv(0x06, out)


def check_snmp(findings, ip):
    asset = f"{ip}:161 (SNMP)"
    try:
        varbind = _ber_tlv(0x30, _ber_oid([1, 3, 6, 1, 2, 1, 1, 1, 0]) + b"\x05\x00")
        pdu = _ber_tlv(0xA0, _ber_int(1) + _ber_int(0) + _ber_int(0)
                       + _ber_tlv(0x30, varbind))
        msg = _ber_tlv(0x30, _ber_int(0) + _ber_tlv(0x04, b"public") + pdu)
        sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sk.settimeout(2.5)
        sk.sendto(msg, (ip, 161))
        data, _ = sk.recvfrom(4096)
        sk.close()
        if len(data) > 20 and data[0] == 0x30:
            printable = re.findall(rb"[\x20-\x7e]{6,}", data)
            descr = printable[-1].decode("iso-8859-1", "replace")[:100] if printable else ""
            findings.append(Finding(
                "high", "SNMP responds to default community 'public'", asset,
                "A Network", 7.5, "high",
                f"GetRequest for sysDescr with community 'public' got a response.{(' sysDescr: ' + descr) if descr else ''}",
                f"`snmpwalk -v2c -c public {ip}` or `onesixtyone {ip}`.",
                "SNMP with a default community leaks full device inventories (interfaces, routes, software) and on many devices allows configuration writes with the 'private' community.",
                "Disable SNMP if unused; otherwise use SNMPv3 with auth and change all communities."))
    except Exception:
        pass


# ---------------------------------------------------------------- TLS checks
def _tls_connect(ip, port, ctx, timeout=4):
    sk = socket.create_connection((ip, port), timeout=timeout)
    ss = ctx.wrap_socket(sk, server_hostname=ip)
    return ss


def check_tls(findings, ip, port, profile):
    asset = f"{ip}:{port} (TLS)"
    # 1) verifying handshake — proves validity; the failure text is evidence
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    try:
        ss = _tls_connect(ip, port, ctx)
        cert = ss.getpeercert() or {}
        ss.close()
        na = cert.get("notAfter")
        if na:
            try:
                exp = datetime.datetime.strptime(
                    " ".join(na.replace("  ", " 0").split()), "%b %d %H:%M:%S %Y %Z")
                days = (exp - datetime.datetime.utcnow()).days
                if days < 0:
                    findings.append(Finding(
                        "medium", "TLS certificate expired", asset, "F Crypto/TLS",
                        5.3, "high", f"Certificate notAfter = {na} (expired {-days} days ago).",
                        f"`openssl s_client -connect {ip}:{port}` and check the dates.",
                        "Expired certificates train users to click through warnings and enable man-in-the-middle attacks.",
                        "Renew the certificate and automate renewal."))
                elif days < 14:
                    findings.append(Finding(
                        "low", "TLS certificate expiring soon", asset, "F Crypto/TLS",
                        3.7, "high", f"Certificate notAfter = {na} ({days} days left).",
                        f"`openssl s_client -connect {ip}:{port}`.",
                        "An unnoticed expiry becomes an outage or an expired-cert finding later.",
                        "Renew now and automate renewal."))
            except Exception:
                pass
    except ssl.SSLCertVerificationError as e:
        msg = str(e)
        low = msg.lower()
        if "expired" in low:
            sev, title = "medium", "TLS certificate expired"
        elif "self signed" in low or "self-signed" in low:
            sev, title = "low", "Self-signed TLS certificate"
        elif "hostname" in low or "doesn't match" in low:
            sev, title = "low", "TLS certificate hostname mismatch"
        else:
            sev, title = "low", "TLS certificate fails validation"
        findings.append(Finding(
            sev, title, asset, "F Crypto/TLS", 5.3 if sev == "medium" else 3.7, "high",
            f"Validating handshake failed: {msg[:160]}",
            f"`openssl s_client -connect {ip}:{port}` or open the service in a browser.",
            "Clients cannot authenticate the server, enabling man-in-the-middle interception.",
            "Install a valid certificate from a trusted CA matching the service name."))
    except Exception:
        return  # not actually TLS — banner checks already covered it

    # 2) protocol floor (deep, or standard for 443)
    if profile in ("standard", "deep"):
        for ver, label, sev, cvss in (
                (ssl.TLSVersion.TLSv1, "TLS 1.0", "medium", 5.3),
                (ssl.TLSVersion.TLSv1_1, "TLS 1.1", "low", 3.7)):
            try:
                c2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                c2.check_hostname = False
                c2.verify_mode = ssl.CERT_NONE
                c2.minimum_version = ver
                c2.maximum_version = ver
                ss = _tls_connect(ip, port, c2, timeout=3)
                ss.close()
                findings.append(Finding(
                    sev, f"{label} still accepted", asset, "F Crypto/TLS", cvss, "high",
                    f"A handshake restricted to {label} completed successfully.",
                    f"`openssl s_client -connect {ip}:{port} -tls1` (or -tls1_1).",
                    "Legacy TLS versions have known weaknesses (BEAST/POODLE class) and fail PCI-DSS.",
                    "Disable TLS below 1.2; offer 1.2 and 1.3 only."))
            except Exception:
                pass


# ---------------------------------------------------------------- HTTP fetch
def http_fetch(ip, port, use_ssl, path="/", method="GET", extra_headers=None,
               host_header=None, timeout=4):
    """Tiny raw HTTP client. Returns (status, headers{list}, body, head) or
    None. Hard total deadline: a trickling server cannot hold it forever."""
    import time as _time
    deadline = _time.monotonic() + max(10.0, timeout * 3)
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
        if use_ssl:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(raw, server_hostname=host_header or ip)
        else:
            s = raw
        s.settimeout(timeout)
        lines = [f"{method} {path} HTTP/1.1", f"Host: {host_header or ip}",
                 "User-Agent: CredLens-Scan", "Connection: close"]
        if extra_headers:
            lines += [f"{k}: {v}" for k, v in extra_headers.items()]
        s.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
        data = b""
        while len(data) < 262144:
            left = deadline - _time.monotonic()
            if left <= 0:
                break
            try:
                s.settimeout(min(timeout, left))
                chunk = s.recv(16384)
            except Exception:
                break
            if not chunk:
                break
            data += chunk
        s.close()
        head_b, _, body = data.partition(b"\r\n\r\n")
        head = head_b.decode("iso-8859-1", "replace")
        m = re.search(r"HTTP/[\d.]+ (\d+)", head)
        status = int(m.group(1)) if m else 0
        headers = {}
        for ln in head.split("\r\n")[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                headers.setdefault(k.strip().lower(), []).append(v.strip())
        return status, headers, body, head
    except Exception:
        return None


# ----------------------------------------------------------------- web checks
def check_web(findings, ip, port, disp, profile, stop=None):
    use_ssl = port in (443, 8443)
    scheme = "https" if use_ssl else "http"
    base = f"{disp}:{port}"
    r = http_fetch(ip, port, use_ssl, "/", host_header=disp)
    if not r and not use_ssl:
        # TLS-only service on an alt port (8000/8080/8888/9090...): the
        # plaintext probe fails silently — retry wrapped before giving up
        r = http_fetch(ip, port, True, "/", host_header=disp)
        if r:
            use_ssl, scheme = True, "https"
    if not r:
        return
    status, headers, body, _head = r
    server = (headers.get("server") or [""])[0]
    if server:
        check_banner_rules(findings, server, base, ip, port)

    missing = []
    if use_ssl and "strict-transport-security" not in headers:
        missing.append("Strict-Transport-Security")
    if "content-security-policy" not in headers:
        missing.append("Content-Security-Policy")
    if "x-content-type-options" not in headers:
        missing.append("X-Content-Type-Options")
    if "x-frame-options" not in headers and "content-security-policy" not in headers:
        missing.append("X-Frame-Options")
    if missing and status:
        findings.append(Finding(
            "low", "Missing security response headers", base, "I Config", 3.7, "high",
            f"GET {scheme}://{base}/ did not return: {', '.join(missing)}.",
            f"`curl -I {scheme}://{base}/`",
            "Missing headers weaken browser-side protections (clickjacking, MIME sniffing, downgrade).",
            "Add the listed headers at the web server / reverse proxy."))

    sess_re = re.compile(r"(sess|auth|token|sid|jwt|login)", re.I)
    for sc in headers.get("set-cookie", []):
        name = sc.split("=")[0].strip()
        if not sess_re.search(name):
            continue
        low_sc = sc.lower()
        lacks = []
        if "httponly" not in low_sc:
            lacks.append("HttpOnly")
        if use_ssl and "secure" not in low_sc:
            lacks.append("Secure")
        if "samesite" not in low_sc:
            lacks.append("SameSite")
        if lacks:
            findings.append(Finding(
                "low", f"Session cookie '{name}' missing flags: {', '.join(lacks)}",
                base, "E Auth", 3.7, "high",
                f"Set-Cookie: {sc[:110]}",
                f"`curl -I {scheme}://{base}/` and inspect Set-Cookie.",
                "Cookies without HttpOnly/Secure/SameSite are easier to steal (XSS, plaintext downgrade, CSRF).",
                f"Set {', '.join(lacks)} on the '{name}' cookie."))

    if b"Index of /" in body or b"Directory listing for" in body:
        findings.append(Finding(
            "medium", "Directory listing enabled", base + "/", "I Config", 5.3, "high",
            "GET / returned an 'Index of /' listing page.",
            f"Open {scheme}://{base}/ in a browser.",
            "Attackers can enumerate files (backups, configs, uploads) without guessing names.",
            "Disable autoindex / directory browsing on the web server."))

    probes = [("/.git/HEAD", "git"), ("/.env", "env")]
    if profile == "deep":
        probes += [("/.git/config", "gitconfig"), ("/phpinfo.php", "phpinfo"),
                   ("/server-status", "status")]
    for path, kind in probes:
        if stop and stop():
            return
        rr = http_fetch(ip, port, use_ssl, path, host_header=disp)
        if not rr or rr[0] != 200:
            continue
        b = rr[2]
        if kind == "git" and (b.startswith(b"ref:") or re.match(rb"[0-9a-f]{40}", b)):
            findings.append(Finding(
                "high", "Exposed .git repository data", base + path, "I Config", 7.5, "high",
                f"GET {path} returned a git HEAD reference — the repository metadata is downloadable.",
                f"`curl {scheme}://{base}{path}` (tools like git-dumper can rebuild the source).",
                "Full source code disclosure: secrets, internal logic and history become public.",
                "Block /.git/ at the server and remove the directory from the web root."))
        elif kind == "gitconfig" and b"[core]" in b:
            findings.append(Finding(
                "high", "Exposed .git repository data", base + path, "I Config", 7.5, "high",
                f"GET {path} returned a git config file.",
                f"`curl {scheme}://{base}{path}`.",
                "Repository metadata (remotes, structure) is public and aids source recovery.",
                "Block /.git/ at the server and remove the directory from the web root."))
        elif kind == "env" and re.search(rb"(?m)^[A-Z][A-Z0-9_]{2,}=", b):
            names = [n.decode() for n in
                     re.findall(rb"(?m)^([A-Z][A-Z0-9_]{2,})=", b)][:6]
            findings.append(Finding(
                "high", "Exposed .env file", base + path, "J Data", 7.5, "high",
                f"GET {path} returned environment variables (names only shown): {', '.join(names)}.",
                f"`curl {scheme}://{base}{path}`.",
                ".env files typically hold database passwords and API keys — assume every value in it is compromised.",
                "Remove .env from the web root, block dotfile access, and rotate every secret it contained."))
        elif kind == "phpinfo" and b"phpinfo()" in b:
            findings.append(Finding(
                "medium", "phpinfo() page exposed", base + path, "I Config", 5.3, "high",
                f"GET {path} returned a full phpinfo() dump.",
                f"`curl {scheme}://{base}{path}`.",
                "Leaks paths, modules, environment and configuration details that sharpen further attacks.",
                "Delete the phpinfo file from production."))
        elif kind == "status" and b"Apache Server Status" in b:
            findings.append(Finding(
                "medium", "Apache server-status exposed", base + path, "I Config", 5.3, "high",
                f"GET {path} returned the Apache Server Status page.",
                f"`curl {scheme}://{base}{path}`.",
                "Reveals live URLs, client IPs and request details of other users.",
                "Restrict /server-status to localhost."))

    if profile == "deep":
        for p in ("/images/", "/uploads/", "/backup/", "/files/"):
            rr = http_fetch(ip, port, use_ssl, p, host_header=disp)
            if rr and (b"Index of /" in rr[2] or b"Directory listing for" in rr[2]):
                findings.append(Finding(
                    "medium", "Directory listing enabled", base + p, "I Config", 5.3, "high",
                    f"GET {p} returned an 'Index of /' listing page.",
                    f"Open {scheme}://{base}{p} in a browser.",
                    "Attackers can enumerate files without guessing names.",
                    "Disable autoindex / directory browsing on the web server."))
                break

    rr = http_fetch(ip, port, use_ssl, "/", host_header=disp,
                    extra_headers={"Origin": "https://credlens-check.example"})
    if rr:
        acao = (rr[1].get("access-control-allow-origin") or [""])[0]
        acac = (rr[1].get("access-control-allow-credentials") or [""])[0]
        if acao == "https://credlens-check.example":
            findings.append(Finding(
                "medium", "CORS reflects arbitrary origins", base, "D Web", 5.3, "high",
                "A request with Origin: https://credlens-check.example got Access-Control-Allow-Origin echoing that origin.",
                f"`curl -H 'Origin: https://credlens-check.example' -I {scheme}://{base}/`",
                "Any website may be allowed to read this app's responses from a victim's browser.",
                "Allowlist trusted origins; never reflect arbitrary Origin values."))
        elif acao == "*" and acac.lower() == "true":
            findings.append(Finding(
                "medium", "CORS wildcard origin with credentials allowed", base,
                "D Web", 5.3, "high",
                "Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true.",
                f"`curl -H 'Origin: https://example.org' -I {scheme}://{base}/`",
                "Credentialed cross-origin reads should never be wildcarded.",
                "Replace the wildcard with an explicit origin allowlist."))

    if profile == "deep":
        rr = http_fetch(ip, port, use_ssl, "/", method="TRACE", host_header=disp)
        if rr and rr[0] == 200 and b"CredLens-Scan" in rr[2]:
            findings.append(Finding(
                "low", "HTTP TRACE method enabled", base, "D Web", 3.7, "high",
                "TRACE / returned 200 and echoed the request (Cross-Site Tracing).",
                f"`curl -X TRACE {scheme}://{base}/`",
                "TRACE can help steal headers/cookies in legacy attack chains.",
                "Disable the TRACE method on the web server."))


# ----------------------------------------------------------------- DNS checks
TAKEOVER_SUFFIXES = ("github.io", "herokuapp.com", "azurewebsites.net",
                     "s3.amazonaws.com", "wordpress.com", "ghost.io",
                     "netlify.app", "vercel.app", "surge.sh")


def check_dns(findings, domain, notes):
    zones = [domain]
    parts = domain.split(".")
    if len(parts) > 2:
        zones.append(".".join(parts[1:]))
    for zone in zones:
        txts = [v for t, v in dns_query(zone, 16) if t == 16]
        spf = next((t for t in txts if t.lower().startswith("v=spf1")), None)
        gaps = []
        if not spf:
            gaps.append("no SPF record")
        elif "+all" in spf:
            findings.append(Finding(
                "medium", "SPF record permits any host (+all)", zone, "G DNS", 5.3, "high",
                f"TXT on {zone}: {spf[:100]}",
                f"`nslookup -type=TXT {zone}`",
                "Any server on the internet may send mail as this domain — spoofing is unimpeded.",
                "List legitimate senders in SPF and end with -all (hard fail)."))
        dmarc = [v for t, v in dns_query("_dmarc." + zone, 16) if t == 16]
        dm = next((t for t in dmarc if t.lower().startswith("v=dmarc1")), None)
        if not dm:
            gaps.append("no DMARC record")
        elif "p=none" in dm.lower():
            gaps.append("DMARC policy is p=none (monitor only, no enforcement)")
        if gaps:
            findings.append(Finding(
                "low", "Email authentication gaps (SPF/DMARC)", zone, "G DNS", 3.7, "high",
                f"Public DNS for {zone}: " + "; ".join(gaps) + ".",
                f"`nslookup -type=TXT {zone}` and `nslookup -type=TXT _dmarc.{zone}`",
                "Without SPF/DMARC enforcement, attackers can spoof mail from this domain convincingly.",
                "Publish SPF for legitimate senders and a DMARC record; move the policy to quarantine, then reject."))
        ns = [v for t, v in dns_query(zone, 2) if t == 2]
        notes.append(f"DNS: {zone} checked (SPF/DMARC/NS" + (f" via {ns[0]}" if ns else "") + ")")
        for nsh in ns[:1]:
            cnt = dns_axfr(zone, nsh)
            if cnt:
                findings.append(Finding(
                    "medium", "DNS zone transfer (AXFR) allowed", f"{zone} via {nsh}",
                    "G DNS", 5.3, "high",
                    f"AXFR request to {nsh} returned {cnt} records.",
                    f"`dig AXFR {zone} @{nsh}`",
                    "The whole zone is public — attackers get a complete map of named assets.",
                    "Restrict zone transfers to secondary nameservers only."))
    try:
        import json as _json
        import urllib.request
        req = urllib.request.Request(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            headers={"User-Agent": "CredLens-Scan"})
        with urllib.request.urlopen(req, timeout=12) as fh:
            rows = _json.loads(fh.read().decode("utf-8", "replace"))
        names = sorted({n.strip().lower() for row in rows
                        for n in row.get("name_value", "").split("\n")
                        if n.strip() and "*" not in n})
        if names:
            notes.append(f"Certificate transparency: {len(names)} subdomain(s) of {domain} appear in public certificates")
        for sub in names[:20]:
            cn = [v for t, v in dns_query(sub, 5) if t == 5]
            if cn and any(cn[0].lower().rstrip(".").endswith(sfx)
                          for sfx in TAKEOVER_SUFFIXES):
                if not dns_query(sub, 1):
                    findings.append(Finding(
                        "low", "Possible dangling subdomain (takeover risk)", sub,
                        "G DNS", 3.7, "low",
                        f"{sub} CNAMEs to {cn[0]} but returns no A record — the external resource may be unclaimed.",
                        f"`nslookup {sub}` and inspect the CNAME target.",
                        "If the external resource was deleted, an attacker can claim it and serve content under this subdomain.",
                        "Remove the stale DNS record or reclaim the external resource."))
    except Exception:
        notes.append("Certificate transparency lookup unreachable from this machine")


# ------------------------------------------------------------- orchestration
def discover_hosts(candidates, known=(), timeout=0.45, workers=64, stop=None):
    """Fast liveness sweep for ranges: a candidate counts as live if it is
    already known (ARP / seen traffic) or answers on any common port."""
    probe_ports = (80, 443, 22, 445, 8080, 3389, 1883, 53)
    known_set = set(known)
    live = {ip for ip in candidates if ip in known_set}

    def probe(ip):
        if stop and stop():
            return None
        for p in probe_ports:
            try:
                sk = socket.create_connection((ip, p), timeout=timeout)
                sk.close()
                return ip
            except Exception:
                continue
        return None

    rest = [ip for ip in candidates if ip not in live]
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for r in ex.map(probe, rest):
            if r:
                live.add(r)
    return sorted(live, key=lambda x: int(ipaddress.ip_address(x)))



def run_scan(target_raw, profile="standard", exclude_csv="", progress=None,
             stop=None, known_hosts=(), names=None, label_override=None):
    profile = profile if profile in ("passive", "standard", "deep") else "standard"
    spec = parse_target(target_raw)
    if label_override:
        spec["label"] = label_override
    names = names or {}
    excludes = {e.strip().lower() for e in (exclude_csv or "").split(",") if e.strip()}
    hosts = [h for h in spec["hosts"] if h.lower() not in excludes]
    findings, notes = [], []
    stopped = False

    def say(msg):
        if progress:
            progress(msg)

    say(f"Phase 0 — scope: {len(hosts)} host(s), profile {profile}")
    if profile != "passive" and len(hosts) > 8:
        say(f"Phase 1 — discovering live devices ({len(hosts)} addresses)…")
        live = discover_hosts(hosts, known_hosts, stop=stop)
        notes.append(f"Discovery: {len(live)} live device(s) answered out of "
                     f"{len(hosts)} addresses")
        if len(live) > 64:
            notes.append("Discovery cap: only the first 64 live devices were "
                         "vulnerability-scanned")
            live = live[:64]
        hosts = live
    if spec["domain"] and "." in spec["domain"]:
        say("Phase 1 — DNS & certificate transparency")
        check_dns(findings, spec["domain"], notes)
    if profile == "passive":
        notes.append("Passive profile: no connections were made to the target")
    else:
        ports = STD_PORTS if profile == "standard" else sorted(set(range(1, 1025)) | set(STD_PORTS))
        for ip in hosts:
            if stop and stop():
                stopped = True
                break
            disp = spec["hostname"] or ip
            say(f"Phase 2 — scanning {ip} ({len(ports)} ports)")
            open_ports = scan_ports(ip, ports, stop=stop)
            if not open_ports:
                notes.append(f"{ip}: no open ports in the scanned set (host down, filtered, or quiet)")
                continue
            nm = f" ({names[ip]})" if names.get(ip) else ""
            notes.append(f"{ip}{nm}: open ports — " + ", ".join(
                f"{p}/{SERVICE_NAMES.get(p, '?')}" for p in open_ports))
            banners = {}
            for p in open_ports:
                if p in WEB_PORTS:
                    continue
                banners[p] = grab_banner(ip, p)
                if banners[p]:
                    check_banner_rules(findings, banners[p], f"{ip}:{p}", ip, p)
            say(f"Phase 4 — service checks on {ip} ({len(open_ports)} open)")
            host_find_start = len(findings)
            for p in open_ports:
                asset = f"{ip}:{p}"
                if p == 21:
                    check_ftp(findings, ip, p, banners.get(p, ""))
                elif p == 23:
                    findings.append(Finding(
                        "medium", "Telnet service exposed (plaintext protocol)",
                        asset + " (Telnet)", "A Network", 5.3, "high",
                        f"Port 23 answers{(' with banner: ' + banners.get(p, '').splitlines()[0][:80]) if banners.get(p) else ''}. Telnet sends credentials unencrypted — exactly what CredLens captures.",
                        f"`telnet {ip} 23`",
                        "Logins can be passively sniffed by anyone on the path (see the CredLens wire view).",
                        "Disable Telnet; use SSH."))
                elif p == 1883:
                    check_mqtt(findings, ip, p)
                elif p == 6379:
                    check_redis(findings, ip, p)
                elif p == 9200:
                    check_elasticsearch(findings, ip, p, disp)
                elif p in DB_PORTS:
                    findings.append(Finding(
                        "medium", f"{DB_PORTS[p]} database service reachable on the network",
                        asset + f" ({DB_PORTS[p]})", "A Network", 5.3, "high",
                        f"Port {p} is open and reachable from this scanner"
                        + (f"; banner: {banners[p].splitlines()[0][:80]!r}" if banners.get(p) else "") + ".",
                        f"`nc {ip} {p}` or any DB client.",
                        "Database services exposed beyond application hosts invite brute force and exploitation of DB CVEs.",
                        f"Bind {DB_PORTS[p]} to application hosts / localhost only and firewall {p}."))
                elif p == 3389:
                    findings.append(Finding(
                        "low", "RDP service exposed", asset + " (RDP)", "A Network", 3.7, "high",
                        "Port 3389 is open and reachable from this scanner.",
                        f"`xfreerdp /v:{ip}` or any RDP client.",
                        "Exposed RDP is a top ransomware entry point (brute force, BlueKeep-class CVEs).",
                        "Put RDP behind a VPN/gateway; never expose it broadly."))
                elif p == 5900:
                    findings.append(Finding(
                        "low", "VNC service exposed", asset + " (VNC)", "A Network", 3.7, "high",
                        "Port 5900 is open and reachable from this scanner.",
                        f"Any VNC client to {ip}:5900.",
                        "VNC often has weak or no authentication and an unencrypted session.",
                        "Tunnel VNC over SSH/VPN or disable it."))
                if p in TLS_PORTS:
                    check_tls(findings, ip, p, profile)
                if p in WEB_PORTS:
                    check_web(findings, ip, p, disp, profile, stop=stop)
            check_snmp(findings, ip)
            notes.append(f"{ip}: service checks done ({len(findings) - host_find_start} finding(s) on this host)")

    # de-dupe by root cause (same title + asset), keep the first
    seen, uniq = set(), []
    for f in findings:
        if f.key() in seen:
            continue
        seen.add(f.key())
        uniq.append(f)
    uniq.sort(key=lambda f: (SEV_ORDER[f.sev], -f.cvss))
    return format_report(spec, profile, hosts, uniq, notes, stopped), {
        "assets": len(hosts), "findings": len(uniq),
        "counts": {s: sum(1 for f in uniq if f.sev == s) for s in SEV_ORDER}}


def format_report(spec, profile, hosts, findings, notes, stopped):
    counts = {s: sum(1 for f in findings if f.sev == s) for s in SEV_ORDER}
    if counts["critical"]:
        risk = "Critical — proven critical issues present; fix before anything else."
    elif counts["high"]:
        risk = "High — serious proven issues present."
    elif counts["medium"]:
        risk = "Medium — real weaknesses present; no criticals found in the tested scope."
    elif counts["low"]:
        risk = "Low — minor issues only, in the tested scope."
    else:
        risk = "No proven findings in the tested scope — see Coverage for what was and wasn't checked."
    date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    out = []
    out.append("SCAN REPORT")
    out.append(f"Target: {spec['label']}   Profile: {profile}   Date: {date}")
    out.append("")
    out.append("SUMMARY")
    out.append(f"- Assets scanned: {len(hosts)}")
    out.append(f"- Findings: {counts['critical']} critical, {counts['high']} high, "
               f"{counts['medium']} medium, {counts['low']} low")
    out.append(f"- Overall risk: {risk}")
    out.append("")
    out.append("FINDINGS")
    if not findings:
        out.append("")
        out.append("None — nothing in the tested scope produced a proven finding.")
    for i, f in enumerate(findings, 1):
        out.append("")
        out.append(f"[{f.sev.upper()}] #{i} — {f.title}")
        out.append(f"  Asset:      {f.asset}")
        out.append(f"  Category:   {f.category}")
        out.append(f"  CVSS:       {f.cvss}   Confidence: {f.confidence}")
        out.append(f"  Evidence:   {f.evidence}")
        out.append(f"  Repro:      {f.repro}")
        out.append(f"  Impact:     {f.impact}")
        out.append(f"  Fix:        {f.fix}")
    out.append("")
    out.append("COVERAGE")
    out.append("- Tested:")
    for n in notes:
        out.append(f"    * {n}")
    if stopped:
        out.append("    * Scan was stopped early — results are partial")
    out.append("- Skipped:")
    for sk in (
        "Password/default-credential guessing — not run (anonymous-access checks only, by policy)",
        "Denial-of-service tests (taxonomy N) — never run",
        "Host-internal checks (taxonomy B: patches, SUID, cron, local shares) — need an on-host agent",
        "Authenticated / credentialed scanning — no credentials supplied",
        "Business-logic, race and OTP tests (taxonomy K) — need application-specific interaction",
        "Wireless checks (taxonomy O) — out of scope for a network scan",
        "Deep web-app crawling and client-side JS analysis (taxonomy D depth / L) — use the Reconix web scanner",
        "UDP ports — only SNMP/161 probed",
    ):
        out.append(f"    * {sk}")
    out.append("- Why:      Scanner policy is non-destructive and proof-only; checks needing "
               "credentials, local access, or heavy traffic generation are excluded by design. "
               "Results reflect the scanner's network vantage point.")
    out.append("")
    out.append("TOP FIXES (do first)")
    if findings:
        done = []
        for f in findings:
            first = f.fix.split(". ")[0].rstrip(".") + "."
            if first not in done:
                done.append(first)
            if len(done) >= 5:
                break
        for i, t in enumerate(done, 1):
            out.append(f"{i}. {t}")
    else:
        out.append("1. No fixes required by this scan's findings — keep patching and re-scan regularly.")
    return "\n".join(out) + "\n"
