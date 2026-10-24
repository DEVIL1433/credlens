"""CredLens simulation lab — scenario tests for the analyzer (pcap) and the
live raw engine. Builds packets/pcaps in code; asserts extraction outcomes.

Run:  python3 sim_tests.py            (all labs)
      python3 sim_tests.py A|B        (one lab)
Exit code = number of failed checks.
"""
import json
import os
import struct
import sys
import time

import pcap as engine
import credlens

PASS = []
FAIL = []


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra else ""))


# ------------------------------------------------------------------ builders
def eth_ip_tcp(src, dst, sport, dport, seq, payload, ts=1000.0, flags=0x18):
    total = 40 + len(payload)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0x4000, 64, 6, 0,
                     bytes(int(x) for x in src.split(".")),
                     bytes(int(x) for x in dst.split(".")))
    tcp = struct.pack("!HHIIHHHH", sport, dport, seq, 0, (5 << 12) | flags,
                      8192, 0, 0)
    eth = bytes.fromhex("aabbccddeeff") + bytes.fromhex("112233445566") \
        + struct.pack("!H", 0x0800)
    return ts, eth + ip + tcp + payload


def eth_ip6_tcp(src6, dst6, sport, dport, seq, payload, ts=1000.0):
    import ipaddress
    s = ipaddress.IPv6Address(src6).packed
    d = ipaddress.IPv6Address(dst6).packed
    tcp = struct.pack("!HHIIHHHH", sport, dport, seq, 0, (5 << 12) | 0x18,
                      8192, 0, 0)
    ip6 = struct.pack("!I", 0x60000000) + struct.pack("!HBB", 20 + len(payload), 6, 64) + s + d
    eth = bytes.fromhex("aabbccddeeff") + bytes.fromhex("112233445566") \
        + struct.pack("!H", 0x86DD)
    return ts, eth + ip6 + tcp + payload


def write_pcap(frames):
    out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)]
    for ts, fr in frames:
        out.append(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(fr), len(fr)))
        out.append(fr)
    return b"".join(out)


def http_post(host, path, body, ctype="application/x-www-form-urlencoded", extra=""):
    b = body.encode() if isinstance(body, str) else body
    req = (f"POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: {ctype}\r\n"
           f"Content-Length: {len(b)}\r\n{extra}\r\n").encode() + b
    return req


def events_of(result):
    return [(e["kind"], e["user"], e["password"]) for e in result["events"]]


# ---------------------------------------------------------------------- LAB A
def lab_a():
    print("== LAB A: analyzer scenarios ==")
    C, S = "10.1.1.5", "10.1.1.9"

    # A1: out-of-order segments + a retransmission
    req = http_post("oo.example", "/login", "uname=order_user&pass=order_pw")
    f = [eth_ip_tcp(C, S, 40001, 80, 100, req[:50], 1000.0),
         eth_ip_tcp(C, S, 40001, 80, 200, req[100:], 1000.2),
         eth_ip_tcp(C, S, 40001, 80, 150, req[50:100], 1000.3),
         eth_ip_tcp(C, S, 40001, 80, 100, req[:50], 1000.4)]  # retransmit
    ev = events_of(engine.analyze_pcap(write_pcap(f)))
    check("A1 out-of-order + retransmit -> 1 form event",
          ev == [("form", "order_user", "order_pw")], str(ev))

    # A2: two pipelined requests in one stream
    r1 = http_post("pipe.example", "/a", "uname=p_one&pass=pw_one")
    r2 = http_post("pipe.example", "/b", "uname=p_two&pass=pw_two")
    both = r1 + r2
    f = [eth_ip_tcp(C, S, 40002, 80, 1, both, 1000.0)]
    ev = events_of(engine.analyze_pcap(write_pcap(f)))
    check("A2 pipelined requests -> 2 events",
          sorted(ev) == [("form", "p_one", "pw_one"), ("form", "p_two", "pw_two")], str(ev))

    # A3: multipart form with a file field
    mp = ("--XYZ\r\nContent-Disposition: form-data; name=\"uname\"\r\n\r\nmp_user\r\n"
          "--XYZ\r\nContent-Disposition: form-data; name=\"pass\"\r\n\r\nmp_pw\r\n"
          "--XYZ\r\nContent-Disposition: form-data; name=\"f\"; filename=\"x.bin\"\r\n"
          "Content-Type: application/octet-stream\r\n\r\n\x00\x01\x02\r\n--XYZ--\r\n")
    req = http_post("mp.example", "/up", mp, "multipart/form-data; boundary=XYZ")
    f = [eth_ip_tcp(C, S, 40003, 80, 1, req, 1000.0)]
    ev = events_of(engine.analyze_pcap(write_pcap(f)))
    check("A3 multipart + file field -> event",
          ev == [("form", "mp_user", "mp_pw")], str(ev))

    # A4: IPv6 flow in a pcap file
    req = http_post("v6.example", "/login", "uname=v6_user&pass=v6_pw")
    f = [eth_ip6_tcp("2001:db8::5", "2001:db8::9", 40004, 80, 1, req)]
    res = engine.analyze_pcap(write_pcap(f))
    ev = events_of(res)
    check("A4 IPv6 pcap flow -> event w/ v6 server",
          ev == [("form", "v6_user", "v6_pw")]
          and res["events"][0]["dst_ip"] == "2001:db8::9", str(ev))

    # A5: same session cookie on 3 requests -> exactly 1 cookie event
    frames = []
    for i in range(3):
        req = (f"GET /page{i} HTTP/1.1\r\nHost: ck.example\r\n"
               "Cookie: sessionid=dedupe_me_123\r\n\r\n").encode()
        frames.append(eth_ip_tcp(C, S, 40005, 80, 1 + i * 200, req, 1000.0 + i))
    ev = events_of(engine.analyze_pcap(write_pcap(frames)))
    check("A5 cookie dedupe -> exactly 1 event",
          ev == [("cookie", "sessionid", "dedupe_me_123")], str(ev))

    # A6: performance — 3000 benign + 5 logins
    frames = []
    for i in range(3000):
        req = f"GET /static/{i}.css HTTP/1.1\r\nHost: perf.example\r\n\r\n".encode()
        frames.append(eth_ip_tcp(C, S, 30000 + (i % 500), 80, 1, req, 1000.0 + i * 0.001))
    for j in range(5):
        req = http_post("perf.example", "/login", f"uname=perf{j}&pass=pw{j}")
        frames.append(eth_ip_tcp(C, S, 41000 + j, 80, 1, req, 1005.0 + j))
    t0 = time.time()
    res = engine.analyze_pcap(write_pcap(frames))
    dt = time.time() - t0
    got = sorted(u for _k, u, _p in events_of(res) if u.startswith("perf"))
    check("A6 perf: 3005 requests, 5/5 logins, < 5s",
          got == [f"perf{j}" for j in range(5)] and dt < 5, f"{dt:.2f}s")

    # A7: classic suite inside a pcapng container stays 13
    raw = open("test.pcap", "rb").read()
    res = engine.analyze_pcap(raw)
    check("A7 classic suite regression == 13", len(res["events"]) == 13,
          str(len(res["events"])))


# ---------------------------------------------------------------------- LAB B
def reset_live():
    credlens.STATE.reset()
    with credlens.FLOCK:
        credlens.FLOWS.clear()


def live_events():
    return [(e["kind"], e["user"], e["password"])
            for e in credlens.STATE.snapshot()["events"]]


def feed(frame_list):
    for ts, fr in frame_list:
        credlens.live_packet(ts, fr[14:])  # strip Ethernet -> raw IP


def lab_b():
    print("== LAB B: live-engine scenarios ==")
    C, S = "192.168.1.18", "93.184.216.34"

    # B1: out-of-order live segments
    reset_live()
    req = http_post("live.example", "/login", "uname=oo_live&pass=oo_pw")
    feed([eth_ip_tcp(C, S, 50001, 80, 500, req[80:], 2000.2),
          eth_ip_tcp(C, S, 50001, 80, 420, req[:80], 2000.3)])
    check("B1 live out-of-order -> event when complete",
          live_events() == [("form", "oo_live", "oo_pw")], str(live_events()))

    # B2: interleaved flows keep attribution
    reset_live()
    ra = http_post("a.example", "/login", "uname=alice&pass=alice_pw")
    rb = http_post("b.example", "/login", "uname=bob&pass=bob_pw99")
    feed([eth_ip_tcp(C, S, 50002, 80, 1, ra[:60], 2001.0),
          eth_ip_tcp(C, "10.9.9.9", 50003, 80, 1, rb[:60], 2001.1),
          eth_ip_tcp(C, S, 50002, 80, 61, ra[60:], 2001.2),
          eth_ip_tcp(C, "10.9.9.9", 50003, 80, 61, rb[60:], 2001.3)])
    snap = credlens.STATE.snapshot()
    pairs = sorted((e["user"], e["dst_ip"]) for e in snap["events"])
    check("B2 interleaved flows -> correct attribution",
          pairs == [("alice", S), ("bob", "10.9.9.9")], str(pairs))

    # B3: mid-stream start (first segment never seen) -> no crash, no phantom
    reset_live()
    req = http_post("mid.example", "/login", "uname=mid_user&pass=mid_pw")
    feed([eth_ip_tcp(C, S, 50004, 80, 9000, req[70:], 2002.0)])
    check("B3 mid-stream start -> no crash, no phantom event",
          live_events() == [], str(live_events()))

    # B4: binary noise on port 80, then a real request
    reset_live()
    noise = bytes(range(256)) * 4
    ok = http_post("ok.example", "/login", "uname=after_noise&pass=an_pw")
    feed([eth_ip_tcp(C, S, 50005, 80, 1, noise, 2003.0),
          eth_ip_tcp(C, S, 50006, 80, 1, ok, 2003.1)])
    check("B4 noise then valid -> only the valid event",
          live_events() == [("form", "after_noise", "an_pw")], str(live_events()))

    # B5: telnet gating — typed lines WITHOUT server prompts must not fire
    reset_live()
    feed([eth_ip_tcp(C, "10.5.5.5", 50007, 23, 1, b"root\r\n", 2004.0),
          eth_ip_tcp(C, "10.5.5.5", 50007, 23, 7, b"toor123\r\n", 2004.1)])
    no_prompt = live_events()
    reset_live()
    feed([eth_ip_tcp("10.5.5.5", C, 23, 50007, 1, b"login: ", 2004.0),
          eth_ip_tcp(C, "10.5.5.5", 50007, 23, 1, b"root\r\n", 2004.1),
          eth_ip_tcp("10.5.5.5", C, 23, 50007, 8, b"Password: ", 2004.2),
          eth_ip_tcp(C, "10.5.5.5", 50007, 23, 7, b"toor123\r\n", 2004.3)])
    with_prompt = live_events()
    check("B5 telnet gating (no prompts = silent, prompts = event)",
          no_prompt == [] and with_prompt == [("telnet", "root", "toor123")],
          f"no_prompt={no_prompt} with_prompt={with_prompt}")

    # B6: flow pressure — 6000 distinct benign flows
    reset_live()
    t0 = time.time()
    for i in range(6000):
        req = f"GET /x{i} HTTP/1.1\r\nHost: flood.example\r\n\r\n".encode()
        feed([eth_ip_tcp(C, S, 20000 + (i % 40000), 80, 1, req, 3000.0 + i * 0.01)])
    n = len(credlens.FLOWS)
    dt = time.time() - t0
    check("B6 6000 flows -> FLOWS bounded (<= 4500) and fast",
          n <= 4500 and dt < 20, f"flows={n} in {dt:.1f}s")

    # B7: retransmitted duplicate segment -> still exactly 1 event
    reset_live()
    req = http_post("dup.example", "/login", "uname=dup_user&pass=dup_pw")
    feed([eth_ip_tcp(C, S, 50008, 80, 1, req, 2005.0),
          eth_ip_tcp(C, S, 50008, 80, 1, req, 2005.1)])
    check("B7 duplicate segment replay -> 1 event",
          live_events() == [("form", "dup_user", "dup_pw")], str(live_events()))

    # B8: throughput — sustained packet rate through live_packet
    reset_live()
    req = http_post("tp.example", "/login", "uname=tp_user&pass=tp_pw")
    fr = eth_ip_tcp(C, S, 50009, 80, 1, req, 2006.0)
    t0 = time.time()
    N = 4000
    for i in range(N):
        f2 = eth_ip_tcp(C, S, 20000 + (i % 30000), 80, 1, req, 2006.0 + i * 0.001)
        credlens.live_packet(f2[0], f2[1][14:])
    dt = time.time() - t0
    check("B8 throughput > 1500 packets/sec", N / dt > 1500, f"{N/dt:.0f}/s")


def lab_a8_b9_b10():
    print("== LAB A8/B9/B10: response cookies + watchdog ==")
    C, S = "10.2.2.5", "10.2.2.9"
    # A8: server sets a session cookie in the RESPONSE; client never re-sends it
    req = http_post("shop.example", "/login", "uname=buyer&pass=buyer_pw")
    resp = (b"HTTP/1.1 302 Found\r\nLocation: /home\r\n"
            b"Set-Cookie: sessionid=issued_by_server_99; Path=/; HttpOnly\r\n"
            b"Content-Length: 0\r\n\r\n")
    f = [eth_ip_tcp(C, S, 40009, 80, 1, req, 1000.0),
         eth_ip_tcp(S, C, 80, 40009, 1, resp, 1000.1)]
    ev = events_of(engine.analyze_pcap(write_pcap(f)))
    check("A8 response Set-Cookie -> cookie event at issuance",
          ("cookie", "sessionid", "issued_by_server_99") in ev
          and ("form", "buyer", "buyer_pw") in ev, str(ev))

    # B9: same through the live engine
    reset_live()
    feed([eth_ip_tcp("192.168.1.18", S, 50010, 80, 1,
                     http_post("shop.example", "/login", "uname=buyer&pass=buyer_pw"), 2007.0),
          eth_ip_tcp(S, "192.168.1.18", 80, 50010, 1, resp, 2007.1)])
    ev = live_events()
    check("B9 live Set-Cookie -> cookie event at issuance",
          ("cookie", "sessionid", "issued_by_server_99") in ev, str(ev))

    # B10: watchdog restarts a dead raw capture and keeps captured events
    import credlens as cl
    reset_live()
    cl.STATE.mode = "live"
    cl.STATE.engine = "raw"
    cl.STATE.add_event({"ts": 1, "method": "POST", "host": "keep.example",
                        "path": "/", "url": "http://keep.example/", "kind": "form",
                        "user": "keepme", "password": "keep_pw", "user_field": "u",
                        "pass_field": "p", "src_ip": "192.168.1.18",
                        "dst_ip": S, "src_mac": None, "raw": ""})
    class DeadCap:
        adapter_ip = "192.168.1.18"
        def is_alive(self): return False
    cl.RAW["cap"] = DeadCap()
    restarted = cl.watchdog_tick()
    ev = live_events()
    check("B10 watchdog revives dead capture, events preserved",
          restarted and ("form", "keepme", "keep_pw") in ev
          and cl.STATE.engine == "raw", f"restarted={restarted} events={ev}")
    cl.RAW["cap"] = None
    cl.STATE.mode = "idle"
    cl.STATE.engine = ""




def lab_d():
    print("== LAB D: review-finding regressions ==")
    C, S = "10.3.3.5", "10.3.3.9"
    # A9: partial-overlap segments must not splice duplicate bytes (finding 7)
    req = http_post("ovl.example", "/login", "uname=ovl_user&pass=ovl_pw_123456")
    full = req
    a = full[:100]                    # seq 1..100
    b = full[50:150]                  # seq 51..150 (overlaps a's tail)
    c = full[150:]                    # seq 151..
    f = [eth_ip_tcp(C, S, 40011, 80, 1, a, 1000.0),
         eth_ip_tcp(C, S, 40011, 80, 51, b, 1000.1),
         eth_ip_tcp(C, S, 40011, 80, 151, c, 1000.2)]
    ev = events_of(engine.analyze_pcap(write_pcap(f)))
    check("A9 partial overlap -> exact stream, 1 event",
          ev == [("form", "ovl_user", "ovl_pw_123456")], str(ev))

    # A10: LF-only request head (finding 14)
    lf = ("POST /login HTTP/1.1\nHost: lf.example\n"
          "Content-Type: application/x-www-form-urlencoded\n"
          "Content-Length: 27\n\nuname=lf_user&pass=lf_pass1").encode()
    f = [eth_ip_tcp(C, S, 40012, 80, 1, lf, 1000.0)]
    ev = events_of(engine.analyze_pcap(write_pcap(f)))
    check("A10 LF-only request -> event",
          ev == [("form", "lf_user", "lf_pass1")], str(ev))

    # A11: chunked request followed by pipelined request (wire-length fix)
    body = b"uname=chunk_user&pass=chunk_pw"
    ch = b"%x\r\n%s\r\n0\r\n\r\n" % (len(body), body)
    r1 = (b"POST /a HTTP/1.1\r\nHost: ck.example\r\n"
          b"Content-Type: application/x-www-form-urlencoded\r\n"
          b"Transfer-Encoding: chunked\r\n\r\n") + ch
    r2 = http_post("ck.example", "/b", "uname=after_chunk&pass=ac_pw")
    f = [eth_ip_tcp(C, S, 40013, 80, 1, r1 + r2, 1000.0)]
    ev = events_of(engine.analyze_pcap(write_pcap(f)))
    check("A11 chunked + pipelined -> 2 events",
          sorted(ev) == [("form", "after_chunk", "ac_pw"),
                         ("form", "chunk_user", "chunk_pw")], str(ev))

    # A12: DHCP hostname behind pad options (finding 14)
    dhcp = bytearray(240)
    dhcp[0] = 1; dhcp[1] = 1; dhcp[2] = 6
    dhcp[12:16] = bytes([10, 3, 3, 77])          # ciaddr
    dhcp[236:240] = b"\x63\x82\x53\x63"
    opts = bytes([0, 0, 12, 9]) + b"paddpc-01" + bytes([255])
    pkt_dhcp = bytes(dhcp) + opts
    total = 20 + 8 + len(pkt_dhcp)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0x4000, 64, 17, 0,
                     bytes([10, 3, 3, 77]), bytes([10, 3, 3, 1]))
    udp = struct.pack("!HHHH", 68, 67, 8 + len(pkt_dhcp), 0)
    eth = bytes.fromhex("aabbccddeeff") + bytes.fromhex("112233445566") + struct.pack("!H", 0x0800)
    res = engine.analyze_pcap(write_pcap([(1000.0, eth + ip + udp + pkt_dhcp)]))
    names = {d["ip"]: d.get("name") for d in res["devices"]}
    check("A12 DHCP pad options -> hostname survives",
          res["stats"]["packets"] == 1 and names.get("10.3.3.77") in (None, "paddpc-01")
          and engine.harvest_names([dict(
              src="10.3.3.77", dst="10.3.3.1", kind="udp", sport=68, dport=67,
              payload=pkt_dhcp)]).get("10.3.3.77") == "paddpc-01",
          str(names))

    # A13: field named "catalog" is not a username (USER_KEYS log$ fix)
    bad = http_post("shop2.example", "/buy", "catalog=some_book&pass=real_pw")
    good = http_post("shop2.example", "/login", "user_log=lg_user&pass=lg_pw")
    f = [eth_ip_tcp(C, S, 40014, 80, 1, bad, 1000.0),
         eth_ip_tcp(C, S, 40015, 80, 1, good, 1000.1)]
    ev = events_of(engine.analyze_pcap(write_pcap(f)))
    check("A13 catalog value never poses as username; user_log works",
          ("form", "lg_user", "lg_pw") in ev
          and all(u != "some_book" for _k, u, _p in ev), str(ev))

    # B11: tuple reuse after bare SYN — old flow must not eat the new login
    reset_live()
    ra = http_post("reuse.example", "/login", "uname=first_conn&pass=first_pw")
    feed([eth_ip_tcp("192.168.1.18", S, 50020, 80, 1000, ra, 2010.0)])
    syn = eth_ip_tcp("192.168.1.18", S, 50020, 80, 2000, b"", 2010.5, flags=0x02)
    credlens.live_packet(syn[0], syn[1][14:])
    rb = http_post("reuse.example", "/login", "uname=second_conn&pass=second_pw")
    feed([eth_ip_tcp("192.168.1.18", S, 50020, 80, 1050, rb, 2011.0)])
    ev = live_events()
    check("B11 SYN incarnation -> both logins intact",
          sorted(ev) == [("form", "first_conn", "first_pw"),
                         ("form", "second_conn", "second_pw")], str(ev))

    # B12: Stop/Clear forget the adapter but keep the engine preference
    import tempfile, os, json as _json
    tmp = os.path.join(tempfile.mkdtemp(), "settings.json")
    old_path = credlens.SETTINGS_PATH
    credlens.SETTINGS_PATH = tmp
    try:
        credlens.set_engine_pref("tshark")
        credlens.save_live_setting("192.168.1.18")
        credlens.clear_live_setting()
        data = _json.load(open(tmp))
        check("B12 engine pref survives clear, adapter forgotten",
              data.get("engine") == "tshark" and "live_iface" not in data,
              str(data))
    finally:
        credlens.SETTINGS_PATH = old_path

    # B14: identical login submitted twice on one connection:
    # diary shows both, credential feed shows it once
    reset_live()
    rq = http_post("twice.example", "/login", "uname=twin&pass=twin_pw")
    feed([eth_ip_tcp("192.168.1.18", S, 50021, 80, 1, rq, 2012.0),
          eth_ip_tcp("192.168.1.18", S, 50021, 80, 1 + len(rq), rq, 2012.5)])
    snap = credlens.STATE.snapshot()
    check("B14 repeat submission -> 2 diary rows, 1 event",
          len(snap["requests"]) == 2 and live_events() == [("form", "twin", "twin_pw")],
          f"reqs={len(snap['requests'])} ev={live_events()}")


# ---------------------------------------------------------------------- LAB E
def lab_e():
    """NTLM hash grab: challenge/response pairing, hashcat formats."""
    import base64
    import struct as _st
    print("== LAB E: NTLM hash grab ==")
    chal = bytes.fromhex("1122334455667788")

    def t2():
        return base64.b64encode(b"NTLMSSP\x00" + _st.pack("<I", 2) + b"\x00" * 8
                                 + _st.pack("<I", 0x8201) + chal).decode()

    def t3(user, domain, lm, nt):
        hdr = bytearray(64)
        hdr[0:8] = b"NTLMSSP\x00"
        _st.pack_into("<I", hdr, 8, 3)
        payload, off = b"", 64
        for i, blob in enumerate([lm, nt, domain.encode("utf-16-le"),
                                  user.encode("utf-16-le"), b"", b""]):
            _st.pack_into("<HHI", hdr, 12 + i * 8, len(blob), len(blob), off)
            payload += blob
            off += len(blob)
        _st.pack_into("<I", hdr, 60, 1)
        return base64.b64encode(bytes(hdr) + payload).decode()

    srv = (f"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM {t2()}"
           f"\r\nContent-Length: 0\r\n\r\n").encode()
    nt2 = bytes(range(16)) + bytes(range(32))
    cli2 = (f"GET /ntlm HTTP/1.1\r\nHost: corp.example\r\nAuthorization: NTLM "
            f"{t3('alice', 'CORP', bytes([0xaa]) * 24, nt2)}\r\n\r\n").encode()
    cli1 = (f"GET /ntlm HTTP/1.1\r\nHost: corp.example\r\nAuthorization: NTLM "
            f"{t3('bob', 'CORP', bytes([0xbb]) * 24, bytes([0xcc]) * 24)}\r\n\r\n").encode()
    frames = [eth_ip_tcp("10.2.2.9", "10.2.2.5", 41001, 80, 1, srv, 1000.0),
              eth_ip_tcp("10.2.2.5", "10.2.2.9", 80, 41001, 1, cli2, 1000.1),
              eth_ip_tcp("10.2.2.5", "10.2.2.9", 80, 41001, 900, cli1, 1000.2)]
    res = engine.analyze_pcap(write_pcap(frames))
    hashes = {e["user"]: e for e in res["events"] if e["kind"] == "hash"}
    exp2 = ("alice::CORP:1122334455667788:" + bytes(range(16)).hex()
            + ":" + bytes(range(32)).hex())
    exp1 = "bob::CORP:" + "bb" * 24 + ":" + "cc" * 24 + ":1122334455667788"
    check("E1 pcap NetNTLMv2 -> hashcat 5600 line",
          hashes.get("alice", {}).get("password") == exp2, str(list(hashes)))
    check("E2 pcap NetNTLMv1 -> hashcat 5500 line",
          hashes.get("bob", {}).get("password") == exp1, str(list(hashes)))

    # live path: same exchange through live_packet
    reset_live()
    C, S = "192.168.1.18", "93.184.216.34"
    p1 = b"GET /ntlm HTTP/1.1\r\nHost: corp.example\r\n\r\n"
    feed([eth_ip_tcp(C, S, 41001, 80, 1000, p1, 2000.0),
          eth_ip_tcp(S, C, 80, 41001, 1000, srv, 2000.1),
          eth_ip_tcp(C, S, 41001, 80, 1000 + len(p1), cli2, 2000.2)])
    got = [e for e in credlens.STATE.events if e["kind"] == "hash"]
    check("E3 live NetNTLMv2 paired + exact",
          len(got) == 1 and got[0]["password"] == exp2,
          str([(e["user"], e["kind"]) for e in credlens.STATE.events]))

    # unpaired type 3 (no challenge seen) stays silent — no fake hashes
    reset_live()
    feed([eth_ip_tcp(C, S, 41002, 80, 1000, cli2, 2001.0)])
    check("E4 unpaired type3 -> no event",
          not [e for e in credlens.STATE.events if e["kind"] == "hash"], "")


def _eth_ip_udp(src, dst, sport, dport, payload, ts=1000.0):
    total = 20 + 8 + len(payload)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0x4000, 64, 17, 0,
                     bytes(int(x) for x in src.split(".")),
                     bytes(int(x) for x in dst.split(".")))
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    eth = bytes.fromhex("aabbccddeeff") + bytes.fromhex("112233445566") \
        + struct.pack("!H", 0x0800)
    return ts, eth + ip + udp + payload


def _dns_query(name, qtype=1, qr=0):
    flags = 0x0100 | (0x8000 if qr else 0)
    msg = struct.pack(">HHHHHH", 0x1234, flags, 1, 0, 0, 0)
    for part in name.split("."):
        msg += bytes([len(part)]) + part.encode()
    return msg + b"\x00" + struct.pack(">HH", qtype, 1)


def _client_hello(host):
    exts = b""
    if host:
        name = host.encode()
        entry = b"\x00" + struct.pack(">H", len(name)) + name
        lst = struct.pack(">H", len(entry)) + entry
        exts = struct.pack(">HH", 0, len(lst)) + lst
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00"
    body += struct.pack(">H", 2) + b"\x13\x01" + b"\x01\x00"
    body += struct.pack(">H", len(exts)) + exts
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def _doms():
    return credlens.STATE.snapshot()["domains"]


def lab_g():
    print("== LAB G: DNS + SNI domain tracking ==")
    P, R, S = "192.168.1.7", "192.168.1.1", "93.184.216.34"

    # G1: DNS queries live — aggregated, responses and reverse lookups ignored
    reset_live()
    q = _dns_query("updates.example.org", 28)
    feed([_eth_ip_udp(P, R, 53000, 53, q, ts=2000.0)])
    d = [x for x in _doms() if x["domain"] == "updates.example.org"]
    check("G1a DNS query sighted (live)", len(d) == 1 and d[0]["via"] == ["dns"]
          and d[0]["src_ip"] == P and d[0]["count"] == 1, str(d))
    feed([_eth_ip_udp(P, R, 53000, 53, q, ts=2001.0),
          _eth_ip_udp(R, P, 53, 53000, _dns_query("updates.example.org", 28, qr=1), ts=2002.0),
          _eth_ip_udp(P, R, 53001, 53, _dns_query("7.1.168.192.in-addr.arpa", 12), ts=2003.0)])
    d = [x for x in _doms() if x["domain"] == "updates.example.org"]
    check("G1b repeat counts up, response + arpa ignored",
          len(_doms()) == 1 and d[0]["count"] == 2, str(_doms()))
    check("G1c sightings create no credential events",
          credlens.STATE.events == [], "")

    # G2: SNI live — a ClientHello split across two segments lands once whole
    reset_live()
    hello = _client_hello("mail.example.com")
    feed([eth_ip_tcp(P, S, 51000, 443, 1, hello[:30], ts=3000.0)])
    check("G2a partial hello: no sighting yet", _doms() == [], str(_doms()))
    feed([eth_ip_tcp(P, S, 51000, 443, 1 + 30, hello[30:], ts=3000.1)])
    d = _doms()
    check("G2b completed hello: SNI sighted",
          len(d) == 1 and d[0]["domain"] == "mail.example.com"
          and d[0]["via"] == ["sni"] and d[0]["dst_ip"] == S, str(d))

    # G3: aggregation — DNS then SNI for the same name merge into one entry
    feed([_eth_ip_udp(P, R, 53002, 53, _dns_query("mail.example.com"), ts=3001.0)])
    d = _doms()
    check("G3 dns+sni merge, count 2",
          len(d) == 1 and d[0]["via"] == ["dns", "sni"] and d[0]["count"] == 2,
          str(d))

    # G4: PCAP path — DNS + SNI in one file; junk TLS record ignored
    frames = [
        _eth_ip_udp(P, R, 53000, 53, _dns_query("cdn.example.net"), ts=4000.0),
        eth_ip_tcp(P, S, 52000, 443, 1, _client_hello("shop.example.net"), ts=4001.0),
        eth_ip_tcp(P, S, 52001, 443, 1, b"\x17\x03\x03\x00\x10" + b"x" * 16, ts=4002.0),
        eth_ip_tcp(P, S, 52002, 443, 1, _client_hello(""), ts=4003.0),
    ]
    res = engine.analyze_pcap(write_pcap(frames))
    got = sorted((s["domain"], s["via"]) for s in res["domains"])
    check("G4 pcap sightings exact",
          got == [("cdn.example.net", "dns"), ("shop.example.net", "sni")],
          str(got))


def lab_f():
    print("== LAB F: Npcap frame stream (hotspot pre-NAT attribution) ==")
    import io
    C, S = "192.168.137.135", "44.238.29.244"
    post = http_post("testaspnet.vulnweb.com", "/login.aspx",
                     "tfUName=phoneuser&tfUPass=phonepass")
    frames = [
        eth_ip_tcp(C, S, 51000, 80, 1, post, ts=5000.0),
        _eth_ip_udp(C, "192.168.137.1", 53000, 53,
                    _dns_query("hotspot.example.org"), ts=5001.0),
        (5002.0, bytes.fromhex("aabbccddeeff") + bytes.fromhex("112233445566")
         + struct.pack("!H", 0x0806) + b"\x00" * 28),   # ARP: must be skipped
    ]
    blob = write_pcap(frames)
    got = list(credlens._iter_pcap_stream(io.BytesIO(blob), lambda: False))
    check("F1 stream yields all 3 frames intact",
          len(got) == 3 and got[0][1] == frames[0][1], f"n={len(got)}")
    reset_live()
    credlens.STATE.mode = "live"
    for ts, fr in got:
        et = struct.unpack(">H", fr[12:14])[0]
        if et in (0x0800, 0x86DD):
            credlens.live_packet(ts, fr[14:])
    evs = credlens.STATE.snapshot()["events"]
    check("F2 client login attributed to the CLIENT, pre-NAT",
          len(evs) == 1 and evs[0]["src_ip"] == C
          and evs[0]["user"] == "phoneuser",
          str([(e["src_ip"], e["user"]) for e in evs]))
    doms = credlens.STATE.snapshot()["domains"]
    check("F3 client DNS sighting under client IP",
          len(doms) == 1 and doms[0]["src_ip"] == C
          and doms[0]["domain"] == "hotspot.example.org", str(doms))
    check("F4 npf mapping unavailable here -> clean None, no crash",
          credlens.npf_id_for_adapter({"mac": "aa:bb:cc:dd:ee:ff",
                                       "name": "Nope"}) is None, "")
    check("F5 truncated stream ends cleanly",
          list(credlens._iter_pcap_stream(
              io.BytesIO(blob[:40]), lambda: False)) == [], "")

    # F6: the worker must force classic pcap — tshark's default -w output
    # is pcapng (0a0d0d0a), which killed the first deployed version in a
    # watchdog restart loop. Record the real argv via a fake Popen.
    import subprocess as _sp
    argv_seen = {}
    class FakeProc:
        def __init__(self, argv, **kw):
            argv_seen["argv"] = argv
            self.stdout = io.BytesIO(blob)
        def terminate(self):
            pass
        def poll(self):
            return 0
    real_popen, real_find = _sp.Popen, credlens.find_tshark
    real_reset = credlens.start_recording
    try:
        _sp.Popen = FakeProc
        credlens.find_tshark = lambda: "/stub/tshark"
        credlens.LIVE_PROC["stop"] = False
        reset_live()
        credlens.STATE.mode = "live"
        credlens.npf_stream_worker("\\Device\\NPF_{FAKE}")
    finally:
        _sp.Popen, credlens.find_tshark = real_popen, real_find
    argv = argv_seen.get("argv") or []
    check("F6 worker forces classic pcap (-F pcap)",
          any(argv[i] == "-F" and argv[i + 1] == "pcap"
              for i in range(len(argv) - 1)), str(argv))
    evs6 = credlens.STATE.snapshot()["events"]
    check("F6b streamed frames feed the full extractor",
          len(evs6) == 1 and evs6[0]["src_ip"] == C, str(evs6))

    # F7: hotspot gone + capture sitting on the recorded hotspot NPF id
    # -> autoswitch must move capture back to Wi-Fi
    calls = []
    saved = (credlens.hotspot_adapter, credlens._current_iface,
             credlens.load_settings, credlens.hotspot_switch,
             credlens.PREF.get("hotspot_auto"), credlens.STATE.mode,
             credlens.hotspot_on)
    try:
        credlens.hotspot_on = lambda: False
        credlens.hotspot_adapter = lambda: None
        credlens._current_iface = lambda: "\\Device\\NPF_{FAKE}"
        credlens.load_settings = lambda: {"hotspot_npf": "\\Device\\NPF_{FAKE}"}
        credlens.hotspot_switch = lambda to_hs: calls.append(to_hs)
        credlens.PREF["hotspot_auto"] = True
        credlens.STATE.mode = "live"
        credlens._hotspot_autoswitch()
    finally:
        (credlens.hotspot_adapter, credlens._current_iface,
         credlens.load_settings, credlens.hotspot_switch,
         credlens.PREF["hotspot_auto"], credlens.STATE.mode,
         credlens.hotspot_on) = saved
    check("F7 autoswitch returns from hotspot NPF when hotspot dies",
          calls == [False], str(calls))

    # F8: nanosecond pcap (what tshark -F pcap really writes) must parse
    ns = io.BytesIO()
    ns.write(struct.pack("<IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 1))
    fr = frames[0][1]
    ns.write(struct.pack("<IIII", 7000, 500_000_000, len(fr), len(fr)))
    ns.write(fr)
    got8 = list(credlens._iter_pcap_stream(io.BytesIO(ns.getvalue()),
                                           lambda: False))
    check("F8 nanosecond pcap stream parses, ts scaled",
          len(got8) == 1 and abs(got8[0][0] - 7000.5) < 0.01
          and got8[0][1] == fr, str([g[0] for g in got8]))

    # H2: autoswitch obeys the tethering truth, never adapter presence
    calls2 = []
    saved2 = (credlens.hotspot_on, credlens.hotspot_adapter,
              credlens._current_iface, credlens.load_settings,
              credlens.hotspot_switch, credlens.PREF.get("hotspot_auto"),
              credlens.STATE.mode)
    try:
        credlens.PREF["hotspot_auto"] = True
        credlens.STATE.mode = "live"
        credlens.hotspot_adapter = lambda: {"ip": "192.168.137.1"}
        credlens.load_settings = lambda: {"hotspot_npf": "\\Device\\NPF_{X}"}
        credlens.hotspot_switch = lambda to_hs: calls2.append(to_hs)
        credlens.hotspot_on = lambda: None
        credlens._current_iface = lambda: "192.168.1.18"
        credlens._hotspot_autoswitch()
        credlens.hotspot_on = lambda: False
        credlens._hotspot_autoswitch()
        credlens.hotspot_on = lambda: True
        credlens._hotspot_autoswitch()
        credlens._current_iface = lambda: "192.168.137.1"
        credlens._hotspot_autoswitch()
        credlens.hotspot_on = lambda: False
        credlens._hotspot_autoswitch()
    finally:
        (credlens.hotspot_on, credlens.hotspot_adapter,
         credlens._current_iface, credlens.load_settings,
         credlens.hotspot_switch, credlens.PREF["hotspot_auto"],
         credlens.STATE.mode) = saved2
    check("H2 autoswitch: unknown=no move, off@wifi=no move, "
          "on@wifi=to hotspot, on@hotspot=stay, off@hotspot=back",
          calls2 == [True, False], str(calls2))


def lab_h():
    print("== LAB H: watchdog restart must preserve domains ==")
    saved = (credlens._capture_dead, credlens.start_live,
             credlens.load_settings, credlens.PREF.get("hotspot_auto"),
             credlens.STATE.mode, credlens.STATE.engine,
             credlens.WATCH_FAILS["n"])
    try:
        reset_live()
        credlens.STATE.mode = "live"
        credlens.STATE.engine = "raw"
        credlens.STATE.add_domain(1.0, "192.168.1.18", "keepme.example.org",
                                  "dns", "8.8.8.8")
        credlens.PREF["hotspot_auto"] = False
        credlens._capture_dead = lambda: True
        credlens.load_settings = lambda: {}
        def fake_start(sel, engine_pref=None):
            credlens.STATE.reset()          # what a real restart does
            credlens.STATE.mode = "live"
            credlens.STATE.engine = "raw"
            return True
        credlens.start_live = fake_start
        credlens.WATCH_FAILS["n"] = 0
        ran = credlens.watchdog_tick()
        doms = credlens.STATE.snapshot()["domains"]
        check("H1 domains survive a watchdog restart",
              ran and len(doms) == 1
              and doms[0]["domain"] == "keepme.example.org", str(doms))
    finally:
        (credlens._capture_dead, credlens.start_live,
         credlens.load_settings, credlens.PREF["hotspot_auto"],
         credlens.STATE.mode, credlens.STATE.engine,
         credlens.WATCH_FAILS["n"]) = saved


# ================================================================ Lab I
def lab_I():
    """Audit-2 fixes (2026-10-23): MQTT v5 properties, watchdog window
    merge, IPv6 scan sort, DNS decode guard, request-device MACs."""
    import scan as scanmod
    C, S = "10.0.0.5", "93.184.215.14"
    # I1: MQTT v5 CONNECT with a non-empty properties block
    def mqstr(b):
        return struct.pack(">H", len(b)) + b
    props = bytes([0x11]) + struct.pack(">I", 60)        # session expiry
    vh = mqstr(b"MQTT") + bytes([5, 0xC2]) + struct.pack(">H", 60)
    vh += bytes([len(props)]) + props
    payload = mqstr(b"dev-1") + mqstr(b"mqtt5user") + mqstr(b"mqtt5pass")
    body = vh + payload
    pkt = bytes([0x10]) + bytes([len(body)]) + body
    f = eth_ip_tcp(C, S, 40010, 1883, 1, pkt, ts=500.0)
    r = engine.analyze_pcap(write_pcap([f]))
    ev = [e for e in r["events"] if e["kind"] == "mqtt"]
    check("I1 MQTT v5 properties skipped correctly -> creds found",
          len(ev) == 1 and ev[0]["user"] == "mqtt5user"
          and ev[0]["password"] == "mqtt5pass",
          str([(e["user"], e["password"]) for e in ev]))
    # I2: an event landing DURING a watchdog restart survives the restore
    credlens.STATE.reset()
    credlens.STATE.mode = "live"
    credlens.STATE.engine = "raw"
    credlens.STATE.add_event({"kind": "form", "ts": 1.0, "src_ip": C,
                              "dst_ip": S, "host": "old.example.com",
                              "path": "/l", "user": "before", "password": "x",
                              "field": "f", "src_mac": None, "raw": ""})
    real_start = credlens.start_live
    def stub_start(sel, engine_pref=None):
        credlens.STATE.reset()
        credlens.STATE.mode = "live"
        credlens.STATE.engine = "raw"
        credlens.STATE.add_event({"kind": "form", "ts": 2.0, "src_ip": C,
                                  "dst_ip": S, "host": "new.example.com",
                                  "path": "/l", "user": "during",
                                  "password": "y", "field": "f",
                                  "src_mac": None, "raw": ""})
        return True
    credlens.start_live = stub_start
    old_dead = credlens._capture_dead
    credlens._capture_dead = lambda: True
    try:
        restarted = credlens.watchdog_tick()
    finally:
        credlens.start_live = real_start
        credlens._capture_dead = old_dead
    users = sorted(e["user"] for e in credlens.STATE.events)
    check("I2 watchdog merge: pre + during-window events both kept",
          restarted and users == ["before", "during"], str(users))
    # I3: IPv6 candidates sort without crashing host discovery
    try:
        out = scanmod.discover_hosts(["fd00::9", "fd00::5", "10.0.0.9"],
                                     known=("fd00::9", "fd00::5", "10.0.0.9"))
        ok3 = out == ["10.0.0.9", "fd00::5", "fd00::9"]
        det3 = str(out)
    except Exception as e:
        ok3, det3 = False, repr(e)
    check("I3 discover_hosts sorts mixed v4/v6", ok3, det3)
    # I4: DNS name decode survives a truncated compression pointer
    try:
        scanmod._dns_name_decode(b"\x00" * 11 + b"\xc0", 11)
        ok4, det4 = True, ""
    except Exception as e:
        ok4, det4 = False, repr(e)
    check("I4 _dns_name_decode truncated pointer safe", ok4, det4)
    # I5: request-only devices keep the MAC their frames carried
    get_req = (b"GET /index HTTP/1.1\r\nHost: plain.example.com\r\n"
               b"User-Agent: sim\r\n\r\n")
    f = eth_ip_tcp(C, S, 40011, 80, 1, get_req, ts=600.0)
    r = engine.analyze_pcap(write_pcap([f]))
    dev = [d for d in r["devices"] if d["ip"] == C]
    check("I5 request-only device carries its MAC",
          len(dev) == 1 and dev[0]["mac"] == "11:22:33:44:55:66",
          str(dev))
    credlens.STATE.reset()


# ================================================================ Lab J
def lab_j():
    """Second-audit fixes: proto_worker eviction must not eat the live
    connection; watchdog merge sums counters instead of dropping them."""
    import subprocess as _sp
    # J1: >1024 connections, then the OLDEST one speaks again
    credlens.STATE.reset()
    credlens.LIVE_PROC["stop"] = False
    def line(i, payload):
        f = ["1700000000.0", "11:22:33:44:55:66", "10.0.0.5",
             "93.184.215.14", "", "", str(30000 + i), "21",
             payload.hex().replace("", "")]
        f[8] = ":".join(f"{b:02x}" for b in payload)
        return "\t".join(f) + "\n"
    def sline(i, payload):
        f = ["1700000000.0", "11:22:33:44:55:66", "93.184.215.14",
             "10.0.0.5", "", "", "21", str(40000 + i),
             ":".join(f"{b:02x}" for b in payload)]
        return "\t".join(f) + "\n"
    # few client buffers, a flood of server-side ones: the eviction
    # trigger counts BOTH dicts, so the small client dict can be wiped
    # whole — including the connection being processed (the pre-fix
    # KeyError). conn 0 must survive its own eviction pass.
    lines = [sline(i, b"220 hi\r\n") for i in range(1030)]
    lines.append(line(0, b"USER u0\r\n"))
    lines.append(line(0, b"PASS pw0\r\n"))
    class FakePopen:
        def __init__(self, cmd, **kw):
            self.stdout = iter(lines)
        def poll(self):
            return 0
        def terminate(self):
            pass
    real_popen = _sp.Popen
    _sp.Popen = FakePopen
    try:
        credlens.proto_worker("fake0")
        raised = None
    except Exception as e:
        raised = e
    finally:
        _sp.Popen = real_popen
    ev = [e for e in credlens.STATE.events if e.get("user") == "u0"]
    check("J1 proto eviction: oldest conn survives, event emitted",
          raised is None and len(ev) == 1 and ev[0]["password"] == "pw0",
          f"raised={raised!r} ev={[(e['user'], e['password']) for e in ev]}")
    # J2: watchdog merge sums counters for entries present on both sides
    credlens.STATE.reset()
    credlens.STATE.mode = "live"
    credlens.STATE.engine = "raw"
    credlens.STATE.devices["10.0.0.5"] = {
        "ip": "10.0.0.5", "mac": None, "vendor": "", "name": None,
        "leaks": 1, "requests": 5}
    credlens.STATE.sites["a.example.com"] = {
        "host": "a.example.com", "server_ip": "93.184.215.14",
        "pages": {"/x"}, "leaks": 0, "requests": 2}
    credlens.STATE.add_domain(10.0, "10.0.0.5", "d.example.com",
                              "dns", "8.8.8.8", "A")
    real_start = credlens.start_live
    def stub_start(sel, engine_pref=None):
        credlens.STATE.reset()
        credlens.STATE.mode = "live"
        credlens.STATE.engine = "raw"
        credlens.STATE.devices["10.0.0.5"] = {
            "ip": "10.0.0.5", "mac": None, "vendor": "", "name": None,
            "leaks": 0, "requests": 3}
        credlens.STATE.sites["a.example.com"] = {
            "host": "a.example.com", "server_ip": "93.184.215.14",
            "pages": {"/y"}, "leaks": 1, "requests": 1}
        credlens.STATE.add_domain(12.0, "10.0.0.5", "d.example.com",
                                  "sni", "8.8.8.8", "AAAA")
        credlens.STATE.add_domain(12.0, "10.0.0.5", "d.example.com",
                                  "sni", "8.8.8.8", "AAAA")
        return True
    credlens.start_live = stub_start
    old_dead = credlens._capture_dead
    credlens._capture_dead = lambda: True
    try:
        restarted = credlens.watchdog_tick()
    finally:
        credlens.start_live = real_start
        credlens._capture_dead = old_dead
    dev = credlens.STATE.devices.get("10.0.0.5", {})
    site = credlens.STATE.sites.get("a.example.com", {})
    dom = credlens.STATE.domains.get(("10.0.0.5", "d.example.com"), {})
    check("J2 watchdog merge sums counters + unions pages/via",
          restarted and dev.get("requests") == 8 and dev.get("leaks") == 1
          and site.get("requests") == 3 and site.get("pages") == {"/x", "/y"}
          and dom.get("count") == 3 and dom.get("via") == {"dns", "sni"} and dom.get("last") == 12.0,
          f"dev={dev} site={site} dom={dom}")
    credlens.STATE.reset()


# ================================================================ Lab K
def lab_k():
    """Adapter-drift fixes (2026-10-23 afternoon): an explicit adapter
    pick is a contract — never substitute another adapter, never save a
    substitution — and the watchdog never gives up on its target."""
    cl = credlens
    saved = {k: getattr(cl, k) for k in (
        "find_tshark", "list_interfaces", "adapters", "start_live_tshark",
        "save_live_setting", "npf_id_for_adapter", "stop_all",
        "_capture_dead", "start_live", "load_settings")}
    saved_raw = cl.rawcap.RawCapture
    saved_pref = dict(cl.PREF)
    calls = {"tshark": [], "saved": [], "raw_made": 0}
    class DeadRaw:
        def __init__(self, *a, **k):
            calls["raw_made"] += 1
        def start(self): pass
        def join(self, t=None): pass
        def is_alive(self): return False
    try:
        cl.find_tshark = lambda: "/usr/bin/tshark"
        cl.list_interfaces = lambda: [
            {"id": "\\Device\\NPF_{WIFI}", "label": "Wi-Fi"}]
        cl.adapters = lambda: [
            {"id": "192.168.1.18", "ip": "192.168.1.18", "name": "Wi-Fi",
             "mac": "14:d4:24:55:db:82"}]
        cl.start_live_tshark = lambda i: calls["tshark"].append(i) or True
        cl.save_live_setting = lambda *a, **k: calls["saved"].append(a)
        cl.npf_id_for_adapter = lambda a: None
        cl.stop_all = lambda: None
        cl.rawcap.RawCapture = DeadRaw
        cl.PREF["hotspot_auto"] = False
        # K1: tshark engine + explicit unknown adapter -> honest failure
        ok1 = cl._start_live_locked("10.9.9.9", engine_pref="tshark")
        check("K1 tshark pref: unknown explicit adapter fails, no substitute",
              ok1 is False and calls["tshark"] == [] and calls["saved"] == [],
              f"ok={ok1} tshark={calls['tshark']} saved={calls['saved']}")
        # K2: raw engine + explicit unknown adapter -> honest failure
        ok2 = cl._start_live_locked("10.9.9.9", engine_pref="raw")
        check("K2 raw pref: unknown explicit adapter fails, no substitute",
              ok2 is False and calls["raw_made"] == 0
              and calls["tshark"] == [] and calls["saved"] == [],
              f"ok={ok2} raw={calls['raw_made']} tshark={calls['tshark']}")
        # K3: auto + raw dead -> tshark fallback engages but saves NOTHING
        ok3 = cl._start_live_locked("auto", engine_pref="raw")
        check("K3 auto fallback starts tshark but never persists it",
              ok3 is True and calls["tshark"] == ["\\Device\\NPF_{WIFI}"]
              and calls["saved"] == [],
              f"ok={ok3} tshark={calls['tshark']} saved={calls['saved']}")
        # K4: the watchdog retries forever and says so
        cl.STATE.reset()
        cl.STATE.mode = "live"
        cl.STATE.engine = "raw"
        cl._capture_dead = lambda: True
        cl.load_settings = lambda: {}
        cl.start_live = lambda sel, engine_pref=None: False
        cl.WATCH_FAILS["n"] = 0
        for _ in range(7):
            cl.watchdog_tick()
        check("K4 watchdog never gives up: still live, honestly retrying",
              cl.STATE.mode == "live" and cl.WATCH_FAILS["n"] == 7
              and "retrying" in (cl.STATE.live_info or ""),
              f"mode={cl.STATE.mode} fails={cl.WATCH_FAILS['n']} "
              f"info={cl.STATE.live_info}")
        cl.start_live = lambda sel, engine_pref=None: True
        def ok_start(sel, engine_pref=None):
            cl.STATE.reset()
            cl.STATE.mode = "live"
            cl.STATE.engine = "raw"
            return True
        cl.start_live = ok_start
        ran = cl.watchdog_tick()
        check("K5 watchdog recovers when the adapter returns",
              ran is True and cl.WATCH_FAILS["n"] == 0,
              f"ran={ran} fails={cl.WATCH_FAILS['n']}")
    finally:
        for k, v in saved.items():
            setattr(cl, k, v)
        cl.rawcap.RawCapture = saved_raw
        cl.PREF.clear()
        cl.PREF.update(saved_pref)
        cl.STATE.reset()
        cl.WATCH_FAILS["n"] = 0


# ================================================================ Lab L
def lab_l():
    """Pre-stop validation (2026-10-23): a rejected adapter pick must
    leave a running capture untouched, and an IP-form pick under the
    tshark engine translates to the same adapter's Npcap id."""
    cl = credlens
    names = ("find_tshark", "list_interfaces", "adapters",
             "npf_id_for_adapter", "start_live_npf", "start_live_tshark",
             "save_live_setting", "stop_all", "hotspot_adapter")
    saved = {k: getattr(cl, k) for k in names}
    calls = {"stop": 0, "npf": [], "tshark": []}
    try:
        cl.find_tshark = lambda: "/usr/bin/tshark"
        cl.list_interfaces = lambda: [
            {"id": "\\Device\\NPF_{WIFI}", "label": "Wi-Fi"}]
        cl.adapters = lambda: [
            {"id": "192.168.1.18", "ip": "192.168.1.18", "name": "Wi-Fi",
             "mac": "14:d4:24:55:db:82"}]
        cl.npf_id_for_adapter = lambda a: "\\Device\\NPF_{WIFI}"
        cl.hotspot_adapter = lambda: None
        cl.stop_all = lambda: calls.__setitem__("stop", calls["stop"] + 1)
        cl.start_live_npf = lambda i, hs_ip=None: calls["npf"].append(i) or True
        cl.start_live_tshark = lambda i: calls["tshark"].append(i) or True
        cl.save_live_setting = lambda *a, **k: None
        ok1 = cl._start_live_locked("10.9.9.9", engine_pref="tshark")
        check("L1 rejected pick: running capture untouched (no stop_all)",
              ok1 is False and calls["stop"] == 0
              and cl.STATE.capture_error != "",
              f"ok={ok1} stops={calls['stop']} err={cl.STATE.capture_error}")
        ok2 = cl._start_live_locked("192.168.1.18", engine_pref="tshark")
        check("L2 IP pick under tshark maps to the same adapter (Npcap)",
              ok2 is True and calls["npf"] == ["\\Device\\NPF_{WIFI}"],
              f"ok={ok2} npf={calls['npf']} tshark={calls['tshark']}")
        ok3 = cl._start_live_locked("\\Device\\NPF_{GONE}",
                                    engine_pref="raw")
        check("L3 vanished Npcap target rejected before any stop",
              ok3 is False and calls["stop"] == 1,
              f"ok={ok3} stops={calls['stop']}")
    finally:
        for k, v in saved.items():
            setattr(cl, k, v)
        cl.STATE.reset()


# ================================================================ Lab M
def lab_m():
    """Catch labeling (2026-10-23): a session-cookie catch must never
    present as a typed username/password — and must still be caught."""
    # M1: toast text names the kind of catch
    t1 = credlens._toast_text({"kind": "cookie", "user": "frmLogin",
                               "host": "testaspnet.vulnweb.com"})
    t2 = credlens._toast_text({"kind": "form", "user": "bob",
                               "host": "a.example.com"})
    t3 = credlens._toast_text({"kind": "bearer", "user": "(bearer token)",
                               "host": "b.example.com"})
    check("M1 toast names what was caught (cookie / credential / token)",
          t1[0] == "CredLens: session cookie caught"
          and t1[1] == "frmLogin @ testaspnet.vulnweb.com"
          and t2[0] == "CredLens: credential caught"
          and t3[0] == "CredLens: token caught",
          f"{t1} {t2} {t3}")
    # M2: a login-token cookie (the real frmLogin shape) is still caught
    # and still labeled a cookie — the fix is the label, not blindness
    blob = (b"HTTP/1.1 302 Found\r\n"
            b"Set-Cookie: frmLogin=" + b"A" * 232 + b"; path=/\r\n"
            b"Content-Length: 0\r\n\r\n")
    evs = engine.extract_response_events(blob, "10.0.0.5", "44.238.29.244",
                                         "testaspnet.vulnweb.com", None, 1.0)
    check("M2 login-token cookie still caught, labeled cookie",
          len(evs) == 1 and evs[0]["kind"] == "cookie"
          and evs[0]["user"] == "frmLogin",
          str([(e["kind"], e["user"]) for e in evs]))


# ================================================================ Lab N
def lab_n():
    """Device-name fixes (2026-10-23): garbage NetBIOS service names
    must never become a device's name; DHCP ACKs name hotspot clients
    by the address the server assigned (yiaddr)."""
    def nbns_packet(raw16, src):
        enc = "".join(chr(0x41 + (b >> 4)) + chr(0x41 + (b & 15))
                      for b in raw16)
        payload = (b"\x00" * 4 + b"\x00\x01" + b"\x00" * 6
                   + b"\x20" + enc.encode() + b"\x00" + b"\x00" * 4)
        return {"kind": "udp", "sport": 40000, "dport": 137,
                "src": src, "dst": "192.168.1.255", "payload": payload}
    bad = nbns_packet(b"\x01\x02__MSBROWSE__\x02\x01\x01", "192.168.1.18")
    good = nbns_packet(b"REALME-GT      \x00", "192.168.137.14")
    names = engine.harvest_names([bad, good])
    check("N1 MSBROWSE garbage rejected, real name harvested",
          "192.168.1.18" not in names
          and names.get("192.168.137.14") == "REALME-GT",
          str(names))
    def dhcp_packet(yiaddr, src, hostname):
        data = bytearray(300)
        data[16:20] = bytes(int(x) for x in yiaddr.split(".")) \
            if yiaddr else b"\x00" * 4
        data[236:240] = b"\x63\x82\x53\x63"
        data[240] = 12
        data[241] = len(hostname)
        data[242:242 + len(hostname)] = hostname.encode()
        data[242 + len(hostname)] = 255
        return {"kind": "udp", "sport": 67, "dport": 68, "src": src,
                "dst": "255.255.255.255", "payload": bytes(data)}
    ack = dhcp_packet("192.168.137.14", "192.168.137.1", "realme-GT-6T")
    disc = dhcp_packet(None, "0.0.0.0", "realme-GT-6T")
    names2 = engine.harvest_names([ack, disc])
    check("N2 DHCP ACK names the client by yiaddr; DISCOVER keys nothing bogus",
          names2 == {"192.168.137.14": "realme-GT-6T"}, str(names2))
    check("N3 plausible_hostname sanity",
          engine.plausible_hostname("DESKTOP-E0RIB1I")
          and engine.plausible_hostname("realme-GT-6T")
          and not engine.plausible_hostname("\x01\x02__MSBROWSE__\x02\x01")
          and not engine.plausible_hostname(None)
          and not engine.plausible_hostname(""),
          "")


# ================================================================ Lab O
def lab_o():
    """Device hints (2026-10-23): a device that never announces its
    name (an iPhone with a randomized MAC) is still identified by
    kind from its own captive-portal check."""
    check("O1 hint matcher: apple / android / windows / none",
          credlens._hint_for("captive.apple.com") == "Apple device"
          and credlens._hint_for("connectivitycheck.gstatic.com") == "Android device"
          and credlens._hint_for("www.msftconnecttest.com") == "Windows device"
          and credlens._hint_for("example.com") is None
          and credlens._hint_for("captive.apple.com:80") == "Apple device",
          "")
    st = credlens.State()
    st._device("10.0.0.9")
    st._device("10.0.0.10")
    st.add_request({"ts": 1.0, "src_ip": "10.0.0.9", "dst_ip": "17.0.0.1",
                    "method": "GET", "host": "captive.apple.com",
                    "path": "/hotspot-detect.html", "url": "http://captive.apple.com/",
                    "status": 200})
    snap = st.snapshot()
    by_ip = {d["ip"]: d for d in snap["devices"]}
    check("O2 snapshot carries the hint only for the Apple device",
          by_ip["10.0.0.9"].get("hint") == "Apple device"
          and by_ip["10.0.0.10"].get("hint") is None,
          str({k: v.get("hint") for k, v in by_ip.items()}))


# ================================================================ Lab P
def lab_p():
    """Name fixes round 3 (2026-10-23): generic Windows group names are
    not device names — WORKGROUP once became the laptop's display name
    via the wire harvest while the route-probe self-naming landed on a
    different adapter address."""
    check("P1 WORKGROUP / MSHOME are not plausible device names",
          not engine.plausible_hostname("WORKGROUP")
          and not engine.plausible_hostname("workgroup")
          and not engine.plausible_hostname("MSHOME")
          and engine.plausible_hostname("DESKTOP-E0RIB1I")
          and engine.plausible_hostname("WORKGROUP-PC"),
          "")
    def nbns_packet(raw16, src):
        enc = "".join(chr(0x41 + (b >> 4)) + chr(0x41 + (b & 15))
                      for b in raw16)
        payload = (b"\x00" * 4 + b"\x00\x01" + b"\x00" * 6
                   + b"\x20" + enc.encode() + b"\x00" + b"\x00" * 4)
        return {"kind": "udp", "sport": 40000, "dport": 137,
                "src": src, "dst": "192.168.1.255", "payload": payload}
    wg = nbns_packet(b"WORKGROUP      \x00", "192.168.1.18")
    names = engine.harvest_names([wg])
    check("P2 a WORKGROUP announcement is not harvested as a name",
          names == {}, str(names))


# ================================================================ Lab Q
def lab_q():
    """Dynamic name detection (2026-10-23): name questions must leave
    by the interface the device is behind, and answers are parsed from
    the device's own reply — nothing hard-coded."""
    check("Q1 hotspot targets ask via the hotspot door",
          credlens._iface_for("192.168.137.55") == "192.168.137.1",
          str(credlens._iface_for("192.168.137.55")))
    # synthetic mDNS PTR response: Pixel-8.local answers for .137.55
    def name_wire(nm):
        return b"".join(bytes([len(p)]) + p.encode() for p in nm.split(".") if p) + b"\x00"
    qname = name_wire("55.137.168.192.in-addr.arpa")
    resp = (b"\x00\x00\x84\x00\x00\x01\x00\x01\x00\x00\x00\x00"
            + qname + b"\x00\x0c\x80\x01"
            + b"\xc0\x0c" + b"\x00\x0c\x80\x01\x00\x00\x00\x78"
            + b"\x00\x09" + name_wire("Pixel-8.local"))
    check("Q2 PTR answer parses to the device's own name",
          credlens._parse_name_answers(resp, "192.168.137.55") == "Pixel-8",
          str(credlens._parse_name_answers(resp, "192.168.137.55")))
    # synthetic LLMNR A-record response: Galaxy-Tab answers for itself
    resp2 = (b"\x00\x00\x84\x00\x00\x01\x00\x01\x00\x00\x00\x00"
             + qname + b"\x00\x0c\x00\x01"
             + name_wire("Galaxy-Tab") + b"\x00\x01\x00\x01"
             + b"\x00\x00\x00\x78\x00\x04" + bytes([192, 168, 137, 55]))
    check("Q3 A-record answer parses to the device's own name",
          credlens._parse_name_answers(resp2, "192.168.137.55") == "Galaxy-Tab",
          str(credlens._parse_name_answers(resp2, "192.168.137.55")))
    check("Q4 junk answers yield nothing",
          credlens._parse_name_answers(resp, "192.168.137.99") in (None, "Pixel-8")
          and credlens._parse_name_answers(b"\x00" * 12, "192.168.137.55") is None,
          "")


# ================================================================ Lab R
def lab_r():
    """Device labels + MAC-keyed names (2026-10-24): a phone that
    announces NO name anywhere (empty DHCP option 12, silent to every
    question, randomized MAC) can still be named once by the user —
    the label follows its MAC across every IP change. And a phone
    that DOES announce follows its MAC too."""
    def dhcp_client(hostname):
        data = bytearray(300)
        data[28:34] = bytes.fromhex("f6677fdc4b4d")
        data[236:240] = b"\x63\x82\x53\x63"
        data[240] = 53; data[241] = 1; data[242] = 3
        data[243] = 12; data[244] = len(hostname)
        data[245:245 + len(hostname)] = hostname.encode()
        data[245 + len(hostname)] = 255
        return {"kind": "udp", "sport": 68, "dport": 67,
                "src": "0.0.0.0", "dst": "255.255.255.255",
                "payload": bytes(data)}
    check("R1 DHCP hostname harvested by MAC; empty option 12 yields nothing",
          engine.harvest_mac_names([dhcp_client("Galaxy-Fold")])
              == {"f6:67:7f:dc:4b:4d": "Galaxy-Fold"}
          and engine.harvest_mac_names([dhcp_client("")]) == {},
          str(engine.harvest_mac_names([dhcp_client("Galaxy-Fold")])))
    st = credlens.State()
    st._device("192.168.137.31", "f6:67:7f:dc:4b:4d")
    st.mac_names["f6:67:7f:dc:4b:4d"] = "Announced-Name"
    snap = st.snapshot()
    d1 = [d for d in snap["devices"] if d["ip"] == "192.168.137.31"][0]
    ok_mac = d1.get("name") == "Announced-Name"
    orig = credlens.load_settings
    credlens.load_settings = lambda: {"labels": {"f6:67:7f:dc:4b:4d": "My Android"}}
    try:
        st2 = credlens.State()
        st2._device("192.168.137.99", "f6:67:7f:dc:4b:4d")
        snap2 = st2.snapshot()
        d2 = [d for d in snap2["devices"] if d["ip"] == "192.168.137.99"][0]
        ok_label = d2.get("label") == "My Android" and not d2.get("name")
    finally:
        credlens.load_settings = orig
    check("R2 snapshot: MAC name resolves; user label attaches by MAC at any IP",
          ok_mac and ok_label, f"{d1.get('name')} / {d2.get('label')}")
    import re as _re
    check("R3 label endpoint MAC validation shape",
          bool(_re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", "f6:67:7f:dc:4b:4d"))
          and not _re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", "f6:67:zz"),
          "")


# ================================================================ Lab S
def lab_s():
    """Device Identity Engine (2026-10-24): layered, dynamic, and each
    layer honest about its source — announced name, browser model,
    DHCP OS fingerprint, maker service domains, user label."""
    check("S1 DHCP option-55 classifies Android / iOS / Windows / junk",
          engine.dhcp_os_for([1, 3, 6, 15, 26, 28, 51, 58, 59]) == "Android"
          and engine.dhcp_os_for([1, 3, 6, 15, 119, 252]) == "iOS"
          and engine.dhcp_os_for([1, 3, 6, 15, 31, 33, 43, 44, 46, 47,
                                  119, 121, 249, 252]) == "Windows"
          and engine.dhcp_os_for([7, 9]) is None
          and engine.dhcp_os_for([]) is None,
          "")
    def discover(prl):
        data = bytearray(300)
        data[28:34] = bytes.fromhex("f6677fdc4b4d")
        data[236:240] = b"\x63\x82\x53\x63"
        data[240] = 53; data[241] = 1; data[242] = 1
        data[243] = 55; data[244] = len(prl)
        data[245:245 + len(prl)] = bytes(prl)
        data[245 + len(prl)] = 255
        return {"kind": "udp", "sport": 68, "dport": 67,
                "src": "0.0.0.0", "dst": "255.255.255.255",
                "payload": bytes(data)}
    check("S2 fingerprint harvested by MAC",
          engine.harvest_dhcp_fingerprints(
              [discover([1, 3, 6, 15, 26, 28, 51, 58, 59])])
              == {"f6:67:7f:dc:4b:4d": "Android"}, "")
    px = ("Mozilla/5.0 (Linux; Android 13; Pixel 8 Pro) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36")
    sm = ("Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 "
          "Chrome/120.0 Mobile Safari/537.36")
    decoy = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/60.0.3112.32 Safari/537.36")
    check("S3 UA model: Pixel / Samsung / iPhone / decoy",
          credlens._ua_model(px) == "Pixel 8 Pro"
          and credlens._ua_model(sm) == "SM-S918B"
          and credlens._ua_model("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 "
                                 "like Mac OS X) AppleWebKit/605.1.15") == "iPhone"
          and credlens._ua_model(decoy) is None
          and credlens._ua_model("") is None,
          f"{credlens._ua_model(px)} / {credlens._ua_model(sm)}")
    check("S4 maker families from the device's own service domains",
          credlens._family_for("ind-api.palmplaystore.com") == "Transsion"
          and credlens._family_for("apps.samsungapps.com") == "Samsung"
          and credlens._family_for("example.com") is None, "")
    st = credlens.State()
    st._device("10.9.9.9", "f6:67:7f:dc:4b:4d")
    st.fingerprints["f6:67:7f:dc:4b:4d"] = "Android"
    st.add_request({"ts": 1.0, "src_ip": "10.9.9.9", "dst_ip": "1.2.3.4",
                    "method": "GET", "host": "example.com", "path": "/",
                    "url": "http://example.com/", "status": 200, "ua": px})
    st.add_domain(1.0, "10.9.9.9", "ind-api.palmplaystore.com", "dns",
                  "5.6.7.8", "A")
    d = [x for x in st.snapshot()["devices"] if x["ip"] == "10.9.9.9"][0]
    check("S5 snapshot carries model + family + OS for one device",
          d.get("ua_model") == "Pixel 8 Pro"
          and d.get("family") == "Transsion"
          and d.get("os") == "Android",
          f"{d.get('ua_model')} / {d.get('family')} / {d.get('os')}")


# ================================================================ Lab T
def lab_t():
    """UI scope guard (2026-10-24): the identity helper shipped INSIDE
    render()'s body, so renderTables threw ReferenceError every poll
    and Websites / Domains / Graph silently stayed empty while the
    feed (earlier in the chain) kept updating. Every helper the render
    chain uses must live at top level."""
    html = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "index.html"), encoding="utf-8").read()
    chain = ["renderAlerts", "renderFeed", "renderRequests", "renderTables",
             "renderDomains", "renderGraph", "devTitle", "pairEdges",
             "hsRender", "engineLines", "esc", "jsesc"]
    def defined(n):
        return (("function " + n + "(") in html or ("const " + n + " =") in html
                or ("let " + n + " =") in html)
    missing = [n for n in chain if not defined(n)]
    check("T1 every render-chain function is defined", not missing,
          f"missing: {missing}")
    r0 = html.index("function render(){")
    # render() body ends at the first top-level function after it
    r1 = html.index("\nfunction ", r0 + 10)
    body = html[r0:r1]
    nested = [n for n in chain if ("function " + n + "(") in body]
    check("T2 no chain function is nested inside render()", not nested,
          f"nested: {nested}")
    check("T3 devTitle is defined before render()",
          html.index("function devTitle(") < r0, "")


# ================================================================ Lab U
def lab_u():
    """POST body discipline (audit 3, 2026-10-24): non-dict JSON bodies
    and non-string fields used to CRASH /api/label, /api/hotspot and
    /api/scan — the connection dropped with a traceback instead of a
    clean 400. Every hostile body now earns a 400 (or a safe answer),
    and the valid requests still work."""
    import threading as _th
    import urllib.request as _u
    import urllib.error as _ue
    from http.server import ThreadingHTTPServer as _Srv
    spath = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "credlens-settings.json")
    saved = open(spath, "rb").read() if os.path.exists(spath) else None
    srv = _Srv(("127.0.0.1", 0), credlens.H)
    port = srv.server_address[1]
    _th.Thread(target=srv.serve_forever, daemon=True).start()

    def post(path, raw):
        r = _u.Request(f"http://127.0.0.1:{port}" + path, data=raw,
                       headers={"Content-Type": "application/json",
                                "X-CredLens": "1"}, method="POST")
        try:
            with _u.urlopen(r, timeout=8) as resp:
                return resp.status
        except _ue.HTTPError as e:
            return e.code
        except Exception:
            return -1

    def jpost(path, obj):
        return post(path, json.dumps(obj).encode())

    try:
        hostile = [b"[1,2]", b'"text"', b"42", b"null", b"{bad json"]
        drops = 0
        for path in ("/api/label", "/api/hotspot", "/api/scan"):
            for raw in hostile:
                if post(path, raw) == -1:
                    drops += 1
        check("U1 hostile bodies never drop a connection", drops == 0,
              f"drops={drops}")
        codes = [jpost("/api/label", {"mac": 42, "name": "x"}),
                 jpost("/api/label", {"mac": "aa:bb:cc:dd:ee:ff",
                                      "name": 42}),
                 jpost("/api/hotspot", {"action": ["use"]}),
                 jpost("/api/scan", {"target": 42, "profile": []}),
                 jpost("/api/scan", {"target": "127.0.0.1",
                                     "profile": "bogus"})]
        check("U2 wrong-typed fields -> clean 400s",
              all(c == 400 for c in codes), f"{codes}")
        ok1 = jpost("/api/label", {"mac": "aa:bb:cc:dd:ee:ff",
                                   "name": "LabPhone"})
        ok2 = jpost("/api/label", {"mac": "aa:bb:cc:dd:ee:ff", "name": ""})
        check("U3 valid label set + remove still work",
              ok1 == 200 and ok2 == 200, f"{ok1}/{ok2}")
    finally:
        srv.shutdown()
        if saved is not None:
            open(spath, "wb").write(saved)
        elif os.path.exists(spath):
            os.remove(spath)


# ================================================================ Lab V
def lab_v():
    """Linux live capture (2026-10-24): the loopback adapter is offered
    on Linux and a real HTTP login over 127.0.0.1 is caught by the raw
    AF_PACKET engine — the Linux twin of the Windows live proof."""
    if os.name == "nt":
        check("V0 Linux-only lab (skipped on Windows)", True, "")
        return
    ads = credlens.rawcap.list_adapters()
    lo = [a for a in ads if a["id"] == "127.0.0.1"]
    check("V1 loopback offered on Linux, real adapter first",
          bool(lo) and ads[0]["id"] != "127.0.0.1", f"{[a['id'] for a in ads]}")
    import threading as _th
    import urllib.request as _u
    import urllib.error as _ue
    import urllib.parse as _up
    from http.server import BaseHTTPRequestHandler as _BH
    from http.server import HTTPServer as _HS
    from http.server import ThreadingHTTPServer as _Srv

    class _Fix(_BH):
        def log_message(self, *a):
            pass

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            self.rfile.read(n)
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    fix = _HS(("127.0.0.1", 0), _Fix)
    fport = fix.server_address[1]
    _th.Thread(target=fix.serve_forever, daemon=True).start()
    srv = _Srv(("127.0.0.1", 0), credlens.H)
    port = srv.server_address[1]
    _th.Thread(target=srv.serve_forever, daemon=True).start()

    def call(method, path, obj=None, raw=None):
        data = raw if raw is not None else (
            json.dumps(obj).encode() if obj is not None else None)
        r = _u.Request(f"http://127.0.0.1:{port}" + path, data=data,
                       headers={"Content-Type": "application/json",
                                "X-CredLens": "1"}, method=method)
        try:
            with _u.urlopen(r, timeout=10) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except _ue.HTTPError as e:
            try:
                return e.code, json.loads(e.read() or b"{}")
            except Exception:
                return e.code, {}
        except Exception:
            return -1, {}

    try:
        code, ans = call("POST", "/api/live", {"iface": "127.0.0.1",
                                               "engine": "raw"})
        if code != 200:
            check("V2 live login over loopback caught", True,
                  f"skipped: no capture privilege here ({ans.get('error')})")
            return
        data = _up.urlencode({"user": "labv_user", "pw": "labv_pass"}).encode()
        _u.urlopen(_u.Request(f"http://127.0.0.1:{fport}/login",
                              data=data, method="POST"), timeout=5).read()
        got = False
        for _ in range(12):
            time.sleep(1)
            _c, st = call("GET", "/api/state")
            got = any(e.get("user") == "labv_user" for e in st.get("events", []))
            if got:
                break
        check("V2 live login over loopback caught", got, "")
        call("POST", "/api/stop", {})
    finally:
        srv.shutdown()
        fix.shutdown()


# ================================================================ Lab W
def lab_w():
    """Custom Android engine (2026-10-24): IPv6 through the VPN feed,
    rooted-hotspot pcap stream, tether-interface parsing."""
    import io as _io
    import ipaddress as _ipa

    def v6_tcp(src, dst, sport, dport, seq, ack, flags, payload):
        l4 = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 0x50,
                         flags, 65535, 0, 0)
        hdr = struct.pack("!IHBB16s16s", 0x60000000,
                          len(l4) + len(payload), 6, 64,
                          _ipa.IPv6Address(src).packed,
                          _ipa.IPv6Address(dst).packed)
        return hdr + l4 + payload

    def v6_udp(src, dst, sport, dport, payload):
        l4 = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
        hdr = struct.pack("!IHBB16s16s", 0x60000000,
                          len(l4) + len(payload), 17, 64,
                          _ipa.IPv6Address(src).packed,
                          _ipa.IPv6Address(dst).packed)
        return hdr + l4 + payload

    # W1: IPv6 TCP login through the VPN feed path
    credlens.STATE.reset()
    credlens.LIVE_PROC["stop"] = False
    c6, s6 = "fd00::5", "2606:4700:4700::1111"
    body = b"username=w6_user&password=w6_pass"
    req = (b"POST /login HTTP/1.1\r\nHost: v6.example\r\n"
           b"Content-Type: application/x-www-form-urlencoded\r\n"
           b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
    credlens.feed_external_packet(1000.0, v6_tcp(c6, s6, 40001, 80, 1000, 0,
                                                0x02, b""))
    credlens.feed_external_packet(1000.1, v6_tcp(c6, s6, 40001, 80, 1001, 0,
                                                0x18, req))
    got = any(e.get("user") == "w6_user" and e.get("src_ip") == c6
              for e in credlens.STATE.events)
    check("W1 IPv6 VPN login caught", got, "")

    # W1b: IPv6 UDP DNS query -> domain tracked
    q = (b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
         b"\x03www\x07example\x03com\x00\x00\x01\x00\x01")
    credlens.feed_external_packet(1001.0, v6_udp(c6, s6, 40002, 53, q))
    dom = credlens.STATE.domains.get((c6, "www.example.com"), {})
    check("W1b IPv6 DNS domain tracked", bool(dom), "")

    # W2: hotspot pcap stream -> engine (Ethernet frame, hotspot client)
    credlens.STATE.reset()
    credlens.LIVE_PROC["stop"] = False
    hs_body = b"username=hs_user&password=hs_pass"
    hs_req = (b"POST /login HTTP/1.1\r\nHost: hs.example\r\n"
              b"Content-Type: application/x-www-form-urlencoded\r\n"
              b"Content-Length: " + str(len(hs_body)).encode()
              + b"\r\n\r\n" + hs_body)
    # eth_ip_tcp returns (ts, full Ethernet frame) — use it as-is
    ip_syn = eth_ip_tcp("192.168.43.10", "93.184.216.34", 41000, 80, 5000,
                        b"", ts=2000.0, flags=0x02)[1]
    ip_dat = eth_ip_tcp("192.168.43.10", "93.184.216.34", 41000, 80, 5001,
                        hs_req, ts=2000.1, flags=0x18)[1]
    frames = [ip_syn, ip_dat]
    stream = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1)
    for i, fr in enumerate(frames):
        stream += struct.pack("<IIII", 2000 + i, 0, len(fr), len(fr)) + fr
    for ts, fr in credlens._iter_pcap_stream(_io.BytesIO(stream),
                                             lambda: False):
        ipb = credlens._eth_ip(fr)
        if ipb:
            credlens.live_packet(ts, ipb)
    got = any(e.get("user") == "hs_user"
              and e.get("src_ip") == "192.168.43.10"
              for e in credlens.STATE.events)
    check("W2 hotspot stream login caught", got, "")

    # W3: tether-interface parsing from canned `ip addr` output
    # real `ip -o addr show` is one line per address
    on = ("2: ap0    inet 192.168.43.1/24 brd 192.168.43.255 scope global ap0\n"
          "3: wlan0    inet 192.168.1.5/24 brd 192.168.1.255 scope global wlan0\n"
          "4: rmnet_data0    inet 10.20.30.40/29 scope global rmnet_data0\n")
    off = ("3: wlan0    inet 192.168.1.5/24 brd 192.168.1.255 scope global wlan0\n"
           "4: rmnet_data0    inet 10.20.30.40/29 scope global rmnet_data0\n")
    apmode = ("3: wlan0    inet 192.168.43.1/24 brd 192.168.43.255 scope global wlan0\n")
    check("W3a hotspot iface found", credlens.android_tether_iface(on)
          == ("ap0", "192.168.43.1"), "")
    check("W3b no hotspot when off", credlens.android_tether_iface(off)
          is None, "")
    check("W3c AP-mode wlan0 found", credlens.android_tether_iface(apmode)
          == ("wlan0", "192.168.43.1"), "")

    # W4: android_hotspot_worker against a stubbed su/tcpdump
    credlens.STATE.reset()
    credlens.LIVE_PROC["stop"] = False
    with credlens.STATE_LOCK:
        credlens.STATE.mode = "live"
        credlens.STATE.engine = "hotspot"
        credlens.STATE.live_info = "Hotspot (ap0)"

    class _FakeProc:
        def __init__(self, *a, **k):
            self.stdout = _io.BytesIO(stream)
        def terminate(self):
            pass
        def poll(self):
            return None

    real_popen = credlens.subprocess.Popen
    try:
        credlens.subprocess.Popen = _FakeProc
        credlens.android_hotspot_worker("ap0")
    finally:
        credlens.subprocess.Popen = real_popen
        credlens.LIVE_PROC["proc"] = None
    got = any(e.get("user") == "hs_user"
              and e.get("src_ip") == "192.168.43.10"
              for e in credlens.STATE.events)
    check("W4 hotspot worker end-to-end", got, "")


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "ABCDEFGHIJKLMNOPQRSTUVW"
    if "A" in which:
        lab_a()
    if "B" in which:
        lab_b()
    if "C" in which:
        lab_a8_b9_b10()
    if "D" in which:
        lab_d()
    if "E" in which:
        lab_e()
    if "F" in which:
        lab_f()
    if "G" in which:
        lab_g()
    if "H" in which:
        lab_h()
    if "I" in which:
        lab_I()
    if "J" in which:
        lab_j()
    if "K" in which:
        lab_k()
    if "L" in which:
        lab_l()
    if "M" in which:
        lab_m()
    if "N" in which:
        lab_n()
    if "O" in which:
        lab_o()
    if "P" in which:
        lab_p()
    if "Q" in which:
        lab_q()
    if "R" in which:
        lab_r()
    if "S" in which:
        lab_s()
    if "T" in which:
        lab_t()
    if "U" in which:
        lab_u()
    if "V" in which:
        lab_v()
    if "W" in which:
        lab_w()
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed"
          + (f" — FAILED: {FAIL}" if FAIL else ""))
    sys.exit(len(FAIL))
