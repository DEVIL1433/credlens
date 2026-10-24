"""Generate a synthetic test.pcap for CredLens (fictional data only)."""
import base64
import struct
import time


def ip_pkt(src, dst, proto, payload, sport=None, dport=None, seq=1):
    if proto == 6:
        l4 = struct.pack(">HHIIBBHHH", sport, dport, seq, 0, 5 << 4, 0x18, 65535, 0, 0) + payload
    else:
        l4 = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    total = 20 + len(l4)
    hdr = struct.pack(">BBHHHBBH", 0x45, 0, total, 1, 0x4000, 64, proto, 0)
    hdr += bytes(int(x) for x in src.split(".")) + bytes(int(x) for x in dst.split("."))
    return hdr + l4


def eth(mac_src, payload, ethertype=0x0800):
    return bytes.fromhex("ffffffffffff") + bytes.fromhex(mac_src.replace(":", "")) + struct.pack(">H", ethertype) + payload


def dhcp_hostname(mac, ip, hostname):
    # BOOTP: op=1, htype=1, hlen=6, xid, ciaddr at 12, chaddr at 28, magic at 236
    bootp = bytearray(240)
    bootp[0] = 1
    bootp[1] = 1
    bootp[2] = 6
    struct.pack_into(">I", bootp, 4, 0x1234)
    bootp[12:16] = bytes(int(x) for x in ip.split("."))
    bootp[28:34] = bytes.fromhex(mac.replace(":", ""))
    bootp[236:240] = b"\x63\x82\x53\x63"
    opts = bytes([53, 1, 3, 12, len(hostname)]) + hostname.encode() + bytes([255])
    return bytes(bootp) + opts


pkts = []
T = int(time.time()) - 3600


def add(ts_off, frame):
    pkts.append((T + ts_off, frame))


MAC_PHONE = "5c:3c:27:aa:bb:cc"   # Samsung OUI
MAC_LAP = "3c:fd:fe:11:22:33"     # Intel OUI
MAC_XIA = "64:cc:2e:44:55:66"     # Xiaomi OUI

# 1. DHCP with hostname Galaxy-M34 for 192.168.1.42 (UDP 68 -> 67)
udp = ip_pkt("192.168.1.42", "255.255.255.255", 17, dhcp_hostname(MAC_PHONE, "192.168.1.42", "Galaxy-M34"), 68, 67)
add(1, eth(MAC_PHONE, udp))

# 2. POST form login: phone -> testphp.vulnweb.com (176.28.50.165)
body = b"uname=demo_user&pass=Sunshine%40123&login=Login"
req = (b"POST /login.php HTTP/1.1\r\nHost: testphp.vulnweb.com\r\n"
       b"Content-Type: application/x-www-form-urlencoded\r\n"
       b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
add(10, eth(MAC_PHONE, ip_pkt("192.168.1.42", "176.28.50.165", 6, req, 51000, 80)))

# 3. GET with creds in query: laptop -> shop.examplemart.in (103.77.209.14)
req = (b"GET /auth/signin?email=priya.sharma88&password=Priya%212024 HTTP/1.1\r\n"
       b"Host: shop.examplemart.in\r\n\r\n")
add(20, eth(MAC_LAP, ip_pkt("192.168.1.17", "103.77.209.14", 6, req, 52000, 80)))

# 4. Basic Auth: phone -> router 192.168.1.1
cred = base64.b64encode(b"admin:router123")
req = b"GET /admin/ HTTP/1.1\r\nHost: 192.168.1.1\r\nAuthorization: Basic " + cred + b"\r\n\r\n"
add(30, eth(MAC_PHONE, ip_pkt("192.168.1.42", "192.168.1.1", 6, req, 53000, 80)))

# 5. Benign GET — no credentials, must NOT fire
req = b"GET /index.html HTTP/1.1\r\nHost: example.org\r\n\r\n"
add(40, eth(MAC_LAP, ip_pkt("192.168.1.17", "93.184.215.14", 6, req, 54000, 80)))

# 6. Chunked POST wp-login: xiaomi device -> blog.oldsite.net (185.93.11.60)
body = b"log=webmaster&pwd=Blog%23Pass99"
chunked = ("%x\r\n" % len(body)).encode() + body + b"\r\n0\r\n\r\n"
req = (b"POST /wp-login.php HTTP/1.1\r\nHost: blog.oldsite.net\r\n"
       b"Content-Type: application/x-www-form-urlencoded\r\n"
       b"Transfer-Encoding: chunked\r\n\r\n" + chunked)
add(50, eth(MAC_XIA, ip_pkt("192.168.1.8", "185.93.11.60", 6, req, 55000, 80)))

# 7. FTP login: laptop -> 203.0.113.50:21
ftp = b"USER ftpuser\r\nPASS Ftp#Pass1\r\n"
add(60, eth(MAC_LAP, ip_pkt("192.168.1.17", "203.0.113.50", 6, ftp, 56000, 21)))

# 8. POP3 login: phone -> 203.0.113.60:110
pop = b"USER priya.mail\r\nPASS Mail#2024\r\n"
add(70, eth(MAC_PHONE, ip_pkt("192.168.1.42", "203.0.113.60", 6, pop, 57000, 110)))

# 9. IMAP LOGIN: laptop -> 203.0.113.61:143
imap = b'a001 LOGIN "devil.ops" "Imap$ecret7"\r\n'
add(80, eth(MAC_LAP, ip_pkt("192.168.1.17", "203.0.113.61", 6, imap, 58000, 143)))

# 10. SMTP AUTH LOGIN (base64 rounds): xiaomi -> 203.0.113.62:587
smtp = (b"AUTH LOGIN\r\n" + base64.b64encode(b"alerts@devil.local") + b"\r\n"
        + base64.b64encode(b"Smtp!Pass8") + b"\r\n")
add(90, eth(MAC_XIA, ip_pkt("192.168.1.8", "203.0.113.62", 6, smtp, 59000, 587)))

# 11. MQTT CONNECT with username/password: phone -> 203.0.113.70:1883
def mqtt_str(b):
    return struct.pack(">H", len(b)) + b
mqtt_payload = mqtt_str(b"cam-client-01") + mqtt_str(b"iot-cam-04") + mqtt_str(b"Cam3ra!pass")
mqtt_vh = mqtt_str(b"MQTT") + bytes([4, 0xC2, 0, 60])
mqtt_body = mqtt_vh + mqtt_payload
mqtt = bytes([0x10, len(mqtt_body)]) + mqtt_body
add(100, eth(MAC_PHONE, ip_pkt("192.168.1.42", "203.0.113.70", 6, mqtt, 60000, 1883)))

# 12. Telnet: server prompts (sport 23), then the typed lines (dport 23)
srv = b"\r\nlogin: "
add(110, eth(MAC_LAP, ip_pkt("203.0.113.80", "192.168.1.17", 6, srv, 23, 61000)))
typed1 = b"root\r\n"
add(111, eth(MAC_LAP, ip_pkt("192.168.1.17", "203.0.113.80", 6, typed1, 61000, 23, seq=1)))
srv2 = b"Password: "
add(112, eth(MAC_LAP, ip_pkt("203.0.113.80", "192.168.1.17", 6, srv2, 23, 61000)))
typed2 = b"toor123\r\n"
add(113, eth(MAC_LAP, ip_pkt("192.168.1.17", "203.0.113.80", 6, typed2, 61000, 23, seq=7)))

# 13. HTTP session cookie exposed: laptop -> app.oldportal.in (203.0.113.90)
req = (b"GET /dashboard HTTP/1.1\r\nHost: app.oldportal.in\r\n"
       b"Cookie: theme=dark; PHPSESSID=abc123sessiontoken\r\n\r\n")
add(120, eth(MAC_LAP, ip_pkt("192.168.1.17", "203.0.113.90", 6, req, 62000, 80)))
# same cookie again on another page — must dedupe to ONE cookie event
req = (b"GET /profile HTTP/1.1\r\nHost: app.oldportal.in\r\n"
       b"Cookie: theme=dark; PHPSESSID=abc123sessiontoken\r\n\r\n")
add(130, eth(MAC_LAP, ip_pkt("192.168.1.17", "203.0.113.90", 6, req, 62500, 80)))

# 14. API key in URL query: phone -> api.legacyservice.io (203.0.113.91)
req = b"GET /v1/data?api_key=AKIA-TEST-KEY-9876&format=json HTTP/1.1\r\nHost: api.legacyservice.io\r\n\r\n"
add(140, eth(MAC_PHONE, ip_pkt("192.168.1.42", "203.0.113.91", 6, req, 63000, 80)))

# 15. Bearer token over HTTP: xiaomi -> 203.0.113.92
req = (b"GET /api/me HTTP/1.1\r\nHost: devbox.localapi.io\r\n"
       b"Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.testtoken\r\n\r\n")
add(150, eth(MAC_XIA, ip_pkt("192.168.1.8", "203.0.113.92", 6, req, 64000, 80)))

out = bytearray()
out += struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
for ts, frame in pkts:
    out += struct.pack("<IIII", ts, 0, len(frame), len(frame)) + frame

open("test.pcap", "wb").write(bytes(out))
print("test.pcap written:", len(out), "bytes,", len(pkts), "packets")
