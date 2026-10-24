package com.devil.credlens;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import com.chaquo.python.Python;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Capture-and-forward VPN. Every packet is handed to the Python engine
 * (both directions, so request AND response analysis works), then
 * forwarded with a minimal userspace TCP/UDP relay:
 *  - UDP: one protected DatagramChannel per flow.
 *  - TCP: one protected SocketChannel per flow, with synthetic
 *    SYN-ACK / ACK / FIN generated locally (ports stay private: this is
 *    the phone's OWN traffic only, by the user's action).
 * IPv4 + IPv6: the TUN carries a ULA address and a ::/0 route, and the
 * relay forwards both families through the same flow machinery (IPv6
 * UDP/TCP checksums are mandatory, so they are computed over the v6
 * pseudo-header). Multicast, link-local and extension-header traffic
 * (AH/ESP, non-first fragments) is observed by the Python engine but
 * not forwarded.
 */
public class CredVpnService extends VpnService {
    private static final String TAG = "CredVpn";
    private static final String CHANNEL = "credlens";
    private static volatile boolean running = false;

    public static boolean isRunning() { return running; }

    private ParcelFileDescriptor tun;
    private FileOutputStream tunOut;
    private final Object tunLock = new Object();
    private Selector selector;
    private Thread pumpThread;
    private Thread ioThread;
    private final Map<String, UdpFlow> udpFlows = new ConcurrentHashMap<>();
    private final Map<String, TcpFlow> tcpFlows = new ConcurrentHashMap<>();
    private final Random rnd = new Random();

    // ------------------------------------------------------------ lifecycle
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (running) return START_STICKY;
        try {
            startForegroundNote();
            Builder b = new Builder();
            b.setSession("CredLens");
            b.addAddress("10.0.0.2", 32);
            b.addRoute("0.0.0.0", 0);
            b.addAddress("fd00::2", 120);
            b.addRoute("::", 0);
            b.addDnsServer("1.1.1.1");
            b.setMtu(1500);
            b.setBlocking(true);
            tun = b.establish();
            if (tun == null) {
                Log.e(TAG, "establish() returned null");
                stopSelf();
                return START_NOT_STICKY;
            }
            tunOut = new FileOutputStream(tun.getFileDescriptor());
            selector = Selector.open();
            running = true;
            pumpThread = new Thread(this::pump, "credlens-tun");
            pumpThread.setDaemon(true);
            pumpThread.start();
            ioThread = new Thread(this::ioLoop, "credlens-io");
            ioThread.setDaemon(true);
            ioThread.start();
        } catch (Exception e) {
            Log.e(TAG, "vpn start failed", e);
            CrashLog.write(this, "vpn", e);
            stopSelf();
            return START_NOT_STICKY;
        }
        return START_STICKY;
    }

    private void startForegroundNote() {
        try {
            NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
            if (Build.VERSION.SDK_INT >= 26 && nm != null) {
                nm.createNotificationChannel(new NotificationChannel(
                        CHANNEL, "CredLens engine", NotificationManager.IMPORTANCE_LOW));
            }
            Intent open = new Intent(this, MainActivity.class);
            PendingIntent pi = PendingIntent.getActivity(this, 0, open,
                    PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
            Notification.Builder b = Build.VERSION.SDK_INT >= 26
                    ? new Notification.Builder(this, CHANNEL)
                    : new Notification.Builder(this);
            Notification n = b.setContentTitle("CredLens is capturing")
                    .setContentText("Watching this phone's traffic (VPN)")
                    .setSmallIcon(R.drawable.icon)
                    .setContentIntent(pi)
                    .build();
            try {
                if (Build.VERSION.SDK_INT >= 29) {
                    startForeground(2, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC);
                } else {
                    startForeground(2, n);
                }
            } catch (Exception e) {
                try { startForeground(2, n); } catch (Exception ignored) {}
            }
        } catch (Exception ignored) {}
    }

    @Override
    public void onRevoke() {
        shutdown();
        super.onRevoke();
    }

    @Override
    public void onDestroy() {
        shutdown();
        super.onDestroy();
    }

    private void shutdown() {
        running = false;
        try { if (selector != null) selector.wakeup(); } catch (Exception ignored) {}
        try { if (tun != null) tun.close(); } catch (Exception ignored) {}
        for (UdpFlow f : udpFlows.values()) closeQuietly(f.ch);
        for (TcpFlow f : tcpFlows.values()) closeQuietly(f.ch);
        udpFlows.clear();
        tcpFlows.clear();
    }

    private static void closeQuietly(java.nio.channels.Channel ch) {
        try { if (ch != null) ch.close(); } catch (Exception ignored) {}
    }

    // ------------------------------------------------------------ python feed
    private void feed(byte[] pkt, int len) {
        try {
            if (!Python.isStarted()) return;
            byte[] copy = (len == pkt.length) ? pkt : Arrays.copyOf(pkt, len);
            Python.getInstance().getModule("credlens").callAttr(
                    "feed_external_packet",
                    System.currentTimeMillis() / 1000.0, copy);
        } catch (Throwable ignored) {}
    }

    // ------------------------------------------------------------ TUN pump
    private void pump() {
        byte[] buf = new byte[32767];
        FileInputStream in = new FileInputStream(tun.getFileDescriptor());
        try {
            while (running) {
                int n = in.read(buf);
                if (n <= 0) break;
                byte[] pkt = Arrays.copyOf(buf, n);
                feed(pkt, n);
                dispatch(pkt);
            }
        } catch (IOException e) {
            if (running) Log.e(TAG, "tun read ended", e);
        }
    }

    private void dispatch(byte[] pkt) {
        if (pkt.length < 1) return;
        int ver = (pkt[0] >> 4) & 0xF;
        if (ver == 4) {
            if (pkt.length < 20) return;
            int ihl = (pkt[0] & 0x0F) * 4;
            int proto = pkt[9] & 0xFF;
            byte[] srcIp = Arrays.copyOfRange(pkt, 12, 16);
            byte[] dstIp = Arrays.copyOfRange(pkt, 16, 20);
            if (proto == 17 && pkt.length >= ihl + 8) {
                handleUdp(pkt, ihl, srcIp, dstIp);
            } else if (proto == 6 && pkt.length >= ihl + 20) {
                handleTcp(pkt, ihl, srcIp, dstIp);
            }
        } else if (ver == 6) {
            handleV6(pkt);
        }
        // other protocols: observed (fed to Python) but not forwarded
    }

    /** IPv6: walk extension headers to the TCP/UDP header, then reuse
     *  the shared flow machinery. Returns silently for anything that
     *  cannot be forwarded (multicast, link-local, AH/ESP, fragments
     *  past the first) — the Python engine still sees those packets. */
    private void handleV6(byte[] pkt) {
        if (pkt.length < 40) return;
        byte[] srcIp = Arrays.copyOfRange(pkt, 8, 24);
        byte[] dstIp = Arrays.copyOfRange(pkt, 24, 40);
        if ((dstIp[0] & 0xFF) == 0xFF) return;          // multicast
        if (dstIp[0] == (byte) 0xFE && (dstIp[1] & 0xC0) == 0x80) return; // fe80::/10
        boolean allZero = true;
        for (byte b : dstIp) if (b != 0) { allZero = false; break; }
        if (allZero) return;
        int nh = pkt[6] & 0xFF;
        int off = 40;
        while (nh != 6 && nh != 17) {
            if (nh == 0 || nh == 43 || nh == 60) {     // HbyH / Routing / DestOpts
                if (off + 2 > pkt.length) return;
                int hlen = ((pkt[off + 1] & 0xFF) + 1) * 8;
                nh = pkt[off] & 0xFF;
                off += hlen;
            } else if (nh == 44) {                     // Fragment
                if (off + 8 > pkt.length) return;
                int frag = u16(pkt, off + 2);
                if ((frag & 0xFFF8) != 0) return;      // not the first fragment
                nh = pkt[off] & 0xFF;
                off += 8;
            } else {
                return;                                // AH, ESP, ICMPv6, unknown
            }
            if (off > pkt.length) return;
        }
        if (nh == 17 && pkt.length >= off + 8) {
            handleUdp(pkt, off, srcIp, dstIp);
        } else if (nh == 6 && pkt.length >= off + 20) {
            handleTcp(pkt, off, srcIp, dstIp);
        }
    }

    // ------------------------------------------------------------ UDP
    private static class UdpFlow {
        DatagramChannel ch;
        byte[] clientIp, serverIp;
        int clientPort, serverPort;
    }

    private void handleUdp(byte[] pkt, int ihl, byte[] srcIp, byte[] dstIp) {
        int sport = u16(pkt, ihl), dport = u16(pkt, ihl + 2);
        int ulen = u16(pkt, ihl + 4);
        String key = sport + "|" + ipStr(dstIp) + "|" + dport;
        UdpFlow f = udpFlows.get(key);
        try {
            if (f == null) {
                DatagramChannel ch = DatagramChannel.open();
                protect(ch.socket());
                ch.configureBlocking(false);
                ch.connect(new InetSocketAddress(ipStr(dstIp), dport));
                f = new UdpFlow();
                f.ch = ch; f.clientIp = srcIp; f.serverIp = dstIp;
                f.clientPort = sport; f.serverPort = dport;
                udpFlows.put(key, f);
                ch.register(selector, SelectionKey.OP_READ, f);
                selector.wakeup();
            }
            int plen = Math.min(ulen - 8, pkt.length - (ihl + 8));
            if (plen > 0) f.ch.write(ByteBuffer.wrap(pkt, ihl + 8, plen));
        } catch (IOException e) {
            udpFlows.remove(key);
            if (f != null) closeQuietly(f.ch);
        }
    }

    // ------------------------------------------------------------ TCP
    private static class TcpFlow {
        SocketChannel ch;
        byte[] clientIp, serverIp;
        int clientPort, serverPort;
        long clientNext;       // next seq expected from the client
        long serverSeq;        // our next seq toward the client
        long serverAcked;      // last ack from the client for our data
        boolean finClient, finSent, established;
        int clientWindow = 65535;
        ByteBuffer pending = ByteBuffer.allocate(0);
    }

    private void handleTcp(byte[] pkt, int ihl, byte[] srcIp, byte[] dstIp) {
        int sport = u16(pkt, ihl), dport = u16(pkt, ihl + 2);
        long seq = u32(pkt, ihl + 4), ack = u32(pkt, ihl + 8);
        int doff = ((pkt[ihl + 12] >> 4) & 0xF) * 4;
        int flags = pkt[ihl + 13] & 0xFF;
        int win = u16(pkt, ihl + 14);
        int plen = Math.max(0, pkt.length - (ihl + doff));
        String key = sport + "|" + ipStr(dstIp) + "|" + dport;
        TcpFlow f = tcpFlows.get(key);
        try {
            if (f == null) {
                if ((flags & 0x02) == 0) return;          // mid-stream: ignore
                SocketChannel ch = SocketChannel.open();
                protect(ch.socket());
                ch.configureBlocking(false);
                f = new TcpFlow();
                f.ch = ch; f.clientIp = srcIp; f.serverIp = dstIp;
                f.clientPort = sport; f.serverPort = dport;
                f.clientNext = seq + 1;
                f.serverSeq = (rnd.nextInt(1_000_000) + 1000L) & 0xFFFFFFFFL;
                f.serverAcked = f.serverSeq;
                tcpFlows.put(key, f);
                boolean done = ch.connect(new InetSocketAddress(ipStr(dstIp), dport));
                f.established = done;
                ch.register(selector, done ? SelectionKey.OP_READ
                                           : SelectionKey.OP_CONNECT, f);
                selector.wakeup();
                sendTcp(f, 0x12, null, 0, 0);             // SYN+ACK
                f.serverSeq = (f.serverSeq + 1) & 0xFFFFFFFFL;
                return;
            }
            f.clientWindow = win;
            if ((flags & 0x04) != 0) {                    // RST
                closeTcp(key, f);
                return;
            }
            if ((flags & 0x10) != 0) f.serverAcked = ack;
            if (plen > 0) {
                if (seq == f.clientNext) {
                    f.clientNext = (f.clientNext + plen) & 0xFFFFFFFFL;
                    queueOut(f, Arrays.copyOfRange(pkt, ihl + doff, ihl + doff + plen));
                    sendTcp(f, 0x10, null, 0, 0);         // ACK
                }
                // out-of-order / retransmit: drop; the client retries
            }
            if ((flags & 0x01) != 0) {                    // FIN
                f.clientNext = (f.clientNext + 1) & 0xFFFFFFFFL;
                f.finClient = true;
                sendTcp(f, 0x10, null, 0, 0);             // ACK
                maybeFin(key, f);
            }
        } catch (IOException e) {
            closeTcp(key, f);
        }
    }

    private void queueOut(TcpFlow f, byte[] data) throws IOException {
        if (f.pending.remaining() == 0 && f.established) {
            int n = f.ch.write(ByteBuffer.wrap(data));
            if (n == data.length) return;
            data = Arrays.copyOfRange(data, n, data.length);
        }
        ByteBuffer nb = ByteBuffer.allocate(f.pending.remaining() + data.length);
        nb.put(f.pending);
        nb.put(data);
        nb.flip();
        f.pending = nb;
        SelectionKey k = f.ch.keyFor(selector);
        if (k != null && k.isValid()) {
            k.interestOps(k.interestOps() | SelectionKey.OP_WRITE);
            selector.wakeup();
        }
    }

    private void maybeFin(String key, TcpFlow f) {
        if (f.finClient && !f.finSent) {
            try {
                sendTcp(f, 0x11, null, 0, 0);             // FIN+ACK
            } catch (IOException e) { /* closing anyway */ }
            f.finSent = true;
            f.serverSeq = (f.serverSeq + 1) & 0xFFFFFFFFL;
            closeTcp(key, f);
        }
    }

    private void closeTcp(String key, TcpFlow f) {
        tcpFlows.remove(key);
        closeQuietly(f.ch);
    }

    /** Build + feed + write one TCP packet toward the client. */
    private void sendTcp(TcpFlow f, int flags, byte[] payload, int off, int len)
            throws IOException {
        byte[] pkt = buildTcp(f.serverIp, f.clientIp, f.serverPort, f.clientPort,
                f.serverSeq, f.clientNext, flags, payload, off, len);
        feed(pkt, pkt.length);
        writeTun(pkt);
    }

    // ------------------------------------------------------------ IO loop
    private void ioLoop() {
        ByteBuffer buf = ByteBuffer.allocate(32767);
        try {
            while (running) {
                selector.select(250);
                Iterator<SelectionKey> it = selector.selectedKeys().iterator();
                while (it.hasNext()) {
                    SelectionKey k = it.next();
                    it.remove();
                    if (!k.isValid()) continue;
                    try {
                        if (k.attachment() instanceof UdpFlow) {
                            if (k.isReadable()) readUdp((UdpFlow) k.attachment(), buf);
                        } else if (k.attachment() instanceof TcpFlow) {
                            TcpFlow f = (TcpFlow) k.attachment();
                            if (k.isConnectable()) {
                                f.ch.finishConnect();
                                f.established = true;
                                k.interestOps(SelectionKey.OP_READ
                                        | (f.pending.remaining() > 0
                                           ? SelectionKey.OP_WRITE : 0));
                                if (f.pending.remaining() > 0) flushPending(f, k);
                            }
                            if (k.isValid() && k.isWritable()) flushPending(f, k);
                            if (k.isValid() && k.isReadable()) readTcp(f, buf, k);
                        }
                    } catch (IOException | java.nio.channels.CancelledKeyException e) {
                        Object att = k.attachment();
                        if (att instanceof TcpFlow) {
                            TcpFlow f = (TcpFlow) att;
                            closeTcp(f.clientPort + "|" + ipStr(f.serverIp) + "|" + f.serverPort, f);
                            if (!f.finSent) {
                                try {
                                    sendTcp(f, 0x11, null, 0, 0);
                                    f.finSent = true;
                                } catch (Exception ignored) {}
                            }
                        } else if (att instanceof UdpFlow) {
                            closeQuietly(((UdpFlow) att).ch);
                        }
                    }
                }
            }
        } catch (IOException e) {
            if (running) Log.e(TAG, "selector loop ended", e);
        }
    }

    private void flushPending(TcpFlow f, SelectionKey k) throws IOException {
        if (f.pending.remaining() > 0) {
            f.ch.write(f.pending);
            if (f.pending.remaining() == 0 && k.isValid()) {
                k.interestOps(k.interestOps() & ~SelectionKey.OP_WRITE);
            }
        }
    }

    private void readUdp(UdpFlow f, ByteBuffer buf) throws IOException {
        buf.clear();
        int n = f.ch.read(buf);
        if (n <= 0) return;
        byte[] payload = Arrays.copyOf(buf.array(), n);
        byte[] pkt = buildUdp(f.serverIp, f.clientIp, f.serverPort, f.clientPort, payload);
        feed(pkt, pkt.length);
        writeTun(pkt);
    }

    private void readTcp(TcpFlow f, ByteBuffer buf, SelectionKey k) throws IOException {
        buf.clear();
        int n = f.ch.read(buf);
        if (n < 0) {                                     // server closed
            if (!f.finSent) {
                sendTcp(f, 0x11, null, 0, 0);            // FIN+ACK
                f.finSent = true;
                f.serverSeq = (f.serverSeq + 1) & 0xFFFFFFFFL;
            }
            if (f.finClient) closeTcp(f.clientPort + "|" + ipStr(f.serverIp) + "|" + f.serverPort, f);
            else if (k.isValid()) k.interestOps(0);
            return;
        }
        if (n == 0) return;
        byte[] data = Arrays.copyOf(buf.array(), n);
        sendTcp(f, 0x18, data, 0, data.length);          // PSH+ACK with payload
        f.serverSeq = (f.serverSeq + data.length) & 0xFFFFFFFFL;
    }

    private void writeTun(byte[] pkt) {
        synchronized (tunLock) {
            try {
                tunOut.write(pkt);
                tunOut.flush();
            } catch (IOException ignored) {}
        }
    }

    // ------------------------------------------------------------ packet building
    private static int u16(byte[] b, int off) {
        return ((b[off] & 0xFF) << 8) | (b[off + 1] & 0xFF);
    }

    private static long u32(byte[] b, int off) {
        return ((long) (b[off] & 0xFF) << 24) | ((b[off + 1] & 0xFF) << 16)
                | ((b[off + 2] & 0xFF) << 8) | (b[off + 3] & 0xFF);
    }

    private static String ipStr(byte[] b) {
        if (b.length == 4) {
            return (b[0] & 0xFF) + "." + (b[1] & 0xFF) + "." + (b[2] & 0xFF) + "." + (b[3] & 0xFF);
        }
        try {
            return java.net.InetAddress.getByAddress(b).getHostAddress();
        } catch (Exception e) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 16; i += 2) {
                if (i > 0) sb.append(':');
                sb.append(Integer.toHexString(((b[i] & 0xFF) << 8) | (b[i + 1] & 0xFF)));
            }
            return sb.toString();
        }
    }

    private static int checksum(byte[] data, int off, int len, int initial) {
        long sum = initial;
        int i = off;
        while (len > 1) {
            sum += ((data[i] & 0xFF) << 8) | (data[i + 1] & 0xFF);
            i += 2;
            len -= 2;
        }
        if (len == 1) sum += (data[i] & 0xFF) << 8;
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return (int) (~sum & 0xFFFF);
    }

    private static byte[] ipv4(byte[] src, byte[] dst, int proto, byte[] l4) {
        byte[] pkt = new byte[20 + l4.length];
        pkt[0] = 0x45;
        int total = pkt.length;
        pkt[2] = (byte) (total >> 8);
        pkt[3] = (byte) total;
        pkt[6] = 0x40;                                   // don't fragment
        pkt[8] = 64;                                     // TTL
        pkt[9] = (byte) proto;
        System.arraycopy(src, 0, pkt, 12, 4);
        System.arraycopy(dst, 0, pkt, 16, 4);
        System.arraycopy(l4, 0, pkt, 20, l4.length);
        int c = checksum(pkt, 0, 20, 0);
        pkt[10] = (byte) (c >> 8);
        pkt[11] = (byte) c;
        return pkt;
    }

    private static byte[] buildUdp(byte[] src, byte[] dst, int sport, int dport, byte[] payload) {
        byte[] l4 = new byte[8 + payload.length];
        l4[0] = (byte) (sport >> 8); l4[1] = (byte) sport;
        l4[2] = (byte) (dport >> 8); l4[3] = (byte) dport;
        int len = l4.length;
        l4[4] = (byte) (len >> 8); l4[5] = (byte) len;
        System.arraycopy(payload, 0, l4, 8, payload.length);
        if (src.length == 16) {
            // IPv6 UDP checksum is MANDATORY — over the v6 pseudo-header.
            int c = checksum(l4, 0, l4.length, pseudo6(src, dst, 17, l4.length));
            l4[6] = (byte) (c >> 8); l4[7] = (byte) c;
            return ipv6(src, dst, 17, l4);
        }
        // IPv4 UDP checksum is optional — leave 0.
        return ipv4(src, dst, 17, l4);
    }

    private static byte[] buildTcp(byte[] src, byte[] dst, int sport, int dport,
                                   long seq, long ack, int flags,
                                   byte[] payload, int off, int len) {
        int plen = (payload == null) ? 0 : len;
        byte[] l4 = new byte[20 + plen];
        l4[0] = (byte) (sport >> 8); l4[1] = (byte) sport;
        l4[2] = (byte) (dport >> 8); l4[3] = (byte) dport;
        l4[4] = (byte) (seq >> 24); l4[5] = (byte) (seq >> 16);
        l4[6] = (byte) (seq >> 8); l4[7] = (byte) seq;
        l4[8] = (byte) (ack >> 24); l4[9] = (byte) (ack >> 16);
        l4[10] = (byte) (ack >> 8); l4[11] = (byte) ack;
        l4[12] = (byte) (5 << 4);
        l4[13] = (byte) flags;
        l4[14] = (byte) (65535 >> 8); l4[15] = (byte) 65535;
        if (payload != null && plen > 0) System.arraycopy(payload, off, l4, 20, plen);
        if (src.length == 16) {
            int c = checksum(l4, 0, l4.length, pseudo6(src, dst, 6, l4.length));
            l4[16] = (byte) (c >> 8);
            l4[17] = (byte) c;
            return ipv6(src, dst, 6, l4);
        }
        // TCP checksum over the IPv4 pseudo-header + segment
        long sum = 0;
        sum += ((src[0] & 0xFF) << 8) | (src[1] & 0xFF);
        sum += ((src[2] & 0xFF) << 8) | (src[3] & 0xFF);
        sum += ((dst[0] & 0xFF) << 8) | (dst[1] & 0xFF);
        sum += ((dst[2] & 0xFF) << 8) | (dst[3] & 0xFF);
        sum += 6;
        sum += l4.length;
        int c = checksum(l4, 0, l4.length, (int) sum);
        l4[16] = (byte) (c >> 8);
        l4[17] = (byte) c;
        return ipv4(src, dst, 6, l4);
    }

    /** IPv6 pseudo-header sum for a checksum: src + dst + length + next. */
    private static int pseudo6(byte[] src, byte[] dst, int next, int len) {
        long sum = 0;
        for (int i = 0; i < 16; i += 2) {
            sum += ((src[i] & 0xFF) << 8) | (src[i + 1] & 0xFF);
            sum += ((dst[i] & 0xFF) << 8) | (dst[i + 1] & 0xFF);
        }
        sum += (len >> 16) & 0xFFFF;
        sum += len & 0xFFFF;
        sum += next;
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return (int) sum;
    }

    private static byte[] ipv6(byte[] src, byte[] dst, int next, byte[] l4) {
        byte[] pkt = new byte[40 + l4.length];
        pkt[0] = 0x60;                                   // version 6
        int total = l4.length;
        pkt[4] = (byte) (total >> 8);
        pkt[5] = (byte) total;
        pkt[6] = (byte) next;
        pkt[7] = 64;                                     // hop limit
        System.arraycopy(src, 0, pkt, 8, 16);
        System.arraycopy(dst, 0, pkt, 24, 16);
        System.arraycopy(l4, 0, pkt, 40, l4.length);
        return pkt;
    }
}
