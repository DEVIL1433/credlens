package com.devil.credlens;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.IBinder;
import android.os.PowerManager;
import android.util.Log;

import com.chaquo.python.Python;
import com.chaquo.python.android.AndroidPlatform;

import java.io.File;

public class CredLensService extends Service {
    private static final String CHANNEL = "credlens";
    private static final String TAG = "CredLensSvc";
    private Thread worker;
    private Thread vpnWatch;
    private PowerManager.WakeLock wakeLock;

    @Override
    public void onCreate() {
        super.onCreate();
        try {
            PowerManager pm = (PowerManager) getSystemService(POWER_SERVICE);
            if (pm != null) {
                wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "CredLens::engine");
                wakeLock.setReferenceCounted(false);
                wakeLock.acquire(4 * 60 * 60 * 1000L);
            }
        } catch (Exception e) {
            Log.e(TAG, "wakelock failed", e);
        }
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
            Notification n = b.setContentTitle("CredLens is running")
                    .setContentText("Analysis engine on 127.0.0.1:8890")
                    .setSmallIcon(R.drawable.icon)
                    .setContentIntent(pi)
                    .build();
            try {
                if (Build.VERSION.SDK_INT >= 29) {
                    startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC);
                } else {
                    startForeground(1, n);
                }
            } catch (Exception e) {
                Log.e(TAG, "typed startForeground failed, retrying untyped", e);
                try { startForeground(1, n); } catch (Exception e2) {
                    Log.e(TAG, "startForeground failed entirely", e2);
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "onCreate notification setup failed", e);
        }
        startVpnWatch();
    }

    /** Enforcer: keep the VPN service in step with the Python side's
     *  vpn_wanted() flag (set by the web UI's Live/Stop buttons). */
    private void startVpnWatch() {
        if (vpnWatch != null && vpnWatch.isAlive()) return;
        vpnWatch = new Thread(() -> {
            boolean running = false;
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    Thread.sleep(1000);
                    if (!Python.isStarted()) continue;
                    boolean want = Python.getInstance().getModule("credlens")
                            .callAttr("vpn_wanted").toBoolean();
                    if (want && !running) {
                        if (android.net.VpnService.prepare(getApplicationContext()) == null) {
                            startService(new Intent(getApplicationContext(), CredVpnService.class));
                            running = true;
                        }
                    } else if (!want && running) {
                        stopService(new Intent(getApplicationContext(), CredVpnService.class));
                        running = false;
                    } else if (want && running
                            && !CredVpnService.isRunning()) {
                        running = false;   // it died (revoked?) — allow restart
                    }
                } catch (InterruptedException e) {
                    return;
                } catch (Throwable t) {
                    // Python not ready yet / transient — keep watching.
                    try { Thread.sleep(1000); } catch (InterruptedException e) { return; }
                }
            }
        }, "credlens-vpn-watch");
        vpnWatch.setDaemon(true);
        vpnWatch.start();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (worker != null && !worker.isAlive()) worker = null;
        if (worker == null) {
            worker = new Thread(() -> {
                try {
                    if (!Python.isStarted()) {
                        Python.start(new AndroidPlatform(getApplicationContext()));
                    }
                    extractTcpdump();
                    File dir = new File(getFilesDir(), "credlens");
                    Python.getInstance().getModule("launcher")
                            .callAttr("start_server", dir.getAbsolutePath());
                } catch (Throwable t) {
                    Log.e(TAG, "python engine failed", t);
                    CrashLog.write(this, "engine", t);
                } finally {
                    worker = null;
                }
            }, "credlens-server");
            worker.setDaemon(true);
            worker.start();
        }
        return START_STICKY;
    }

    /** Bundled static tcpdump (assets/tcpdump) -> private files dir,
     *  executable, path handed to the Python engine. Absent in builds
     *  without the binary: the engine then falls back to a system
     *  tcpdump under su, and reports clearly if neither exists. */
    private void extractTcpdump() {
        try {
            java.io.InputStream in = getAssets().open("tcpdump");
            File out = new File(getFilesDir(), "tcpdump");
            long assetLen = -1;
            try { assetLen = in.available(); } catch (Exception ignored) {}
            if (!out.exists() || (assetLen > 0 && out.length() != assetLen)) {
                java.io.OutputStream os = new java.io.FileOutputStream(out);
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) > 0) os.write(buf, 0, n);
                os.close();
            }
            in.close();
            out.setExecutable(true, false);
            Python.getInstance().getModule("credlens")
                    .callAttr("set_tcpdump_path", out.getAbsolutePath());
        } catch (Exception ignored) {}
    }

    @Override
    public void onDestroy() {
        try {
            if (vpnWatch != null) vpnWatch.interrupt();
            if (wakeLock != null && wakeLock.isHeld()) wakeLock.release();
        } catch (Exception ignored) {}
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
