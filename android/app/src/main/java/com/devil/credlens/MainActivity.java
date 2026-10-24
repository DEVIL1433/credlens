package com.devil.credlens;

import android.Manifest;
import android.app.Activity;
import android.app.DownloadManager;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.res.AssetManager;
import android.net.Uri;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.CookieManager;
import android.webkit.URLUtil;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.FrameLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class MainActivity extends Activity {
    private static final String VERSION_MARK = "1.6-cl1";
    private static final String APPV = "v1.6";
    private static final int VPN_REQ = 2002;
    private WebView web;
    private TextView splash;
    private volatile boolean booting = false;
    private int bootRetries = 0;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                        != PackageManager.PERMISSION_GRANTED) {
            try {
                requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 1001);
            } catch (Exception ignored) {}
        }
        // Ask for VPN consent up front; capture starts only when the
        // user presses Live in the UI, but consent is a one-time dialog.
        try {
            Intent prep = VpnService.prepare(this);
            if (prep != null) startActivityForResult(prep, VPN_REQ);
        } catch (Exception ignored) {}

        FrameLayout root = new FrameLayout(this);
        splash = new TextView(this);
        splash.setTextSize(15);
        splash.setPadding(48, 24, 48, 48);
        String prior = CrashLog.read(this);
        String prevStage = readStage();
        boolean prevOk = new File(getFilesDir(), "boot-ok").exists();
        new File(getFilesDir(), "boot-ok").delete();
        splash.setText("starting..."
                + (!prevOk && !prevStage.isEmpty()
                    ? "\n\nLast time it stopped at stage: " + prevStage : "")
                + (prior.isEmpty() ? ""
                    : "\n\n--- previous crash (screenshot this for Gideon) ---\n" + tail(prior, 1500)));
        android.widget.LinearLayout splashBox = new android.widget.LinearLayout(this);
        splashBox.setOrientation(android.widget.LinearLayout.VERTICAL);
        android.widget.ImageView splashIcon = new android.widget.ImageView(this);
        try { splashIcon.setImageResource(R.drawable.icon); } catch (Exception ignored) {}
        android.widget.LinearLayout.LayoutParams iconParams =
                new android.widget.LinearLayout.LayoutParams(192, 192);
        iconParams.gravity = android.view.Gravity.CENTER_HORIZONTAL;
        iconParams.topMargin = 96;
        splashBox.addView(splashIcon, iconParams);
        android.widget.TextView splashMark = new android.widget.TextView(this);
        splashMark.setText("CREDLENS");
        splashMark.setTextSize(28);
        splashMark.setTypeface(null, android.graphics.Typeface.BOLD);
        splashMark.setGravity(android.view.Gravity.CENTER_HORIZONTAL);
        splashMark.setPadding(0, 16, 0, 0);
        splashBox.addView(splashMark);
        android.widget.TextView splashTag = new android.widget.TextView(this);
        splashTag.setText("See the traffic. Detect the exposure.");
        splashTag.setTextSize(14);
        splashTag.setGravity(android.view.Gravity.CENTER_HORIZONTAL);
        splashTag.setPadding(0, 6, 0, 24);
        splashBox.addView(splashTag);
        splash.setLayoutParams(new android.widget.LinearLayout.LayoutParams(
                android.view.ViewGroup.LayoutParams.MATCH_PARENT,
                android.view.ViewGroup.LayoutParams.WRAP_CONTENT));
        splashBox.addView(splash);
        ScrollView scroll = new ScrollView(this);
        scroll.addView(splashBox);
        root.addView(scroll, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));

        try {
            web = new WebView(this);
        } catch (Throwable t) {
            CrashLog.write(this, "webview-create", t);
            splash.setText("CREDLENS " + APPV + "\nWebView failed to start:\n" + t
                    + "\n\nScreenshot this for Gideon.");
            setContentView(root);
            return;
        }
        web.setVisibility(View.INVISIBLE);
        WebSettings ws = web.getSettings();
        ws.setJavaScriptEnabled(true);
        ws.setDomStorageEnabled(true);
        ws.setLoadWithOverviewMode(false);
        ws.setUseWideViewPort(false);
        ws.setBuiltInZoomControls(false);
        ws.setDisplayZoomControls(false);
        ws.setAllowFileAccess(false);
        ws.setAllowContentAccess(false);
        web.setWebViewClient(new WebViewClient() {
            @Override
            public void onReceivedError(WebView view, WebResourceRequest req,
                                        WebResourceError err) {
                if (req.isForMainFrame() && bootRetries < 3) {
                    bootRetries++;
                    web.setVisibility(View.INVISIBLE);
                    stage("Engine unreachable — restarting (try "
                            + bootRetries + "/3)...");
                    startBoot();
                }
            }
        });
        // Report / PCAP downloads go to the system Downloads folder.
        web.setDownloadListener((url, userAgent, contentDisposition, mimeType, length) -> {
            try {
                String name = URLUtil.guessFileName(url, contentDisposition, mimeType);
                DownloadManager.Request req = new DownloadManager.Request(Uri.parse(url));
                req.setMimeType(mimeType);
                req.setTitle(name);
                req.setDescription("CredLens download");
                req.setNotificationVisibility(
                        DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED);
                req.setDestinationInExternalPublicDir(Environment.DIRECTORY_DOWNLOADS, name);
                String cookies = CookieManager.getInstance().getCookie(url);
                if (cookies != null) req.addRequestHeader("Cookie", cookies);
                req.addRequestHeader("User-Agent", userAgent);
                ((DownloadManager) getSystemService(DOWNLOAD_SERVICE)).enqueue(req);
                Toast.makeText(this, "Downloading " + name + " to Downloads",
                        Toast.LENGTH_LONG).show();
            } catch (Exception e) {
                Toast.makeText(this, "Download failed: " + e.getMessage(),
                        Toast.LENGTH_LONG).show();
            }
        });
        root.addView(web, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        setContentView(root);

        startBoot();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == VPN_REQ && resultCode != RESULT_OK) {
            Toast.makeText(this, "Without VPN permission, CredLens can analyze "
                    + "PCAP files but cannot capture this phone's traffic.",
                    Toast.LENGTH_LONG).show();
        }
    }

    private void startBoot() {
        if (booting) return;
        booting = true;
        new Thread(() -> {
            try {
                try {
                    stage("copying app files...");
                    ensureCopied();
                    stage("starting engine...");
                    Intent svc = new Intent(this, CredLensService.class);
                    if (Build.VERSION.SDK_INT >= 26) {
                        startForegroundService(svc);
                    } else {
                        startService(svc);
                    }
                } catch (Throwable t) {
                    CrashLog.write(this, "boot", t);
                    stage("START FAILED:\n" + t + "\n\nScreenshot this for Gideon.");
                    return;
                }
                for (int i = 0; i < 90; i++) {
                    if (portOpen()) {
                        bootRetries = 0;
                        try (OutputStream o = new FileOutputStream(
                                new File(getFilesDir(), "boot-ok"))) {
                            o.write(1);
                        } catch (Exception ignored) {}
                        runOnUiThread(() -> {
                            web.setVisibility(View.VISIBLE);
                            web.loadUrl("http://127.0.0.1:8890/mobile.html");
                        });
                        return;
                    }
                    if (i % 10 == 9) stage("waiting for engine... " + (i + 1) + "s");
                    try { Thread.sleep(1000); } catch (InterruptedException ignored) {}
                }
                String err = "";
                try {
                    File log = new File(new File(getFilesDir(), "credlens"), "server-error.log");
                    if (log.exists()) {
                        java.util.Scanner s = new java.util.Scanner(log, "UTF-8").useDelimiter("\\A");
                        err = s.hasNext() ? s.next() : "";
                    }
                } catch (Exception ignored) {}
                stage("Engine did not start in 90s.\n\n" + tail(err, 1500)
                        + "\nScreenshot this for Gideon.");
            } finally {
                booting = false;
            }
        }, "credlens-boot").start();
    }

    private static String tail(String s, int n) {
        return s.length() <= n ? s : s.substring(s.length() - n);
    }

    private void stage(String msg) {
        try (OutputStream o = new FileOutputStream(new File(getFilesDir(), "stage.txt"))) {
            o.write(msg.getBytes("UTF-8"));
        } catch (Exception ignored) {}
        runOnUiThread(() -> splash.setText("CREDLENS " + APPV + "\n" + msg));
    }

    private String readStage() {
        try {
            File f = new File(getFilesDir(), "stage.txt");
            if (!f.exists()) return "";
            java.util.Scanner s = new java.util.Scanner(f, "UTF-8").useDelimiter("\\A");
            return s.hasNext() ? s.next() : "";
        } catch (Exception e) {
            return "";
        }
    }

    private boolean portOpen() {
        try (Socket s = new Socket()) {
            s.connect(new java.net.InetSocketAddress("127.0.0.1", 8890), 500);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private void ensureCopied() throws IOException {
        File dest = new File(getFilesDir(), "credlens");
        File mark = new File(dest, ".apk-version");
        if (mark.exists()) {
            try (InputStream in = new java.io.FileInputStream(mark)) {
                byte[] buf = new byte[32];
                int n = in.read(buf);
                String v = new String(buf, 0, Math.max(n, 0), "UTF-8").trim();
                if (VERSION_MARK.equals(v)) return;
            } catch (Exception ignored) {}
        }
        copyAssetDir("credlens", dest);
        try (OutputStream out = new FileOutputStream(mark)) {
            out.write(VERSION_MARK.getBytes("UTF-8"));
        }
    }

    private void copyAssetDir(String assetPath, File dest) throws IOException {
        AssetManager am = getAssets();
        String[] items = am.list(assetPath);
        if (items == null || items.length == 0) {
            copyAssetFile(assetPath, dest);
            return;
        }
        if (!dest.exists()) dest.mkdirs();
        for (String item : items) {
            copyAssetDir(assetPath + "/" + item, new File(dest, item));
        }
    }

    private void copyAssetFile(String assetPath, File dest) throws IOException {
        File parent = dest.getParentFile();
        if (parent != null && !parent.exists()) parent.mkdirs();
        try (InputStream in = getAssets().open(assetPath);
             OutputStream out = new FileOutputStream(dest)) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
        }
    }

    @Override
    public void onBackPressed() {
        if (web != null && web.canGoBack()) {
            web.goBack();
        } else {
            super.onBackPressed();
        }
    }

    @Override
    protected void onDestroy() {
        if (web != null) web.destroy();
        super.onDestroy();
    }
}
