# Building

## Windows exe (PyInstaller)

From the project directory on Windows:

```powershell
python -m PyInstaller CredLens.spec --noconfirm
```

The spec bundles `index.html`, `mobile.html`, and `test.pcap` next to
the exe. The scheduled-task build used during development runs the same
spec; the live app itself runs the Python sources, not the exe.

## Android APK (Gradle + Chaquopy)

Requirements: JDK 17, Gradle 8.9, Android SDK (cmdline tools,
platform 34, build-tools 34), Chaquopy 16.0.0 / Python 3.11.

```bash
cd android
gradle assembleRelease --no-daemon
# -> app/build/outputs/apk/release/app-release.apk
```

The Python payload lives in `app/src/main/assets/credlens/` and is kept
in sync with the top-level sources. The Java shell calls two Python
entry points: `credlens.vpn_wanted()` and
`credlens.feed_external_packet()`.

### tcpdump for rooted hotspot watch

The bundled `app/src/main/assets/tcpdump` is built from source, not
downloaded: libpcap 1.10.4 + tcpdump 4.99.4, cross-compiled with
`aarch64-linux-android24-clang` (NDK r27c), statically linked and
stripped. Rebuild it the same way if you need a different architecture.

### Signing

This tree ships **no** release signing config and no keystore. Create
your own keystore and add a `signingConfigs.release` block to
`android/app/build.gradle` before building a release APK.
