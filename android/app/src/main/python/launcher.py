"""Chaquopy entry point: launch the bundled CredLens server.

The CredLens tree is copied by MainActivity into app-private storage
before this is called, so every __file__-relative write in credlens.py
(settings, session recording) lands somewhere writable. Capture on
Android comes from the Java VpnService: it feeds raw IP packets into
credlens.feed_external_packet() and polls credlens.vpn_wanted().
"""
import os
import sys
import traceback

_started = False


def start_server(workdir):
    global _started
    if _started:
        return "already running"
    _started = True
    try:
        os.environ["CREDLENS_ANDROID"] = "1"
        os.chdir(workdir)
        if workdir not in sys.path:
            sys.path.insert(0, workdir)
        sys.argv = ["credlens.py", "--port", "8890"]
        import credlens
        credlens.main()
        return "server exited"
    except Exception:
        try:
            with open(os.path.join(workdir, "server-error.log"), "w") as fh:
                fh.write(traceback.format_exc())
        except Exception:
            pass
        traceback.print_exc()
        return "error"
    finally:
        _started = False
