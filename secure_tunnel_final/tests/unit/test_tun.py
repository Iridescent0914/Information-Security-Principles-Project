import os
import signal
import time

from tun_utils import create_tun


tun_fd = None


def cleanup(signum=None, frame=None):
    global tun_fd

    print("\n[TUN] Closing test TUN")

    if tun_fd is not None:
        os.close(tun_fd)
        tun_fd = None

    raise SystemExit(0)


signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)


tun_fd, tun_name = create_tun()

print(f"[PASS] TUN created: {tun_name}")
print(f"[INFO] tun_fd = {tun_fd}")
print("[INFO] Keep this process running.")
print("[INFO] Press Ctrl+C after the interface test.")

while True:
    time.sleep(1)
