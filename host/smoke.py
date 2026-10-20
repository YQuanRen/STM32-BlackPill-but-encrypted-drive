"""Packaged runtime check; never enumerates devices or opens a HID path."""
import json
import platform
from pathlib import Path


def run(destination):
    import tkinter as tk
    import hid
    import bpctl as bp
    import volume
    from gui import App
    root = tk.Tk()
    root.withdraw()
    try:
        class NoHardware:
            def discover(self):
                raise RuntimeError("Self-test must not access hardware")
        app = App(root, NoHardware(), auto_scan=False)
        root.update()
        if app.current() is not None or not app.primary.instate(['disabled']):
            raise RuntimeError("Invalid initial GUI state")
        identity = bytes(range(16))
        secret = bytes(range(32))  # Self-test only, never used with a device.
        h, key = volume.build(identity, secret, 2, bytes(16), 32, "runtime test")
        ready = bytearray(h)
        ready[12:16] = (2).to_bytes(4, 'little')
        auth, _ = bp.file_keys(secret, identity)
        ready[224:] = bp.mac(auth, b'BP1/header', ready[:224])
        if volume.unwrap(bytes(ready), identity, secret, "runtime test") != key:
            raise RuntimeError("Crypto runtime check failed")
        handle = hid.device()
        handle.close()  # Import/load the native HID module without opening any device.
        Path(destination).write_text(json.dumps({
            "passed": True, "python": platform.python_version(),
            "architecture": platform.machine(), "tk": root.tk.call("info", "patchlevel"),
            "checks": ["Tk widgets", "native HID import", "Argon2id", "AES-GCM/HKDF wrapping"],
            "hardware_accessed": False,
        }, indent=2), encoding="utf-8")
    finally:
        root.destroy()
