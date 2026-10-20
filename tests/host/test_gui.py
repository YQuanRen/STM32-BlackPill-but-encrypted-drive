"""Real Tk controller + real firmware DLL workflows. No physical HID access."""
import ctypes as C
import hashlib
from pathlib import Path
import sys
import tempfile
import threading
import time
import tkinter as tk
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'host'))
import bpctl as bp
from bpworkflow import Service, Device
from gui import App

lib = C.CDLL(str(Path(sys.argv.pop(1)).resolve()))
for name, args, result in [
    ('sim_fresh', [], None), ('sim_reset', [], None), ('sim_step', [], None),
    ('sim_request', [C.c_void_p, C.c_size_t, C.c_void_p], C.c_size_t),
    ('sim_capacity', [], C.c_uint32), ('sim_writes', [], C.c_int),
    ('sim_card', [C.c_int, C.c_int], None),
    ('sim_fault', [C.c_int, C.c_int, C.c_int], None),
    ('sim_geometry', [C.c_uint32], None),
    ('sim_write', [C.c_uint32, C.c_void_p, C.c_uint16], C.c_int),
    ('sim_read', [C.c_uint32, C.c_void_p, C.c_uint16], C.c_int),
]:
    fn = getattr(lib, name)
    fn.argtypes, fn.restype = args, result

IDENTITY = (bytes(range(1, 13)) + bytes(4)).hex()
PASSWORD = 'GUI test \u2603'


class Wire:
    closed = 0
    paths = []
    def __init__(self, path):
        self.paths.append(path)
        self.path = path
    def exchange(self, data):
        out = C.create_string_buffer(256)
        n = lib.sim_request(data, len(data), out)
        response = out.raw[:n]
        if self.path == b'other' and data[1] == 1:
            response = response[:9] + bytes([99]) + response[10:]
        return response
    def close(self):
        Wire.closed += 1


def advance(_):
    for _ in range(49):
        lib.sim_step()


def service():
    return Service(lambda: [{'path': b'one'}], Wire, advance)


class Workflows(unittest.TestCase):
    def setUp(self):
        lib.sim_fresh()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / 'auth.json')
        self.service = service()
        self.device = self.service.discover()[0]

    def setup_volume(self, mode=2):
        ticket = self.service.prepare(self.device, self.path, mode, True)
        self.assertEqual(lib.sim_writes(), 0)
        self.service.initialize(ticket, PASSWORD, ticket.phrase)
        return ticket

    def test_both_modes_file_hash_reconnect(self):
        for mode in (1, 2):
            with self.subTest(mode=mode):
                lib.sim_fresh()
                path = str(Path(self.tmp.name) / f'{mode}.json')
                ticket = self.service.prepare(self.device, path, mode, True)
                progress = []
                self.service.initialize(ticket, PASSWORD, ticket.phrase, lambda a, b: progress.append((a, b)))
                self.assertEqual(lib.sim_capacity(), 48)
                self.assertEqual(progress[-1], (48, 48))
                content = hashlib.shake_256(b'GUI workflow data').digest(1536)
                source = C.create_string_buffer(content, 1536)
                self.assertEqual(lib.sim_write(4, source, 3), 0)
                lib.sim_reset()
                self.service.unlock(self.device, path, PASSWORD)
                output = C.create_string_buffer(1536)
                self.assertEqual(lib.sim_read(4, output, 3), 0)
                self.assertEqual(hashlib.sha256(content).digest(), hashlib.sha256(output.raw).digest())

    def test_confirmation_card_swap_password_and_wrong_file(self):
        ticket = self.service.prepare(self.device, self.path, 2, True)
        with self.assertRaises(bp.ProtocolError):
            self.service.initialize(ticket, PASSWORD, 'ERASE')
        lib.sim_card(1, 1)
        with self.assertRaises(bp.ProtocolError):
            self.service.initialize(ticket, PASSWORD, ticket.phrase)
        self.assertEqual(lib.sim_writes(), 0)
        lib.sim_card(1, 0)
        self.service.initialize(ticket, PASSWORD, ticket.phrase)
        lib.sim_reset()
        with self.assertRaises(bp.ProtocolError):
            self.service.unlock(self.device, self.path, 'wrong')
        self.assertEqual(lib.sim_capacity(), 0)
        wrong = str(Path(self.tmp.name) / 'wrong.json')
        bp.save_file(wrong, bytes(16), bytes(32), 2)
        with self.assertRaises(bp.ProtocolError):
            self.service.unlock(self.device, wrong, PASSWORD)
        self.service.unlock(self.device, self.path, PASSWORD)

    def test_disconnect_restart_and_mode_change(self):
        ticket = self.service.prepare(self.device, self.path, 2, True)
        lib.sim_fault(20, 0, 0)
        with self.assertRaises(bp.ProtocolError):
            self.service.initialize(ticket, PASSWORD, ticket.phrase)
        self.assertEqual(lib.sim_capacity(), 0)
        lib.sim_fault(-1, 0, 0)
        lib.sim_reset()
        ticket = self.service.prepare(self.device, self.path, 1)
        self.service.initialize(ticket, '', ticket.phrase)
        lib.sim_reset()
        self.service.unlock(self.device, self.path, '')
        self.assertEqual(lib.sim_capacity(), 48)

    def test_identity_and_duplicate_selection(self):
        multi = Service(lambda: [{'path': b'one'}, {'path': b'other'}], Wire, advance)
        devices = multi.discover()
        self.assertEqual(len(devices), 2)
        stale = Device(b'other', IDENTITY, 0, 2)
        with self.assertRaises(bp.ProtocolError):
            multi.prepare(stale, self.path, 2, True)
        self.assertFalse(Path(self.path).exists())
        duplicate = Service(lambda: [{'path': b'one'}, {'path': b'one'}], Wire)
        with self.assertRaises(bp.ProtocolError):
            duplicate.discover()
        self.assertGreater(Wire.closed, 0)

    def test_exclusive_file_and_stale_credential_hint(self):
        self.setup_volume()
        original = Path(self.path).read_bytes()
        lib.sim_reset()
        with self.assertRaises(bp.ProtocolError):
            self.service.prepare(self.device, self.path, 2, True)
        self.assertEqual(Path(self.path).read_bytes(), original)

    def test_initialization_stall_is_reported(self):
        ticket = self.service.prepare(self.device, self.path, 2, True)
        self.service.sleep = lambda _: None
        with patch('bpworkflow.time.monotonic', side_effect=[0, 0, 301]):
            with self.assertRaisesRegex(bp.ProtocolError, 'no progress'):
                self.service.initialize(ticket, PASSWORD, ticket.phrase)
        self.assertEqual(lib.sim_capacity(), 0)

    def test_large_card_fast_progress(self):
        lib.sim_geometry(122167296)
        ticket = self.service.prepare(self.device, self.path, 2, True)
        progress = []
        self.service.initialize(ticket, PASSWORD, ticket.phrase, lambda a, b: progress.append((a,b)))
        self.assertEqual(progress[-1], (67,67))
        self.assertEqual(lib.sim_writes(), 99)
        self.assertEqual(lib.sim_capacity(), 122167280)


class GUI(unittest.TestCase):
    def setUp(self):
        Workflows.setUp(self)
        self.root = tk.Tk()
        self.root.withdraw()
        self.app = App(self.root, self.service, auto_scan=False)
        self.addCleanup(self.root.destroy)

    def pump(self):
        deadline = time.monotonic() + 15
        while self.app.busy and time.monotonic() < deadline:
            self.root.update()
            time.sleep(.01)
        self.root.update()
        self.assertFalse(self.app.busy, 'GUI operation timed out')

    def scan(self):
        self.app.scan()
        self.pump()

    def test_full_gui_setup_unlock_and_errors(self):
        self.scan()
        self.assertEqual(self.app.action.get(), 'setup')
        self.app.file.set(self.path)
        self.app.create_file = True
        self.app.submit()
        self.pump()
        ticket = self.app.setup
        self.assertIsNotNone(ticket)
        self.assertEqual(lib.sim_writes(), 0)
        self.assertIn(IDENTITY, self.app.card_text.get())
        self.assertIn("NOT erase old data", self.app.detail.get())
        self.assertIn("Old data may remain recoverable", self.app.card_text.get())
        self.app.password.set(PASSWORD)
        self.app.repeat.set('different')
        self.app.confirmation.set(ticket.phrase)
        self.app.submit()
        self.assertFalse(self.app.busy)
        self.assertEqual(lib.sim_writes(), 0)
        self.app.repeat.set(PASSWORD)
        self.app.submit()
        self.pump()
        self.assertEqual(lib.sim_capacity(), 48)
        self.assertEqual(self.app.password.get(), '')
        self.assertTrue(self.app.primary.instate(['disabled']))
        self.assertIn("QUICK-format through the Black Pill", self.app.status.get())
        lib.sim_reset()
        self.scan()
        self.assertEqual(self.app.action.get(), 'unlock')
        self.app.file.set(self.path)
        self.app.password.set('wrong')
        self.app.submit()
        self.pump()
        self.assertEqual(lib.sim_capacity(), 0)
        self.assertIn('Wrong password', self.app.status.get())
        self.app.password.set(PASSWORD)
        self.app.submit()
        self.pump()
        self.assertEqual(lib.sim_capacity(), 48)
        self.assertIn('Safely eject', self.app.status.get())

    def test_busy_state_event_loop_and_close(self):
        self.scan()
        gate = threading.Event()
        self.app.launch(lambda: gate.wait(5), lambda _: None)
        self.assertTrue(self.app.primary.instate(['disabled']))
        self.assertEqual(str(self.app.selector['state']), 'disabled')
        marker = []
        self.root.after(1, lambda: marker.append(True))
        time.sleep(.01)
        self.root.update()
        self.assertTrue(marker)  # Main event loop remains responsive while worker waits.
        with patch('gui.messagebox.showinfo') as dialog:
            self.app.close()
            dialog.assert_called_once()
        gate.set()
        self.pump()

    def test_multi_device_selection_and_file_dialog_cancellation(self):
        self.app.service = Service(lambda: [{'path': b'one'}, {'path': b'other'}], Wire)
        self.scan()
        self.assertIsNone(self.app.current())
        self.assertTrue(self.app.primary.instate(['disabled']))
        self.app.selector.current(1)
        self.app.selected()
        with patch('gui.filedialog.asksaveasfilename', return_value=''):
            self.app.save_file()
        self.assertEqual(self.app.file.get(), '')
        self.assertFalse(self.app.create_file)
        with patch('gui.filedialog.askopenfilename', return_value=''):
            self.app.choose_file()
        self.assertEqual(lib.sim_writes(), 0)
        self.assertEqual(self.app.current().path, b'other')


if __name__ == '__main__':
    unittest.main()
