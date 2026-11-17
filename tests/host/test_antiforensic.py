"""Anti-forensic host workflows against the real firmware DLL. No physical HID.

Run exactly like tests/host/test_gui.py, passing the storage simulator built from
tests/storage (it now wires the DESTROY hook):

    python tests/host/test_antiforensic.py build/storage-host/Debug/storage_sim.dll

Requires the host crypto dependencies (cryptography, argon2-cffi). These tests were
authored alongside the firmware DESTROY logic test (tests/antiforensic/test_destroy.c,
which runs standalone with only a C compiler) but execute the host Python paths.
"""
import ctypes as C
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'host'))
import bpctl as bp
from bpworkflow import Service, Device
import volume

lib = C.CDLL(str(Path(sys.argv.pop(1)).resolve()))
for name, args, result in [
    ('sim_fresh', [], None), ('sim_reset', [], None), ('sim_step', [], None),
    ('sim_request', [C.c_void_p, C.c_size_t, C.c_void_p], C.c_size_t),
    ('sim_capacity', [], C.c_uint32), ('sim_writes', [], C.c_int),
    ('sim_geometry', [C.c_uint32], None),
]:
    fn = getattr(lib, name)
    fn.argtypes, fn.restype = args, result

PASSWORD = 'Real pass ☃ 9!'
DECOY = 'decoy pass 4@'


class Wire:
    def __init__(self, path):
        self.path = path
    def exchange(self, data):
        out = C.create_string_buffer(256)
        n = lib.sim_request(data, len(data), out)
        return out.raw[:n]
    def close(self):
        pass


def advance(_):
    for _ in range(49):
        lib.sim_step()


def service():
    return Service(lambda: [{'path': b'one'}], Wire, advance)


class HostFlows(unittest.TestCase):
    def setUp(self):
        lib.sim_fresh()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / 'auth.json')
        self.service = service()
        self.device = self.service.discover()[0]

    def setup_encrypted(self, version=2):
        ticket = self.service.prepare(self.device, self.path, 2, True, version)
        self.service.initialize(ticket, PASSWORD, ticket.phrase)

    # --- authentication file v2 + duress verifier ---------------------------
    def test_auth_file_v2_duress_roundtrip(self):
        self.setup_encrypted()
        self.assertIsNone(bp.load_file(self.path)[3])
        self.service.set_duress(self.device, self.path, DECOY)
        identity, root, mode, duress = bp.load_file(self.path)
        self.assertEqual(mode, 2)
        self.assertIsNotNone(duress)
        self.assertTrue(volume.duress_match(duress, DECOY))
        self.assertFalse(volume.duress_match(duress, 'something else'))
        self.assertFalse(volume.duress_match(None, DECOY))
        self.service.set_duress(self.device, self.path, None)   # clear
        self.assertIsNone(bp.load_file(self.path)[3])

    def test_duress_requires_encrypted_mode(self):
        ticket = self.service.prepare(self.device, self.path, 1, True)   # plaintext
        self.service.initialize(ticket, '', ticket.phrase)
        with self.assertRaises(bp.ProtocolError):
            self.service.set_duress(self.device, self.path, DECOY)

    # --- explicit crypto-erase ----------------------------------------------
    def test_explicit_crypto_erase_blanks_device(self):
        self.setup_encrypted()
        lib.sim_reset()
        self.service.erase(self.device, self.path)
        self.assertEqual(lib.sim_capacity(), 0)
        self.assertEqual(self.service.discover()[0].state, 0)   # back to virgin
        # The real password can no longer unlock: there is nothing left to unlock.
        with self.assertRaises(bp.ProtocolError):
            self.service.unlock(self.device, self.path, PASSWORD)

    # --- duress password triggers erase on unlock ---------------------------
    def test_duress_password_erases_and_looks_like_failure(self):
        self.setup_encrypted()
        self.service.set_duress(self.device, self.path, DECOY)
        lib.sim_reset()
        try:
            self.service.unlock(self.device, self.path, DECOY)
            self.fail('duress unlock should raise')
        except Service.DuressTriggered as exc:
            # Message is identical to an ordinary wrong-password error.
            self.assertIn('Wrong password', str(exc))
        self.assertEqual(lib.sim_capacity(), 0)
        self.assertEqual(self.service.discover()[0].state, 0)

    def test_wrong_password_does_not_erase(self):
        self.setup_encrypted()
        self.service.set_duress(self.device, self.path, DECOY)
        lib.sim_reset()
        with self.assertRaises(bp.ProtocolError):
            self.service.unlock(self.device, self.path, 'not the decoy or real')
        # An ordinary typo leaves the provisioned device intact.
        self.assertEqual(self.service.discover()[0].state, 1)

    # --- full secure-erase (format 1) overwrites all sectors ----------------
    def test_full_secure_erase_covers_every_sector(self):
        lib.sim_geometry(200)              # physical 200, logical 184
        self.assertEqual(volume.setup_total(200, 2), 67)
        self.assertEqual(volume.setup_total(200, 1), 184)
        ticket = self.service.prepare(self.device, self.path, 2, True, version=1)
        progress = []
        self.service.initialize(ticket, PASSWORD, ticket.phrase, lambda a, b: progress.append((a, b)))
        self.assertEqual(progress[-1], (184, 184))
        self.assertGreater(lib.sim_writes(), 99)   # strictly more than fast setup
        self.assertEqual(lib.sim_capacity(), 184)


class GuiBits(unittest.TestCase):
    def test_strength_tiers(self):
        from gui import password_strength
        self.assertEqual(password_strength('')[0], 0)
        self.assertEqual(password_strength('abc')[0], 1)
        self.assertGreaterEqual(password_strength('Abcd1234!xyzLMNO')[0], 3)


if __name__ == '__main__':
    unittest.main()
