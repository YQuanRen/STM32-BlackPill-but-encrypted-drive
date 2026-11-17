"""BlackPill GUI workflows. No Tk calls; device operations run on one worker."""
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
import secrets
import time

import bpctl as bp
import volume


@dataclass(frozen=True)
class Device:
    path: bytes
    identity: str
    state: int
    mode: int


@dataclass(frozen=True)
class Setup:
    device: Device
    file: str
    mode: int
    cid: bytes
    physical: int
    version: int = 2          # 2 fast setup, 1 full secure-erase (overwrite all)
    duress_password: str = '' # optional decoy password written to the file after setup

    @property
    def phrase(self):
        # Short, human-typable confirmation (no long hex to retype).
        return f"ERASE {self.cid.hex()[:8].upper()}"


class Service:
    def __init__(self, enumerate_devices=bp.devices, wire=bp.HIDWire, sleep=time.sleep):
        self.enumerate = enumerate_devices
        self.wire = wire
        self.sleep = sleep

    def discover(self):
        found = []
        for item in self.enumerate():
            wire = self.wire(item['path'])
            try:
                info = bp.Client(wire).info()
                self.validate_info(info)
                found.append(Device(item['path'], info['device'], info['state'], info['mode']))
            finally:
                wire.close()
        if len({d.identity for d in found}) != len(found):
            raise bp.ProtocolError('Duplicate device identities. Disconnect duplicates and refresh.')
        return found

    @staticmethod
    def validate_info(info):
        if len(bytes.fromhex(info['device'])) != 16 or info['state'] not in (0, 1, 2):
            raise bp.ProtocolError('Invalid device identity or provisioning state')
        if info['state'] == 1 and info['mode'] not in (1, 2):
            raise bp.ProtocolError('Invalid provisioned mode')

    @contextmanager
    def connection(self, device):
        wire = self.wire(device.path)
        client = bp.Client(wire)
        try:
            info = client.info()
            self.validate_info(info)
            if info['device'] != device.identity:
                raise bp.ProtocolError('Device changed. Refresh and select it again.')
            if info['state'] == 2:
                raise bp.ProtocolError('Credential flash fault. Reconnect; persistent faults require service.')
            yield client, info
        finally:
            client.send_key = client.recv_key = None
            wire.close()

    @staticmethod
    def credentials(file, device):
        if not file:
            raise bp.ProtocolError('Choose an authentication file on another drive.')
        identity, root, hint, duress = bp.load_file(file)
        if identity.hex() != device.identity:
            raise bp.ProtocolError('This authentication file belongs to another device.')
        auth, _ = bp.file_keys(root, identity)
        return identity, root, auth, hint, duress

    def prepare(self, device, file, mode, create=False, version=2):
        """Save/enroll credentials and inspect card; never writes SD sectors."""
        if mode not in (1, 2):
            raise bp.ProtocolError('Choose a setup mode.')
        if version not in (1, 2):
            raise bp.ProtocolError('Choose a setup method.')
        with self.connection(device) as (client, info):
            if create:
                if info['state'] != 0:
                    raise bp.ProtocolError('Use the existing authentication file for this device.')
                bp.save_file(file, bytes.fromhex(device.identity), secrets.token_bytes(32), mode)
            identity, root, auth, hint, _ = self.credentials(file, device)
            if info['state'] == 0:
                client.enroll(identity, hint, auth)
                info = client.info()
            client.authenticate(identity, info['mode'], auth, 2)
            card = volume.status(client)
            return Setup(device, str(Path(file).resolve()), mode, card['cid'], card['physical'], version)

    def initialize(self, setup, password, confirmation, progress=lambda done, total: None):
        if confirmation != setup.phrase:
            raise bp.ProtocolError('Confirmation does not match the selected device and card.')
        identity, root, auth, _, _ = self.credentials(setup.file, setup.device)
        with self.connection(setup.device) as (client, info):
            client.authenticate(identity, info['mode'], auth, 2)
            card = volume.status(client)
            if (card['cid'], card['physical']) != (setup.cid, setup.physical):
                raise bp.ProtocolError('Card changed after confirmation. Inspect it again before setup.')
            h, key = volume.build(identity, root, setup.mode, setup.cid, setup.physical, password, version=setup.version)
            volume.start_setup(client, h, key)
            last_done, last_change = -1, time.monotonic()
            while True:
                status = volume.status(client)
                if (status['cid'], status['physical']) != (setup.cid, setup.physical):
                    raise bp.ProtocolError('Card changed during initialization. Reconnect and restart explicitly.')
                if status['total'] != volume.setup_total(setup.physical, setup.version) or not last_done <= status['done'] <= status['total']:
                    raise bp.ProtocolError('Invalid initialization progress. Reconnect and inspect the card.')
                if status['done'] != last_done:
                    last_done, last_change = status['done'], time.monotonic()
                elif time.monotonic() - last_change >= 300:
                    raise bp.ProtocolError('Initialization made no progress for five minutes. Reconnect and restart setup.')
                progress(status['done'], status['total'])
                if status['state'] == 2:
                    if status['done'] != status['total']:
                        raise bp.ProtocolError('Setup did not finish preparing partition metadata.')
                    break
                if status['state'] != 1:
                    raise bp.ProtocolError('Initialization stopped. Keep the file; reconnect and restart setup.')
                self.sleep(0.2)
            client.authenticate(identity, setup.mode, auth)
            ready = volume.read_header(client, identity, auth)
            # State/HMAC change at commit; immutable metadata must remain identical.
            if ready[:12] != h[:12] or ready[16:224] != h[16:224]:
                raise bp.ProtocolError('Volume changed before unlock. Reconnect and inspect it.')
            client.exchange(5, b'\x02' if setup.mode == 1 else b'\x03' + key, secure=True)
        # Decoy/duress password is a host-only file update; apply it after a clean unlock.
        if setup.duress_password and setup.mode == 2:
            bp.update_file(setup.file, volume.duress_make(setup.duress_password))

    class DuressTriggered(bp.ProtocolError):
        """Raised after a decoy password has crypto-erased the drive. The message is
        deliberately identical to an ordinary wrong-password error."""

    def unlock(self, device, file, password):
        identity, root, auth, _, duress = self.credentials(file, device)
        with self.connection(device) as (client, info):
            client.authenticate(identity, info['mode'], auth)
            h = volume.read_header(client, identity, auth)
            mode = volume.validate(h, identity, auth)
            if mode != info['mode']:
                raise bp.ProtocolError('Header mode differs from the authenticated device mode.')
            key = None
            if mode == 2:
                try:
                    key = volume.unwrap(h, identity, root, password)
                except bp.ProtocolError:
                    if volume.duress_match(duress, password):
                        try:
                            client.authenticate(identity, mode, auth, 3)
                            volume.destroy(client)
                        except Exception:
                            pass
                        raise self.DuressTriggered('Wrong password/file or damaged wrapped key')
                    raise
            client.authenticate(identity, mode, auth)
            if volume.read_header(client, identity, auth) != h:
                raise bp.ProtocolError('Card changed before unlock. Reconnect and retry.')
            client.exchange(5, b'\x02' if mode == 1 else b'\x03' + key, secure=True)

    def erase(self, device, file):
        """Explicit anti-forensic crypto-erase: destroy the on-card header (wrapped
        key) and wipe the credential journal. Permanent and unrecoverable."""
        identity, _, auth, _, _ = self.credentials(file, device)
        with self.connection(device) as (client, info):
            if info['state'] != 1:
                raise bp.ProtocolError('This device is not provisioned; nothing to erase.')
            client.authenticate(identity, info['mode'], auth, 3)
            volume.destroy(client)

    def set_duress(self, device, file, password):
        """Set (password given) or clear (password falsy) the decoy/duress verifier
        on the authentication file. Host-only; the board is never contacted."""
        identity, _, _, hint, _ = self.credentials(file, device)
        if password:
            if hint != 2:
                raise bp.ProtocolError('A decoy password applies only to encrypted (file + password) drives.')
            bp.update_file(file, volume.duress_make(password))
        else:
            bp.update_file(file, None)
