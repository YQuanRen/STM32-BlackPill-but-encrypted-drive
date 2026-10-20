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

    @property
    def phrase(self):
        return f"ERASE {self.device.identity} {self.cid.hex()}"


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
        identity, root, hint = bp.load_file(file)
        if identity.hex() != device.identity:
            raise bp.ProtocolError('This authentication file belongs to another device.')
        auth, _ = bp.file_keys(root, identity)
        return identity, root, auth, hint

    def prepare(self, device, file, mode, create=False):
        """Save/enroll credentials and inspect card; never writes SD sectors."""
        if mode not in (1, 2):
            raise bp.ProtocolError('Choose a setup mode.')
        with self.connection(device) as (client, info):
            if create:
                if info['state'] != 0:
                    raise bp.ProtocolError('Use the existing authentication file for this device.')
                bp.save_file(file, bytes.fromhex(device.identity), secrets.token_bytes(32), mode)
            identity, root, auth, hint = self.credentials(file, device)
            if info['state'] == 0:
                client.enroll(identity, hint, auth)
                info = client.info()
            client.authenticate(identity, info['mode'], auth, 2)
            card = volume.status(client)
            return Setup(device, str(Path(file).resolve()), mode, card['cid'], card['physical'])

    def initialize(self, setup, password, confirmation, progress=lambda done, total: None):
        if confirmation != setup.phrase:
            raise bp.ProtocolError('Confirmation does not match the selected device and card.')
        identity, root, auth, _ = self.credentials(setup.file, setup.device)
        with self.connection(setup.device) as (client, info):
            client.authenticate(identity, info['mode'], auth, 2)
            card = volume.status(client)
            if (card['cid'], card['physical']) != (setup.cid, setup.physical):
                raise bp.ProtocolError('Card changed after confirmation. Inspect it again before setup.')
            h, key = volume.build(identity, root, setup.mode, setup.cid, setup.physical, password)
            volume.start_setup(client, h, key)
            last_done, last_change = -1, time.monotonic()
            while True:
                status = volume.status(client)
                if (status['cid'], status['physical']) != (setup.cid, setup.physical):
                    raise bp.ProtocolError('Card changed during initialization. Reconnect and restart explicitly.')
                if status['total'] != setup.physical - 16 or not last_done <= status['done'] <= status['total']:
                    raise bp.ProtocolError('Invalid initialization progress. Reconnect and inspect the card.')
                if status['done'] != last_done:
                    last_done, last_change = status['done'], time.monotonic()
                elif time.monotonic() - last_change >= 300:
                    raise bp.ProtocolError('Initialization made no progress for five minutes. Reconnect and restart setup.')
                progress(status['done'], status['total'])
                if status['state'] == 2:
                    if status['done'] != status['total']:
                        raise bp.ProtocolError('Initialization did not cover the full volume.')
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

    def unlock(self, device, file, password):
        identity, root, auth, _ = self.credentials(file, device)
        with self.connection(device) as (client, info):
            client.authenticate(identity, info['mode'], auth)
            h = volume.read_header(client, identity, auth)
            mode = volume.validate(h, identity, auth)
            if mode != info['mode']:
                raise bp.ProtocolError('Header mode differs from the authenticated device mode.')
            key = volume.unwrap(h, identity, root, password) if mode == 2 else None
            client.authenticate(identity, mode, auth)
            if volume.read_header(client, identity, auth) != h:
                raise bp.ProtocolError('Card changed before unlock. Reconnect and retry.')
            client.exchange(5, b'\x02' if mode == 1 else b'\x03' + key, secure=True)
