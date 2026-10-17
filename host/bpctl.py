"""Milestone-3 development CLI. Never initializes or writes an SD card."""
import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import struct
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def kdf(ikm, salt, info, n=32):
    return HKDF(algorithm=hashes.SHA256(), length=n, salt=salt, info=info).derive(ikm)

def file_keys(root, identity):
    return (kdf(root, identity, b'BP1/file-auth'), kdf(root, identity, b'BP1/file-wrap'))

def mac(key, label, data):
    return hmac.digest(key, label + data, 'sha256')

def header(cmd, rid, length):
    return struct.pack('<BBIH', 1, cmd, rid, length)

class ProtocolError(Exception):
    pass

class Client:
    def __init__(self, wire):
        self.wire = wire
        self.rid = secrets.randbits(32)
        self.send_key = self.recv_key = None
        self.tx = self.rx = 0

    def exchange(self, cmd, payload=b'', secure=False):
        self.rid = (self.rid + 1) & 0xffffffff
        rid = self.rid
        if secure:
            if self.send_key is None or self.tx >= 2**64-1:
                raise ProtocolError('No usable authenticated session')
            count = struct.pack('<Q', self.tx)
            aad = header(cmd, rid, len(payload)+24) + count
            request = aad + AESGCM(self.send_key).encrypt(bytes(4)+count, payload, aad)
            self.tx += 1
        else:
            request = header(cmd, rid, len(payload)) + payload
        response = self.wire.exchange(request)
        if len(response) < 9:
            raise ProtocolError('Truncated response')
        version, code, response_id, n = struct.unpack('<BBIH', response[:8])
        if (version, code, response_id, n) != (1, cmd|128, rid, len(response)-8):
            raise ProtocolError('Response header mismatch')
        data = response[8:]
        if secure:
            if len(data) < 25 or struct.unpack('<Q',data[:8])[0] != self.rx:
                self.send_key = self.recv_key = None
                raise ProtocolError('Session rejected or response replayed')
            try:
                data = AESGCM(self.recv_key).decrypt(bytes(4)+data[:8], data[8:], response[:16])
            except Exception as exc:
                self.send_key = self.recv_key = None
                raise ProtocolError('Invalid protected response') from exc
            self.rx += 1
        if data[0]:
            names = {1:'Malformed request',2:'Wrong device state',3:'Authentication failed',
                     4:'Challenge expired',5:'Credential flash fault',
                     6:'Storage setup/integration requires milestone 4'}
            raise ProtocolError(names.get(data[0], 'Device rejected request'))
        return data[1:]

    def info(self):
        data = self.exchange(1)
        if len(data) != 26: raise ProtocolError('Malformed device information')
        return {'device':data[:16].hex(),'state':data[16],'mode':data[17],
                'epoch':struct.unpack('<Q',data[18:])[0]}

    def enroll(self, identity, mode, auth):
        payload = identity + bytes([mode]) + auth
        proof = self.exchange(2,payload)
        if not hmac.compare_digest(proof,mac(auth,b'BP1/enrolled',payload[:17])):
            raise ProtocolError('Enrollment confirmation failed; keep the saved file')

    def authenticate(self, identity, mode, auth, operation=1):
        nonce = secrets.token_bytes(32)
        response = self.exchange(3,bytes([operation])+nonce)
        if len(response)!=48: raise ProtocolError('Malformed challenge')
        t = b'BP1'+identity+bytes([mode,operation])+response[:16]+nonce+struct.pack('<I',self.rid)
        challenge = response[16:]
        if not hmac.compare_digest(challenge,mac(auth,b'BP1/challenge',t)):
            raise ProtocolError('Wrong authentication file or untrusted device challenge')
        host = mac(auth,b'BP1/host',t+challenge)
        transcript = t+challenge+host
        confirm = self.exchange(4,host)
        if not hmac.compare_digest(confirm,mac(auth,b'BP1/device',transcript)):
            raise ProtocolError('Device confirmation failed')
        salt = hashlib.sha256(transcript).digest()
        self.send_key = kdf(auth,salt,b'BP1/host-to-device')
        self.recv_key = kdf(auth,salt,b'BP1/device-to-host')
        self.tx = self.rx = 0

    def ping(self):
        if self.exchange(5,b'\x01',secure=True) != b'BP1':
            raise ProtocolError('Invalid ping response')

class HIDWire:
    def __init__(self, path):
        import hid
        self.dev = hid.device()
        self.dev.open_path(path)
        self.transfer = secrets.randbits(16)

    def close(self): self.dev.close()

    def exchange(self, request):
        if not 8 <= len(request) <= 256: raise ProtocolError('Request length')
        self.transfer = (self.transfer + 1) & 65535
        for off in range(0,len(request),56):
            report = struct.pack('<BBHHH',1,1,self.transfer,len(request),off)+request[off:off+56]
            report = report.ljust(64,b'\0')
            if self.dev.send_feature_report(report)!=64: raise ProtocolError('Short HID write')
        result = bytearray(); total = None; deadline = time.monotonic()+15
        while time.monotonic()<deadline:
            r = bytes(self.dev.get_feature_report(1,64))
            if len(r)!=64 or r[:2]!=b'\x01\x01': raise ProtocolError('Invalid HID report')
            tid,n,off = struct.unpack('<HHH',r[2:8])
            if n==0:
                time.sleep(0.01); continue
            if tid!=self.transfer or not 8<=n<=256 or off!=len(result) or (total is not None and n!=total):
                raise ProtocolError('Out-of-order HID response; reconnect and retry')
            total=n; take=min(56,n-off)
            if any(r[8+take:]): raise ProtocolError('Nonzero report padding')
            result.extend(r[8:8+take])
            if len(result)==n: return bytes(result)
        raise ProtocolError('HID timeout; reconnect and retry with the saved credential file')

def devices():
    import hid
    # Existing ST development VID/PID only. Not licensed for product distribution.
    return [d for d in hid.enumerate(0x0483,0x572a)
            if d.get('usage_page')==0xff00 and d.get('usage')==1]

def load_file(path):
    if Path(path).stat().st_size>4096: raise ProtocolError('Oversized credential file')
    data=json.loads(Path(path).read_text(encoding='utf-8'))
    if set(data)!={'version','device','root','mode'} or data['version']!=1 or data['mode'] not in [1,2]:
        raise ProtocolError('Invalid credential file format')
    identity,root=bytes.fromhex(data['device']),bytes.fromhex(data['root'])
    if len(identity)!=16 or len(root)!=32: raise ProtocolError('Invalid credential lengths')
    return identity,root,data['mode']

def save_file(path, identity, root, mode):
    # Exclusive create: never overwrite another credential. Save and fsync BEFORE enrollment.
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w',encoding='utf-8') as f:
        json.dump({'version':1,'device':identity.hex(),'root':root.hex(),'mode':mode},f)
        f.flush();os.fsync(f.fileno())

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('command',choices=['list','info','enroll','auth','unlock'])
    p.add_argument('--device',help='exact 32-hex-digit identity from list')
    p.add_argument('--file',help='authentication file on another drive; keep a backup')
    p.add_argument('--mode',choices=['auth','encrypted'])
    args=p.parse_args(); selected=[]
    try:
        for d in devices():
            wire=HIDWire(d['path'])
            try:
                client=Client(wire);info=client.info()
                if args.command=='list': print(json.dumps(info))
                if args.device and info['device']==args.device.lower(): selected.append((wire,client,info))
                else: wire.close()
            except Exception:
                wire.close();raise
        if args.command=='list':return
        if len(selected)!=1: raise ProtocolError('Select exactly one connected device using --device')
        wire,client,info=selected[0]
        if args.command=='info':print(json.dumps(info));return
        if not args.file: raise ProtocolError('--file is required')
        identity=bytes.fromhex(info['device'])
        if args.command=='enroll' and not Path(args.file).exists():
            if info['state']!=0 or not args.mode:raise ProtocolError('New enrollment needs a virgin device and --mode')
            mode=1 if args.mode=='auth' else 2
            root=secrets.token_bytes(32);save_file(args.file,identity,root,mode)
        fid,root,mode=load_file(args.file)
        if fid!=identity:raise ProtocolError('File belongs to another device')
        if args.mode and mode!=(1 if args.mode=='auth' else 2):raise ProtocolError('Mode does not match saved file')
        auth,_=file_keys(root,identity)
        if args.command=='enroll' and info['state']==0:client.enroll(identity,mode,auth)
        client.authenticate(identity,mode,auth);client.ping()
        if args.command=='unlock':
            if mode==2:raise ProtocolError('Encrypted key unwrapping requires milestone 4')
            client.exchange(5,b'\x02',secure=True)
        print('Authenticated. Milestone 3 keeps SD media unavailable until milestone 4 setup.')
    finally:
        for wire,_,_ in selected:wire.close()

if __name__=='__main__':
    try:main()
    except (ProtocolError,OSError,ValueError,KeyError,TypeError) as exc:
        raise SystemExit(f'Error: {exc}')
