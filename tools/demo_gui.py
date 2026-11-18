"""BlackPill encryption demo - GUI version of demo_decrypt.py.

Shows that data written through the Black Pill is unreadable on the bare SD card,
then unlocks it with the authentication file + password to prove it was there.

    python tools/demo_gui.py                 # reads the card directly (asks for admin)
    python tools/demo_gui.py --image card.bin  # or use a raw dump instead

Put the SD card in an ordinary USB card reader (NOT the Black Pill). Windows may
say the disk needs formatting: click Cancel. This tool only ever READS the card.

Flow:
  1. Pick the card (USB disks are probed for the BlackPill header automatically).
  2. "What a thief sees": the raw sectors, plus a search of the raw card for the
     text you wrote. It is not there.
  3. Unlock: choose the auth file, type the password. The data key is unwrapped
     exactly as demo_decrypt.py explains step by step.
  4. The filesystem (FAT32 / exFAT / NTFS) is decrypted on the fly, your files are
     listed, and each file's ciphertext on the card is shown next to its plaintext.

Decryption uses Google's pure-Python reference Adiantum (independent of the
firmware's C code). It is slow (~6 ms/sector), so only the sectors needed to walk
the filesystem and read the chosen files are decrypted.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import queue
import struct
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'host'), str(ROOT / 'tests/crypto/reference')]

SECTOR = 512
OFFSET = 16                     # logical sector L lives at physical sector L + 16
SEARCH_LIMIT = 512 * 2**20      # raw-card text search covers the first 512 MiB
CONTENT_LIMIT = 64 * 1024       # decrypt at most 64 KiB of any one file
SKIP_DIRS = {'system volume information', '$recycle.bin'}


# =============================================================================
# Card access (read-only)
# =============================================================================

class Card:
    """Read-only access to a raw card: a \\\\.\\PhysicalDriveN or a dump file."""

    def __init__(self, path, size=None):
        self.path = path
        self.f = open(path, 'rb', buffering=0)
        if size is None:
            size = os.path.getsize(path)
        self.size = size
        self.lock = threading.Lock()

    def read(self, physical, count=1):
        """Read whole 512-byte sectors (raw devices require aligned reads)."""
        with self.lock:
            self.f.seek(physical * SECTOR)
            data = self.f.read(count * SECTOR)
        if len(data) != count * SECTOR:
            raise IOError(f'Could not read physical sectors {physical}..{physical + count - 1}')
        return data

    def close(self):
        self.f.close()


def list_disks():
    """Disks Windows knows about, via WMI (no admin needed for the list itself)."""
    cmd = ('Get-CimInstance Win32_DiskDrive | Select-Object Index,Model,Size,'
           'InterfaceType,MediaType | ConvertTo-Json -Compress')
    out = subprocess.run(['powershell', '-NoProfile', '-Command', cmd], capture_output=True,
                         text=True, timeout=30, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)).stdout
    if not out.strip():
        return []
    data = json.loads(out)
    disks = data if isinstance(data, list) else [data]
    return sorted(disks, key=lambda d: d.get('Index') or 0)


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin():
    """Restart this script elevated (UAC prompt). Returns True if it launched."""
    exe = Path(sys.executable)
    windowed = exe.with_name('pythonw.exe')
    params = subprocess.list2cmdline([str(Path(__file__).resolve())] + sys.argv[1:])
    rc = ctypes.windll.shell32.ShellExecuteW(None, 'runas', str(windowed if windowed.exists() else exe),
                                             params, str(ROOT), 1)
    return rc > 32


# =============================================================================
# Key unwrap (same steps as demo_decrypt.py, reported through a callback)
# =============================================================================

def header_info(card):
    """Return (header bytes, physical sector it came from) - first valid-looking copy."""
    for phys in (0, 8):
        h = card.read(phys)[:256]
        if h[:8] == b'BPVOL001':
            return h, phys
    return None, None


def describe_header(h):
    version, state = struct.unpack_from('<II', h, 8)
    physical, logical, mode, _ = struct.unpack_from('<QQII', h, 64)
    return {
        'Magic': h[:8].decode(),
        'Format': f'v{version} ({"fast setup" if version == 2 else "full initialization"})',
        'State': {1: 'initializing', 2: 'ready'}.get(state, str(state)),
        'Mode': {1: 'plaintext (auth only)', 2: 'encrypted (Adiantum)'}.get(mode, str(mode)),
        'Device ID': h[16:32].hex(),
        'Volume ID': h[32:48].hex(),
        'Card size': f'{physical:,} sectors ({physical * SECTOR / 1e9:.1f} GB)',
        'Wrapped data key': h[128:176].hex()[:32] + '...',
    }


def unwrap_key(card, auth_path, password, step):
    """Turn auth file + password + card header into the data key."""
    from argon2.low_level import hash_secret_raw, Type
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import bpctl
    import volume

    identity, root = bpctl.load_file(auth_path)[:2]
    auth_key, wrap_secret = bpctl.file_keys(root, identity)

    # STEP 1 - the header is signed with a key derived from the auth file.
    header, mode, last_error = None, None, None
    for phys in (0, 8):
        h = card.read(phys)[:256]
        try:
            mode = volume.validate(h, identity, auth_key)
            header = h
            break
        except Exception as exc:
            last_error = exc
    if header is None:
        raise ValueError('The card header does not match this authentication file '
                         f'({last_error}). Is this the right card and file?')
    if mode != 2:
        raise ValueError('This card is in plaintext (auth-only) mode: there is no encryption to show.')
    step(1, 'Header signature verified with the auth file')

    # STEP 2 - stretch the password with Argon2id (64 MiB, 3 passes).
    step(2, 'Running Argon2id on the password (64 MiB)...', busy=True)
    pw_key = hash_secret_raw(password.encode('utf-8'), header[100:116], time_cost=3,
                             memory_cost=65536, parallelism=1, hash_len=32, type=Type.ID, version=19)
    step(2, 'Password stretched with Argon2id (64 MiB, 3 passes)')

    # STEP 3 - mix password + auth file into the key-encryption key.
    salt = hashlib.sha256(b'BP1/wrap-salt' + header[16:48]).digest()
    kek = bpctl.kdf(pw_key + wrap_secret, salt, b'BP1/data-wrap')
    step(3, 'Key-encryption key = HKDF(password key + auth file secret)')

    # STEP 4 - AES-256-GCM unwrap; the tag check rejects a wrong password.
    try:
        key = AESGCM(kek).decrypt(header[116:128], header[128:176], volume.aad(header))
    except Exception:
        raise ValueError('Wrong password (or wrong auth file): the data key did not unwrap.')
    step(4, 'Data key unwrapped with AES-256-GCM (tag verified)')
    return key


# =============================================================================
# Decrypted view of the drive
# =============================================================================

def _variant():
    vectors = json.loads((ROOT / 'tests/crypto/reference/Adiantum_XChaCha12_32_AES256.json').read_text())
    return vectors[0]['cipher']


class Drive:
    """The logical drive the PC sees through the Black Pill, decrypted lazily."""

    def __init__(self, card, key):
        import adiantum
        self.card, self.key = card, key
        self.cipher = adiantum.Adiantum()
        self.cipher.variant = _variant()
        self.cache = {}

    def raw(self, lba, count=1):
        return self.card.read(lba + OFFSET, count)

    def read(self, lba, count=1):
        out = bytearray()
        missing = [l for l in range(lba, lba + count) if l not in self.cache]
        if missing:
            raw = self.raw(missing[0], missing[-1] - missing[0] + 1)
            for l in missing:
                i = l - missing[0]
                tweak = struct.pack('<Q', l) + bytes(24)
                self.cache[l] = self.cipher.decrypt(raw[i * SECTOR:(i + 1) * SECTOR], key=self.key, tweak=tweak)
        for l in range(lba, lba + count):
            out += self.cache[l]
        return bytes(out)


def u16(b, o): return struct.unpack_from('<H', b, o)[0]
def u32(b, o): return struct.unpack_from('<I', b, o)[0]
def u64(b, o): return struct.unpack_from('<Q', b, o)[0]


class FileInfo:
    """A file (or, with meta=True, a filesystem structure) and where it lives.

    sectors: logical sectors holding the data, in order.
    data_offset: byte offset of content[0] inside sectors[0] (non-zero for NTFS
    small files, whose data sits inside the MFT record).
    summary: human-readable decoding, shown for structures in text mode.
    """

    def __init__(self, path, size, sectors, content, note='', data_offset=0, meta=False, summary=''):
        self.path, self.size, self.sectors, self.content, self.note = path, size, sectors, content, note
        self.data_offset, self.meta, self.summary = data_offset, meta, summary


PART_TYPES = {0x01: 'FAT12', 0x04: 'FAT16', 0x06: 'FAT16', 0x07: 'NTFS / exFAT', 0x0B: 'FAT32 (CHS)',
              0x0C: 'FAT32 (LBA)', 0x0E: 'FAT16 (LBA)', 0x0F: 'Extended', 0xEE: 'GPT protective'}
GPT_TYPES = {'ebd0a0a2-b9e5-4433-87c0-68b6b72699c7': 'Microsoft basic data',
             'e3c9e316-0b5c-4db8-817d-f92df00215ae': 'Microsoft reserved',
             'c12a7328-f81f-11d2-ba4b-00a0c93ec93b': 'EFI system'}


def describe_boot(kind, bs):
    serial = lambda v, n: f'{v:0{n}X}'
    if kind == 'exFAT':
        return '\n'.join([
            'exFAT boot sector (volume boot record)', '',
            f'Volume length        {u64(bs, 72):,} sectors',
            f'FAT                  at +{u32(bs, 80):,}, {u32(bs, 84):,} sectors long',
            f'Cluster heap         at +{u32(bs, 88):,}, {u32(bs, 92):,} clusters',
            f'Cluster size         {512 << bs[109]:,} bytes',
            f'Root directory       cluster {u32(bs, 96):,}',
            f'Volume serial        {serial(u32(bs, 100), 8)}',
            f'Signature            {bs[510]:02X} {bs[511]:02X}'])
    if kind == 'NTFS':
        return '\n'.join([
            'NTFS boot sector (volume boot record)', '',
            f'Bytes per sector     {u16(bs, 11)}',
            f'Sectors per cluster  {bs[13]}',
            f'Volume length        {u64(bs, 40):,} sectors',
            f'$MFT                 cluster {u64(bs, 48):,}',
            f'$MFTMirr             cluster {u64(bs, 56):,}',
            f'Volume serial        {serial(u64(bs, 72), 16)}',
            f'Signature            {bs[510]:02X} {bs[511]:02X}'])
    fat32 = kind == 'FAT32'
    lines = [f'{kind} boot sector (volume boot record)', '',
             f'OEM name             {bs[3:11].decode("latin-1").strip()}',
             f'Bytes per sector     {u16(bs, 11)}',
             f'Sectors per cluster  {bs[13]}',
             f'Reserved sectors     {u16(bs, 14)}',
             f'Number of FATs       {bs[16]}',
             f'Sectors per FAT      {(u32(bs, 36) if fat32 else u16(bs, 22)):,}',
             f'Total sectors        {(u16(bs, 19) or u32(bs, 32)):,}']
    if fat32:
        lines.append(f'Root directory       cluster {u32(bs, 44):,}')
    o = 67 if fat32 else 39
    lines += [f'Volume serial        {serial(u32(bs, o), 8)}',
              f'Volume label         {bs[o + 4:o + 15].decode("latin-1").strip()}',
              f'Signature            {bs[510]:02X} {bs[511]:02X}']
    return '\n'.join(lines)


def vbr_kind(b):
    if b[3:11] == b'EXFAT   ':
        return 'exFAT'
    if b[3:11] == b'NTFS    ':
        return 'NTFS'
    if b[510:512] == b'\x55\xaa' and (b[0x52:0x57] == b'FAT32' or b[0x36:0x39] == b'FAT'):
        return 'FAT32' if b[0x52:0x57] == b'FAT32' else 'FAT16'
    return None


def _structure(drive, name, lbas, summary, note=''):
    data = drive.read(lbas[0], len(lbas)) if lbas == list(range(lbas[0], lbas[0] + len(lbas))) \
        else b''.join(drive.read(l) for l in lbas)
    return FileInfo(name, len(data), list(lbas), data, note=note, meta=True, summary=summary)


def find_volume(drive):
    """Locate the filesystem: superfloppy, MBR partition or GPT partition.

    Returns (start, kind, boot sector, description, [partition-table structures]).
    """
    s0 = drive.read(0)
    kind = vbr_kind(s0)
    if kind:
        return 0, kind, s0, 'no partition table', []
    if s0[510:512] != b'\x55\xaa':
        raise ValueError('Decrypted sector 0 holds no partition table or filesystem. '
                         'Was the drive formatted through the Black Pill?')
    entries = [s0[446 + 16 * i:462 + 16 * i] for i in range(4)]
    mbr_lines = ['Master Boot Record (sector 0 of the drive)', '']
    for i, e in enumerate(entries, 1):
        if e[4]:
            mbr_lines.append(f'Partition {i}   type 0x{e[4]:02X} ({PART_TYPES.get(e[4], "?")}), '
                             f'{"active, " if e[0] == 0x80 else ""}starts at drive sector {u32(e, 8):,} (card sector {u32(e, 8) + OFFSET:,}), '
                             f'{u32(e, 12):,} sectors ({u32(e, 12) * SECTOR / 1e9:.2f} GB)')
        else:
            mbr_lines.append(f'Partition {i}   (empty)')
    mbr_lines += [f'Signature     {s0[510]:02X} {s0[511]:02X}', '',
                  f'Drive sector N is card sector N + {OFFSET}: the first {OFFSET} card sectors hold the BlackPill header.']
    starts, scheme = [], 'MBR'
    structures = [_structure(drive, 'Partition table (MBR)', [0], '\n'.join(mbr_lines))]
    if any(e[4] == 0xEE for e in entries):
        import uuid
        scheme = 'GPT'
        g = drive.read(1)
        if g[:8] != b'EFI PART':
            raise ValueError('Protective MBR found but no GPT header')
        elba, n, esz = u64(g, 72), u32(g, 80), u32(g, 84)
        nsec = (min(n, 128) * esz + SECTOR - 1) // SECTOR
        table = drive.read(elba, nsec)
        lines = ['GUID Partition Table', '',
                 f'Disk GUID       {uuid.UUID(bytes_le=g[56:72])}',
                 f'Usable sectors  {u64(g, 40):,} .. {u64(g, 48):,}',
                 f'Entries         {n} x {esz} bytes at drive sector {elba:,}', '']
        used = 0
        for i in range(min(n, 128)):
            e = table[i * esz:(i + 1) * esz]
            if any(e[:16]):
                t = str(uuid.UUID(bytes_le=e[:16]))
                label = e[56:128].decode('utf-16-le', 'replace').split('\x00')[0]
                lines.append(f'Partition {i + 1}  {GPT_TYPES.get(t, t)}{f" {label!r}" if label else ""}, '
                             f'drive sectors {u64(e, 32):,} .. {u64(e, 40):,} (card sector {u64(e, 32) + OFFSET:,} on)')
                starts.append(u64(e, 32))
                used = i + 1
        shown = [1] + list(range(elba, elba + max(1, (used * esz + SECTOR - 1) // SECTOR)))
        structures = [_structure(drive, 'Partition table (protective MBR)', [0], '\n'.join(mbr_lines)),
                      _structure(drive, 'Partition table (GPT)', shown, '\n'.join(lines))]
    else:
        starts = [u32(e, 8) for e in entries if e[4]]
    for start in starts:
        b = drive.read(start)
        kind = vbr_kind(b)
        if kind:
            return start, kind, b, f'{scheme} partition at sector {start:,}', structures
    raise ValueError(f'{scheme} partition table found, but no FAT32/exFAT/NTFS volume in it')


def list_files(drive, progress=lambda msg: None):
    """Returns (kind, description, files, structures)."""
    start, kind, bs, where, structures = find_volume(drive)
    progress(f'{kind} filesystem ({where})')
    structures.append(_structure(drive, 'Boot sector', [start], describe_boot(kind, bs)))
    if kind.startswith('FAT'):
        files, table, lines, title = *_fat_files(drive, start, bs, kind == 'FAT32'), 'File table (root directory)'
    elif kind == 'exFAT':
        files, table, lines, title = *_exfat_files(drive, start, bs), 'File table (root directory)'
    else:
        files, table, lines, title = *_ntfs_files(drive, start, bs), 'File table (MFT records)'
    if table:
        structures.append(_structure(drive, title, table, '\n'.join(lines)))
    return kind, where, sorted(files, key=lambda f: f.path.lower()), structures


def _read_content(drive, sectors, size):
    take = sectors[:(min(size, CONTENT_LIMIT) + SECTOR - 1) // SECTOR]
    data = bytearray()
    # Read contiguous runs together.
    i = 0
    while i < len(take):
        j = i
        while j + 1 < len(take) and take[j + 1] == take[j] + 1:
            j += 1
        data += drive.read(take[i], j - i + 1)
        i = j + 1
    return bytes(data[:min(size, CONTENT_LIMIT)]), take


# ---- FAT16 / FAT32 ----------------------------------------------------------

def _fat_files(drive, start, bs, fat32):
    spc, rsv, nfats, rootent = bs[13], u16(bs, 14), bs[16], u16(bs, 17)
    fatsz = u16(bs, 22) or u32(bs, 36)
    rootsecs = (rootent * 32 + SECTOR - 1) // SECTOR
    first_data = start + rsv + nfats * fatsz + rootsecs

    def nxt(c):
        width = 4 if fat32 else 2
        off = c * width
        b = drive.read(start + rsv + off // SECTOR)
        e = (u32(b, off % SECTOR) & 0x0FFFFFFF) if fat32 else u16(b, off % SECTOR)
        return None if e < 2 or e >= (0x0FFFFFF8 if fat32 else 0xFFF8) else e

    def chain_sectors(c, limit):
        out, seen = [], set()
        while c and c not in seen and len(out) < limit:
            seen.add(c)
            base = first_data + (c - 2) * spc
            out += range(base, base + spc)
            c = nxt(c)
        return out

    def entries(sectors, visited=None):
        for lba in sectors:
            if visited is not None:
                visited.append(lba)
            b = drive.read(lba)
            for o in range(0, SECTOR, 32):
                if b[o] == 0:
                    return
                yield b[o:o + 32]

    files, root_lbas = [], []
    lines = [f'{"FAT32" if fat32 else "FAT16"} root directory: 32-byte entries', '']

    def walk(sectors, prefix, depth):
        lfn = []
        for e in entries(sectors, root_lbas if depth == 0 else None):
            if e[0] == 0xE5:
                if depth == 0:
                    lines.append('Deleted entry')
                lfn = []
                continue
            if e[11] == 0x0F:
                part = e[1:11] + e[14:26] + e[28:32]
                lfn.insert(0, part.decode('utf-16-le', 'replace').split('\x00')[0].rstrip('\uffff'))
                continue
            if e[11] & 0x08:
                if depth == 0:
                    lines.append(f'Volume label  {e[0:11].decode("latin-1").strip()!r}')
                lfn = []
                continue
            base, ext = e[0:8].decode('latin-1').rstrip(), e[8:11].decode('latin-1').rstrip()
            if e[12] & 0x08:    # Windows NT flags: base / extension stored lower-case
                base = base.lower()
            if e[12] & 0x10:
                ext = ext.lower()
            short = base + ('.' + ext if ext else '')
            name = ''.join(lfn) or short
            lfn = []
            if name in ('.', '..'):
                continue
            cluster = (u16(e, 20) << 16 | u16(e, 26)) if fat32 else u16(e, 26)
            if depth == 0:
                where = f'cluster {cluster:,} (card sector {first_data + (cluster - 2) * spc + OFFSET:,})' if cluster else 'no clusters'
                kind = 'Folder' if e[11] & 0x10 else 'File  '
                lines.append(f'{kind}  {name!r}  8.3 name {short!r}  {u32(e, 28):,} bytes  first {where}')
            if e[11] & 0x10:
                if depth < 4 and name.lower() not in SKIP_DIRS and cluster:
                    walk(chain_sectors(cluster, 64 * spc), prefix + name + '\\', depth + 1)
                continue
            size = u32(e, 28)
            secs = chain_sectors(cluster, (min(size, CONTENT_LIMIT) + SECTOR - 1) // SECTOR) if cluster and size else []
            content, used = _read_content(drive, secs, size)
            files.append(FileInfo(prefix + name, size, used, content))

    root = (chain_sectors(u32(bs, 44), 64 * spc) if fat32
            else list(range(start + rsv + nfats * fatsz, start + rsv + nfats * fatsz + rootsecs)))
    walk(root, '', 0)
    lines.append('(end of directory)')
    return files, root_lbas, lines


# ---- exFAT ------------------------------------------------------------------

def _exfat_files(drive, start, bs):
    fatoff, heap, rootc = u32(bs, 80), u32(bs, 88), u32(bs, 96)
    if bs[108] != 9:
        raise ValueError('Only 512-byte exFAT sectors are supported')
    spc = 1 << bs[109]

    def nxt(c):
        off = c * 4
        e = u32(drive.read(start + fatoff + off // SECTOR), off % SECTOR)
        return None if e < 2 or e >= 0xFFFFFFF7 else e

    def sectors_of(c, nofat, length, limit):
        out, seen = [], set()
        clusters_needed = max(1, (length + spc * SECTOR - 1) // (spc * SECTOR)) if length else 10**9
        while c and c not in seen and len(out) < limit and len(seen) < clusters_needed:
            seen.add(c)
            base = start + heap + (c - 2) * spc
            out += range(base, base + spc)
            c = c + 1 if nofat else nxt(c)
        return out[:limit]

    def entries(sectors, visited=None):
        for lba in sectors:
            if visited is not None:
                visited.append(lba)
            b = drive.read(lba)
            for o in range(0, SECTOR, 32):
                if b[o] == 0:
                    return
                yield b[o:o + 32]

    files, root_lbas = [], []
    lines = ['exFAT root directory: 32-byte entries', '']
    sector_of = lambda c: f'cluster {c:,} (card sector {start + heap + (c - 2) * spc + OFFSET:,})'

    def walk(sectors, prefix, depth):
        it = entries(sectors, root_lbas if depth == 0 else None)
        for e in it:
            if depth == 0:
                if e[0] == 0x81:
                    lines.append(f'Allocation bitmap   {sector_of(u32(e, 20))}, {u64(e, 24):,} bytes')
                elif e[0] == 0x82:
                    lines.append(f'Up-case table       {sector_of(u32(e, 20))}, {u64(e, 24):,} bytes')
                elif e[0] == 0x83:
                    lines.append(f'Volume label        {e[2:2 + 2 * e[1]].decode("utf-16-le", "replace")!r}')
                elif e[0] == 0xA0:
                    lines.append('Volume GUID entry')
                elif e[0] == 0x05:   # 0x85 with the in-use bit cleared
                    lines.append('Deleted file entry')
            if e[0] != 0x85:
                continue
            count, attrs = e[1], u16(e, 4)
            group = []
            for _ in range(count):
                n = next(it, None)
                if n is None:
                    break
                group.append(n)
            stream = next((g for g in group if g[0] == 0xC0), None)
            if stream is None:
                continue
            namelen = stream[3]
            name = b''.join(g[2:32] for g in group if g[0] == 0xC1).decode('utf-16-le', 'replace')[:namelen]
            nofat, cluster, length = bool(stream[1] & 2), u32(stream, 20), u64(stream, 24)
            if depth == 0:
                kind = 'Folder' if attrs & 0x10 else 'File  '
                where = f'first {sector_of(cluster)}' if cluster else 'no clusters'
                lines.append(f'{kind}              {name!r}  {length:,} bytes  {where}'
                             f'{"  contiguous" if nofat else ""}  ({1 + count} entries)')
            if attrs & 0x10:
                if depth < 4 and name.lower() not in SKIP_DIRS and cluster:
                    walk(sectors_of(cluster, nofat, length, 64 * spc), prefix + name + '\\', depth + 1)
                continue
            limit = (min(length, CONTENT_LIMIT) + SECTOR - 1) // SECTOR
            secs = sectors_of(cluster, nofat, length, limit) if cluster and length else []
            content, used = _read_content(drive, secs, length)
            files.append(FileInfo(prefix + name, length, used, content))

    walk(sectors_of(rootc, False, 0, 64 * spc), '', 0)
    lines.append('(end of directory)')
    return files, root_lbas, lines


# ---- NTFS -------------------------------------------------------------------

def _runs(b, o, end):
    """Decode an NTFS data-run list into [(lcn, clusters)]."""
    runs, lcn = [], 0
    while o < end and b[o]:
        ln, lo = b[o] & 0xF, b[o] >> 4
        count = int.from_bytes(b[o + 1:o + 1 + ln], 'little')
        delta = int.from_bytes(b[o + 1 + ln:o + 1 + ln + lo], 'little', signed=True) if lo else 0
        o += 1 + ln + lo
        if lo:
            lcn += delta
            runs.append((lcn, count))
    return runs


def _ntfs_files(drive, start, bs):
    if u16(bs, 11) != SECTOR:
        raise ValueError('Only 512-byte NTFS sectors are supported')
    spc, mftc = bs[13], u64(bs, 48)
    cpr = struct.unpack_from('<b', bs, 64)[0]
    rec = 2 ** -cpr if cpr < 0 else cpr * spc * SECTOR
    per = rec // SECTOR

    def fixup(r):
        r = bytearray(r)
        usa, n = u16(r, 4), u16(r, 6)
        for i in range(1, n):
            if i * SECTOR <= len(r):
                r[i * SECTOR - 2:i * SECTOR] = r[usa + 2 * i:usa + 2 * i + 2]
        return bytes(r)

    def attrs(r):
        o = u16(r, 20)
        while o + 16 <= len(r):
            t, ln = u32(r, o), u32(r, o + 4)
            if t == 0xFFFFFFFF or ln == 0:
                return
            yield t, r[o:o + ln], o
            o += ln

    # Map MFT record numbers to sectors using $MFT's own (record 0) run list.
    first = start + mftc * spc
    r0 = fixup(drive.read(first, per))
    mft_sectors = []
    for t, a, _ in attrs(r0):
        if t == 0x80 and a[8]:
            for lcn, n in _runs(a, u16(a, 32), len(a)):
                base = start + lcn * spc
                mft_sectors += range(base, base + n * spc)
            break
    total = min(len(mft_sectors) // per, 4096)

    names, raw_files, unused = {}, [], 0
    for i in range(total):
        if i >= 32 and unused >= 64:
            break
        lbas = mft_sectors[i * per:(i + 1) * per]
        if lbas != list(range(lbas[0], lbas[0] + per)):
            continue
        r = drive.read(lbas[0], per)
        if r[:4] != b'FILE' or not u16(r, 22) & 1:
            unused += 1
            continue
        unused = 0
        r = fixup(r)
        is_dir = bool(u16(r, 22) & 2)
        best, data = None, None
        for t, a, aoff in attrs(r):
            if t == 0x30 and not a[8]:
                c = a[u16(a, 20):]
                ns = c[65]
                nm = c[66:66 + 2 * c[64]].decode('utf-16-le', 'replace')
                if best is None or best[2] == 2:
                    best = (u64(c, 0) & 0xFFFFFFFFFFFF, nm, ns)
            elif t == 0x80 and a[9] == 0 and data is None:
                if a[8]:
                    data = ('runs', u64(a, 48), _runs(a, u16(a, 32), len(a)))
                else:
                    off, ln = u16(a, 20), u32(a, 16)
                    data = ('resident', ln, a[off:off + ln], aoff + off)   # offset inside the record
        if best is None:
            continue
        names[i] = (best[0], best[1])
        if not is_dir and i >= 24 and data:
            raw_files.append((i, best[0], best[1], data, lbas))

    def path_of(parent, name):
        parts, seen = [name], set()
        while parent != 5 and parent in names and parent not in seen:
            seen.add(parent)
            parent, nm = names[parent]
            parts.insert(0, nm)
        return '\\'.join(parts)

    files, table = [], []
    lines = [f'NTFS Master File Table: {rec}-byte records, one per file', '']
    for i, parent, name, data, lbas in raw_files:
        path = path_of(parent, name)
        if path.startswith('$') or path.lower().split('\\')[0] in SKIP_DIRS:
            continue
        if len(table) < 8:   # show up to four records' worth of sectors
            table += lbas
        if data[0] == 'resident':
            lines.append(f'Record {i:<5} {path!r}  {data[1]:,} bytes  data stored IN the record '
                         f'(card sector {lbas[0] + OFFSET:,}, offset {data[3]})')
            files.append(FileInfo(path, data[1], lbas, data[2][:CONTENT_LIMIT], data_offset=data[3],
                                  note='inside its MFT record'))
        else:
            secs = []
            for lcn, n in data[2]:
                base = start + lcn * spc
                secs += range(base, base + n * spc)
                if len(secs) * SECTOR >= CONTENT_LIMIT:
                    break
            runs = ', '.join(f'{n:,} clusters at card sector {start + lcn * spc + OFFSET:,}' for lcn, n in data[2][:3])
            lines.append(f'Record {i:<5} {path!r}  {data[1]:,} bytes  data runs: {runs}')
            content, used = _read_content(drive, secs, data[1])
            files.append(FileInfo(path, data[1], used, content))
    if len(files) * per > len(table):
        lines += ['', f'(the hex panels show the first {len(table) // per} records only)']
    return files, table, lines


# =============================================================================
# Helpers
# =============================================================================

def hexdump(data, base=0, limit=1024):
    lines = []
    for o in range(0, min(len(data), limit), 16):
        chunk = data[o:o + 16]
        hx = ' '.join(f'{c:02x}' for c in chunk)
        txt = ''.join(chr(c) if 32 <= c < 127 else '.' for c in chunk)
        lines.append(f'{base + o:08x}  {hx:<47}  {txt}')
    if len(data) > limit:
        lines.append(f'... ({len(data) - limit:,} more bytes)')
    return '\n'.join(lines)


def card_hexdump(data, sectors, start=0, limit=4096):
    """Hex dump labelled with real card byte addresses.

    data[0] sits at byte `start` of logical sector sectors[0]; data continues
    through sectors[1], sectors[2]... which need not be contiguous on the card.
    A separator line marks each jump to a non-adjacent sector.
    """
    lines, prev = [], None
    for o in range(0, min(len(data), limit), 16):
        pos = start + o
        idx = pos // SECTOR
        if idx >= len(sectors):
            break
        card_sector = sectors[idx] + OFFSET
        if prev is not None and card_sector not in (prev, prev + 1):
            lines.append(f'--- jumps to card sector {card_sector:,} ---')
        prev = card_sector
        chunk = data[o:o + 16]
        hx = ' '.join(f'{c:02x}' for c in chunk)
        txt = ''.join(chr(c) if 32 <= c < 127 else '.' for c in chunk)
        lines.append(f'{card_sector * SECTOR + pos % SECTOR:08x}  {hx:<47}  {txt}')
    if len(data) > limit:
        lines.append(f'... ({len(data) - limit:,} more bytes)')
    return '\n'.join(lines)


def search_raw(card, text, limit, progress, cancelled):
    """Scan the raw card for the text (ASCII/UTF-8 and UTF-16LE). Returns hits."""
    needles = {text.encode('utf-8'), text.encode('utf-16-le')}
    needles |= {n.lower() for n in needles} if text.isascii() else set()
    keep = max(len(n) for n in needles) - 1
    total = min(card.size, limit) // SECTOR
    chunk, pos, tail, hits = 2048, 0, b'', []
    while pos < total and not cancelled():
        n = min(chunk, total - pos)
        data = card.read(pos, n)
        buf = tail + data
        low = buf.lower() if text.isascii() else buf
        for needle in needles:
            j = low.find(needle)
            while j != -1 and len(hits) < 50:
                hits.append(pos * SECTOR - len(tail) + j)
                j = low.find(needle, j + 1)
        tail = buf[-keep:] if keep else b''
        pos += n
        progress(pos, total)
    return sorted(set(hits)), pos * SECTOR


def human(n):
    for unit in ('bytes', 'KB', 'MB', 'GB', 'TB'):
        if n < 1024 or unit == 'TB':
            return f'{n:,} {unit}' if unit == 'bytes' else f'{n:.1f} {unit}'
        n /= 1024


# =============================================================================
# GUI
# =============================================================================

INK, MUTED, BG, CARD_BG = '#1e293b', '#64748b', '#eef2f7', '#ffffff'
ACCENT, DANGER, OK, LINE = '#2563eb', '#dc2626', '#15803d', '#d7dee8'
FONT, MONO = 'Segoe UI', 'Consolas'
STEPS = ['Card', 'Raw card', 'Unlock', 'Decrypted']


class App:
    def __init__(self, root, image=None):
        self.root = root
        self.card = None
        self.key = None
        self.drive = None
        self.files = []
        self.queue = queue.Queue()
        self.cancel_search = False
        root.title('BlackPill encryption demo')
        # Fonts scale with Windows display scaling; scale the window to match.
        self.scale = max(1.0, root.winfo_fpixels('1i') / 96)
        w = min(int(1120 * self.scale), int(root.winfo_screenwidth() * 0.95))
        h = min(int(800 * self.scale), int(root.winfo_screenheight() * 0.9))
        root.geometry(f'{w}x{h}')
        root.minsize(min(w, int(900 * self.scale)), min(h, int(640 * self.scale)))
        root.configure(bg=BG)
        self.style()
        self.build_chrome()
        self.root.after(50, self.pump)
        root.report_callback_exception = lambda *exc: messagebox.showerror('Error', str(exc[1]))
        if image:
            self.open_card(image, os.path.getsize(image), f'Dump file {Path(image).name}')
        else:
            self.page_select()

    # ---- plumbing --------------------------------------------------------------

    def style(self):
        s = ttk.Style()
        try:
            s.theme_use('clam')
        except tk.TclError:
            pass
        s.configure('.', font=(FONT, 10), background=CARD_BG, foreground=INK)
        s.configure('Bg.TFrame', background=BG)
        s.configure('TFrame', background=CARD_BG)
        s.configure('TLabel', background=CARD_BG, foreground=INK)
        s.configure('Muted.TLabel', foreground=MUTED)
        s.configure('Title.TLabel', background=BG, font=(FONT, 20, 'bold'))
        s.configure('Step.TLabel', background=BG, foreground=MUTED, font=(FONT, 10))
        s.configure('StepOn.TLabel', background=BG, foreground=ACCENT, font=(FONT, 10, 'bold'))
        s.configure('H.TLabel', font=(FONT, 15, 'bold'))
        s.configure('Big.TLabel', font=(FONT, 13, 'bold'))
        s.configure('Good.TLabel', foreground=OK, font=(FONT, 12, 'bold'))
        s.configure('Bad.TLabel', foreground=DANGER, font=(FONT, 12, 'bold'))
        s.configure('TButton', padding=(12, 6))
        s.configure('Accent.TButton', padding=(16, 8), font=(FONT, 11, 'bold'))
        s.map('Accent.TButton', background=[('!disabled', ACCENT), ('disabled', '#9db7ef')],
              foreground=[('!disabled', 'white'), ('disabled', '#eef2ff')])
        s.configure('Bar.Horizontal.TProgressbar', troughcolor=LINE, background=ACCENT)
        # ttk does not scale Treeview rows with DPI; size them from the font.
        from tkinter import font as tkfont
        s.configure('Treeview', rowheight=tkfont.Font(font=(FONT, 10)).metrics('linespace') + int(8 * self.scale))
        s.configure('Treeview.Heading', font=(FONT, 10, 'bold'))

    def build_chrome(self):
        top = ttk.Frame(self.root, style='Bg.TFrame', padding=(22, 14, 22, 4))
        top.pack(fill='x')
        ttk.Label(top, text='BlackPill encryption demo', style='Title.TLabel').pack(anchor='w')
        steps = ttk.Frame(top, style='Bg.TFrame')
        steps.pack(anchor='w', pady=(2, 0))
        self.step_labels = []
        for i, name in enumerate(STEPS):
            lbl = ttk.Label(steps, text=f'{i + 1}  {name}', style='Step.TLabel', padding=(0, 0, 20, 0))
            lbl.pack(side='left')
            self.step_labels.append(lbl)
        self.body = ttk.Frame(self.root, padding=20)
        self.body.pack(fill='both', expand=True, padx=22, pady=(8, 22))

    def page(self, step):
        for w in self.body.winfo_children():
            w.destroy()
        self.root.unbind('<Return>')
        for i, lbl in enumerate(self.step_labels):
            lbl.configure(style='StepOn.TLabel' if i == step else 'Step.TLabel')
        return self.body

    def run(self, work, done, fail=None):
        """Run work() on a thread; deliver done(result) / fail(exc) on the Tk thread."""
        def target():
            try:
                self.queue.put((done, work()))
            except BaseException as exc:
                self.queue.put((fail or self.show_error, exc))
        threading.Thread(target=target, daemon=True).start()

    def ui(self, fn, *args):
        """Schedule fn(*args) on the Tk thread from a worker thread."""
        self.queue.put((lambda _: fn(*args), None))

    def pump(self):
        try:
            while True:
                fn, value = self.queue.get_nowait()
                fn(value)
        except queue.Empty:
            pass
        self.root.after(40, self.pump)

    def show_error(self, exc):
        messagebox.showerror('BlackPill demo', str(exc))

    def mono(self, parent, height):
        frame = ttk.Frame(parent)
        text = tk.Text(frame, font=(MONO, 10), height=height, wrap='none', bg='#0f172a', fg='#cbd5e1',
                       insertbackground='white', relief='flat', padx=10, pady=8)
        sb = ttk.Scrollbar(frame, command=text.yview)
        text.configure(yscrollcommand=sb.set)
        sb.pack(side='right', fill='y')
        text.pack(side='left', fill='both', expand=True)
        return frame, text

    @staticmethod
    def set_text(widget, value):
        widget.configure(state='normal')
        widget.delete('1.0', 'end')
        widget.insert('1.0', value)
        widget.configure(state='disabled')

    # ---- page 1: choose the card ---------------------------------------------

    def page_select(self):
        p = self.page(0)
        ttk.Label(p, text='Insert the SD card in a normal USB card reader', style='H.TLabel').pack(anchor='w')
        ttk.Label(p, style='Muted.TLabel', wraplength=int(980 * self.scale), justify='left', text=(
            'Not through the Black Pill - this shows what anyone who pulls the card out would see. '
            'Windows will probably say the disk needs to be formatted: click Cancel. '
            'This tool only reads the card, it never writes to it.')).pack(anchor='w', pady=(4, 14))
        if not is_admin():
            warn = ttk.Frame(p)
            warn.pack(fill='x', pady=(0, 12))
            ttk.Label(warn, style='Bad.TLabel', text='Reading a disk directly needs Administrator rights.').pack(side='left')
            ttk.Button(warn, text='Restart as Administrator', command=self.elevate).pack(side='left', padx=12)
        cols = ('disk', 'model', 'size', 'bus', 'status')
        self.tree = ttk.Treeview(p, columns=cols, show='headings', height=8, selectmode='browse')
        for c, w, t in zip(cols, (70, 360, 110, 80, 330), ('Disk', 'Model', 'Size', 'Bus', 'BlackPill card?')):
            self.tree.heading(c, text=t)
            self.tree.column(c, width=int(w * self.scale), anchor='w')
        self.tree.pack(fill='x')
        self.tree.bind('<<TreeviewSelect>>', lambda _: self.update_select())
        self.tree.bind('<Double-1>', lambda _: self.select_next())
        bar = ttk.Frame(p)
        bar.pack(fill='x', pady=14)
        ttk.Button(bar, text='Refresh', command=self.refresh_disks).pack(side='left')
        ttk.Button(bar, text='Open a dump file instead...', command=self.open_dump).pack(side='left', padx=8)
        self.next_btn = ttk.Button(bar, text='Next  \u2192', style='Accent.TButton', command=self.select_next,
                                   state='disabled')
        self.next_btn.pack(side='right')
        self.select_status = ttk.Label(p, style='Muted.TLabel', text='')
        self.select_status.pack(anchor='w')
        self.disks = {}
        self.root.bind('<Return>', lambda _: self.select_next())
        self.refresh_disks()

    def elevate(self):
        if relaunch_as_admin():
            self.root.destroy()
        else:
            messagebox.showwarning('BlackPill demo', 'Administrator rights were not granted.')

    def refresh_disks(self):
        self.select_status.configure(text='Looking for disks...')
        self.tree.delete(*self.tree.get_children())

        def work():
            found = []
            for d in list_disks():
                idx = d.get('Index')
                path = rf'\\.\PhysicalDrive{idx}'
                status, ok = '', False
                # Probe every disk (some readers report SCSI, not USB). Read-only, sector 0/8 only.
                if not d.get('Size'):
                    status = 'no card inserted?'
                else:
                    try:
                        c = Card(path, int(d['Size']))
                        h, _ = header_info(c)
                        c.close()
                        ok = h is not None
                        status = ('\u2714 BlackPill header found (' +
                                  ('encrypted' if ok and u32(h, 80) == 2 else 'plaintext') + ')') if ok else 'no BlackPill header'
                    except PermissionError:
                        status = 'needs Administrator'
                    except OSError as exc:
                        status = f'cannot read ({exc.strerror or exc})'
                found.append((idx, d, path, status, ok))
            return found

        def done(found):
            first = None
            for idx, d, path, status, ok in found:
                iid = str(idx)
                size = human(int(d['Size'])) if d.get('Size') else '-'
                self.tree.insert('', 'end', iid=iid, values=(idx, d.get('Model') or '?', size,
                                                             d.get('InterfaceType') or '?', status))
                self.disks[iid] = (path, int(d.get('Size') or 0), ok, f"Disk {idx} - {d.get('Model')}")
                if ok and first is None:
                    first = iid
            if first:
                self.tree.selection_set(first)
            n = sum(1 for f in found if f[4])
            self.select_status.configure(text=f'{n} BlackPill card(s) found.' if n else
                                         'No BlackPill card found. Check the reader, then Refresh.')
            self.update_select()

        self.run(work, done)

    def update_select(self):
        sel = self.tree.selection()
        ok = bool(sel) and self.disks.get(sel[0], (0, 0, False))[2]
        self.next_btn.configure(state='normal' if ok else 'disabled')

    def select_next(self):
        sel = self.tree.selection()
        if not sel or not self.disks[sel[0]][2]:
            return
        path, size, _, label = self.disks[sel[0]]
        self.open_card(path, size, label)

    def open_dump(self):
        path = filedialog.askopenfilename(title='Raw card dump (must start at card sector 0)',
                                          filetypes=[('Raw dumps', '*.bin *.img *.raw *.dd'), ('All files', '*.*')])
        if path:
            self.open_card(path, os.path.getsize(path), f'Dump file {Path(path).name}')

    def open_card(self, path, size, label):
        try:
            card = Card(path, size)
            h, _ = header_info(card)
        except PermissionError:
            messagebox.showerror('BlackPill demo', 'Access denied. Restart as Administrator.')
            return
        if h is None:
            card.close()
            messagebox.showerror('BlackPill demo', 'No BlackPill header (BPVOL001) at the start of this card/dump.')
            return
        if self.card:
            self.card.close()
        self.card, self.card_label, self.header = card, label, h
        self.key = self.drive = None
        self.page_raw()

    # ---- page 2: what a thief sees -------------------------------------------

    def page_raw(self):
        p = self.page(1)
        ttk.Label(p, text='What anyone with a card reader sees', style='H.TLabel').pack(anchor='w')
        ttk.Label(p, style='Muted.TLabel', text=self.card_label).pack(anchor='w', pady=(0, 10))

        top = ttk.Frame(p)
        top.pack(fill='x')
        info = ttk.Frame(top)
        info.pack(side='left', fill='y', padx=(0, 20))
        ttk.Label(info, text='Card header (public, not secret)', style='Big.TLabel').grid(columnspan=2, sticky='w', pady=(0, 4))
        for r, (k, v) in enumerate(describe_header(self.header).items(), 1):
            ttk.Label(info, text=k, style='Muted.TLabel').grid(row=r, column=0, sticky='w', padx=(0, 10))
            ttk.Label(info, text=v, font=(MONO, 9)).grid(row=r, column=1, sticky='w')
        ttk.Label(info, style='Muted.TLabel', wraplength=int(420 * self.scale), justify='left', text=(
            'The data key is only stored wrapped (AES-GCM encrypted) with a key made from the '
            'auth file AND the password. Everything after this header is ciphertext.')).grid(
            row=r + 1, columnspan=2, sticky='w', pady=(8, 0))

        srch = ttk.Frame(top)
        srch.pack(side='left', fill='both', expand=True)
        ttk.Label(srch, text='Search the raw card for your text', style='Big.TLabel').pack(anchor='w')
        ttk.Label(srch, style='Muted.TLabel', wraplength=int(480 * self.scale), justify='left', text=(
            f'Type a word from the file you saved. The first {SEARCH_LIMIT // 2**20} MiB of the card '
            '(where a freshly formatted drive puts new files) are scanned as plain text and UTF-16.')).pack(anchor='w', pady=(2, 8))
        row = ttk.Frame(srch)
        row.pack(fill='x')
        self.needle = tk.StringVar()
        entry = ttk.Entry(row, textvariable=self.needle, font=(FONT, 12))
        entry.pack(side='left', fill='x', expand=True)
        entry.bind('<Return>', lambda _: self.do_search())
        self.search_btn = ttk.Button(row, text='Search card', command=self.do_search)
        self.search_btn.pack(side='left', padx=(8, 0))
        self.search_bar = ttk.Progressbar(srch, style='Bar.Horizontal.TProgressbar', maximum=1)
        self.search_bar.pack(fill='x', pady=(10, 4))
        self.search_result = ttk.Label(srch, text='', wraplength=int(480 * self.scale), justify='left')
        self.search_result.pack(anchor='w')
        entry.focus_set()

        ttk.Label(p, style='Big.TLabel', text=(
            'Where Windows keeps the partition table and file list: card sectors 16-17')).pack(anchor='w', pady=(16, 2))
        ttk.Label(p, style='Muted.TLabel', text=(
            'On a normal USB stick this is readable structure (and the file names). '
            'Here it is indistinguishable from random noise.')).pack(anchor='w', pady=(0, 6))
        frame, text = self.mono(p, 14)
        frame.pack(fill='both', expand=True)
        self.set_text(text, hexdump(self.card.read(OFFSET, 2), OFFSET * SECTOR))

        bar = ttk.Frame(p)
        bar.pack(fill='x', pady=(12, 0))
        ttk.Button(bar, text='\u2190  Back', command=self.page_select).pack(side='left')
        ttk.Button(bar, text='Unlock with auth file + password  \u2192', style='Accent.TButton',
                   command=self.page_unlock).pack(side='right')
        self.root.bind('<Return>', lambda e: None if e.widget is entry else self.page_unlock())

    def do_search(self):
        text = self.needle.get().strip()
        if not text or str(self.search_btn['state']) == 'disabled':
            return
        self.search_btn.configure(state='disabled')
        self.search_result.configure(text='Searching...', style='TLabel')
        self.cancel_search = False
        card = self.card

        def progress(done, total):
            self.ui(lambda: self.search_bar.configure(value=done / total) if self.search_bar.winfo_exists() else None)

        def finished(result):
            if not self.search_btn.winfo_exists():
                return
            hits, scanned = result
            self.search_btn.configure(state='normal')
            if hits:
                self.search_result.configure(style='Bad.TLabel', text=(
                    f'Found "{text}" {len(hits)} time(s) in the raw card, first at byte {hits[0]:,} '
                    f'(sector {hits[0] // SECTOR:,}). That data is NOT encrypted.'))
            else:
                self.search_result.configure(style='Good.TLabel', text=(
                    f'"{text}" not found anywhere in the first {human(scanned)} of the card.'))

        self.run(lambda: search_raw(card, text, SEARCH_LIMIT, progress, lambda: self.cancel_search), finished)

    # ---- page 3: unlock --------------------------------------------------------

    def page_unlock(self):
        self.cancel_search = True
        p = self.page(2)
        ttk.Label(p, text='Unlock: authentication file + password', style='H.TLabel').pack(anchor='w')
        ttk.Label(p, style='Muted.TLabel', wraplength=int(980 * self.scale), justify='left', text=(
            'This repeats, on the PC, what the BlackPill utility and the board do together when you '
            'unlock the drive. Both secrets are needed: either one alone gives the wrong key.')).pack(anchor='w', pady=(4, 16))
        form = ttk.Frame(p)
        form.pack(fill='x')
        form.columnconfigure(1, weight=1)
        ttk.Label(form, text='Auth file').grid(row=0, column=0, sticky='w', padx=(0, 12), pady=6)
        self.auth_path = tk.StringVar(value=getattr(self, 'last_auth', ''))
        ttk.Entry(form, textvariable=self.auth_path).grid(row=0, column=1, sticky='ew')
        ttk.Button(form, text='Browse...', command=self.pick_auth).grid(row=0, column=2, padx=(8, 0))
        ttk.Label(form, text='Password').grid(row=1, column=0, sticky='w', padx=(0, 12), pady=6)
        self.password = tk.StringVar()
        self.pw_entry = ttk.Entry(form, textvariable=self.password, show='\u2022', font=(FONT, 12))
        self.pw_entry.grid(row=1, column=1, sticky='ew')
        self.pw_entry.bind('<Return>', lambda _: self.do_unlock())
        self.reveal = tk.BooleanVar()
        ttk.Checkbutton(form, text='Show', variable=self.reveal,
                        command=lambda: self.pw_entry.configure(show='' if self.reveal.get() else '\u2022')
                        ).grid(row=1, column=2, padx=(8, 0), sticky='w')
        self.unlock_btn = ttk.Button(p, text='Unlock', style='Accent.TButton', command=self.do_unlock)
        self.unlock_btn.pack(anchor='w', pady=(14, 14))

        steps = ttk.Frame(p)
        steps.pack(fill='x')
        self.step_rows = {}
        texts = ['Check the card header with the auth file', 'Stretch the password with Argon2id',
                 'Combine password + auth file into the key-encryption key',
                 'Unwrap the data key (AES-256-GCM)', 'Decrypt the filesystem and find your files']
        for i, t in enumerate(texts, 1):
            row = ttk.Frame(steps)
            row.pack(fill='x', pady=2)
            mark = ttk.Label(row, text='\u25cb', width=3, font=(FONT, 12), foreground=MUTED)
            mark.pack(side='left')
            lbl = ttk.Label(row, text=t, foreground=MUTED, font=(FONT, 11))
            lbl.pack(side='left')
            self.step_rows[i] = (mark, lbl)

        keyrow = ttk.Frame(p)
        keyrow.pack(fill='x', pady=(16, 0))
        self.key_label = ttk.Label(keyrow, text='', font=(MONO, 10))
        self.key_label.pack(side='left')
        self.key_btn = ttk.Button(keyrow, text='Reveal key', command=self.toggle_key)
        self.unlock_error = ttk.Label(p, text='', style='Bad.TLabel', wraplength=int(980 * self.scale), justify='left')
        self.unlock_error.pack(anchor='w', pady=(10, 0))

        bar = ttk.Frame(p)
        bar.pack(side='bottom', fill='x')
        ttk.Button(bar, text='\u2190  Back', command=self.page_raw).pack(side='left')
        self.files_btn = ttk.Button(bar, text='Show my files  \u2192', style='Accent.TButton',
                                    command=self.page_files, state='disabled')
        self.files_btn.pack(side='right')
        (self.pw_entry if self.auth_path.get() else form).focus_set()
        if self.key:   # already unlocked earlier this session
            self.unlocked_view()

    def pick_auth(self):
        path = filedialog.askopenfilename(title='Authentication file',
                                          filetypes=[('Auth file', '*.json'), ('All files', '*.*')])
        if path:
            self.auth_path.set(path)
            self.pw_entry.focus_set()

    def mark(self, n, text=None, state='done'):
        if n not in getattr(self, 'step_rows', {}) or not self.step_rows[n][0].winfo_exists():
            return
        mark, lbl = self.step_rows[n]
        sym, color = {'done': ('\u2714', OK), 'busy': ('\u2026', ACCENT), 'fail': ('\u2716', DANGER),
                      'todo': ('\u25cb', MUTED)}[state]
        mark.configure(text=sym, foreground=color)
        lbl.configure(foreground=INK if state != 'todo' else MUTED)
        if text:
            lbl.configure(text=text)

    def do_unlock(self):
        auth, pw = self.auth_path.get().strip(), self.password.get()
        if not auth or not Path(auth).is_file():
            self.unlock_error.configure(text='Choose the authentication file first.')
            return
        if not pw:
            self.unlock_error.configure(text='Enter the password.')
            return
        if str(self.unlock_btn['state']) == 'disabled':
            return
        self.last_auth = auth
        self.unlock_btn.configure(state='disabled')
        self.unlock_error.configure(text='')
        for i in range(1, 6):
            self.mark(i, state='todo')
        self.mark(1, state='busy')
        card = self.card
        progress_state = {'n': 1}

        def step(n, text, busy=False):
            progress_state['n'] = n if busy else n + 1   # the step that is now running
            self.ui(self.mark, n, text, 'busy' if busy else 'done')
            if not busy and n < 5:
                self.ui(self.mark, n + 1, None, 'busy')

        def work():
            key = unwrap_key(card, auth, pw, step)
            drive = Drive(card, key)
            kind, where, files, structures = list_files(drive)
            return key, drive, kind, where, files, structures

        def done(result):
            self.key, self.drive, kind, where, self.files, self.structures = result
            self.fs_desc = f'{kind}, {where}'
            self.password.set('')
            if self.unlock_btn.winfo_exists():
                self.unlocked_view()

        def fail(exc):
            if not self.unlock_btn.winfo_exists():
                return
            self.unlock_btn.configure(state='normal')
            self.mark(progress_state['n'], state='fail')
            self.unlock_error.configure(text=str(exc))

        self.run(work, done, fail)

    def unlocked_view(self):
        for i in range(1, 5):
            self.mark(i, state='done')
        n = len(self.files)
        self.mark(5, f'Decrypted the filesystem ({self.fs_desc}): {n} file{"s" if n != 1 else ""} found')
        self.key_shown = False
        self.key_label.configure(text='Data key: ' + '\u2022' * 64)
        self.key_btn.pack(side='left', padx=10)
        self.unlock_btn.configure(state='disabled')
        self.files_btn.configure(state='normal')
        self.files_btn.focus_set()
        self.root.bind('<Return>', lambda _: self.page_files())

    def toggle_key(self):
        self.key_shown = not self.key_shown
        self.key_label.configure(text='Data key: ' + (self.key.hex() if self.key_shown else '\u2022' * 64))
        self.key_btn.configure(text='Hide key' if self.key_shown else 'Reveal key')

    # ---- page 4: decrypted files -------------------------------------------------

    def page_files(self):
        p = self.page(3)
        ttk.Label(p, text='Your files, decrypted', style='H.TLabel').pack(anchor='w')
        ttk.Label(p, style='Muted.TLabel', text=(
            f'{self.fs_desc}. Without the key nobody can even tell where these files are on the card: '
            'the file list itself is encrypted.')).pack(anchor='w', pady=(0, 10))
        main = ttk.Frame(p)
        main.pack(fill='both', expand=True)
        left = ttk.Frame(main)
        left.pack(side='left', fill='y', padx=(0, 14))
        self.file_list = ttk.Treeview(left, columns=('size',), show='tree headings', height=20, selectmode='browse')
        self.file_list.heading('#0', text='File')
        self.file_list.heading('size', text='Size')
        self.file_list.column('#0', width=int(260 * self.scale))
        self.file_list.column('size', width=int(95 * self.scale), anchor='e')
        self.file_list.pack(fill='y', expand=True)
        self.items = {}
        self.file_list.insert('', 'end', iid='g_meta', text='Drive structure', open=True)
        for i, s in enumerate(self.structures):
            self.file_list.insert('g_meta', 'end', iid=f'm{i}', text=s.path,
                                  values=(f'{len(s.sectors)} sector{"s" if len(s.sectors) != 1 else ""}',))
            self.items[f'm{i}'] = s
        self.file_list.insert('', 'end', iid='g_files', text='Files', open=True)
        for i, f in enumerate(self.files):
            self.file_list.insert('g_files', 'end', iid=f'f{i}', text=f.path, values=(human(f.size),))
            self.items[f'f{i}'] = f
        self.file_list.bind('<<TreeviewSelect>>', lambda _: self.show_file())

        right = ttk.Frame(main)
        right.pack(side='left', fill='both', expand=True)
        self.cipher_title = ttk.Label(right, text='On the card (ciphertext)', style='Big.TLabel')
        self.cipher_title.pack(anchor='w')
        cf, self.cipher_text = self.mono(right, 11)
        cf.pack(fill='both', expand=True, pady=(2, 10))
        plain_head = ttk.Frame(right)
        plain_head.pack(fill='x')
        ttk.Label(plain_head, text='Decrypted', style='Big.TLabel').pack(side='left')
        self.as_hex = tk.BooleanVar()
        ttk.Checkbutton(plain_head, text='Show as hex', variable=self.as_hex, command=self.show_file).pack(side='right')
        pf = ttk.Frame(right)
        pf.pack(fill='both', expand=True, pady=(2, 0))
        self.plain_text = tk.Text(pf, font=(MONO, 13), height=9, wrap='word', bg='#f8fafc', fg=INK,
                                  relief='flat', padx=12, pady=10)
        sb = ttk.Scrollbar(pf, command=self.plain_text.yview)
        self.plain_text.configure(yscrollcommand=sb.set)
        sb.pack(side='right', fill='y')
        self.plain_text.pack(side='left', fill='both', expand=True)

        bar = ttk.Frame(p)
        bar.pack(fill='x', pady=(12, 0))
        ttk.Button(bar, text='\u2190  Back', command=self.page_unlock).pack(side='left')
        ttk.Button(bar, text='Start over', command=self.page_select).pack(side='left', padx=8)
        ttk.Button(bar, text='Save decrypted copy...', command=self.save_file).pack(side='right')

        if not self.files:
            self.file_list.selection_set('m0')
            return
        # Prefer a non-empty .txt in the root folder (the demo file), then any .txt.
        order = sorted(range(len(self.files)), key=lambda i: (
            not self.files[i].path.lower().endswith('.txt'), self.files[i].size == 0,
            '\\' in self.files[i].path, i))
        pick = f'f{order[0]}'
        self.file_list.selection_set(pick)
        self.file_list.focus(pick)

    def current(self):
        sel = self.file_list.selection()
        return self.items.get(sel[0]) if sel else None

    def show_file(self):
        f = self.current()
        if f is None:
            return
        # Top: the raw ciphertext of the sectors holding this item.
        shown = f.sectors[:8] if f.meta else f.sectors[:2]
        if shown:
            raw = b''.join(self.drive.raw(s) for s in shown)
            first, last = shown[0] + OFFSET, shown[-1] + OFFSET
            where = f'card sector {first:,}' if first == last else f'card sectors {first:,}-{last:,}'
            if shown != list(range(shown[0], shown[0] + len(shown))):
                where = f'card sectors from {first:,} (not contiguous)'
            self.cipher_title.configure(text=f'On the card (ciphertext): {where}' + (f' - {f.note}' if f.note else ''))
            self.set_text(self.cipher_text, card_hexdump(raw, shown, 0, len(raw)))
        else:
            self.cipher_title.configure(text='On the card (ciphertext)')
            self.set_text(self.cipher_text, 'Empty file: no data sectors.')
        # Bottom: the same bytes decrypted, labelled with the same card addresses.
        body = f.content
        if self.as_hex.get():
            value = card_hexdump(body, f.sectors, f.data_offset, len(shown) * SECTOR if f.meta else 4096)
        elif f.meta:
            value = f.summary + '\n\n(Tick "Show as hex" to see the decrypted bytes.)'
        else:
            value = body.decode('utf-8-sig', 'replace') if not body.startswith((b'\xff\xfe', b'\xfe\xff')) \
                else body.decode('utf-16', 'replace')
        if not f.meta and f.size > len(body):
            value += f'\n\n[... showing first {human(len(body))} of {human(f.size)}]'
        self.set_text(self.plain_text, value)
        dense = f.meta or self.as_hex.get()
        self.plain_text.configure(wrap='none' if self.as_hex.get() else 'word', font=(MONO, 11 if dense else 13))

    def save_file(self):
        f = self.current()
        if f is None:
            return
        path = filedialog.asksaveasfilename(title='Save decrypted copy', initialfile=Path(f.path.replace('\\', '/')).name)
        if path:
            Path(path).write_bytes(f.content)
            if f.size > len(f.content):
                messagebox.showinfo('BlackPill demo', f'Saved the first {human(len(f.content))} only.')


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--image', help='raw card dump file to use instead of a physical card')
    args = ap.parse_args()
    if not args.image and sys.platform == 'win32' and not is_admin():
        if relaunch_as_admin():
            return
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    root = tk.Tk()
    App(root, args.image)
    root.mainloop()


if __name__ == '__main__':
    main()
