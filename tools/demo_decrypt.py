"""Demo helper: recover the data key and decrypt raw sectors read from the SD card.

Read the card in an ordinary card reader (NOT through the Black Pill) so you get
raw ciphertext. Then:

    python tools/demo_decrypt.py --image card.bin --file drive-auth.json --lba 0 --count 64

`--image` is either a raw dump file (e.g. saved from HxD) or a physical disk such
as \\\\.\\PhysicalDrive2 (needs an Administrator prompt). The dump must start at
physical sector 0 of the card, because the volume header lives there.

The script unwraps the data key with the auth file + password, prints it, and
writes the decrypted logical sectors to an output file you can open in a hex
editor. Logical sector L is stored at physical sector L+16.
Uses the pure-Python reference Adiantum: fine for a few thousand sectors, too
slow for a whole card.
"""
# ---------------------------------------------------------------------------
# THE BIG PICTURE
#
# The Black Pill sits between the PC and the SD card. Every sector the PC
# writes is encrypted on the microcontroller before it reaches the card, so
# the card itself only ever holds scrambled bytes.
#
# There are two layers of keys:
#
#   1. The DATA KEY - a random 32-byte key that actually encrypts the sectors.
#      It is never stored in the clear anywhere.
#
#   2. The KEY-ENCRYPTION KEY (KEK) - built from TWO secrets:
#        - your password, and
#        - a random secret in your drive-auth.json file.
#      The KEK locks ("wraps") the data key, and the wrapped copy is kept in
#      a header at the very start of the SD card.
#
# So to read the card you need the card + the auth file + the password.
# Any two of the three are useless on their own.
#
# This script does by hand exactly what the PC utility and the Black Pill do
# together when you unlock the drive:
#   step 1-4: rebuild the KEK and unwrap the data key from the header
#   step 5:   decrypt raw sectors with that data key (Adiantum)


#KEK = HKDF( Argon2id(password)  +  wrap secret from drive-auth.json )
#data key = AES-GCM-decrypt(KEK, wrapped key in card header)

# ---------------------------------------------------------------------------
import argparse
import getpass
import hashlib
from pathlib import Path
import struct
import sys

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Reuse the project's own code: the host utility and the reference Adiantum
# implementation that the firmware is tested against.
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'host'), str(ROOT / 'tests/crypto/reference')]
import adiantum  # noqa: E402  Google's reference Adiantum, pure Python
import bpctl  # noqa: E402     HKDF/HMAC helpers and auth-file loader
import volume  # noqa: E402    header checks

SECTOR = 512   # bytes per SD card sector
OFFSET = 16    # the first 16 sectors hold two copies of the 4 KiB header,
               # so the drive's sector 0 really lives at card sector 16


def read_sectors(f, physical, count):
    """Read `count` raw 512-byte sectors starting at a PHYSICAL card sector."""
    f.seek(physical * SECTOR)
    data = f.read(count * SECTOR)
    if len(data) != count * SECTOR:
        raise SystemExit(f'Image too short: wanted physical sectors {physical}..{physical + count - 1}')
    return data


def unwrap_data_key(header, identity, root, password):
    """Steps 1-4: turn auth file + password + card header into the data key.

    This mirrors volume.unwrap() in the host utility, written out one step
    at a time so each stage can be explained.
    """
    # Header layout (first 256 bytes of the card, see Storage/FORMAT.md):
    #   0..7     "BPVOL001" magic
    #   16..31   device ID (the STM32's unique chip ID)
    #   32..47   random volume ID
    #   100..115 password salt
    #   116..127 AES-GCM nonce
    #   128..175 wrapped data key (32 bytes) + GCM tag (16 bytes)
    #   176..207 key-check value
    #   224..255 HMAC signature over the header

    # STEP 1 - Is this header genuine?
    # The auth file's root secret gives an "auth" key. The header is signed
    # with it, so a tampered or foreign header is rejected here before we
    # spend any time on the password.
    auth_key, wrap_file_secret = bpctl.file_keys(root, identity)
    if volume.validate(header, identity, auth_key) != 2:
        raise SystemExit('This volume is not in encrypted mode')
    print('[1] Header signature OK (auth file matches this card)')

    # STEP 2 - Stretch the password with Argon2id.
    # Argon2id is deliberately slow and memory-hungry (64 MiB, 3 passes), so
    # an attacker guessing passwords can only try a few per second.
    # The random salt stored in the header makes each card's result unique.
    salt = header[100:116]
    print('[2] Running Argon2id on the password (64 MiB, takes a moment)...', flush=True)
    password_key = hash_secret_raw(password.encode('utf-8'), salt,
                                   time_cost=3, memory_cost=65536, parallelism=1,
                                   hash_len=32, type=Type.ID, version=19)

    # STEP 3 - Combine password + auth file into the key-encryption key.
    # HKDF mixes both secrets together. Without BOTH, you get the wrong KEK.
    # The salt ties the result to this exact chip and this exact volume.
    hkdf_salt = hashlib.sha256(b'BP1/wrap-salt' + header[16:48]).digest()
    kek = bpctl.kdf(password_key + wrap_file_secret, hkdf_salt, b'BP1/data-wrap')
    print('[3] Key-encryption key derived from password + auth file')

    # STEP 4 - Unwrap the data key with AES-256-GCM.
    # GCM is authenticated encryption: if the password or file is wrong, the
    # tag check fails and we get an error instead of a garbage key.
    # The "associated data" is the rest of the header, so it can't be swapped
    # onto a different volume either.
    nonce = header[116:128]
    wrapped = header[128:176]
    try:
        data_key = AESGCM(kek).decrypt(nonce, wrapped, volume.aad(header))
    except Exception:
        raise SystemExit('Wrong password or wrong auth file - key did not unwrap')
    print('[4] Data key unwrapped (GCM tag verified)')
    return data_key


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--image', required=True, help='raw card dump or \\\\.\\PhysicalDriveN')
    p.add_argument('--file', help='drive-auth.json (needed unless --key is given)')
    p.add_argument('--key', help='data key as 64 hex chars (skips file/password)')
    p.add_argument('--lba', type=int, default=0, help='first LOGICAL sector to decrypt (default 0)')
    p.add_argument('--count', type=int, default=64, help='number of sectors (default 64)')
    p.add_argument('--out', default='decrypted.bin', help='output file (default decrypted.bin)')
    p.add_argument('--cipher-out', help='also save the matching raw ciphertext sectors here')
    a = p.parse_args()

    with open(a.image, 'rb', buffering=0) as f:
        if a.key:
            # Shortcut for repeat runs: reuse a key printed by an earlier run.
            key = bytes.fromhex(a.key)
            if len(key) != 32:
                raise SystemExit('--key must be 32 bytes (64 hex chars)')
        else:
            if not a.file:
                raise SystemExit('Give --file (plus password prompt) or --key')

            # The auth file holds the chip's ID and a 32-byte random root secret.
            identity, root = bpctl.load_file(a.file)[:2]

            # The wrapped key lives in the header at the very start of the card.
            header = read_sectors(f, 0, 1)[:256]
            if header[:8] != b'BPVOL001':
                raise SystemExit('No BPVOL001 header at sector 0: is this the raw card from sector 0?')

            if sys.stdin.isatty():
                password = getpass.getpass('Drive password: ')
            else:
                password = sys.stdin.readline().rstrip('\r\n')

            key = unwrap_data_key(header, identity, root, password)
        # (Blur this line in the video - it is the key to everything on the card.)
        print(f'Data key: {key.hex()}')

        # Read the raw, still-encrypted sectors. Remember the +16 shift.
        cipher = read_sectors(f, a.lba + OFFSET, a.count)

    # STEP 5 - Decrypt each sector with Adiantum.
    # Adiantum (designed by Google for low-power devices without AES hardware)
    # encrypts a whole 512-byte sector as one block: change one bit of input
    # and the entire sector's output changes.
    # The "tweak" is the sector number, so identical data written to two
    # different sectors still looks completely different on the card.
    ref = adiantum.Adiantum()
    ref.variant = _variant()  # XChaCha12 + AES-256, same as the firmware
    plain = bytearray()
    for i in range(a.count):
        lba = a.lba + i
        tweak = struct.pack('<Q', lba) + bytes(24)  # sector number, padded to 32 bytes
        plain += ref.decrypt(cipher[i * SECTOR:(i + 1) * SECTOR], key=key, tweak=tweak)
        if a.count >= 200 and i % 200 == 199:
            print(f'  {i + 1}/{a.count} sectors', flush=True)

    # Save both versions so they can be compared side by side in a hex editor.
    Path(a.out).write_bytes(plain)
    if a.cipher_out:
        Path(a.cipher_out).write_bytes(cipher)
    print(f'[5] Decrypted logical sectors {a.lba}..{a.lba + a.count - 1} '
          f'(physical {a.lba + OFFSET}..{a.lba + OFFSET + a.count - 1}) -> {a.out}')


def _variant():
    """Load the exact Adiantum settings from Google's official test vectors."""
    import json
    vectors = json.loads((ROOT / 'tests/crypto/reference/Adiantum_XChaCha12_32_AES256.json').read_text())
    return vectors[0]['cipher']


if __name__ == '__main__':
    main()
