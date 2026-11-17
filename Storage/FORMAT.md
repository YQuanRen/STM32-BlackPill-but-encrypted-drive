# Volume formats 1/2 and setup transaction

Format 2 (2026-10-21) is fast setup and is the default for new volumes. Format 1
retains its original full-initialization behavior and remains readable. Both use
the same byte layout and `BPVOL001` magic; the version at offset 8 distinguishes
the setup guarantees. Version is covered by both header HMAC and wrapping/key-check
AAD. Update firmware and host together: old firmware rejects v2 before SD writes,
and old hosts reject v2 headers. New software can unlock existing v1 volumes
without rewriting them. An old host still requesting v1 performs the slow full pass.

All integers are little-endian. Physical sectors 0..7 and 8..15 are identical
4096-byte headers. The first 256 bytes have the layout below; all remaining bytes
must be zero. Both copies must authenticate and match exactly: no automatic repair
or fallback to an older copy. Logical sector L maps to physical L+16 in BOTH modes.
Cards with <=16 sectors, missing cards, mismatched CID/geometry, corrupt/inconsistent
headers and uninitialized volumes stay locked. CID binding detects ordinary card
swaps; it is not a defense against hardware that spoofs a CID.

| Offset | Length | Field |
| --- | --- | --- |
| 0 | 8 | ASCII BPVOL001 |
| 8 | 4 | format 1 full initialization, 2 fast setup |
| 12 | 4 | state: 1 initializing, 2 ready |
| 16 | 16 | device identity |
| 32 | 16 | random volume ID |
| 48 | 16 | SD CID |
| 64 | 8 | physical sector count (17..UINT32_MAX) |
| 72 | 8 | logical sector count = physical - 16 |
| 80 | 4 | mode: 1 plaintext, 2 Adiantum |
| 84 | 4 | sector size 512 |
| 88,92,96 | 4 each | Argon2id memory KiB, iterations, parallelism |
| 100 | 16 | password salt |
| 116 | 12 | wrapping GCM nonce |
| 128 | 48 | wrapped 32-byte key + 16-byte GCM tag |
| 176 | 32 | data-key verification HMAC |
| 208 | 16 | reserved zeros |
| 224 | 32 | HMAC(file-auth, ASCII BP1/header || bytes 0..223) |

Auth-only mode requires bytes 88..207 to be zero. Encryption requires exactly
Argon2id version 19, 65536 KiB, 3 iterations, parallelism 1, output 32 bytes.
Host checks HMAC, identity, sizes and these fixed parameters BEFORE running KDF.
Passwords are UTF-8, no normalization; nonempty, max 1024 encoded bytes. Salt,
volume ID, data key and nonce are newly generated using OS randomness each setup.

AAD = header[0:12] || header[16:128] (124 bytes; excludes mutable state).
PW = Argon2id(password, salt). WRAP_FILE is the independently derived wrapping
secret from the root authentication file (Control/PROTOCOL.md).
KEK = HKDF-SHA256(IKM=PW || WRAP_FILE,
salt=SHA256(ASCII BP1/wrap-salt || deviceID || volumeID), info=ASCII BP1/data-wrap).
Wrapped key = AES256-GCM(KEK, nonce, dataKey, AAD).
Key check = HMAC-SHA256(dataKey, ASCII BP1/data-check || AAD).
The board checks this value before installing any received key. Knowledge of the
board's file-auth secret does not provide WRAP_FILE or replace the password.

## Transaction and journal

Journal format 2 retains the 128-byte record layout, uses bytes 68..83 for volume
ID and leaves 84..91 zero. Version-1 records are read as an unbound volume (zero
ID); the next append uses version 2. Identity/auth stay immutable; mode and volume
are taken from the highest committed epoch. A mode/binding update appends a new
epoch with the existing auth secret. No root secret or plaintext data key is stored.

An authenticated operation-2 session stages header[256] || dataKey[32] in ordered
chunks (key is all zero in auth-only mode). COMMIT revalidates HMAC, device, live
CID/capacity, new nonzero volume ID, state=initializing and data-key check. It then
commits the new mode/volume binding to MCU flash BEFORE touching SD data. From that
point, old headers cannot unlock even if setup fails. It writes and verifies both
initializing headers, then processes one selected logical sector per main-loop
step: zeros in mode 1 or Adiantum-encrypted zeros in mode 2, tweaked by its actual
logical LBA (not its progress index). Every selected write is read back and compared.

- Format 1 selects every exposed sector.
- Format 2 selects the union of logical LBAs `[0,min(34,N))` and
  `[max(0,N-33),N)`, where N is exposed sector count. Overlaps on tiny cards are
  written only once, giving `min(N,67)` selected sectors. The disk's beginning
  and end lose their usual partition signatures; no filesystem or partition is
  created. The usual 512-byte GPT layout uses the first 34 and last 33 sectors;
  see the [UEFI GPT specification](https://uefi.org/specs/UEFI/2.10/05_GUID_Partition_Table_Format.html).
  This is metadata invalidation, not a claim to erase every possible old table.

Only after all selected sectors succeed are both ready headers written/verified.
For normal cards v2 performs 16 + 67 + 16 = 99 sector writes and 99 verification
reads, independent of capacity. Windows must subsequently create a volume and
QUICK-format it through the unlocked Black Pill. Never pre-format using another
reader as a substitute: that bypasses encryption and the logical offset.
Each header phase verifies padding sectors 1..7 and 9..15 first, then writes and
verifies state-bearing sectors 0 and 8 last. A cut before the last ready marker
leaves at least one initializing copy, which normal unlock rejects.
MSC stays unavailable throughout. Completion clears expanded key state and remains
locked until a fresh operation-1 session authorizes/installs the validated key.

Any reset, SD error or card swap stops work and clears volatile key/staging state.
Interrupted setup never resumes: explicit new setup generates a new volume/key and
restarts the selected setup writes. If power fails before the journal commit, no SD write
has happened and the old volume remains usable. If it fails afterward, explicit
restart is required. Flash corruption follows the conservative fault policy in
Control/PROTOCOL.md. Reinitialization/mode changes require the existing file; no
credential rotation or live locking of mounted disks is implemented.

## Protected control additions

All operations use existing AES-GCM SECURE messages and counters. Storage commands
are rejected while media is mounted; setup commands require operation-2 sessions.

| Plaintext opcode | Request body after opcode | Response after encrypted status |
| --- | --- | --- |
| 4 STAGE | offset u16, 1..128 bytes (sequential, total 288) | empty |
| 5 COMMIT | empty | empty (initialization started) |
| 6 STATUS | empty | state u8, mode u8, done u32, setup total u32, CID[16], physical count u32 |
| 7 HEADER | offset u16, length u8 (1..128, within 256) | header slice |

STATUS states: 0 no validated volume, 1 initializing, 2 ready/locked, 3 fault.
During/after setup, done/total count selected logical metadata sectors for v2, or
all logical sectors for v1; header writes are not counted. Before any volume has
been loaded, total remains physical-16 for compatibility with card discovery.
Physical count and exposed MSC capacity never shrink to the setup-work count.
Error statuses add 7 SD failure, 8 invalid/missing header, 9 busy.
HEADER validates both complete copies against the current journal/card before
returning slices. STATUS/HEADER are authenticated. The file's saved mode is only
an enrollment hint; current mode comes from the authenticated transcript and header.

The CLI prints exact device identity, CID, physical capacity and chosen mode and
requires typing `ERASE <deviceID> <CID>` before sending STAGE/COMMIT. No development
test authorizes physical card writes. Safe Windows ejection followed by unplug is
still required.

## Fast setup's changed guarantees

Untouched physical sectors are not read, written or verified. Old plaintext can
remain recoverable through another reader; fast setup is NOT erasure, sanitization
or in-place encryption of existing files. In encrypted mode, unwritten logical
sectors decrypt to arbitrary bytes until overwritten; there is no written-sector
bitmap or zero-read promise. In auth-only mode, those reads expose old contents.
Windows quick-format must establish a fresh filesystem before use. Every subsequent
encrypted-mode write still encrypts its entire 512-byte sector. Credential
requirements, LBA mapping, Adiantum, key wrapping and mounted-media gates are unchanged.
Adiantum does not authenticate sectors. Even v1 full initialization does not
guarantee sanitization of remapped flash cells.

## Anti-forensic additions (2026-11-11)

See `ANTIFORENSIC.md`. These do not change the 256-byte header layout above.

### Authentication file version 2 (duress / decoy password)

The host authentication JSON gains an optional `duress` object and bumps `version` to
2 when present; version 1 files remain valid and carry no duress field. The verifier is
**host-only** — it is never sent to the board.

```
duress = { "version": 1,
           "salt":     <16-byte hex>,
           "verifier": <32-byte hex Argon2id(decoy_password, salt)>,
           "kdf":      [65536, 3, 1] }   # memory KiB, iterations, parallelism
```

At unlock the host first attempts the real key unwrap. Only on failure does it compare
the entered password against this verifier (constant time). A match triggers the DESTROY
flow (operation 3, opcode 8) and the host then reports an error identical to an ordinary
wrong password. The decoy must differ from the real password. Mode-1 (plaintext) files
do not take a duress verifier (there is no key to crypto-erase).

### Crypto-erase and full secure-erase

- **Crypto-erase (DESTROY).** Overwrites physical sectors 0..15 (both header copies),
  destroying both copies of the AES-256-GCM-wrapped data key, then wipes the credential
  journal. For an encrypted volume this is cryptographic erasure: the random data key
  existed only inside the wrapped-key field and cannot be recovered afterward. For a
  plaintext volume it removes the header and credentials but leaves the data region.
- **Full secure-erase.** Format-1 full initialization, now surfaced as an opt-in setup
  method (`--secure-erase` / GUI "Full secure-erase"). Every logical sector is written
  (encrypted-zeros in mode 2, zeros in mode 1), removing old plaintext from the data
  region. Slow by design; fast setup remains the default and still carries the
  "old plaintext may remain recoverable" disclosure.
