# BlackPill control protocol 1 (milestones 3-4 development format)

This is a versioned development protocol, not TLS or a production USB identity.
All integers are little-endian except GCM's internal algorithm. Identity is the
STM32 96-bit UID bytes followed by four zero bytes. Never select a drive by
VID/PID alone: verify this identity against the credential file.

## Credentials and enrollment

The host generates a 32-byte OS-random root and saves a version-1 JSON file
containing `device` (16-byte hex), `root` (32-byte hex), and `mode` (1 auth-only,
2 encrypted), before sending enrollment. HKDF-SHA256 uses identity as salt,
root as IKM, and distinct ASCII info `BP1/file-auth` and `BP1/file-wrap`, each
32-byte output. Only file-auth is sent/stored on the board. File-wrap participates
in password/data-key wrapping (Storage/FORMAT.md). Initial enrollment assumes a trusted USB connection. It is
permitted only on completely erased credential flash. Nonblank invalid flash
is FAULT, never a new device. No USB reset/unenroll/credential replacement exists.
Interrupted enrollment can be retried by authenticating with the already saved
file if it committed; otherwise fail closed and use deliberate offline service.
Service reset requires SWD erase of both credential sectors and subsequent
fresh provisioning; it is not recovery of the old encrypted volume. Normal
firmware updates must preserve those sectors (no mass erase).

## Transport

MSC interface 0 uses bulk EP01/81. Vendor HID interface 1 uses usage page FF00,
usage 1, feature report ID 1, total 64 bytes (including ID). EP82 interrupt IN is
declared for HID enumeration; control exchange uses SET_REPORT/GET_REPORT Feature
via EP0. No HID driver-specific interrupt write behavior is required by the CLI.

Each report: ID=1 at byte 0, version=1 at byte 1, transfer ID u16 at 2,
message length u16 at 4, offset u16 at 6, then up to 56 bytes at 8. Unused bytes
must be zero. Messages are 8..256 bytes; fragments must arrive in order with
identical transfer ID/length, offsets 0,56,... . One request/response at a time.
Partial requests expire after 1000 ms. GET_REPORT with no response returns a
zero-length report; host polls. A response is consumed sequentially. Transport
errors discard assembly; they cannot produce an authenticated operation.

Message: version u8=1, command u8, request ID u32, payload length u16, payload.
Response command is request command OR 80h; payload starts with status u8:
0 OK, 1 malformed, 2 state, 3 authentication, 4 expired, 5 persistence fault,
6 unsupported/needs milestone-4 initialized volume. Lengths must match exactly.
No sensitive material is returned in error strings or logs.

Commands: INFO=1 (empty); ENROLL=2 (identity[16], mode[1], auth[32]);
BEGIN=3 (operation[1], host nonce[32]); PROVE=4 (host tag[32]); SECURE=5.
INFO result is identity[16], state[1] (0 virgin,1 locked/provisioned,2 fault),
mode[1], epoch u64. INFO is advisory, not authenticated.

BEGIN accepts operation 1 unlock or 2 setup. Never start another handshake
while media is authorized. It destroys any previous pending/session state.
Device increments its nonwrapping RAM counter, then forms transcript T:
ASCII `BP1` (3 bytes), identity[16], mode[1], operation[1], epoch u64,
challenge counter u64, host nonce[32], BEGIN request ID u32 (73 bytes total).
Device challenge D = HMAC(auth, ASCII `BP1/challenge` || T).
BEGIN response is epoch u64, counter u64, D[32]. Host recomputes D *before*
responding, preventing predictable future-epoch preplay and wrong-file use.
Host proof H = HMAC(auth, `BP1/host` || T || D).
PROVE consumes the pending challenge even on failure; expires 10 seconds after
BEGIN using wrap-safe tick subtraction. Device confirmation =
HMAC(auth, `BP1/device` || T || D || H). Host verifies it before commands.
This provides role separation and possession confirmation, not protection from
replacement hardware or compromised authentication secrets.

HKDF-SHA256 salt = SHA256(T || D || H), IKM=auth; directional info
`BP1/host-to-device` and `BP1/device-to-host`, output 32 bytes each.
SECURE payload = counter u64 || ciphertext || GCM tag[16]. Each direction
starts at counter 0, strictly increases without wrap. Nonce = four zero bytes
followed by LE64(counter), safe because keys differ per direction/session.
AAD = exact outer 8-byte header || counter u64. Responses include their status
*inside* encryption and use the response outer header. Invalid tag/counter
destroys the session and returns a plaintext error; clients treat it as failure.
Session idle lifetime is 60 seconds, bounded by wrap-safe ticks. Media authorization
persists independently until reset/disconnect/fatal storage failure; protocol
errors cannot live-lock an already mounted disk. No lock command exists.

Protected plaintext commands: PING=1 (no body), AUTHORIZE=2 (auth-only, operation
unlock), INSTALL_KEY=3 (encrypted, operation unlock, 32-byte key), STAGE=4,
COMMIT=5, STATUS=6 and HEADER=7 (specified in Storage/FORMAT.md).
Responses: status[1] and optional payload (PING `BP1`).
AUTHORIZE/INSTALL_KEY call the storage-policy hook; only successful validation
sets the media gate. The board validates both ready headers, journal binding,
live card identity/geometry and the encrypted-mode data-key verification HMAC.
Setup requires operation 2 and locked media; completion does not open media.
Additional errors: 7 SD failure, 8 invalid header, 9 busy; 6 means unsupported.
Control-only tests mock authorization; storage tests use the real volume layer.

## Freshness, persistence and reset

STM32F411CE sectors 6 and 7 are reserved: 08040000..0805FFFF and
08060000..0807FFFF (128 KiB each). Firmware linker region ends at 08040000.
Source: ST [RM0383, flash organization](https://www.st.com/resource/en/reference_manual/dm00119316-stm32f411xce-advanced-armbased-32bit-mcus-stmicroelectronics.pdf).

Each 128-byte append record: magic `BPJ1`[4], format u32=2, identity[16],
auth[32], mode u32, epoch u64 (offset 60), volume ID[16] (offset 68), zero[8],
SHA256(bytes 0..91)[32], commit u32=0 (offset 124, written last). Fields are
explicitly serialized; digest detects accidental corruption, not invasive edits.
Select highest valid epoch; conflicting equal epochs/credentials are a fault.
Version-1 records with zero bytes 68..91 remain readable as unbound volumes.
New records use version 2. Auth/identity are immutable; authenticated setup appends
a new mode/volume binding before SD writes, as specified in Storage/FORMAT.md.
On provisioned power boot, append/verify epoch+1 *before* USB challenges can run.
Enrollment commits epoch 1. Incomplete records with erased commit are skipped,
never overwritten. Invalid committed/torn-commit records fail closed. Epoch or
RAM-counter exhaustion fails closed. Flash errors require reboot/service.

Append within the active sector. At exhaustion, erase the other sector, verify
erasure, write/verify the next record there; keep the previous sector intact.
Each erase therefore amortizes 1024 boot records. Power loss before commit uses
the prior valid record and advances again before serving challenges. If a torn
erase leaves a corrupt committed old record, boot fails closed instead of trying
to guess its history. Service may be required for such corruption; no credential
loss is silently treated as new enrollment. Wear limits are hardware dependent.

USB bus reset/deconfigure/disconnect immediately closes the media gate, discards
transport state and schedules session/key-buffer wiping in the main loop. It
does not reset the epoch or challenge counter. Generation checks prevent a
request interrupted by USB reset from publishing a response or reopening media.
Suspend/resume preserves the session. Setup, control crypto and flash run in the
main loop; HID callbacks only copy bounded reports. MSC sector crypto/SD I/O run
in the existing USB callback path. SysTick priority 0 preempts USB priority 1 so
SD timeouts advance; preserve these priorities on CubeMX regeneration. Disk
callbacks reject I/O after a reset generation change. Flash programming can stall
single-bank instruction fetch; host timeouts allow for this and hardware USB
behavior remains to be measured. No epoch is allocated on enumeration resets.
