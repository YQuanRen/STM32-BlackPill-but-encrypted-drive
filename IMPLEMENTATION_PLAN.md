# Optional Adiantum encryption and file-based authentication

Saved: 2026-10-17; updated 2026-10-20 (Asia/Singapore). Status: milestones 1-4 software implemented and tested; milestone 5 GUI and Windows package implemented with software tests passing. Fresh-machine and physical USB/flash/SD acceptance, throughput and stack measurements remain pending. See HANDOFF.md for evidence and host/VALIDATION.md for the acceptance record.

This document preserves decisions from the planning conversation. Technical defaults below are the intended implementation direction, not a claim that a secure implementation already exists. Resolve the explicitly listed engineering questions before freezing persistent formats or the protocol. Track progress in HANDOFF.md.

## 1. User workflow and scope

The owner distributes a pre-flashed STM32F411 Black Pill drive. The same Windows desktop utility handles initial setup and subsequent unlocking; users do not reflash firmware to select a mode.

| Setup mode | Credentials required on reconnect | SD data |
| --- | --- | --- |
| Authentication only | Authentication file | Plaintext |
| Authentication + encryption | Authentication file AND password | Adiantum encrypted |

First use:

1. Plug in the pre-flashed drive and open the utility.
2. Detect an unprovisioned device and offer setup with either mode.
3. Generate a unique authentication file and require the user to save it outside the locked drive. Recommend a separate backup.
4. For encrypted mode, create and confirm a password.
5. Explicitly confirm destructive initialization of the identified device/card. Existing files must be backed up first.
6. Show initialization progress. After completion, unlock and guide the user through Windows formatting and restoring files.

Subsequent use: plug in, open the same utility, select the authentication file, enter the password if encrypted, and unlock. Windows Explorer then accesses normal USB storage. Safe Windows ejection followed by unplugging ends use; the next connection starts locked.

Agreed scope: Windows first, a simple desktop GUI, setup-time mode selection, fresh initialization, no recovery option. Changing mode requires backup and reinitialization. No in-place conversion, credential rotation, password changes, live locking of mounted disks, automatic unlocking, or macOS/Linux validation in v1. Initialization support is not authorization to erase a connected physical card during development without the specific user's confirmation.

## 2. Security decisions and boundaries

- Require authentication in BOTH modes. Until authorized, enumerate the control interface but reject MSC disk access. A locked device may remain visible as USB hardware; it must not expose usable media.
- Authentication-only mode is a firmware access gate. Removing the SD card and using another reader bypasses it. Its plaintext layout excludes the reserved metadata area but is not intended as a cryptographically protected format.
- Encrypted mode must require both file and password even for offline decryption of an SD image. A firmware-only file check is insufficient.
- An authentication file is a copyable bearer credential, not proof of the identity of a particular executable or computer. A compatible client possessing the credentials can unlock.
- Selected threat scope: locked-device theft and replay of captured unlock traffic, with encryption of key transfer. Full active-interceptor resistance, malicious replacement hardware, compromised hosts, modified firmware, debug extraction, invasive physical attacks and secure boot are outside the validated v1 scope. Do not advertise TLS-equivalent security.
- Adiantum provides confidentiality, not sector authentication. It does not detect malicious sector modification or rollback. HMAC on control/configuration data does not change this.
- No password or file recovery. Losing either credential loses encrypted-data access. Losing the file in authentication-only mode loses access through the board, not readability of raw plaintext SD contents.
- Use independent, domain-separated keys for authentication, session traffic and data-key wrapping. The board's stored authentication secret must not substitute for the file's encryption-related secret.
- Never embed a shared production key in firmware. Never log passwords, file secrets, data keys or session keys. Test keys must be confined to test fixtures.
- Data keys and expanded cipher state reside only in MCU RAM while unlocked. Clear sensitive buffers on disconnect, reset and fatal storage failure. Ordinary suspend preserves the session; reset handling must be reconciled with Windows enumeration in milestone 3.
- Host-side cryptography uses maintained libraries. Minimize secret lifetime and copies; do not claim guaranteed Python-process memory erasure.
- Full accessible-sector initialization is not guaranteed sanitization of remapped SD flash cells.

## 3. Intended technical design

### Authentication and protected control

- Composite USB MSC plus vendor-defined HID, retaining HID while storage is locked. TLS is not selected for v1.
- Generate a per-device random 256-bit root secret on Windows using OS randomness. The exported authentication file includes a version and device identity.
- Derive an authentication secret and a separate wrapping-related secret via HKDF-SHA-256 with distinct labels and identity binding. Store only the authentication secret, identity and necessary provisioning state in reserved MCU flash; never store the root file secret or plaintext data key there.
- HMAC-SHA-256 challenge-response authenticates the protocol version, identity, mode, operation, device challenge and host nonce. Use constant-time tag comparisons, one-use challenges and expiration.
- Planned freshness mechanism: durable boot/session epoch plus a RAM challenge counter. Commit the epoch before issuing challenges. Use a power-loss-safe flash journal; fail closed on invalid state or counter exhaustion. Do not assume the F411 has a usable hardware RNG.
- Derive session keys using HKDF and the complete authenticated transcript. Protect subsequent messages with AES-256-GCM, separate directional keys and monotonic counters. Bind unlock/setup requests to the authenticated session. Reject altered, replayed, incomplete, oversized and invalid-state messages.
- Version the protocol, bound all buffers, include request identifiers, explicit lengths and status codes. Design nonce allocation and restart behavior before coding the secure protocol.
- Initial enrollment is allowed only when unprovisioned. Later destructive setup/mode changes require the existing authentication credential. Initial trusted provisioning is a separate trust assumption, not authenticated by a credential that does not yet exist.
- In authentication-only mode, authentication enables storage. In encrypted mode it permits protected data-key transfer; storage remains blocked until successful key installation.

### Encrypted sectors and volume format

- Add an access-controlled storage abstraction between MSC callbacks and the raw SD driver. Keep physical SPI/SD operations in the existing driver.
- Use standard Adiantum-XChaCha12-AES256, including its specified NH/Poly1305 hashing and subkey derivation. Use portable C and fixed-size buffers, with no dynamic allocation in the sector path. Vendor dependencies with pinned versions and license notices; use maintained primitives rather than inventing AES.
- Encrypt each 512-byte sector independently. The intended tweak is 32 bytes: logical sector number encoded as unsigned little-endian 64-bit, followed by zeros. Test this exact convention against independent reference output.
- Reserve physical sectors 0-15 for two 4 KB header copies. Expose logical sector zero at physical sector 16; reported capacity is physical capacity minus 16 sectors in both modes.
- Headers include format version, volume/device identity, mode, geometry, initialization state and encrypted-mode KDF/wrapped-key fields. Authenticate configuration using the device-authentication secret; explicitly serialize and validate all fields.
- For encryption, generate a random 256-bit data key and 128-bit salt on Windows. Password derivation defaults: Argon2id, 64 MiB memory, three iterations, parallelism one, 256-bit output. Combine that output and the independent file-derived wrapping secret using a precisely specified HKDF construction.
- Wrap the data key with AES-256-GCM using a random 96-bit nonce and authenticated immutable metadata. The GUI authenticates/unwraps the key and sends it only inside the protected control session. Incorrect credentials leave the drive locked.
- Authenticate and validate header fields before trusting mode or geometry. Bound KDF parameters on the host before allocating memory. Do not silently treat corrupt provisioning as a new device.
- Initialization writes an initializing state, then zeros every exposed sector (encrypted zeros in encrypted mode). Keep MSC unavailable. Complete only after both ready headers are written and verified. Interrupted initialization requires explicit restart, not in-place resume.
- Use a ciphertext scratch buffer for writes so caller plaintext buffers remain unchanged. Handle block-count overflow and capacity boundaries. Propagate SD failures; do not acknowledge partially failed requests as successful.
- Run lengthy control/initialization work in the main loop, outside USB interrupts, and serialize state transitions against storage operations.

### Windows utility

- Python/Tkinter GUI, hidapi transport, argon2-cffi and cryptography for host primitives, packaged with PyInstaller.
- Provide device selection, automatic setup/unlock screen choice, authentication-file export/selection, mode selection, password confirmation, hidden password entry, progress and actionable errors.
- Support several connected drives without accidentally initializing or unlocking the wrong one. Bind all actions to the selected device identity.
- Signal media insertion after unlock so Windows discovers storage without unplugging. Leave filesystem creation to Windows with clear instructions.
- Deliver a reproducible executable build process and installation instructions. Do not promise driverless/non-admin operation until Windows HID/MSC behavior is verified.

## 4. Five implementation milestones

| Milestone | Deliverable | Completion evidence |
| --- | --- | --- |
| 1. Specification and handoff | This document plus HANDOFF.md, decisions, open questions and acceptance criteria | Documents reviewed against conversation and current repo; no firmware changes |
| 2. Standalone Adiantum | Portable module and host-side tests; no live SD integration | Official known-answer tests for encrypt/decrypt; independent 512-byte results across keys/tweaks; malformed input and buffer tests; target compilation |
| 3. USB control and authentication | MSC + HID, provisioning, flash credential/freshness persistence, authenticated session and minimal CLI test client | Locked-media tests; wrong-file rejection; primitive vectors; replay across resets; malformed messages; power-loss journal simulations; target enumeration checks |
| 4. Storage integration | Headers, both modes, initialization and gated/encrypted reads/writes through CLI | Header corruption/card-swap tests; interrupted setup; SD errors and boundaries; correct/wrong password; end-to-end file integrity; raw-sector mode checks |
| 5. Windows GUI and validation | Setup/unlock GUI, packaging, docs and hardware validation | Fresh-machine installation; both user workflows; safe eject/reconnect; multi-device selection; file hashes; performance and resource measurements |

Each implementation session reads both documents, checks the working tree, completes its milestone's feasible tests and updates HANDOFF.md. Report unavailable hardware checks as pending, never passed. No sub-agent delegation was requested.

## 5. Engineering questions to resolve before dependent implementation

These are unresolved details, not permission to silently weaken the agreed security requirements.

1. **Crypto sources (resolved in software):** exact Google/BearSSL revisions, MIT licenses, adaptations and vector provenance are recorded in Crypto/README.md and HANDOFF.md. Adiantum and the milestone-3 SHA-256/HMAC/HKDF/AES-GCM primitives pass known-answer and independent tests. Source-level side-channel review and build resource evidence are available; MCU timing, stack high-water and physical side-channel checks remain pending. The linker reserves 8 KiB minimum stack; measure it before integration.
2. **Protocol specification (milestone 3 software implemented):** Control/PROTOCOL.md defines exact transcript bytes, labels, handshake/mutual confirmation, HKDF, GCM AAD/nonces/counters, expiry and errors. Host simulation covers tampering, replay, preplay and reset behavior; hardware validation remains pending.
3. **Persistent freshness (milestone 3 software implemented):** sectors 6/7 are reserved outside the 256 KiB firmware region. Commit-last journal/rollover and conservative corruption faults pass injected power-loss tests. Power boot commits a new epoch; USB reset keeps the RAM counter. Actual flash interruption, wear and USB behavior during flash stalls remain hardware checks.
4. **Provisioning transaction (milestones 3-4 software implemented):** save/flush file before enrollment; reject nonblank corrupt flash. Milestone 4 commits a fresh journal mode/volume binding before SD initialization and writes/verifies both ready markers last. Interrupted work needs explicit restart. No unauthenticated normal-use reset or encrypted-data recovery is provided. Physical interruption checks remain pending.
5. **USB integration (milestone 3 software implemented):** composite dispatcher, bounded feature reports, endpoint/FIFO allocation, separate HID/MSC state, gated callbacks and unit-attention hook are implemented. Stubbed descriptor/EP0 tests and target builds pass. Physical Windows enumeration, permissions, media discovery and reset/suspend handling remain unverified. Existing ST development VID/PID is retained; obtain authorized production IDs before distribution.
6. **Persistent formats (milestone 4 software implemented):** Storage/FORMAT.md specifies header bytes, UTF-8 password encoding, exact password/file HKDF and key wrapping, integrity coverage and write ordering. Both headers must validate/match; CID/geometry, journal binding and key check are required. Missing/undersized/swapped cards and corrupt headers fail closed. CLI generates fresh volume IDs/data keys for reinitialization. Journal v1 is readable; new records use v2 volume binding. Debug/Release tests pass; hardware checks remain pending.
7. **Host delivery (milestone 5 software implemented):** Tkinter GUI, pinned build dependencies and PyInstaller portable Windows x64 package are implemented. Runtime smoke and simulated GUI workflows pass. Intended Windows 10/11 x64 support, fresh-machine installation and HID permissions remain physically unverified. Unsigned-executable behavior is documented; no guaranteed Python secret erasure, production signing or bit-identical rebuild claim is made.
8. **Performance and acceptance (milestones 4-5):** establish baseline throughput, measure crypto overhead and stack high-water usage, and set realistic timeouts on hardware. No numeric speed target has been agreed. Do not change sector size, weaken crypto or skip initialization for speed without documenting the tradeoff.

If a choice changes user workflow, credential requirements or threat scope, bring it back to the user. Routine engineering choices consistent with this design can be resolved and recorded during implementation.

## 6. Repository baseline and validation

Inspected on 2026-10-17:

- Target STM32F411CEU6; linker exposes 512 KB flash and 128 KB RAM, with no credential partition yet.
- `USB_DEVICE/App/usbd_storage_if.c` currently forwards MSC reads/writes directly to SD_SPI and readiness checks only SD readiness.
- `Core/Inc/sd_spi.h` defines 512-byte blocks and raw init/read/write/capacity APIs; `Core/Src/sd_spi.c` implements SPI SD access.
- `USB_DEVICE/App/usb_device.c` initializes SD before registering the single MSC class. Only the MSC class is currently bundled.
- `USB_DEVICE/Target/usbd_conf.h` sets one interface and MSC_MEDIA_PACKET=512. Composite HID requires changes, including checking the existing static allocator and FIFO configuration.
- CMake has Debug and Release presets. `.settings/bundles.store.json` pins ST CMake, Ninja, GCC, programmer, clangd and ST-LINK GDB server bundles. Preserve these unless a dependency needs a documented change.
- No encryption, provisioning protocol, authentication client or GUI has been implemented by this planning task. No hardware/build tests were run in the documentation session.

Acceptance must include official crypto vectors (round trips alone are insufficient), independent sector reference outputs, malformed protocol and replay tests, fault-injected persistence/setup tests, both modes' lock enforcement, correct/wrong credentials, card swaps, Windows file-hash verification after reconnect, raw SD inspection, and Debug/Release builds with resource and throughput measurements.

Reference sources to consult and pin as appropriate:

- Google specification, reference implementation and vectors: https://github.com/google/adiantum
- Adiantum paper: https://google.github.io/adiantum/adiantum-draft.pdf
- HMAC: https://www.rfc-editor.org/rfc/rfc2104.html
- HKDF: https://www.rfc-editor.org/rfc/rfc5869.html
- TLS comparison (TLS not selected): https://www.rfc-editor.org/rfc/rfc8446.html

