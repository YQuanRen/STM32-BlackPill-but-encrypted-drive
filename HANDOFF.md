# Implementation handoff

Updated: 2026-10-21 (Asia/Singapore).

## Start here

Read IMPLEMENTATION_PLAN.md before making changes. It is the source of truth for the agreed workflow, security boundaries, technical defaults and open engineering questions. Check `git status --short` and applicable repository instructions at the start of each session. Preserve unrelated user work.

Milestone 5 GUI and Windows packaging are implemented; software tests pass. The portable EXE/ZIP is under `build/`, with instructions in `host/WINDOWS.md`. Physical acceptance is still pending, so milestone 5 is not fully hardware-validated. No physical device was accessed or flashed and no connected SD card was modified. Flashing alone does not encrypt an existing card: explicitly initialize in encrypted mode first.

Fast setup is now the default for NEW volumes, explicitly authorized on 2026-10-21.
It replaces the full-card pass with bounded metadata preparation. Update firmware
and utility together, retain the existing authentication file, restart any interrupted
setup explicitly, then create a volume and QUICK-format through the unlocked Pill.
Old plaintext in untouched sectors is NOT erased. Completed v1 volumes still unlock.

## Milestone status

| # | Milestone | Status |
| --- | --- | --- |
| 1 | Save specification and handoff | Complete: IMPLEMENTATION_PLAN.md and this file |
| 2 | Standalone Adiantum library and tests | Complete: host Debug/Release vectors and API tests pass; target Debug/Release builds and link smoke pass |
| 3 | Composite USB control, provisioning and authentication | Software implemented and host/target-build tests passed; physical enumeration and flash validation pending |
| 4 | Both storage modes, headers and initialization | Software complete; Debug/Release integration/fault tests and firmware builds pass; hardware validation pending |
| 5 | Windows desktop utility and end-to-end validation | GUI, portable package and software tests complete; fresh-machine/physical acceptance pending |

## Decisions that must survive context loss

- Pre-flashed device; same Windows desktop utility performs first-time setup and later authentication/unlocking.
- Two setup modes: authentication file only with plaintext SD data, or file PLUS password with Adiantum encryption. Authentication is never optional.
- In encrypted mode, both credentials must be required for offline decryption, not just checked by firmware.
- File authentication via HMAC-SHA-256 challenge-response over HID; protected session/key transfer via AES-GCM. TLS was discussed but not selected.
- Protect against theft of a locked device and replay; do not claim resistance to malicious firmware, compromised hosts, physical debug extraction or a fully active USB attacker.
- Auth-only protection is bypassed by reading the SD separately. Adiantum does not authenticate sectors.
- Setup and mode changes are destructive and need explicit confirmation. Back up and initialize afresh; no in-place conversion or recovery.
- User must save the authentication file outside the drive and retain a backup. File loss plus no recovery is intentional; password loss also prevents encrypted-data recovery.
- Disk remains inaccessible until unlocked, while HID stays available. Safe eject then unplug; next connection locks again.
- Windows-first Tkinter GUI with PyInstaller packaging. Start with a minimal CLI for firmware testing before building the GUI.

## Current implementation and inspection evidence

Firmware starts locked with composite MSC/HID. Production authorization validates both ready headers, durable volume/mode binding, card CID/capacity and the encrypted-mode key check. MSC maps logical LBA to physical LBA+16 and encrypts/decrypts each 512-byte encrypted-mode sector using Adiantum; auth-only data stays plaintext. New v2 setup verifies only selected metadata sectors before ready headers; v1 retains its legacy full pass. Target remains STM32F411 with 128 KiB RAM; firmware occupies the first 256 KiB flash, journal sectors 6/7 the remaining 256 KiB. The linker reserves 8 KiB minimum stack, not a measured runtime guarantee.

At milestone 2 start, IMPLEMENTATION_PLAN.md and HANDOFF.md were untracked; other tracked files were clean. No applicable AGENTS.md was found. On the 2026-10-19 continuation, prior implementation was already committed by the workspace owner in `be68373` and the tree was clean. Subsequent changes preserve that commit; no commit or flash operation was performed by this session.

Milestone 2 adds `Crypto/adiantum.{c,h}`, pinned MIT primitives/licenses, `Crypto/README.md`, native tests/reference and vendoring scripts. Milestone 3 reuses the bitsliced AES for control crypto. Milestone 4 integrates Adiantum through `Storage/volume.c`, adds `host/volume.py` and `tests/storage`. Existing dirty milestone-3 documentation/crypto wipe changes were preserved. Build artifacts/dependencies remain under ignored `build/`.

## Crypto decisions resolved in milestone 2

- Google Adiantum revision `4feeb5aada81dc2f319996acd4ac95a2a07c99a4`: MIT scalar XChaCha12, NH and Poly1305 hash, official vectors and unchanged Python reference. No Linux/GPL sources included.
- BearSSL revision `7bea48e5e850ab4cafbe68d3765cdaba13a86d6f`: MIT bitsliced constant-time AES256 source. Benchmark/SIMD code is excluded; bytewise serialization removes alignment/endian assumptions. Reproducible trimming and explicit scratch-buffer wipes are recorded in the vendoring script.
- Same BearSSL revision selected for SHA256/HMAC/HKDF/GCM; milestone 3 has now vendored and tested them. See `tools/vendor_control.py` and `Crypto/bearssl/LICENSE.txt`; algorithm code is retained with added wipes of explicit HMAC/HKDF/CTR scratch buffers.
- Host reference uses pinned PyCryptodomex 3.23.0 (test-only dependency). Python's independent arbitrary-precision hash/reference implementation checks the C implementation.
- Public API supports 16..4096 bytes and 0..32-byte tweaks, explicit destination capacity, exact in-place or disjoint buffers, rejection of partial/context/destination-tweak overlap, and context clearing. The sector API uses `LE64(LBA) || zero[24]` exactly. No heap or variable-size stack allocations.
- Context size 1632 bytes. Cortex-M4 archive object text: Debug 18228 bytes; Release 6024 bytes, zero library data/BSS. No runtime integration resource claim is made.
- Release compiler stack frames include 1440 bytes for initialization and 536 bytes for its nested AES schedule, with further callees additional. Budget at least 4 KiB plus caller/interrupt headroom and measure high-water before integration. Existing 1 KiB linker stack reservation is not adequate evidence. No linker allocation was changed in this milestone.
- Table-free AES and fixed arithmetic paths reviewed at source level. No physical side-channel or compiled timing certification; volatile wipes do not guarantee erasure of all compiler spills/register copies. Adiantum still provides no authentication or wrong-key detection.

## Milestone 3 implementation and decisions

- `Control/PROTOCOL.md` specifies exact transcripts, role labels, key derivation, GCM AAD/nonces/counters, message/report lengths, status codes, timeouts, journal bytes and reset rules. `Control/` implements portable crypto wrappers, the journal, protocol and HID framing.
- HMAC authenticates version, UID, mode, operation, committed epoch, RAM challenge counter, fresh host nonce and BEGIN request ID. The host validates the device challenge before proving possession, preventing future-session preplay. Mutual confirmation precedes directional HKDF/AES256-GCM traffic. No production/shared keys are embedded.
- `Core/Src/control_app.c` supplies STM32 UID and flash access, main-loop processing and generation checks. USB callbacks only move bounded reports; reset/disconnect/deconfigure close the gate immediately, and main-loop processing wipes session state. USB reset preserves the RAM counter; power boot commits a new epoch before starting USB. Suspend/resume preserves the session.
- Sectors 6/7 (`0x08040000..0x0807FFFF`) contain 128-byte append records with SHA256 corruption checks and commit-last writes. Full-bank rollover erases only the other bank and retains the current bank until a new record is verified. Torn writes skip incomplete slots; corrupt committed/torn-commit records fail closed. Some torn erases require offline service rather than guessing history. No automatic re-enrollment or authenticated-data recovery exists. Normal firmware updates must preserve both sectors.
- `USB_DEVICE/App/usbd_composite.c` dispatches MSC interface 0 (EP01/81) and vendor HID interface 1 (feature report ID 1; EP82 declared). HID state is separate from ST's single MSC allocation; allocation size is checked. FIFO allocation fits the 320-word FS budget. `usbd_msc_scsi.c` signals UNIT ATTENTION/MEDIUM HAVE CHANGED when the future validated authorization hook opens media.
- `host/bpctl.py` implements explicit identity selection, exclusive credential-file save/fsync before enrollment, enrollment confirmation, authentication and protected ping. File auth/wrapping keys are separate HKDF outputs. `host/README.md` has commands and limitations. Top-level dependencies: cryptography 46.0.3 and hidapi 0.14.0.post4. Test environment also installed cffi 2.1.1, pycparser 3.11 and setuptools 84.0.0; full delivery lock/packaging remains milestone 5.
- Existing development USB VID/PID `0483:572A` is retained; it is not an assigned production identity. Authorized product IDs must be obtained before distribution. No claim of driverless/non-admin Windows operation is made.
- Encrypted INSTALL_KEY reaches storage only after AEAD verification; temporary plaintext/key buffers are wiped. Milestone 4 replaces the board stub with authenticated volume/key validation; the original control-only test retains its mock validator.
- Milestone 4 implements protected staged SETUP bound to operation 2. Mode changes retain the existing file credential; there is no plaintext re-enrollment bypass.

## Milestone 4 implementation and decisions

- `Storage/FORMAT.md` freezes version-1 header bytes, UTF-8 password encoding, fixed Argon2id parameters, password-plus-file HKDF composition, AES-GCM wrapping/AAD and key verification. Both 4 KiB copies must authenticate and agree; no fallback/repair. Journal format 2 adds a volume ID; v1 records remain readable and upgrade on append.
- Setup commits a fresh mode/volume binding before SD writes. It initializes every logical sector and verifies each write, then writes header padding before the two ready markers. Any unfinished transaction stays locked and requires explicit restart. A new setup generates a fresh volume ID/data key; stale headers cannot bypass a mode change.
- CID is read live via CMD10. Missing/swapped cards, invalid geometry/headers/keys and SD errors reject access. Caller write buffers remain intact. Data keys/expanded state are cleared on reset/failure and after initialization; no root/password/plaintext data key is persisted.
- Setup/control runs in the main loop; MSC sector crypto retains the existing interrupt callback path. Disk callbacks reject work after USB generation changes. SysTick priority 0 preempts USB priority 1 so SPI timeouts advance; preserve these on CubeMX regeneration. Measure performance/timeouts on hardware.
- CLI `setup` requires typed device/CID confirmation, password confirmation for encryption, and reports full initialization progress. `unlock` verifies headers/unwraps keys before protected installation. Current mode comes from the authenticated board/header, not the saved file's enrollment hint. CLI tests use simulated hardware only.
- Added argon2-cffi 25.1.0 (MIT); test environment resolved argon2-cffi-bindings 26.1.0, with existing cffi 2.1.1/pycparser 3.11. Full transitive lock/executable delivery is milestone 5. No guaranteed Python memory erasure or physical timing certification.

## Milestone 5 implementation and decisions

- `host/gui.py` provides Tkinter device selection, automatic new-device setup/provisioned-device unlock, file open/save dialogs, mode selection, masked password/confirmation, explicit device/CID/capacity erase confirmation, progress, errors and safe-eject/Windows-format instructions. Scrollable content accommodates smaller windows. Selecting another device clears credential fields; multiple devices require explicit selection.
- `host/bpworkflow.py` reuses the existing CLI crypto/protocol and volume modules. It opens the selected HID path and verifies UID each time; authenticated setup rechecks CID/capacity after confirmation. File save is exclusive and flushed before enrollment. Existing credentials survive retries. Password/file unwrap and fresh header validation precede unlock. Initialization checks monotonic progress and reports a five-minute no-progress timeout.
- A single worker thread performs I/O/KDF work; queue messages are consumed by Tk on the main thread. Controls are disabled during operations, closing is blocked while busy, and password widgets are cleared after success/error/submission. No background auto-unlock, live lock, driver installation or physical formatting is added. Python memory erasure remains unguaranteed.
- `host/BlackPillDrive.spec`, `host/build-requirements.txt`, `tools/build_windows.py` and `tools/package_windows.py` build an unsigned, windowed, one-folder Windows x64 application. The portable ZIP includes dependency/Python notices, version and source-hash manifest, and a ZIP SHA256 sidecar. No bit-identical archive guarantee is made.
- Actual milestone-5 environment: Windows 11 build 26200, CPython **3.13.1** x64 and Tk 8.6.15. This differs from the older milestone's recorded Python version. PyInstaller 6.22.3, hooks 2026.8, and all resolved packaging dependencies are pinned. The package should be refreshed/retested for production delivery. Windows 10/11 x64 are intended targets; fresh-machine checks remain pending.
- `host/smoke.py` checks hidden Tk widgets, native HID loading and Argon2id/AES-GCM/HKDF wrapping without device enumeration. The packaging script runs the EXE with Python environment overrides removed, no console, and a 60-second timeout. `host/WINDOWS.md` documents extraction, unsigned-executable handling, workflows and recovery limitations; `host/VALIDATION.md` records the remaining physical acceptance checks.
- Existing milestone 3/4 work and unrelated editor/ST bundle configuration changes in the working tree were preserved. No commits, flashes or physical storage operations were performed.

## Next session: physical acceptance and release readiness

The latest implementation is fast setup, described below. Historical milestone-4/5
entries describe the original full-pass behavior, superseded for new v2 volumes.

Suggested prompt:

> Read IMPLEMENTATION_PLAN.md, HANDOFF.md and host/VALIDATION.md. Validate the packaged utility on a fresh Windows machine and the actual board, using an explicitly designated disposable/backed-up card for destructive checks. Record USB behavior, file hashes, raw-card observations, power-loss outcomes, throughput and stack high-water. Resolve failures and update the handoff; do not treat simulation as physical evidence.

Before trusting hardware, complete the pending USB, flash, storage, resource and Windows workflow checks.

## Open details and blockers

See section 5 of IMPLEMENTATION_PLAN.md. Protocol/storage formats, GUI/packaging and simulated failures are implemented. Remaining priorities are fresh-machine launch/permissions, physical USB/flash/SD validation, stack high-water and throughput. Release signing, production USB IDs and dependency/runtime refresh remain distribution work. Strict dual-header validation intentionally favors fail-closed behavior over availability after corruption.

Development control/file/journal formats are in `Control/PROTOCOL.md`; SD/wrapped-key format is in `Storage/FORMAT.md`. A hardware validation session requires the actual board and an explicitly designated disposable/backed-up card for writes. Host data-hash tests are simulated block streams, not Windows filesystem validation.

## Validation record

### Fast setup, 2026-10-21

- User reported a 64 GB card exposing 122167280 logical sectors and about 10,000
  sectors/minute during the old full pass, then explicitly authorized fast setup.
  Build mode and actual hardware timings remain unverified. The agent did not flash,
  enumerate, format or write a physical card during this change.
- `Storage/volume.c` accepts v1/v2; new host proposals use v2. Header offset 8 selects
  semantics, authenticated by header HMAC and the existing wrapping/key-check AAD.
  No other field, sector mapping, cipher, KDF, journal binding or credential changed.
  Old firmware rejects v2 before binding or SD writes. Existing v1 volumes remain
  readable; an old host still requesting v1 will still run full initialization.
- V2 selects logical sectors 0..33 and the final 33, collapsing overlaps for tiny
  geometries. Each is zeroed (encrypted with its actual logical LBA in encrypted
  mode) and read back. Both initializing and ready headers retain verified writes
  with ready markers last. Total normal-card work: 99 writes plus 99 readbacks,
  not including CID commands. Setup progress counts 67 logical metadata sectors;
  MSC capacity stays physical-16. No whole-card verification/zero-read guarantee.
- GUI/CLI describe volume replacement, explicitly warn old plaintext can remain
  recoverable, and instruct Windows QUICK-format THROUGH THE PILL after unlock.
  No automatic formatting is implemented. No SPI/build optimization was changed;
  fast setup does not claim faster ordinary file transfers.
- Extended the simulator with bounded sparse backing for large cards and torn-write
  injection. Ran `python tests/storage/test_fast_setup.py
  build/storage-host/Debug/storage_sim.dll` and Release with
  `PYTHONPATH=build/control-python;build/crypto-python`: both passed.
- New coverage in both modes: 11 geometries including tiny overlaps, 8/64 GB and
  UINT32_MAX; <=99 writes; first/tail ciphertext against independent Google reference;
  unchanged old sectors and expected arbitrary decrypted bytes; full exposed
  capacity; reset/reunlock and new-file integrity; all 99 write interruption points
  and 35 torn-sector cases per mode; v1 full initialization/unlock compatibility.
- Rebuilt/reran original storage regressions in Debug and Release: all groups passed,
  including header corruption, card/key errors, binding power cuts and mode changes.
  Ran GUI suites against both: all 10 tests passed, including large-card progress,
  user-visible retention warning and quick-format instructions.
- STM32 Debug/Release builds passed: Debug FLASH 86784 B / RAM 17816 B;
  Release FLASH 39932 B / RAM 17816 B. Firmware flash limit 256 KiB; RAM 128 KiB.
  Build commands remain `cmake --preset Debug/Release` and `cmake --build --preset
  Debug/Release` using the pinned ST tools. No board was flashed.
- Documentation: `Storage/FORMAT.md`, implementation plan, GUI/CLI instructions and
  physical acceptance checklist now describe v2 and its changed guarantees.
  Actual setup latency, Windows partition discovery/quick-formatting on reused
  cards, and physical power-loss outcomes remain pending.
- Rebuilt with `build/gui-venv/Scripts/python.exe tools/package_windows.py`; the
  packaged hardware-free runtime smoke test passed. Updated EXE is
  `build/dist/BlackPillDrive/BlackPillDrive.exe`; portable ZIP and SHA256 sidecar
  are in `build/`. ZIP SHA256:
  `3529514e9a47a7c7482139a2174c505ea915860201873722228747c9b2a35463`.
  `git diff --check` passed. No physical flash/card operations were performed.

### Milestone 5, 2026-10-20

- Ran `build/gui-venv/Scripts/python.exe tests/host/test_gui.py build/storage-host/Debug/storage_sim.dll -v` and the Release equivalent: all **9 tests** passed in each configuration. Tests use hidden real Tk widgets and actual C protocol/journal/storage code with memory-backed hardware.
- Covered both setup modes and data SHA256 across reset/unlock; wrong file/password; mismatched destructive confirmation; card swap after confirmation; interrupted initialization/restart/mode change; exclusive file preservation; stale/duplicate identities; multi-device selection; file-dialog cancellation; main-loop responsiveness and busy/close behavior; password clearing; five-minute initialization-stall handling.
- Reran the full milestone-4 storage suite against Debug and Release DLLs: all groups passed. Reran milestone-3 Release control tests: all nine groups passed. Firmware was not changed by milestone 5; the last measured link sizes remain the milestone-4 figures below.
- Built with `python tools/build_windows.py`; dependency consistency and packaged runtime self-test passed. `build/package-smoke.json` records Python 3.13.1, Tk 8.6.15 and no hardware access. Source smoke command also passed: `build/gui-venv/Scripts/python.exe host/gui.py --self-test build/gui-source-smoke.json`.
- Deliverables: `build/dist/BlackPillDrive/BlackPillDrive.exe` (retain its `_internal` directory), `build/BlackPillDrive-windows-x64.zip`, and `build/BlackPillDrive-windows-x64.zip.sha256`. Reproduction instructions are in `host/README.md`; notices and source/version manifest are inside the bundle.
- Packaging initially found an unrelated third-party hook for a generic module name; renamed the local module to `bpworkflow` and rebuilt successfully. A PowerShell wrapper was blocked by the machine's script execution policy; replaced it with the tested Python build entry point without changing system policy. PyInstaller warnings concern conditional/optional platform imports; the bundled native modules passed runtime checks.
- No fresh-machine, visible-GUI visual review, physical USB, Windows filesystem, raw-card, throughput or stack high-water result is claimed. These remain in `host/VALIDATION.md`. The executable is unsigned; no board was flashed or card erased.

### Milestone 4, 2026-10-19

- Reproduction commands: `host/README.md`. Built `tests/storage` with VS2022/MSVC 19.43, then ran `python tests/storage/test_storage.py build/storage-host/Debug/storage_sim.dll` and Release with `PYTHONPATH=build/control-python;build/crypto-python`. All groups passed.
- Both modes: all 48 logical sectors initialized correctly in a 64-sector simulated card; encrypted zeros and written sectors matched the independent Google Python reference. Multi-sector caller buffers unchanged; SHA256 of a full simulated data stream matched after reset/reunlock. Mapping, capacity/bounds, partial SD errors and key clearing passed.
- Rejected 263 header/padding corruptions, authenticated malformed metadata, wrong password/file/data key, absent/swapped cards and undersized/mismatched geometry. Bounded KDF parsing and no persisted root/plaintext data key checks passed.
- All 80 SD-write interruption boundaries stayed locked after reboot. All 128 byte positions of journal binding writes failed before any SD mutation. Explicit restart, stale-volume rejection, failed/completed mode changes, readback verification, staging expiry/order and unauthorized setup passed. These are simulations, not guarantees about SD-controller power-loss behavior.
- Actual CLI enrollment/setup/progress/unlock, wrong password and destructive-confirmation cancellation passed against simulated firmware. `python host/bpctl.py --help` and `git diff --check` passed.
- Rebuilt/reran milestone-3 Debug/Release tests: all nine groups passed, including primitive comparisons, replay/framing/composite tests and original 387 flash cuts/128 corruptions/12 erase cuts. Reran milestone-2 Debug/Release tests: 180 official vectors, 128 sector comparisons, 133 boundary comparisons and API tests passed.
- STM32 Debug/Release builds passed: Debug FLASH 86604 B, RAM 17816 B; Release FLASH 39844 B, RAM 17816 B. Limits are 256 KiB firmware flash and 128 KiB RAM. RAM includes the 8 KiB stack reservation; high-water remains unmeasured.
- No board flashed, no hardware HID access, no physical SD writes. Pending: Windows enumeration/HID permissions/media insertion, filesystem hashes after safe eject/reconnect, raw SD inspection, physical power interruption, throughput, stack high-water, SD timeout and suspend/reset behavior.

### Milestone 3, finalized 2026-10-19

- Commands are reproduced in `host/README.md`. Host build: `cmake -S tests/control -B build/control-host -G 'Visual Studio 17 2022' -A x64`, then `cmake --build build/control-host --config Debug` and `--config Release`. With `$env:PYTHONPATH = 'build/control-python'`, ran `python tests/control/test_control.py build/control-host/Debug/bp_sim.dll` and the Release DLL. Both passed all groups.
- Published SHA256/HMAC/HKDF/AES256-GCM cases and 60 independent AEAD comparisons passed. Wrong file/key, protected key transfer, both gates, reset/fatal-SD clearing, challenge expiry/single use, USB/power reset replay, future-session preplay, idle timeout and counter exhaustion tests passed.
- Every-byte protected-request tampering, truncation, oversize, HID fragmentation/order/padding/timeouts/backpressure/reset tests passed. The real Python HID framing client interoperated with the C transport. Compiled composite descriptors, MSC request dispatch, strict HID setup validation and EP0 exchange passed with low-level USB stubs. Actual MSC storage callbacks were tested for zero raw SD access while locked.
- Journal simulation passed 387 byte-cut enrollment/boot-append/rollover cases, each of 128 committed-record byte corruptions, 12 interrupted erase positions, rollover and epoch overflow. Outcomes are either strictly advanced committed freshness or fail-closed fault; tests do not promise availability after corrupt/torn flash.
- Credential file save/load, exclusive-create/no overwrite and size bounds passed. No hardware HID enumeration command was run; CLI operations were tested against simulation only.
- Final checks: `git diff --check` passed; `python host/bpctl.py --help` passed; regenerating pinned control sources with `python tools/vendor_control.py .work-bearssl` produced byte-identical SHA256 hashes for every vendored file.
- STM32 `cmake --preset Debug/Release` and `cmake --build --preset Debug/Release` passed with no compiler warnings in final logs. Debug: FLASH 68592 B / 256 KiB firmware region, RAM 14552 B / 128 KiB. Release: FLASH 32304 B, RAM 14544 B. RAM includes the 8 KiB stack reservation; actual high-water is unmeasured. Final logs: ignored `build/control-host-{Debug,Release}.log` and `build/control-target-{Debug,Release}.log`.
- Pending hardware evidence: Windows enumeration and HID access, real reconnect/reset/suspend behavior, media insertion discovery, flash write/erase power interruption and wear, timing/side channels, stack high-water. No board was flashed and no card was initialized or modified.

### Earlier milestones

- Documentation session: inspected storage APIs, MSC integration, flash/RAM layout, CMake presets, ST bundle configuration and git status.
- Checked documentation diff for whitespace errors and confirmed only the two requested Markdown files were added.
- Milestone 2 commands are reproduced in `Crypto/README.md`. Executed with Python 3.13.11, MSVC 19.43.34808, ST CMake 4.3.1+st.1, Ninja 1.13.2+st.1 and ARM GCC 14.3.1+st.2. Installed test dependency using `python -m pip install --target build/crypto-python -r tests/crypto/requirements.txt`.
- Host configured using `cmake -S tests/crypto -B build/crypto-host -G 'Visual Studio 17 2022' -A x64`; built with `cmake --build build/crypto-host --config Debug` and `--config Release`. With `$env:PYTHONPATH = 'build/crypto-python'`, ran `python tests/crypto/test_adiantum.py build/crypto-host/Debug/adiantum_test.dll` and the corresponding Release path. Both passed: 180 official vectors (both directions, in-place/disjoint, unaligned data and guard checks), 128 independent sector comparisons, 133 independent length/tweak boundaries, and malformed argument/overlap/state/clear tests.
- Ran `cmake --preset Debug`, `cmake --build --preset Debug --clean-first`, and the corresponding Release commands. Both full firmware builds plus standalone archives passed. Existing firmware memory (crypto not linked): Debug FLASH 39044 B / RAM 5616 B; Release FLASH 19260 B / RAM 5624 B.
- Target link-only smoke: `arm-none-eabi-gcc -mcpu=cortex-m4 -mthumb -mfpu=fpv4-sp-d16 -mfloat-abi=hard -Os -ICrypto tests/crypto/target_link.c build/Release/Crypto/libadiantum.a --specs=nosys.specs -o build/crypto-target-link.elf`. Passed, with expected newlib nosys warnings for unavailable `_close`, `_lseek`, `_read`, `_write`. This ELF is not a board image. `arm-none-eabi-size` reports text 11692 / data 1372 / BSS 3528 bytes including test harness/runtime; archive measurements above isolate library objects.
- `git diff --check` passed. Vendored source generation and source/license choices are documented in `Crypto/README.md`; normal builds need no source downloads.
- Re-ran `python tools/vendor_adiantum.py .work-adiantum .work-bearssl` after adding revision checks and compared SHA256 hashes before/after: byte-identical. Official vector JSON SHA256: `33f40095a795e47cf87e60b08a787a482378337b2211028d15250a12b327fa15`.
- Pending: native sanitizers, big-endian execution, MCU runtime vectors, stack high-water, throughput and physical timing/power validation. Compile/link results are not hardware execution results.
- No hardware was flashed, no SD card was initialized and no Windows unlock flow was tested.

## End-of-session update checklist

1. Record the milestone state and concrete changes, including new dependency versions/licenses and resolved design choices.
2. Record exact validation commands and outcomes; separate host tests, target builds and physical hardware checks.
3. List failures, unverified behavior and any security limitations introduced or discovered.
4. Identify the next bounded task and any user decisions still needed.
5. Keep IMPLEMENTATION_PLAN.md consistent with agreed changes. Never mark tests passed or security properties verified based solely on code inspection.

### Anti-forensic additions, 2026-11-11

- Added crypto-erase (DESTROY: `BEGIN` op 3 + SECURE op 8), an opt-in full secure-erase
  (format-1 full init surfaced in CLI/GUI), a host-only duress/decoy password
  (authentication file version 2), and a broad GUI refresh. Design and threat-model
  limits: `ANTIFORENSIC.md`. Byte-level: `Control/PROTOCOL.md`, `Storage/FORMAT.md`.
  Full change list and file map: `CLAUDE.md`.
- Validated in a Linux sandbox (logic/software only): gcc-13 build of
  Crypto+Control+Storage+storage simulator is clean; `tests/antiforensic/test_destroy.c`
  passes 21/21 checks, exercising the real journal/volume/control code and BearSSL
  primitives through both the direct erase API and the full `BEGIN(op3)/PROVE/
  SECURE(op8)` handshake, including fail-safe ordering on SD error. All host modules and
  the new `tests/host/test_antiforensic.py` pass `py_compile`.
- NOT done, pending on the dev machine (do not treat as passed): STM32 Debug/Release
  firmware build (no ARM toolchain in the sandbox; `Core/Src/control_app.c` reviewed,
  not compiled); the host Python suites (`cryptography`/`argon2-cffi` not installable
  here); any hardware flashing, USB enumeration, physical SD writes, or real power-loss
  behaviour of the header-then-journal erase ordering. No board was flashed and no card
  was written.
