# Implementation handoff

Updated: 2026-10-17 (Asia/Singapore).

## Start here

Read IMPLEMENTATION_PLAN.md before making changes. It is the source of truth for the agreed workflow, security boundaries, technical defaults and open engineering questions. Check `git status --short` and applicable repository instructions at the start of each session. Preserve unrelated user work.

The current request authorized milestone 2 implementation and tests. Standalone Adiantum is now implemented and validated on the host and compiled/linked for Cortex-M4. No physical device was accessed. Continue with milestone 3 when requested.

## Milestone status

| # | Milestone | Status |
| --- | --- | --- |
| 1 | Save specification and handoff | Complete: IMPLEMENTATION_PLAN.md and this file |
| 2 | Standalone Adiantum library and tests | Complete: host Debug/Release vectors and API tests pass; target Debug/Release builds and link smoke pass |
| 3 | Composite USB control, provisioning and authentication | Not started |
| 4 | Both storage modes, headers and initialization | Not started |
| 5 | Windows desktop utility and end-to-end validation | Not started |

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

Firmware is still the existing plaintext USB MSC-to-SPI-SD bridge. `USB_DEVICE/App/usbd_storage_if.c` directly calls SD_SPI read/write; `usb_device.c` registers MSC only. Block size is 512 bytes; target is STM32F411 with 512 KB flash and 128 KB RAM. Debug/Release CMake presets and ST tool bundles already exist.

At milestone 2 start, IMPLEMENTATION_PLAN.md and HANDOFF.md were untracked; other tracked files were clean. No applicable AGENTS.md was found. These documents remain untracked (nothing was committed). Unrelated work was preserved.

Milestone 2 adds `Crypto/adiantum.{c,h}`, a standalone C11 static library, pinned MIT primitives/licenses, `Crypto/README.md`, native test DLL harness and Python tests/reference under `tests/crypto`, and `tools/vendor_adiantum.py`. Root CMake builds the archive alongside firmware but does not link or call it in the storage path. `.gitignore` excludes reference checkouts (`.work-*`) and Python caches. Local build artifacts/dependencies are under ignored `build/`.

## Crypto decisions resolved in milestone 2

- Google Adiantum revision `4feeb5aada81dc2f319996acd4ac95a2a07c99a4`: MIT scalar XChaCha12, NH and Poly1305 hash, official vectors and unchanged Python reference. No Linux/GPL sources included.
- BearSSL revision `7bea48e5e850ab4cafbe68d3765cdaba13a86d6f`: MIT bitsliced constant-time AES256 source. Benchmark/SIMD code is excluded; bytewise serialization removes alignment/endian assumptions. Reproducible trimming and explicit scratch-buffer wipes are recorded in the vendoring script.
- Same BearSSL revision selected for future SHA256/HMAC/HKDF/GCM, with exact source paths in `Crypto/README.md`; these control primitives are not yet vendored or tested. Milestone 3 must validate them before use.
- Host reference uses pinned PyCryptodomex 3.23.0 (test-only dependency). Python's independent arbitrary-precision hash/reference implementation checks the C implementation.
- Public API supports 16..4096 bytes and 0..32-byte tweaks, explicit destination capacity, exact in-place or disjoint buffers, rejection of partial/context/destination-tweak overlap, and context clearing. The sector API uses `LE64(LBA) || zero[24]` exactly. No heap or variable-size stack allocations.
- Context size 1632 bytes. Cortex-M4 archive object text: Debug 18228 bytes; Release 6024 bytes, zero library data/BSS. No runtime integration resource claim is made.
- Release compiler stack frames include 1440 bytes for initialization and 536 bytes for its nested AES schedule, with further callees additional. Budget at least 4 KiB plus caller/interrupt headroom and measure high-water before integration. Existing 1 KiB linker stack reservation is not adequate evidence. No linker allocation was changed in this milestone.
- Table-free AES and fixed arithmetic paths reviewed at source level. No physical side-channel or compiled timing certification; volatile wipes do not guarantee erasure of all compiler spills/register copies. Adiantum still provides no authentication or wrong-key detection.

## Next session: milestone 3

Suggested prompt:

> Read IMPLEMENTATION_PLAN.md and HANDOFF.md. Implement milestone 3: specify and implement composite USB HID control, provisioning, replay-safe flash persistence, authenticated protected sessions and a minimal CLI. Resolve transcript/nonce/reset/flash questions before coding dependent behavior, validate selected control primitives, run feasible tests, and update HANDOFF.md. Do not initialize or modify an SD card.

Do not integrate live SD encryption or start the GUI ahead of their milestones. Subsequent sessions follow milestones 3, 4 and 5 in order.

## Open details and blockers

See section 5 of IMPLEMENTATION_PLAN.md for the full list. Adiantum provenance, licensing, correctness vectors and target compilation are resolved. Priorities are control primitive validation; exact authenticated transcript and key derivation; replay-safe flash journaling; USB composite support; enrollment power-loss behavior; precise header/file formats and wrong-data-key rejection; Windows packaging and hardware performance.

These require engineering resolution before dependent implementation. No production protocol or persistent byte layout is frozen yet. A hardware validation session will require access to the actual board and an explicitly designated disposable/backed-up card.

## Validation record

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
