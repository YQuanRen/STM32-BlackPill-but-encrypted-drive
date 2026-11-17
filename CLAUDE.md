# CLAUDE.md — change log and working notes

This file logs the changes made by AI-assisted sessions and gives quick context for
the next one. It complements, and does not replace, `IMPLEMENTATION_PLAN.md` (source
of truth for the agreed design) and `HANDOFF.md` (milestone evidence). Read all three
before changing code. The project discipline holds: **never record a test as passed
or a security property as verified on the strength of code inspection, and report
hardware checks as pending, never passed.**

---

## Session 2026-11-11 (Asia/Singapore) — anti-forensic stretch goals + UI refresh

Added the three agreed stretch goals (anti-forensic capability first), then a broad
GUI refresh and a codebase clean-up pass on the host code. Scope was authorised by
the user: crypto-erase/destroy, an optional full secure-erase pass, and a duress
(decoy) password.

*Amended 2026-11-12:* an authentication-failure video trigger was drafted in this
session and then removed at the user's request before the branch was merged. No video,
browser or network code remains in `host/gui.py`.

### What landed

**Anti-forensic: crypto-erase / DESTROY (firmware + host).**
A new protected operation lets an authenticated session wipe the drive. The board
zeroes **both on-card header copies (physical sectors 0..15)** — destroying both
copies of the AES-GCM-wrapped data key — and then erases the **credential journal
(flash sectors 6/7)**, returning the device to the virgin state. Because the random
data key only ever existed inside that wrapped-key field, erasing the header makes an
encrypted volume **permanently unrecoverable even with the correct file and
password**. The header zeroing happens *first* and is verified, so an SD error leaves
the credential journal intact and the operation is retryable (fail-safe ordering).

- Wire: `BEGIN` now accepts `operation = 3` (destroy); inside the session, protected
  opcode `8 DESTROY` (empty body) runs it. Only valid in an operation-3 session and
  only while media is unmounted.
- Plaintext (mode 1) note: destroy removes the volume binding, header and credentials
  but does **not** erase the plaintext data region. Use the full secure-erase for
  that. This caveat is documented in-code and in `ANTIFORENSIC.md`.

**Anti-forensic: optional full secure-erase pass (host-exposed + firmware-verified).**
The firmware already supported format-1 "full initialization" (every logical sector
written — encrypted-zeros in mode 2, zeros in mode 1). This session exposes it as an
opt-in **"Full secure-erase"** setup method in the GUI and `--secure-erase` in the
CLI, versus the default fast setup. It overwrites the whole logical space, so no old
plaintext survives in the data region. It is slow (hours on large cards at the
measured ~10k sectors/min), so it is opt-in and clearly labelled; crypto-erase remains
the instant anti-forensic primitive for *encrypted* volumes.

**Anti-forensic: duress / decoy password (host-only).**
The authentication file may carry an optional Argon2id verifier for a decoy password
(file version 2). The verifier never touches the board. At unlock, if the entered
password fails the real key unwrap but matches the decoy verifier, the host issues the
crypto-erase and then reports an **ordinary "wrong password" error**, so a coercer
sees a normal failure. This protects the coerced-owner-at-the-GUI case; it does not
stop a sophisticated attacker who drives the raw protocol with the stolen file (that
limitation is documented).

**UI: broader visual refresh (`host/gui.py`).**
Flat `ttk` ("clam") theme with an explicit palette, a header band, sectioned layout
and accent/danger button styles. New auth-flow affordances driven by the demo video:

- **Short confirmation phrase.** The old flow made the user retype a long hex string
  (`ERASE <deviceID> <CID>`). The GUI confirm is now `ERASE <first 8 hex of CID,
  upper>` — still card-specific and deliberate, far less error-prone. (The CLI keeps
  its longer explicit phrase.)
- **Password show/hide** toggle, an advisory **strength meter**, and a best-effort
  **Caps-Lock warning**.
- Setup-method radios (fast vs full secure-erase), an optional **decoy password**
  field for encrypted setup, a **"Decoy password…"** manager and a **"Erase drive
  (crypto-erase)…"** button for provisioned drives.

**Clean-up.** Host modules touched were kept consistent and commented; `host/gui.py`
was reorganised into themed sections with docstrings. Dense embedded C was **not**
reformatted wholesale on purpose — it cannot be compiled to ARM in this environment,
and silent reformatting of crypto code without a target build would violate the
project's no-inspection-only rule. New C is written in a readable, commented style.

### Files changed

| Area | Files |
| --- | --- |
| Firmware — credential wipe | `Control/journal.h`, `Control/journal.c` (`bp_journal_destroy`) |
| Firmware — crypto-erase | `Storage/volume.h`, `Storage/volume.c` (`bp_volume_destroy`) |
| Firmware — protocol | `Control/control.h`, `Control/control.c` (BEGIN op 3; opcode 8 DESTROY) |
| Firmware — glue | `Core/Src/control_app.c` (`control.destroy = destroy_volume`) |
| Host — crypto/volume | `host/volume.py` (`duress_make`/`duress_match`, `destroy`, `DURESS_KDF`) |
| Host — CLI/credentials | `host/bpctl.py` (file v2, `update_file`, `destroy`/`duress` commands, `--secure-erase`) |
| Host — service | `host/bpworkflow.py` (`erase`, `set_duress`, duress unlock, versioned setup, `DuressTriggered`) |
| Host — GUI | `host/gui.py` (visual refresh + all new controls) |
| Tests | `tests/antiforensic/test_destroy.c`, `tests/antiforensic/run.sh`, `tests/host/test_antiforensic.py`, `tests/storage/simulator.c` (destroy hook) |
| Docs | `CLAUDE.md` (new), `ANTIFORENSIC.md` (new), `Control/PROTOCOL.md`, `Storage/FORMAT.md`, `HANDOFF.md`, `IMPLEMENTATION_PLAN.md` |

### Validation performed in this environment (logic/software only)

- **Host C libraries + storage simulator build with gcc 13** (cmake+ninja): clean, no
  warnings. Command: `cmake -S tests/storage -B <dir> -G Ninja && cmake --build <dir>`.
- **`tests/antiforensic/test_destroy.c`: 21/21 checks pass** against the in-tree
  journal/volume/control code and the real BearSSL primitives. Covers: direct
  `bp_volume_destroy` on a loaded encrypted volume (headers zeroed, journal reads back
  virgin, volume no longer loads); the **full `BEGIN(op3)` / `PROVE` / `SECURE(op8)`
  authenticated handshake** ending in a verified crypto-erase; and the **fail-safe
  ordering** (SD write failure returns `BP_IO` and leaves credentials intact, retry
  succeeds). Reproduce: `bash tests/antiforensic/run.sh`.
- **`py_compile`** passes for all four host modules and the new host test.

### NOT done here — pending on the development machine (do not treat as passed)

- **STM32 Debug/Release firmware build** (`cmake --preset Debug/Release`): the ARM
  cross-compiler is absent in this cloud environment, so firmware size/link was not
  re-measured. `Core/Src/control_app.c` (STM32 glue, needs HAL headers) was **reviewed
  only, not compiled**.
- **Host Python suites** (`tests/host/test_gui.py`, `tests/host/test_antiforensic.py`,
  `tests/storage`, `tests/control`): not run here — `cryptography`/`argon2-cffi` are
  not installable in this sandbox (no PyPI). `test_antiforensic.py` was authored to the
  existing `test_gui.py` harness; run it with the storage simulator DLL.
- **No hardware**: no board flashed, no USB enumeration, no physical SD writes, no
  duress/erase exercised on real flash. Power-loss behaviour of the header-zero-then-
  journal-erase ordering is a simulation result, not an SD-controller guarantee.
- **Windows packaging** (PyInstaller) not rebuilt; refresh `build/` before release.

### Suggested next-session prompt

> Read IMPLEMENTATION_PLAN.md, HANDOFF.md and CLAUDE.md. Build the STM32 Debug/Release
> firmware and confirm it links within flash/RAM limits; run tests/host/test_gui.py,
> tests/host/test_antiforensic.py, tests/storage and tests/control against freshly
> built simulators. Then, on an explicitly designated disposable/backed-up card,
> validate crypto-erase (encrypted data unreadable afterwards via a separate reader),
> the duress password, and a full secure-erase. Rebuild the Windows package. Record
> results; do not treat simulation as physical evidence.

---

## Project orientation (for a cold start)

- Pre-flashed STM32F411 Black Pill = composite USB **MSC + vendor HID**. Storage stays
  locked until an authenticated session authorises it. See `IMPLEMENTATION_PLAN.md` §1–2.
- **Control plane** (`Control/`): HMAC-SHA256 challenge-response over HID, then
  AES-256-GCM session. `Control/PROTOCOL.md` is the byte-exact spec. Freshness/journal
  in flash sectors 6/7.
- **Storage plane** (`Storage/`): access-gated Adiantum sector crypto + dual 4 KiB
  headers. `Storage/FORMAT.md` is the byte-exact spec.
- **Host** (`host/`): `bpctl.py` (CLI + protocol client + crypto), `volume.py`
  (header/key/duress), `bpworkflow.py` (GUI service layer), `gui.py` (Tkinter).
- **Crypto** (`Crypto/`): vendored, pinned Adiantum + BearSSL primitives.
- Build firmware with the pinned ST toolchain: `cmake --preset Debug|Release` then
  `cmake --build --preset Debug|Release`. Host simulators build with any C11 compiler.
- Credential loss is intentional and unrecoverable by design. Setup/mode changes and
  the new crypto-erase are destructive and require explicit confirmation.
