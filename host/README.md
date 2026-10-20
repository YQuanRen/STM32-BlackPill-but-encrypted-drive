# BlackPill desktop utility and development CLI

Milestone 5 adds the Tkinter GUI and a portable Windows executable. End-user
instructions are in [WINDOWS.md](WINDOWS.md). Launch the built application at
`build/dist/BlackPillDrive/BlackPillDrive.exe`, or run `python host/gui.py` after
installing `host/requirements.txt`. GUI setup and unlock use the existing tested
protocol/volume modules. Physical acceptance remains pending in
[VALIDATION.md](VALIDATION.md).

**Fast setup (2026-10-21):** update both firmware and utility. New setups use
header version 2 and prepare only the first 34 and last 33 logical sectors,
plus authenticated headers (at most 99 writes total). After unlock, create a
volume and QUICK-format through the Black Pill in Windows. Old plaintext in
untouched sectors remains recoverable; this is not sanitization. Existing
version-1 volumes remain readable without conversion.

## Build the Windows package

The recorded environment is Windows 11 x64, CPython **3.13.1**, Tk 8.6.15 and
PyInstaller 6.22.3. (This is the interpreter actually available for milestone 5,
independent of earlier milestone environment records.) From the repository root:

```powershell
python tools/build_windows.py
```

This creates `build/gui-venv`, installs all pinned resolved dependencies from
`host/build-requirements.txt`, checks their consistency, builds the windowed
one-folder application, includes notices and a source/version manifest, then
runs a hidden hardware-free packaged smoke test. It produces:

- `build/dist/BlackPillDrive/BlackPillDrive.exe` with its required `_internal` folder.
- `build/BlackPillDrive-windows-x64.zip` and `.zip.sha256`.
- `build/package-smoke.json` recording dependency/runtime checks.

The recipe fixes package versions and records source hashes; it does not promise
bit-identical ZIP bytes across paths, OS versions or build times. Build on Windows,
not via a cross-compiler. The package is unsigned and has not passed fresh-machine
or physical-device acceptance. Review/update the pinned runtime and dependencies
before a production release, then repeat validation.

Packaging uses PyInstaller's documented [one-folder and windowed modes](https://www.pyinstaller.org/en/stable/usage.html).
The complete folder is zipped for delivery. Neither build nor smoke test opens
a connected HID device or writes to a physical card.

## GUI tests

Build the storage simulator using the commands below, then run:

```powershell
build/gui-venv/Scripts/python.exe tests/host/test_gui.py build/storage-host/Debug/storage_sim.dll -v
build/gui-venv/Scripts/python.exe tests/host/test_gui.py build/storage-host/Release/storage_sim.dll -v
build/gui-venv/Scripts/python.exe host/gui.py --self-test build/gui-source-smoke.json
```

The tests instantiate hidden real Tk widgets, run asynchronous UI actions, and use
the real protocol/journal/storage firmware with memory-backed hardware. They cover
file hashes across reconnect in both modes, selection and stale identities,
confirmation/card-swap rejection, wrong credentials, interrupted setup/mode change,
exclusive credential saves, initialization stalls, masked-field clearing,
multi-device selection, dialog cancellation and responsive/busy UI behavior.
No GUI screenshot or physical Windows disk behavior is implied by these tests.

Milestone 4 implements authenticated setup/unlock and transparent Adiantum sector
encryption. Flashing alone does not convert an existing card. Setup replaces the
volume and prepares metadata; it does not erase every sector. Software simulation and target
builds pass; physical Windows/STM32 behavior remains unverified.

## Setup and unlock

Python 3.13 tested. From the repository root:

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -r host/requirements.txt
.venv\Scripts\python host/bpctl.py list
.venv\Scripts\python host/bpctl.py setup --device DEVICE_ID --mode encrypted --file C:\SafeFolder\drive-auth.json
```

Replace DEVICE_ID with the exact identity from `list`. Setup displays device ID,
card CID, capacity and mode. Type the displayed `ERASE <deviceID> <CID>` phrase
only after backing up that card. Encrypted mode prompts twice for a hidden password.
Keep the authentication file outside this drive and back it up. On an already
enrolled board, use its existing file. The CLI creates files exclusively and flushes
them before enrollment. Keep the file after an ambiguous timeout and retry with it.
Files inherit Windows ACLs; Python cannot guarantee erasure of all secret copies.

Setup reports metadata preparation progress, unlocks on completion and asks you to QUICK-format
the exposed drive using Windows. There is no in-place conversion. For plaintext
with the board's authentication gate, select `--mode auth` instead. Another card
reader bypasses that gate. Encrypted card data requires both file and password;
metadata remains visible. Adiantum does not authenticate sectors or prevent rollback.

After safely ejecting and reconnecting:

```powershell
.venv\Scripts\python host/bpctl.py unlock --device DEVICE_ID --file C:\SafeFolder\drive-auth.json
```

Encrypted unlock prompts for the password; wrong credentials leave media locked.
Safely eject before unplugging. A mode change uses `setup` again with the same file
and destroys the old volume. Interrupted setup requires explicit restart with a new
volume/key, never automatic resume. There is no credential or encrypted-data recovery.

`info` reports provisioning; `auth` tests a session without opening media; `enroll`
only enrolls a credential; `status` reports authenticated card/setup state while
locked. State 0 means no volume validated in this session, not an erased card.
There is no live lock command; reconnect before changing mounted storage state.

Discovery uses existing ST development VID/PID `0483:572A`, HID usage FF00:1 and
verifies UID. These are not authorized production IDs. Windows HID permissions,
driver binding and media insertion require physical validation. Firmware updates
must preserve journal flash `0x08040000..0x0807FFFF`; mass erase loses credentials.
Offline SWD erase of both sectors is a service reset requiring fresh provisioning
and initialization, not recovery.

## Reproduce software tests

Use CMake and Visual Studio 2022 C tools on PATH, from the repository root:

```powershell
python -m pip install --target build/control-python -r host/requirements.txt
python -m pip install --target build/crypto-python -r tests/crypto/requirements.txt
cmake -S tests/control -B build/control-host -G 'Visual Studio 17 2022' -A x64
cmake -S tests/storage -B build/storage-host -G 'Visual Studio 17 2022' -A x64
cmake -S tests/crypto -B build/crypto-host -G 'Visual Studio 17 2022' -A x64
$env:PYTHONPATH = 'build/control-python;build/crypto-python'
foreach ($config in @('Debug','Release')) {
    cmake --build build/control-host --config $config
    cmake --build build/storage-host --config $config
    cmake --build build/crypto-host --config $config
    python tests/control/test_control.py "build/control-host/$config/bp_sim.dll"
    python tests/storage/test_storage.py "build/storage-host/$config/storage_sim.dll"
    python tests/storage/test_fast_setup.py "build/storage-host/$config/storage_sim.dll"
    python tests/crypto/test_adiantum.py "build/crypto-host/$config/adiantum_test.dll"
}
```

Run without Python `-O`. Tests use memory-backed flash/SD and stubbed USB hardware;
they never access a connected card. Storage tests compile the actual protocol,
journal, volume layer and MSC callbacks, and exercise the CLI. They cover both
modes, independent ciphertext, reconnect hashes, immutable write buffers, header
corruption, wrong credentials, geometry/card swaps, SD failures, 80 SD-write cuts
and 128 binding-write cuts. Control and crypto suites retain primitive vectors,
reference comparisons, replay/framing tests and journal power-loss simulations.
The fast-setup suite additionally covers tiny/overlapping metadata regions,
8/64 GB and UINT32_MAX geometry, the 99-write ceiling, untouched old sectors,
tail-LBA encryption, 99 write cuts and 35 torn-sector cases per mode, and legacy
v1 compatibility. The sparse simulator allocates no card-sized memory.

With the existing ST ARM GCC/Ninja bundles on PATH:

```powershell
cmake --preset Debug
cmake --build --preset Debug
cmake --preset Release
cmake --build --preset Release
```

Formats: [control](../Control/PROTOCOL.md), [volume/wrapping](../Storage/FORMAT.md).
Dependencies are pinned in requirements.txt; Argon2 uses argon2-cffi 25.1.0 (MIT).
Resolved packaging versions are in build-requirements.txt. Firmware primitive sources,
licenses and reproducible vendoring are documented in Crypto/README.md.

Hardware checks remain: USB enumeration, media insertion, Windows file hashes after
eject/reconnect, raw-card inspection, physical power cuts, SD timeouts, throughput,
stack high-water and suspend/reset. Preserve SysTick priority 0 and USB priority 1
on CubeMX regeneration. The 8 KiB stack reservation is not a runtime measurement.
