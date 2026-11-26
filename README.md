# STM32 homemade encrypted thumb drive

A low-cost encrypted USB thumb drive built from off-the-shelf parts: an STM32F411 "Black Pill" board and a microSD card module. The drive stays locked until you unlock it with a desktop utility, and in encrypted mode every sector on the SD card is encrypted with [Adiantum](https://github.com/google/adiantum).


## Features

- **Two modes**
  - **Encrypted:** needs an authentication file **and** a password. Every 512-byte sector is encrypted with Adiantum-XChaCha12-AES256 inside the board.
  - **Authentication only:** needs the authentication file. The board refuses disk access until unlocked, but data on the SD card is plaintext.
- **Locked by default.** Until unlocked, the drive shows no usable disk to the computer. Unplugging, a USB reset or a storage error locks it again.
- **Two-factor key protection.** The data key is wrapped with a key derived from both the password (Argon2id) and a secret in the authentication file. Neither the board nor the SD card stores enough to recover it.
- **Authenticated control channel.** A mutual HMAC-SHA-256 challenge-response unlock with replay protection, followed by an AES-256-GCM session.
- **Anti-forensic options** (see [ANTIFORENSIC.md](ANTIFORENSIC.md))
  - instant crypto-erase;
  - optional full secure-erase of the card;
  - an optional decoy password that erases the drive instead of unlocking it.
- **Bring your own card.** Capacity is whatever microSD card you use. Hardware costs under S$20, excluding the card.

## Hardware

| Part | Notes |
|---|---|
| STM32F411CEU6 Black Pill | USB-C, 25 MHz crystal |
| SPI microSD card module | Any common SPI module |
| microSD card | Standard or high capacity |
| Jumper wires, USB-C data cable | |

Wiring (SPI1):

| SD module | Black Pill |
|---|---|
| CS | PA4 |
| SCK | PA5 |
| MISO | PA6 |
| MOSI | PA7 |
| VCC | 3V3, or 5V if your module has a regulator |
| GND | GND |

The on-board LED (PC13) lights during SD card activity.

## How it works

```
 Windows PC                                  Black Pill (STM32F411)                 microSD
┌──────────────────────┐  USB HID (control)  ┌─────────────────────────────┐  SPI  ┌────────────┐
│ BlackPillDrive utility│ ─────────────────► │ auth + AES-GCM session       │       │ sectors 0–15│
│  (password, auth file)│                    │ credential journal (flash)   │       │  volume hdr │
│                       │  USB MSC (disk)    │ media gate ─► Adiantum ─► SD │ ────► │ sectors 16+ │
│ File Explorer         │ ◄────────────────► │ (locked until unlocked)      │       │  user data  │
└──────────────────────┘                     └─────────────────────────────┘       └────────────┘
```

1. The board appears as a USB composite device with two interfaces. A **mass storage** interface carries disk traffic, and a vendor **HID** interface carries setup and unlock messages.
2. **First setup.** The utility generates a random 32-byte root secret and saves it in an authentication file. The board stores only a secret derived from it. The utility then generates a random data key, wraps it with the password and file, and the board writes a volume header to the SD card.
3. **Unlock.**
   1. The utility authenticates to the board and opens an encrypted session.
   2. It reads the header and unwraps the data key with your password and file.
   3. It sends the key to the board inside the encrypted session.
   4. The board checks the key and the card, then opens the disk.
4. **Normal use.** The board adds a 16-sector offset so the host can't touch the header, then encrypts or decrypts each sector on the way to or from the card. The data key lives only in the board's RAM.

The byte-level details are in [Control/PROTOCOL.md](Control/PROTOCOL.md) (USB control protocol) and [Storage/FORMAT.md](Storage/FORMAT.md) (volume header and setup).

## Repository layout

| Path | Contents |
|---|---|
| `Core/` | Board start-up, SPI SD card driver (`sd_spi.c`), glue between USB and the control/storage code (`control_app.c`) |
| `USB_DEVICE/` | Composite MSC + HID dispatcher and storage callbacks |
| `Control/` | Authentication, encrypted session and the flash credential journal |
| `Storage/` | Volume header validation, setup, the media gate and sector encryption |
| `Crypto/` | Adiantum, plus vendored BearSSL and Google Adiantum primitives |
| `host/` | Desktop utility: Tkinter GUI (`gui.py`), CLI (`bpctl.py`), protocol and crypto |
| `tests/` | Host-side simulators and test suites |
| `tools/` | Windows packaging scripts and demo tools for showing raw vs decrypted card contents |
| `pre_built_utils/` | Prebuilt Windows utility (ZIP) and its SHA-256 checksum |
| `Drivers/`, `Middlewares/` | ST HAL, CMSIS and the ST USB device library |

## Building the firmware

You need the ST toolchain (STM32CubeIDE for VS Code / STM32CubeCLT, which provides `arm-none-eabi-gcc`, CMake and Ninja).

```bash
cmake --preset Release
```

```bash
cmake --build --preset Release
```

The output is `build/Release/BlackPill_homemade_thumbdrive.elf`.

### Flashing

1. Use debugger and set up according to your own env (recommended)

**OR**

1. Hold **BOOT0**, tap **NRST**, and release BOOT0 to enter USB DFU mode.
2. In STM32CubeProgrammer, connect over **USB**, open the `.elf` file and click **Download**.
3. Reconnect the board.

## Using the drive

### Windows utility (GUI)

Extract `pre_built_utils/BlackPillDrive-windows-x64.zip` and run `BlackPillDrive.exe`. The build is unsigned, so check the ZIP against the `.sha256` file first. Alternatively, run it from source: install `host/requirements.txt`, then run `python host/gui.py`.

**First setup**

1. Plug in the drive and click **Refresh**.
2. Pick a mode: file + password (encrypted) or file only.
3. Save the authentication file **on a different drive**, and keep a backup.
4. Enter a password (encrypted mode), type the confirmation phrase shown, and start setup.
5. In **Windows Disk Management**, create a volume on the new disk and **Quick Format** it, through the Black Pill.

**Unlocking**

1. Select the drive and your authentication file.
2. Enter your password and click **Unlock drive**.
3. Safely eject before unplugging. Unplugging locks the drive; closing the utility does not.

Full end-user instructions are in [host/WINDOWS.md](host/WINDOWS.md).

### Command line

`host/bpctl.py` offers these commands:

| Command | Purpose |
|---|---|
| `list` | List connected drives |
| `info` | Show the selected drive's state |
| `enroll` | Enroll a new drive with an authentication file |
| `auth` | Authenticate to the drive |
| `setup` | Set up a new volume (add `--secure-erase` for a full overwrite) |
| `unlock` | Unlock the drive |
| `status` | Show setup progress and card details |
| `destroy` | Crypto-erase the drive |
| `duress` | Set or clear the decoy password |

For example:

```bash
python host/bpctl.py list
```

```bash
python host/bpctl.py unlock --device <32-hex-digit id> --file D:\blackpill-auth.json
```


## Security model and limitations

**Protects against:**
- Someone who finds or steals a **locked** drive.
- Someone who reads the SD card directly. In encrypted mode the card holds only ciphertext and a wrapped key.
- Replay of captured unlock traffic.

**Does not protect against:**
- **Authentication-only mode is not encryption.** Removing the SD card and reading it in another reader bypasses the board.
- **A compromised computer at unlock time.** The utility handles the plaintext data key, and everything you read or write is visible to the computer while the drive is mounted.
- **Losing both factors.** Anyone who has both your authentication file and your password can unlock the drive. The file is a plain JSON file, so keep it private.
- **Physical attacks on the board.** Flash readout protection is not enabled, so the board's authentication secret can be read with a debugger. It does not reveal the data key on its own. A drive left unattended could also be reflashed with malicious firmware that captures the key at the next unlock. Fault injection and side-channel attacks are out of scope.
- **First enrollment over a hostile connection.** Enrollment sends the board's authentication secret unencrypted, so do it on a computer you trust.
- **Tampering with stored data.** Adiantum gives confidentiality, not integrity. Modified or rolled-back sectors aren't detected; a modified sector simply decrypts to garbage.
- **Data written before setup.** Fast setup overwrites only partition metadata. Use the full secure-erase, or a new card, if the card held sensitive data before.
- **Forgotten credentials.** There is no recovery. Losing the file or the password loses the data.
- **No live lock.** The drive locks only when it is unplugged or reset.

The device uses STMicroelectronics' development USB vendor/product IDs (0x0483:0x572A), which are not licensed for distribution.

## Third-party code and licences

| Component | Location | Licence |
|---|---|---|
| Google Adiantum reference (XChaCha12, NH, Poly1305; test vectors; Python reference) | `Crypto/vendor/`, `tests/crypto/reference/` | MIT ([LICENSE.Google](Crypto/vendor/LICENSE.Google)) |
| BearSSL by Thomas Pornin (AES, SHA-256, HMAC, HKDF, GCM) | `Crypto/bearssl/`, `Crypto/vendor/aes_ct*.c` | MIT ([LICENSE.txt](Crypto/bearssl/LICENSE.txt)) |
| STM32 USB Device Library (SCSI handler modified to signal a media change on unlock) | `Middlewares/ST/` | ST SLA0044 ([LICENSE.txt](Middlewares/ST/STM32_USB_Device_Library/LICENSE.txt)) |
| STM32F4 HAL | `Drivers/STM32F4xx_HAL_Driver/` | See its LICENSE.txt |
| CMSIS (Arm) and ST device files | `Drivers/CMSIS/` | See the LICENSE.txt files in that folder |
| Python packages (cryptography, hidapi, argon2-cffi, PyInstaller) | `host/requirements.txt`, `host/build-requirements.txt` | Their own licences |

The ST USB Device Library is licensed under SLA0044, which allows the source to be redistributed. It does not allow the library to be placed under an open-source licence, and it requires the library to run only on ST microcontrollers. Any licence for this project's own code therefore does not cover `Middlewares/ST/` or `Drivers/`.
