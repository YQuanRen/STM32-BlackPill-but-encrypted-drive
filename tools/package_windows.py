"""Build, smoke-test and archive a portable Windows folder in ignored build/."""
import hashlib
import importlib.metadata as md
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    if sys.platform != "win32":
        raise SystemExit("Build the Windows package on Windows.")
    os.chdir(ROOT)
    subprocess.run([sys.executable, "-m", "PyInstaller", "--noconfirm",
                    "--distpath", "build/dist", "--workpath", "build/pyinstaller",
                    "host/BlackPillDrive.spec"], check=True)
    folder = ROOT / "build/dist/BlackPillDrive"
    shutil.copyfile(ROOT / "host/WINDOWS.md", folder / "README.txt")
    licenses = folder / "licenses"
    licenses.mkdir(exist_ok=True)
    shutil.copyfile(Path(sys.base_prefix) / "LICENSE.txt", licenses / "Python-LICENSE.txt")
    # Preserve distribution notices, including Tcl/Tk/Python bundled by PyInstaller.
    manifest = {}
    for line in (ROOT / "host/build-requirements.txt").read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        name, version = line.split("==")
        dist = md.distribution(name)
        if dist.version != version:
            raise RuntimeError(f"Version mismatch: {name}")
        manifest[name] = version
        for entry in dist.files or ():
            if any(word in entry.name.lower() for word in ("license", "copying", "notice")):
                target = licenses / name / str(entry).replace("..", "_")
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(dist.locate_file(entry), target)
    (folder / "BUILD.json").write_text(json.dumps({
        "python": sys.version, "dependencies": manifest,
        "signed": False, "hardware_validated": False,
        "source_sha256": {
            str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted((ROOT / "host").iterdir())
            if path.is_file()
        },
    }, indent=2), encoding="utf-8")
    report = ROOT / "build/package-smoke.json"
    if report.exists():
        report.unlink()
    env = {key: value for key, value in os.environ.items() if key not in ("PYTHONPATH", "PYTHONHOME")}
    subprocess.run([str(folder / "BlackPillDrive.exe"), "--self-test", str(report)],
                   cwd=folder, env=env, check=True, timeout=60,
                   creationflags=subprocess.CREATE_NO_WINDOW)
    if not json.loads(report.read_text())['passed']:
        raise RuntimeError("Packaged runtime check failed")
    archive = Path(shutil.make_archive(str(ROOT / "build/BlackPillDrive-windows-x64"), "zip",
                                      folder.parent, folder.name))
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_suffix(".zip.sha256").write_text(f"{digest}  {archive.name}\n", encoding="ascii")
    print(f"Package: {archive}\nSHA256: {digest}\nRuntime smoke check passed; physical validation remains pending.")


if __name__ == "__main__":
    main()
