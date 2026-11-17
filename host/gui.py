"""BlackPill Windows utility. Tk is used only on the main thread.

Milestone 5 + anti-forensic refresh:
  * Visual refresh (flat ttk theme, sectioned layout, clearer states).
  * Password show/hide, a strength meter and a Caps-Lock warning.
  * Short, card-specific confirmation phrase (no long hex to retype).
  * Fast setup vs full secure-erase (overwrite) choice.
  * Optional decoy/duress password and an explicit crypto-erase button.
"""
import queue
import threading
from dataclasses import replace
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog

import bpctl as bp
from bpworkflow import Service


# Flat palette; redefined for a dark host below where Tk exposes it.
INK = "#1e293b"
MUTED = "#64748b"
BG = "#eef2f7"
CARD = "#ffffff"
ACCENT = "#2563eb"
DANGER = "#dc2626"
OK = "#15803d"
LINE = "#d7dee8"
FONT = "Segoe UI"

def password_strength(password):
    """Return (score 0..4, label). Advisory only; the device enforces nothing."""
    if not password:
        return 0, ""
    length = len(password)
    classes = sum(bool(set(password) & s) for s in (
        set("abcdefghijklmnopqrstuvwxyz"), set("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        set("0123456789"), set("~!@#$%^&*()_+-=[]{};:'\",.<>/?\\|`")))
    if length < 8 or classes <= 1:
        return 1, "Weak"
    if length < 12 or classes == 2:
        return 2, "Fair"
    if length < 16 or classes == 3:
        return 3, "Strong"
    return 4, "Very strong"


class App:
    def __init__(self, root, service=None, auto_scan=True):
        self.root = root
        self.service = service or Service()
        self.events = queue.Queue()
        self.busy = False
        self.devices = []
        self.setup = None
        self.create_file = False
        self.mounted = False
        self.root.title("BlackPill Drive")
        self.root.geometry("820x820")
        self.root.minsize(760, 720)
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.device = tk.StringVar()
        self.file = tk.StringVar()
        self.mode = tk.IntVar(value=2)
        self.method = tk.IntVar(value=2)    # 2 fast setup, 1 full secure-erase
        self.password = tk.StringVar()
        self.repeat = tk.StringVar()
        self.decoy = tk.StringVar()
        self.reveal = tk.BooleanVar(value=False)
        self.confirmation = tk.StringVar()
        self.status = tk.StringVar(value="Connect your BlackPill drive, then refresh.")
        self.action = tk.StringVar(value="unlock")
        self.heading = tk.StringVar(value="Select a drive")
        self.detail = tk.StringVar(value="Your authentication file should be kept on another drive.")
        self.strength = tk.StringVar(value="")
        self.capslock = tk.StringVar(value="")
        self.controls = []
        self.theme()
        self.build()
        self.password.trace_add("write", lambda *_: self.on_password())
        self.root.after(50, self.poll)
        if auto_scan:
            self.scan()

    # ---- styling -------------------------------------------------------------
    def theme(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        self.root.configure(bg=BG)
        style.configure(".", font=(FONT, 10), background=CARD, foreground=INK)
        style.configure("TFrame", background=CARD)
        style.configure("Bg.TFrame", background=BG)
        style.configure("Card.TFrame", background=CARD, relief="flat")
        style.configure("TLabel", background=CARD, foreground=INK)
        style.configure("Muted.TLabel", background=CARD, foreground=MUTED)
        style.configure("Title.TLabel", background=BG, foreground=INK, font=(FONT, 22, "bold"))
        style.configure("Sub.TLabel", background=BG, foreground=MUTED, font=(FONT, 10))
        style.configure("Heading.TLabel", background=CARD, foreground=INK, font=(FONT, 15, "bold"))
        style.configure("Section.TLabel", background=CARD, foreground=MUTED, font=(FONT, 9, "bold"))
        style.configure("Danger.TLabel", background=CARD, foreground=DANGER)
        style.configure("Strength.TLabel", background=CARD, foreground=MUTED, font=(FONT, 9))
        style.configure("TButton", padding=(12, 6))
        style.configure("Accent.TButton", padding=(14, 7), font=(FONT, 10, "bold"))
        style.map("Accent.TButton",
                  background=[("!disabled", ACCENT), ("disabled", "#9db7ef")],
                  foreground=[("!disabled", "#ffffff"), ("disabled", "#eef2ff")])
        style.configure("Danger.TButton", padding=(12, 6))
        style.map("Danger.TButton",
                  background=[("!disabled", "#fde8e8")],
                  foreground=[("!disabled", DANGER)])
        style.configure("TLabelframe", background=CARD, bordercolor=LINE)
        style.configure("TLabelframe.Label", background=CARD, foreground=MUTED, font=(FONT, 9, "bold"))
        style.configure("TRadiobutton", background=CARD)
        style.configure("TCheckbutton", background=CARD)
        style.configure("Bar.Horizontal.TProgressbar", troughcolor=LINE, background=ACCENT)

    def button(self, parent, text, command, style="TButton", **grid):
        widget = ttk.Button(parent, text=text, command=command, style=style)
        widget.grid(**grid)
        self.controls.append(widget)
        return widget

    def build(self):
        header = ttk.Frame(self.root, style="Bg.TFrame", padding=(24, 18, 24, 6))
        header.pack(fill="x")
        ttk.Label(header, text="BlackPill Drive", style="Title.TLabel").pack(anchor="w")
        ttk.Label(header, text="Set up once. Unlock when you reconnect.", style="Sub.TLabel").pack(anchor="w")

        canvas = tk.Canvas(self.root, highlightthickness=0, bg=BG)
        scrollbar = ttk.Scrollbar(self.root, orient="vertical", command=canvas.yview)
        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        canvas.configure(yscrollcommand=scrollbar.set)
        outer = ttk.Frame(canvas, style="Bg.TFrame", padding=(24, 10, 24, 24))
        content = canvas.create_window((0, 0), window=outer, anchor="nw")
        outer.bind("<Configure>", lambda _: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda event: canvas.itemconfigure(content, width=event.width))
        self.root.bind("<MouseWheel>", lambda event: canvas.yview_scroll(-int(event.delta / 120), "units"))
        outer.columnconfigure(0, weight=1)

        # Device selector row.
        row = ttk.Frame(outer, style="Bg.TFrame")
        row.grid(sticky="ew", pady=(0, 14))
        row.columnconfigure(0, weight=1)
        self.selector = ttk.Combobox(row, textvariable=self.device, state="readonly", width=60)
        self.selector.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self.selector.bind("<<ComboboxSelected>>", self.selected)
        self.button(row, "Refresh", self.scan, row=0, column=1)

        # Main card.
        frame = ttk.Frame(outer, style="Card.TFrame", padding=22)
        frame.grid(sticky="ew")
        frame.columnconfigure(0, weight=1)
        ttk.Label(frame, textvariable=self.heading, style="Heading.TLabel").grid(sticky="w")
        ttk.Label(frame, textvariable=self.detail, style="Muted.TLabel", wraplength=700).grid(sticky="w", pady=(2, 14))

        self.form = ttk.Frame(frame)
        self.form.grid(sticky="ew")
        self.form.columnconfigure(0, weight=1)

        ttk.Label(self.form, text="AUTHENTICATION FILE", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        files = ttk.Frame(self.form)
        files.grid(row=1, column=0, sticky="ew", pady=(4, 14))
        files.columnconfigure(0, weight=1)
        self.file_entry = ttk.Entry(files, textvariable=self.file, state="readonly")
        self.file_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self.button(files, "Choose file…", self.choose_file, row=0, column=1)
        self.save_button = self.button(files, "Save new file…", self.save_file, row=0, column=2, padx=(6, 0))

        # Setup-mode radios.
        self.modes = ttk.Frame(self.form)
        self.modes.grid(row=2, column=0, sticky="w", pady=(0, 10))
        ttk.Label(self.modes, text="MODE", style="Section.TLabel").grid(sticky="w")
        for value, label in [(2, "File + password · encrypted SD"), (1, "File only · plaintext SD")]:
            radio = ttk.Radiobutton(self.modes, text=label, variable=self.mode, value=value, command=self.render)
            radio.grid(sticky="w", pady=1)
            self.controls.append(radio)

        # Setup method radios (fast vs secure erase).
        self.methods = ttk.Frame(self.form)
        self.methods.grid(row=3, column=0, sticky="w", pady=(0, 10))
        ttk.Label(self.methods, text="SETUP METHOD", style="Section.TLabel").grid(sticky="w")
        for value, label in [(2, "Fast setup · quick; old data in untouched sectors is NOT erased"),
                             (1, "Full secure-erase · overwrite every sector (slow, but leaves no old data)")]:
            radio = ttk.Radiobutton(self.methods, text=label, variable=self.method, value=value, command=self.render)
            radio.grid(sticky="w", pady=1)
            self.controls.append(radio)

        # Password block.
        self.passwords = ttk.Frame(self.form)
        self.passwords.grid(row=4, column=0, sticky="ew", pady=(2, 4))
        self.passwords.columnconfigure(1, weight=1)
        ttk.Label(self.passwords, text="Password").grid(row=0, column=0, sticky="w", padx=(0, 14))
        self.password_entry = ttk.Entry(self.passwords, textvariable=self.password, show="●")
        self.password_entry.grid(row=0, column=1, sticky="ew", pady=4)
        self.reveal_check = ttk.Checkbutton(self.passwords, text="Show", variable=self.reveal, command=self.toggle_reveal)
        self.reveal_check.grid(row=0, column=2, padx=(8, 0))
        self.controls.append(self.reveal_check)
        self.repeat_label = ttk.Label(self.passwords, text="Confirm password")
        self.repeat_label.grid(row=1, column=0, sticky="w", padx=(0, 14))
        self.repeat_entry = ttk.Entry(self.passwords, textvariable=self.repeat, show="●")
        self.repeat_entry.grid(row=1, column=1, sticky="ew", pady=4)
        self.strength_bar = ttk.Progressbar(self.passwords, mode="determinate", maximum=4,
                                            style="Bar.Horizontal.TProgressbar")
        self.strength_bar.grid(row=2, column=1, sticky="ew", pady=(2, 0))
        ttk.Label(self.passwords, textvariable=self.strength, style="Strength.TLabel").grid(row=2, column=2, padx=(8, 0))
        ttk.Label(self.passwords, textvariable=self.capslock, style="Danger.TLabel").grid(row=3, column=1, sticky="w")
        for widget in (self.password_entry, self.repeat_entry):
            widget.bind("<KeyRelease>", self.on_key)
        self.controls.extend([self.password_entry, self.repeat_entry])

        # Optional decoy/duress password (encrypted setup only).
        self.decoy_frame = ttk.Frame(self.form)
        self.decoy_frame.grid(row=5, column=0, sticky="ew", pady=(8, 0))
        self.decoy_frame.columnconfigure(1, weight=1)
        ttk.Label(self.decoy_frame, text="Decoy password", style="Muted.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 14))
        self.decoy_entry = ttk.Entry(self.decoy_frame, textvariable=self.decoy, show="●")
        self.decoy_entry.grid(row=0, column=1, sticky="ew", pady=4)
        ttk.Label(self.decoy_frame, text="Optional. Typed at unlock, it CRYPTO-ERASES the drive instead of opening it.",
                  style="Muted.TLabel", wraplength=640).grid(row=1, column=1, sticky="w")
        self.controls.append(self.decoy_entry)

        # Destructive-confirmation box.
        self.confirm_frame = ttk.LabelFrame(self.form, text="Confirm volume replacement", padding=12)
        self.confirm_frame.grid(row=6, column=0, sticky="ew", pady=12)
        self.confirm_frame.columnconfigure(0, weight=1)
        self.card_text = tk.StringVar()
        ttk.Label(self.confirm_frame, textvariable=self.card_text, wraplength=660).grid(sticky="w")
        self.phrase_entry = ttk.Entry(self.confirm_frame, textvariable=self.confirmation)
        self.phrase_entry.grid(sticky="ew", pady=(8, 0))
        self.controls.append(self.phrase_entry)

        # Primary / secondary actions.
        actions = ttk.Frame(self.form)
        actions.grid(row=7, column=0, sticky="ew", pady=(14, 6))
        self.primary = self.button(actions, "Unlock drive", self.submit, style="Accent.TButton", row=0, column=0)
        self.change = self.button(actions, "Reinitialize / change mode…", self.reinitialize, row=0, column=1, padx=10)

        # Anti-forensic / maintenance actions.
        self.tools = ttk.Frame(self.form)
        self.tools.grid(row=8, column=0, sticky="ew", pady=(0, 2))
        self.decoy_button = self.button(self.tools, "Decoy password…", self.manage_decoy, row=0, column=0)
        self.erase_button = self.button(self.tools, "Erase drive (crypto-erase)…", self.erase_drive,
                                        style="Danger.TButton", row=0, column=1, padx=10)

        self.progress = ttk.Progressbar(frame, mode="determinate", style="Bar.Horizontal.TProgressbar")
        self.progress.grid(sticky="ew", pady=(14, 8))
        ttk.Label(frame, textvariable=self.status, style="Muted.TLabel", wraplength=700).grid(sticky="w")
        ttk.Label(frame, text="Keep a backup of your authentication file. Lost credentials cannot be recovered.\n"
                  "Safely eject in Windows before unplugging.", style="Muted.TLabel", wraplength=700
                  ).grid(sticky="sw", pady=(16, 0))
        self.render()

    # ---- password helpers ----------------------------------------------------
    def toggle_reveal(self):
        show = "" if self.reveal.get() else "●"
        for entry in (self.password_entry, self.repeat_entry, self.decoy_entry):
            entry.configure(show=show)

    def on_password(self):
        score, label = password_strength(self.password.get())
        self.strength_bar.configure(value=score)
        self.strength.set(label)

    def on_key(self, event):
        # Best-effort Caps-Lock hint; state bit 0x0002 is Lock on X11/Windows.
        self.capslock.set("Caps Lock is on" if (event.state & 0x0002) else "")

    def current(self):
        index = self.selector.current()
        return self.devices[index] if 0 <= index < len(self.devices) else None

    def launch(self, work, done):
        if self.busy:
            return
        self.busy = True
        self.render()
        def run():
            try:
                result = work()
            except Exception as exc:
                text = str(exc) if isinstance(exc, bp.ProtocolError) else (
                    "Cannot access the device or file. Check the connection and file permissions, then refresh. "
                    "Keep any authentication file already saved.")
                self.events.put(("error", text))
            else:
                self.events.put(("done", (done, result)))
        threading.Thread(target=run, daemon=True).start()

    def poll(self):
        try:
            while True:
                kind, value = self.events.get_nowait()
                if kind == "progress":
                    done, total = value
                    self.progress.configure(maximum=max(total, 1), value=done)
                    self.status.set(f"Preparing metadata: {done:,} of {total:,} sectors. Keep the drive connected.")
                else:
                    self.busy = False
                    if kind == "error":
                        self.clear_passwords()
                        self.setup = None
                        self.confirmation.set("")
                        if self.create_file and Path(self.file.get()).is_file():
                            self.create_file = False  # Retain/reuse a saved file after ambiguous enrollment.
                        self.status.set(value + " If setup was interrupted, inspect the card and explicitly restart setup.")
                    else:
                        callback, result = value
                        callback(result)
                    self.render()
        except queue.Empty:
            pass
        self.root.after(50, self.poll)

    def scan(self):
        self.setup = None
        self.devices = []
        self.selector['values'] = []
        self.device.set("")
        self.mounted = False
        self.clear_passwords()
        self.status.set("Looking for drives…")
        def complete(devices):
            self.devices = devices
            self.selector['values'] = [f"{d.identity}  ·  {'New drive' if d.state == 0 else 'Credential fault' if d.state == 2 else 'Encrypted' if d.mode == 2 else 'File only'}" for d in devices]
            self.device.set("")
            if len(devices) == 1:
                self.selector.current(0)
                self.selected()
            self.status.set("Choose a drive." if len(devices) > 1 else "Drive found." if devices else "No drives found. Connect a drive and refresh.")
        self.launch(self.service.discover, complete)

    def selected(self, event=None):
        d = self.current()
        self.file.set("")
        self.setup = None
        self.create_file = False
        self.mounted = False
        self.confirmation.set("")
        self.decoy.set("")
        self.clear_passwords()
        self.action.set("setup" if d and d.state == 0 else "unlock")
        self.mode.set(d.mode if d and d.mode in (1, 2) else 2)
        self.render()

    def clear_passwords(self):
        self.password.set("")
        self.repeat.set("")
        self.decoy.set("")
        self.capslock.set("")

    def choose_file(self):
        path = filedialog.askopenfilename(title="Choose this drive's authentication file", filetypes=[("Authentication files", "*.json"), ("All files", "*.*")])
        if path:
            self.file.set(path)
            self.create_file = False
            self.setup = None
            self.render()

    def save_file(self):
        path = filedialog.asksaveasfilename(title="Save authentication file on another drive", defaultextension=".json", initialfile="blackpill-auth.json", filetypes=[("Authentication files", "*.json")])
        if path:
            self.file.set(path)
            self.create_file = True
            self.setup = None
            self.render()

    def reinitialize(self):
        self.action.set("setup")
        self.setup = None
        self.clear_passwords()
        self.render()

    def render(self):
        d = self.current()
        setting = self.action.get() == "setup"
        self.heading.set("Set up your drive" if setting else "Unlock your drive" if d else "Select a drive")
        if setting:
            self.detail.set("Fast setup replaces the volume but does NOT erase old data in untouched sectors. "
                            "Back up first. Keep the authentication file on another drive."
                            if self.method.get() == 2 else
                            "Full secure-erase overwrites every sector — slow, but no old data is left behind. "
                            "Back up first. Keep the authentication file on another drive.")
        else:
            self.detail.set("Choose this drive's authentication file. Encrypted drives also need the password.")
        self.modes.grid() if setting and not self.setup else self.modes.grid_remove()
        self.methods.grid() if setting and not self.setup else self.methods.grid_remove()
        encrypted = (self.setup.mode if self.setup else self.mode.get()) == 2
        self.passwords.grid() if encrypted else self.passwords.grid_remove()
        # Decoy field: only while configuring a new encrypted volume.
        self.decoy_frame.grid() if (setting and encrypted) else self.decoy_frame.grid_remove()
        for widget in (self.repeat_label, self.repeat_entry):
            widget.grid() if setting else widget.grid_remove()
        self.confirm_frame.grid() if self.setup else self.confirm_frame.grid_remove()
        self.primary.configure(text="Replace volume" if self.setup else
                               "Inspect card and continue" if setting else "Unlock drive")
        for control in self.controls:
            control.configure(state="disabled" if self.busy else "normal")
        self.selector.configure(state="disabled" if self.busy else "readonly")
        provisioned = bool(d) and d.state == 1
        if not d or d.state == 2 or self.busy or self.mounted:
            self.primary.configure(state="disabled")
            self.change.configure(state="disabled")
        self.save_button.configure(state="normal" if d and d.state == 0 and not self.busy and not self.setup else "disabled")
        if setting or self.busy:
            self.change.configure(state="disabled")
        # Maintenance actions need a provisioned drive and a chosen file.
        for btn in (self.erase_button, self.decoy_button):
            btn.configure(state="normal" if provisioned and not self.busy and not self.setup and not self.mounted else "disabled")

    def submit(self):
        d = self.current()
        if not d or self.busy:
            return
        file = self.file.get()
        password = self.password.get()
        if not file:
            self.status.set("Choose or save an authentication file on another drive.")
            return
        if self.action.get() == "unlock":
            self.clear_passwords()
            self.status.set("Verifying credentials and unlocking…")
            self.launch(lambda: self.service.unlock(d, file, password), lambda _: self.success(False))
        elif self.setup:
            setup = self.setup
            if setup.mode == 2 and (password != self.repeat.get() or not 1 <= len(password.encode('utf-8')) <= 1024):
                self.status.set("Enter matching passwords (1–1024 UTF-8 bytes).")
                return
            decoy = self.decoy.get()
            if setup.mode == 2 and decoy and decoy == password:
                self.status.set("The decoy password must differ from the real password.")
                return
            phrase = self.confirmation.get()
            if phrase != setup.phrase:
                self.status.set("Type the complete ERASE phrase shown above to confirm this device and card.")
                return
            setup = replace(setup, duress_password=decoy if setup.mode == 2 else "")
            self.clear_passwords()
            self.status.set("Preparing the confirmed card's metadata. Keep it connected.")
            self.launch(lambda: self.service.initialize(setup, password, phrase, lambda a, b: self.events.put(("progress", (a, b)))),
                        lambda _: self.success(True))
        else:
            mode, create, version = self.mode.get(), self.create_file, self.method.get()
            self.status.set("Saving/verifying credentials and inspecting the card…")
            def prepared(setup):
                self.setup = setup
                self.create_file = False
                method = "Full secure-erase" if setup.version == 1 else "Fast setup"
                self.card_text.set(f"Device: {setup.device.identity}\nCard: {setup.cid.hex()}\n"
                                   f"Capacity: {setup.physical * 512:,} bytes · Mode: {'Encrypted' if setup.mode == 2 else 'Plaintext'} · {method}\n"
                                   f"The current volume will be replaced. Old data may remain recoverable.\nType:\n{setup.phrase}")
                self.confirmation.set("")
                self.status.set("Authentication file saved/verified. Back it up before initializing.")
            self.launch(lambda: self.service.prepare(d, file, mode, create, version), prepared)

    def manage_decoy(self):
        d = self.current()
        file = self.file.get()
        if not d or self.busy:
            return
        if not file:
            self.status.set("Choose this drive's authentication file first.")
            return
        choice = messagebox.askyesnocancel(
            "Decoy (duress) password",
            "Set a decoy password?\n\nYes — set/replace it.\nNo — remove any existing decoy.\n\n"
            "When typed at unlock, a decoy password CRYPTO-ERASES the drive while showing an ordinary "
            "'wrong password' message.")
        if choice is None:
            return
        pw = None
        if choice:
            pw = simpledialog.askstring("Decoy password", "New decoy password:", show="●", parent=self.root)
            if not pw:
                return
            if pw != simpledialog.askstring("Decoy password", "Confirm decoy password:", show="●", parent=self.root):
                self.status.set("Decoy passwords did not match.")
                return
        self.status.set("Updating the authentication file…")
        self.launch(lambda: self.service.set_duress(d, file, pw),
                    lambda _: self.status.set("Decoy password " + ("set." if pw else "removed.")))

    def erase_drive(self):
        d = self.current()
        file = self.file.get()
        if not d or self.busy:
            return
        if not file:
            self.status.set("Choose this drive's authentication file first.")
            return
        if not messagebox.askyesno(
                "Crypto-erase this drive?",
                "This permanently destroys the key and credentials for this drive. Encrypted data becomes "
                "UNRECOVERABLE even with the file and password. This cannot be undone.\n\nErase now?",
                icon="warning", default="no"):
            return
        self.clear_passwords()
        self.status.set("Erasing…")
        self.launch(lambda: self.service.erase(d, file), lambda _: self.after_erase())

    def after_erase(self):
        self.mounted = False
        self.setup = None
        self.status.set("Crypto-erase complete. The drive is now blank; set it up again before use. Refresh to continue.")

    def success(self, initialized):
        self.setup = None
        self.mounted = True
        self.clear_passwords()
        self.confirmation.set("")
        self.status.set(("Fast setup complete and unlocked. Use Windows Disk Management to create a volume and QUICK-format through the Black Pill, then restore files. "
                         if initialized else "Unlocked. Open the drive in Windows Explorer. ") +
                        "Safely eject before unplugging; reconnecting locks the drive again.")

    def close(self):
        if self.busy:
            messagebox.showinfo("Operation in progress", "Keep the drive connected and wait for this operation to finish. If disconnected, initialization must be restarted explicitly.")
            return
        self.clear_passwords()
        self.root.destroy()


def main():
    import sys
    if len(sys.argv) == 3 and sys.argv[1] == "--self-test":
        from smoke import run
        run(sys.argv[2])
        return
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
