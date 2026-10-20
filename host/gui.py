"""BlackPill Windows utility. Tk is used only on the main thread."""
import queue
import threading
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import bpctl as bp
from bpworkflow import Service


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
        self.root.geometry("790x740")
        self.root.minsize(740, 700)
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.device = tk.StringVar()
        self.file = tk.StringVar()
        self.mode = tk.IntVar(value=2)
        self.password = tk.StringVar()
        self.repeat = tk.StringVar()
        self.confirmation = tk.StringVar()
        self.status = tk.StringVar(value="Connect your BlackPill drive, then refresh.")
        self.action = tk.StringVar(value="unlock")
        self.heading = tk.StringVar(value="Select a drive")
        self.detail = tk.StringVar(value="Your authentication file should be kept on another drive.")
        self.controls = []
        self.build()
        self.root.after(50, self.poll)
        if auto_scan:
            self.scan()

    def button(self, parent, text, command, **grid):
        widget = ttk.Button(parent, text=text, command=command)
        widget.grid(**grid)
        self.controls.append(widget)
        return widget

    def build(self):
        canvas = tk.Canvas(self.root, highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.root, orient="vertical", command=canvas.yview)
        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        canvas.configure(yscrollcommand=scrollbar.set)
        frame = ttk.Frame(canvas, padding=24)
        content = canvas.create_window((0, 0), window=frame, anchor="nw")
        frame.bind("<Configure>", lambda _: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda event: canvas.itemconfigure(content, width=event.width))
        self.root.bind("<MouseWheel>", lambda event: canvas.yview_scroll(-int(event.delta / 120), "units"))
        frame.columnconfigure(0, weight=1)
        ttk.Label(frame, text="BlackPill Drive", font=("Segoe UI", 22, "bold")).grid(sticky="w")
        ttk.Label(frame, text="Set up once. Unlock when you reconnect.").grid(sticky="w", pady=(0, 18))
        row = ttk.Frame(frame)
        row.grid(sticky="ew")
        row.columnconfigure(0, weight=1)
        self.selector = ttk.Combobox(row, textvariable=self.device, state="readonly", width=60)
        self.selector.grid(sticky="ew", padx=(0, 8))
        self.selector.bind("<<ComboboxSelected>>", self.selected)
        self.button(row, "Refresh", self.scan, row=0, column=1)
        ttk.Label(frame, textvariable=self.heading, font=("Segoe UI", 15, "bold")).grid(sticky="w", pady=(20, 8))
        ttk.Label(frame, textvariable=self.detail, wraplength=690).grid(sticky="w", pady=(0, 12))
        self.form = ttk.Frame(frame)
        self.form.grid(sticky="ew")
        self.form.columnconfigure(0, weight=1)
        ttk.Label(self.form, text="Authentication file").grid(row=0, column=0, sticky="w")
        files = ttk.Frame(self.form)
        files.grid(row=1, column=0, sticky="ew", pady=(4, 12))
        files.columnconfigure(0, weight=1)
        self.file_entry = ttk.Entry(files, textvariable=self.file, state="readonly")
        self.file_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self.button(files, "Choose file…", self.choose_file, row=0, column=1)
        self.save_button = self.button(files, "Save new file…", self.save_file, row=0, column=2, padx=(6, 0))
        self.modes = ttk.Frame(self.form)
        self.modes.grid(row=2, column=0, sticky="w", pady=(0, 12))
        for value, label in [(2, "File + password · encrypted SD"), (1, "File only · plaintext SD")]:
            radio = ttk.Radiobutton(self.modes, text=label, variable=self.mode, value=value, command=self.render)
            radio.pack(anchor="w", pady=2)
            self.controls.append(radio)
        self.passwords = ttk.Frame(self.form)
        self.passwords.grid(row=3, column=0, sticky="ew")
        self.passwords.columnconfigure(1, weight=1)
        ttk.Label(self.passwords, text="Password").grid(row=0, column=0, sticky="w", padx=(0, 15))
        self.password_entry = ttk.Entry(self.passwords, textvariable=self.password, show="●")
        self.password_entry.grid(row=0, column=1, sticky="ew", pady=4)
        self.repeat_label = ttk.Label(self.passwords, text="Confirm password")
        self.repeat_label.grid(row=1, column=0, sticky="w", padx=(0, 15))
        self.repeat_entry = ttk.Entry(self.passwords, textvariable=self.repeat, show="●")
        self.repeat_entry.grid(row=1, column=1, sticky="ew", pady=4)
        self.controls.extend([self.password_entry, self.repeat_entry])
        self.confirm_frame = ttk.LabelFrame(self.form, text="Confirm volume replacement", padding=10)
        self.confirm_frame.grid(row=4, column=0, sticky="ew", pady=10)
        self.confirm_frame.columnconfigure(0, weight=1)
        self.card_text = tk.StringVar()
        ttk.Label(self.confirm_frame, textvariable=self.card_text, wraplength=650).grid(sticky="w")
        self.phrase_entry = ttk.Entry(self.confirm_frame, textvariable=self.confirmation)
        self.phrase_entry.grid(sticky="ew", pady=(8, 0))
        self.controls.append(self.phrase_entry)
        actions = ttk.Frame(self.form)
        actions.grid(row=5, column=0, sticky="ew", pady=(14, 8))
        self.primary = self.button(actions, "Unlock drive", self.submit, row=0, column=0)
        self.change = self.button(actions, "Reinitialize / change mode…", self.reinitialize, row=0, column=1, padx=10)
        self.progress = ttk.Progressbar(frame, mode="determinate")
        self.progress.grid(sticky="ew", pady=(14, 8))
        ttk.Label(frame, textvariable=self.status, wraplength=690).grid(sticky="w")
        ttk.Label(frame, text="Keep a backup of your authentication file. Lost credentials cannot be recovered.\n"
                  "Safely eject in Windows before unplugging.", wraplength=690).grid(sticky="sw", pady=(18, 0))
        self.render()

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
                # No traceback/secret-bearing payloads are logged or retained.
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
        self.clear_passwords()
        self.action.set("setup" if d and d.state == 0 else "unlock")
        self.mode.set(d.mode if d and d.mode in (1, 2) else 2)
        self.render()

    def clear_passwords(self):
        self.password.set("")
        self.repeat.set("")

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
        self.detail.set("Fast setup replaces the volume but does NOT erase old data in untouched sectors. Back up first. Keep the authentication file on another drive."
                        if setting else "Choose this drive's authentication file. Encrypted drives also need the password.")
        self.modes.grid() if setting and not self.setup else self.modes.grid_remove()
        encrypted = (self.setup.mode if self.setup else self.mode.get()) == 2
        self.passwords.grid() if encrypted else self.passwords.grid_remove()
        for widget in (self.repeat_label, self.repeat_entry):
            widget.grid() if setting else widget.grid_remove()
        self.confirm_frame.grid() if self.setup else self.confirm_frame.grid_remove()
        self.primary.configure(text="Replace volume (fast setup)" if self.setup else "Inspect card and continue" if setting else "Unlock drive")
        for control in self.controls:
            control.configure(state="disabled" if self.busy else "normal")
        self.selector.configure(state="disabled" if self.busy else "readonly")
        if not d or d.state == 2 or self.busy or self.mounted:
            self.primary.configure(state="disabled")
            self.change.configure(state="disabled")
        self.save_button.configure(state="normal" if d and d.state == 0 and not self.busy and not self.setup else "disabled")
        if setting or self.busy:
            self.change.configure(state="disabled")

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
            phrase = self.confirmation.get()
            if phrase != setup.phrase:
                self.status.set("Type the complete ERASE phrase shown above to confirm this device and card.")
                return
            self.clear_passwords()
            self.status.set("Preparing the confirmed card's metadata. Keep it connected.")
            self.launch(lambda: self.service.initialize(setup, password, phrase, lambda a, b: self.events.put(("progress", (a, b)))), lambda _: self.success(True))
        else:
            mode, create = self.mode.get(), self.create_file
            self.status.set("Saving/verifying credentials and inspecting the card…")
            def prepared(setup):
                self.setup = setup
                self.create_file = False
                self.card_text.set(f"Device: {setup.device.identity}\nCard: {setup.cid.hex()}\n"
                                   f"Capacity: {setup.physical * 512:,} bytes · Mode: {'Encrypted' if setup.mode == 2 else 'Plaintext'}\n"
                                   f"The current volume will be replaced. Old data may remain recoverable.\nType:\n{setup.phrase}")
                self.confirmation.set("")
                self.status.set("Authentication file saved/verified. Back it up before initializing.")
            self.launch(lambda: self.service.prepare(d, file, mode, create), prepared)

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
