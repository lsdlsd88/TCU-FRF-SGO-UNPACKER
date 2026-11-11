"""Small native stock-file unpacker GUI; only Python's standard library is needed."""

import argparse
import hashlib
import os
import queue
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk

import sgo_tables
from sgo_image import GUI_PROFILES as PROFILES, build_image, unsupported_reason
from sgo_unpack import SGO

ASSETS = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
SETTINGS_PATH = (Path(os.environ.get("APPDATA") or Path.home())
                 / "TCU-SGO-FRF-Unpacker" / "settings.json")
# Diagnostics (process integrity, index path, write probes) are opt-in: set
# TCU_DEBUG=1 to see them in the log.
DEBUG = bool(os.environ.get("TCU_DEBUG"))


def load_settings():
    try:
        import json
        return json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_settings(**updates):
    try:
        import json
        data = load_settings()
        data.update({key: str(value) for key, value in updates.items() if value})
        SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
        SETTINGS_PATH.write_text(json.dumps(data, indent=1), encoding="utf-8")
    except OSError:
        pass


def last_dir():
    """Last folder used in any dialog; empty when unset or gone."""
    value = load_settings().get("last_dir", "")
    return value if value and Path(value).is_dir() else ""

SIZE_CHOICES = {"Auto": None, "512 KiB · 0x80000": 0x80000,
                "1 MiB · 0x100000": 0x100000, "1.5 MiB · 0x180000": 0x180000,
                "2 MiB · 0x200000": 0x200000, "2.5 MiB · 0x280000": 0x280000,
                "4 MiB · 0x400000": 0x400000}


def number(value):
    text = value.strip()
    return int(text, 16) if text.lower().startswith("0x") else int(text)


def library_write_probe(library_root):
    """Report exactly which file operation the library folder refuses."""
    library_root = Path(library_root)
    notes = []
    for name in (f".probe_write_{os.getpid()}",
                 f"catalogue.json.{os.getpid()}.tmp"):
        path = library_root / name
        try:
            path.write_bytes(b"{}")
            path.unlink()
            notes.append(f"{name}: create ok")
        except OSError as exc:
            notes.append(f"{name}: create FAIL errno={exc.errno} "
                         f"winerror={getattr(exc, 'winerror', None)} {exc}")
    temp = library_root / f".probe_replace_{os.getpid()}.tmp"
    target = library_root / f".probe_replace_{os.getpid()}.json"
    try:
        temp.write_bytes(b"{}")
        target.write_bytes(b"{}")
        os.replace(temp, target)
        target.unlink()
        notes.append("replace ok")
    except OSError as exc:
        notes.append(f"replace FAIL errno={exc.errno} "
                     f"winerror={getattr(exc, 'winerror', None)} {exc}")
    notes.append(f"catalogue exists={(library_root / 'catalogue.json').is_file()}")
    return notes


def process_diagnostics(library_root):
    """Describe this process and where it may write."""
    import subprocess
    import tempfile

    notes = [f"pid={os.getpid()} cwd={os.getcwd()}",
             f"exe={sys.executable}",
             f"frozen={getattr(sys, 'frozen', False)} "
             f"meipass={getattr(sys, '_MEIPASS', None)}"]
    try:
        out = subprocess.run(["whoami", "/groups", "/fo", "csv", "/nh"],
                             capture_output=True, text=True, timeout=15)
        for line in (out.stdout or "").splitlines():
            if any(tag in line for tag in ("Mandatory Level", "AppContainer",
                                           "Label")):
                notes.append(line.strip().strip('"').split('","')[0])
    except Exception as exc:
        notes.append(f"whoami failed: {exc!r}")
    for label, directory in (("temp", Path(tempfile.gettempdir())),
                             ("exe_dir", Path(sys.executable).parent),
                             ("library", Path(library_root))):
        probe = directory / f".probe_diag_{os.getpid()}"
        try:
            probe.write_bytes(b"{}")
            probe.unlink()
            notes.append(f"{label}: write ok")
        except OSError as exc:
            notes.append(f"{label}: write FAIL errno={exc.errno} {exc}")
    try:
        with open(Path(library_root) / "catalogue.json", "r+b"):
            notes.append("library catalogue: open r+b ok")
    except OSError as exc:
        notes.append(f"library catalogue: open r+b FAIL errno={exc.errno}")
    return notes


def enable_dpi_awareness():
    """Opt into Windows per-monitor DPI before Tk creates a window.

    Without this, Windows stretches the whole window bitmap on a 125-150%
    display and every font turns blurry. The three calls are tried in order
    because the older APIs are the only ones available on Windows 7/8.
    """
    import ctypes

    try:
        if ctypes.windll.user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4)):
            return "per-monitor-v2"
    except Exception:
        pass
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
        return "per-monitor"
    except Exception:
        pass
    try:
        ctypes.windll.user32.SetProcessDPIAware()
        return "system"
    except Exception:
        return "unaware"


def apply_tk_scaling(root):
    """Map Tk font points to this window's real pixels (96 dpi -> 96/72)."""
    import ctypes

    try:
        dpi = ctypes.windll.user32.GetDpiForWindow(root.winfo_id()) or 96
    except Exception:
        dpi = 96
    root.tk.call("tk", "scaling", dpi / 72.0)
    return dpi


def apply_fonts(root):
    """One set of named fonts, sized for legibility on a 100% display."""
    from tkinter import font as tkfont

    for name, size, weight in (("TkDefaultFont", 10, "normal"),
                               ("TkTextFont", 10, "normal"),
                               ("TkMenuFont", 10, "normal"),
                               ("TkHeadingFont", 10, "bold"),
                               ("TkFixedFont", 10, "normal")):
        try:
            tkfont.nametofont(name).configure(
                family="Consolas" if name == "TkFixedFont" else "Segoe UI",
                size=size, weight=weight)
        except Exception:
            pass


class App:
    def __init__(self, root):
        self.root = root
        dpi = apply_tk_scaling(root)
        apply_fonts(root)
        # Geometry is in real pixels, so the layout sizes are expressed in
        # 96-dpi units and multiplied by the window scale (125% -> 1.25).
        self.ui_scale = dpi / 96.0
        scale = self.ui_scale
        root.title("TCU FRF SGO Unpacker")
        root.geometry(f"{round(572 * scale)}x{round(408 * scale)}")
        root.minsize(round(480 * scale), round(300 * scale))
        root.resizable(True, True)
        self.events = queue.Queue()
        self.busy = False
        self.last_manifest = None
        self.expanded = False
        self.source = tk.StringVar()
        self.output = tk.StringVar()
        self.profile = tk.StringVar(value=PROFILES["auto"])
        self.table = tk.StringVar()
        self.reference = tk.StringVar()
        program_folder = Path(sys.executable).parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent
        saved = load_settings()
        saved_library = Path(saved["library"]) if saved.get("library") and Path(saved["library"]).is_dir() else None
        # Default donor library: the conventional Downloads\datflash. Falling
        # back to last_dir() made the folder of the last opened file look like
        # the library on a fresh install.
        conventional = Path.home() / "Downloads" / "datflash"
        default_library = (saved_library
                           or (conventional if conventional.is_dir() else None)
                           or (Path(last_dir()) if last_dir() and Path(last_dir()).is_dir() else None)
                           or program_folder)
        self.library = tk.StringVar(value=str(default_library))
        self._saved_library = str(saved_library or "")
        self.root = root
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        root.bind("<Escape>", lambda _: self.on_close())
        self.preserve = tk.BooleanVar(value=False)
        self.size = tk.StringVar(value="Auto")
        self.fill = tk.StringVar(value="FF")
        self.status = tk.StringVar(value="Choose a stock file.")
        self.info = tk.StringVar(value="Full flash image output; missing regions are padded.")
        style = ttk.Style()
        if "vista" in style.theme_names():
            style.theme_use("vista")
        style.configure("TLabel", font="TkDefaultFont")
        style.configure("TButton", font="TkDefaultFont", padding=(6, 3))
        style.configure("Small.TLabel", foreground="#536176", font=("Segoe UI", 9))
        frame = ttk.Frame(root, padding=10)
        frame.pack(fill="both", expand=True)
        frame.columnconfigure(1, weight=1)
        self.path_row(frame, 0, "Stock file", self.source, self.choose_source, "Open")
        self.path_row(frame, 1, "Output", self.output, self.choose_output, "Save as…")
        self.path_row(frame, 2, "Library folder", self.library, self.choose_library,
                      "Browse")
        ttk.Label(frame, text="Type").grid(row=3, column=0, sticky="w", pady=4)
        combo = ttk.Combobox(frame, textvariable=self.profile, state="readonly",
                             values=sorted(PROFILES.values()), font="TkDefaultFont")
        combo.grid(row=3, column=1, columnspan=2, sticky="ew", pady=4)
        combo.bind("<<ComboboxSelected>>", lambda _: self.inspect())
        ttk.Label(frame, textvariable=self.info, style="Small.TLabel").grid(
            row=4, column=0, columnspan=3, sticky="w", pady=(3, 6))
        actions = ttk.Frame(frame)
        actions.grid(row=5, column=0, columnspan=3, sticky="ew")
        self.go = ttk.Button(actions, text="Unpack", command=self.run, width=9)
        self.go.pack(side="left")
        ttk.Button(actions, text="Open flash", command=self.open_flash).pack(side="left", padx=(5, 0))
        self.rescan_button = ttk.Button(actions, text="Rescan folder",
                                        command=self.rescan_library)
        self.rescan_button.pack(side="left", padx=(5, 0))
        self.advanced_button = ttk.Button(actions, text="Advanced ▾", command=self.toggle_advanced)
        self.advanced_button.pack(side="left", padx=6)
        ttk.Button(actions, text="Clear Log", command=self._log_clear).pack(side="right", padx=(0, 5))
        ttk.Button(actions, text="About", command=self.about).pack(side="right", padx=(0, 5))
        self.advanced = ttk.LabelFrame(frame, text="Image options", padding=8)
        self.advanced.grid(row=6, column=0, columnspan=3, sticky="ew", pady=(8, 2))
        self.advanced.columnconfigure(1, weight=1)
        self.path_row(self.advanced, 0, "Table", self.table, self.choose_table)
        self.path_row(self.advanced, 1, "Full read", self.reference, self.choose_reference)
        ttk.Checkbutton(self.advanced, text="Preserve missing regions from full read", variable=self.preserve).grid(
            row=2, column=0, columnspan=3, sticky="w", pady=(4, 6))
        controls = ttk.Frame(self.advanced)
        controls.grid(row=3, column=0, columnspan=3, sticky="ew")
        ttk.Label(controls, text="Size").pack(side="left")
        ttk.Combobox(controls, textvariable=self.size, values=list(SIZE_CHOICES), width=24).pack(
            side="left", padx=(8, 14))
        ttk.Label(controls, text="Pad (hex)").pack(side="left")
        ttk.Combobox(controls, textvariable=self.fill, values=["FF", "00"], width=4).pack(side="left", padx=6)
        ttk.Label(self.advanced, text="Auto size follows the full read or decoder. Custom: decimal / 0x hex.",
                  style="Small.TLabel").grid(row=4, column=0, columnspan=3, sticky="w", pady=(5, 0))
        ttk.Button(self.advanced, text="Clear index / catalogue",
                   command=self.clear_index).grid(
            row=5, column=0, columnspan=3, sticky="w", pady=(8, 0))
        self.advanced.grid_remove()
        self.progress = ttk.Progressbar(frame, mode="indeterminate")
        self.progress.grid(row=7, column=0, columnspan=3, sticky="ew", pady=(8, 5))
        self.status_label = ttk.Label(frame, textvariable=self.status, wraplength=490)
        self.status_label.grid(row=7, column=0, columnspan=3, sticky="w", pady=(0, 5))
        self.log = scrolledtext.ScrolledText(frame, height=3, wrap="word", font=("Consolas", 10),
                                             bg="#f3f6fa", relief="sunken", padx=5, pady=3,
                                             state="disabled", takefocus=1)
        self.log.grid(row=8, column=0, columnspan=3, sticky="nsew")
        # Read-only via widget state, so selection stays possible. Copy has to be
        # bound explicitly: a disabled Text does not run the class <<Copy>> code
        # on every platform, and there was no menu to fall back to.
        for sequence in ("<Control-c>", "<Control-C>", "<Control-Insert>"):
            self.log.bind(sequence, self._log_copy)
        for sequence in ("<Control-a>", "<Control-A>"):
            self.log.bind(sequence, self._log_select_all)
        self.log.bind("<Control-l>", self._log_clear)
        self._log_menu = self._make_log_menu()
        self.log.bind("<Button-3>", self._log_menu_popup)
        self.status_label.bind("<Button-3>", self._status_menu_popup)
        frame.rowconfigure(8, weight=1)
        self.write("Ready. Choose a stock file, select type, unpack.")
        root.after(100, self.poll)

    def toggle_advanced(self):
        self.expanded = not self.expanded
        if self.expanded:
            self.advanced.grid()
        else:
            self.advanced.grid_remove()
        self.advanced_button.configure(text="Advanced ▴" if self.expanded else "Advanced ▾")
        self.root.update_idletasks()
        height = 672 if self.expanded else 408
        self.root.geometry(f"{self.root.winfo_width()}x{round(height * self.ui_scale)}")

    def path_row(self, parent, row, label, variable, command, button_text="Browse"):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", padx=(0, 12), pady=5)
        ttk.Entry(parent, textvariable=variable).grid(row=row, column=1, sticky="ew", pady=5)
        ttk.Button(parent, text=button_text, width=11, command=command).grid(row=row, column=2, padx=(10, 0), pady=5)

    def _make_log_menu(self):
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Copy selection    Ctrl+C", command=self._log_copy)
        menu.add_command(label="Select all        Ctrl+A", command=self._log_select_all)
        menu.add_separator()
        menu.add_command(label="Copy status line", command=self._status_copy)
        menu.add_command(label="Save log to file...", command=self._log_save)
        menu.add_command(label="Clear log         Ctrl+L", command=self._log_clear)
        return menu

    def _log_menu_popup(self, event):
        try:
            self.log.focus_set()
        except tk.TclError:
            pass
        try:
            self._log_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self._log_menu.grab_release()
        return "break"

    def _status_menu_popup(self, event):
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Copy status line", command=self._status_copy)
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()
        return "break"

    def _log_copy(self, _e=None):
        try:
            text = self.log.get("sel.first", "sel.last")
        except tk.TclError:
            text = ""
        if not text:
            text = self.log.get("1.0", "end-1c")
        self._to_clipboard(text)
        return "break"

    def _status_copy(self):
        self._to_clipboard(self.status.get())
        return "break"

    def _to_clipboard(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.status.set("Copied to clipboard.")

    def _log_save(self):
        path = filedialog.asksaveasfilename(
            title="Save log", defaultextension=".txt",
            filetypes=[("Text", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        try:
            Path(path).write_text(self.log.get("1.0", "end-1c"), encoding="utf-8")
            self.status.set(f"Log saved: {path}")
        except OSError as exc:
            messagebox.showerror("Save log", str(exc))

    def _log_select_all(self, _e=None):
        self.log.tag_add("sel", "1.0", "end-1c")
        return "break"

    def _log_clear(self, _e=None):
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")
        return "break"

    def write(self, text):
        self.log.configure(state="normal")
        self.log.insert("end", text + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def profile_key(self):
        return next(key for key, label in PROFILES.items() if label == self.profile.get())

    def choose_source(self):
        # Start in the donor library: stock files usually live there, and it is
        # the folder the user already selected for this session.
        library = self.library.get().strip()
        start = library if library and Path(library).is_dir() else last_dir()
        path = filedialog.askopenfilename(title="Choose a stock file", initialdir=start, filetypes=[("Stock files (FRF / ODX / SGO / SOX)", "*.sgo *.frf *.odx *.sox"), ("All files", "*.*")])
        if path:
            save_settings(last_dir=str(Path(path).parent))
            self.load_source(path)

    def load_source(self, path):
        path = str(path)
        if path.lower().endswith((".frf", ".odx")):
            import sgo_frf
            try:
                if path.lower().endswith(".odx"):
                    members, image, _blocks, family = sgo_frf.load_odx(path)
                else:
                    members, image, _blocks, family = sgo_frf.load(path)
            except ValueError as exc:
                self.write(f"\n*** UNSUPPORTED FRF: {Path(path).name}")
                self.write(f"    {exc}")
                self.status.set(f"Unsupported FRF: {exc}")
                messagebox.showerror("Unsupported FRF", str(exc))
                return
            self._frf_family = family
            # The decoded image stays in memory: nothing is written beside the
            # FRF (no extracted .image.bin, no sidecars).
            self._frf_image = bytes(image)
            # show the detected family in the type combobox
            family_map = {"dq381": "dq381", "dq200mqb": "dq200mqb",
                          "dq500temic": "dq500temic", "dl382": "dl382",
                          "dl501": "dl501", "vl381": "vl381",
                          "zf8hp": "zf8hp", "dq400e": "dq400e"}
            profile_key = family_map.get(family)
            if profile_key in PROFILES:
                self.profile.set(PROFILES[profile_key])
            path = str(Path(path))
        elif hasattr(self, "_frf_family"):
            del self._frf_family
            if hasattr(self, "_frf_image"):
                del self._frf_image
        self.source.set(path)
        self.output.set(str(Path(path).with_name(Path(path).stem + ".full.bin")))
        self.inspect()

    def choose_output(self):
        path = filedialog.asksaveasfilename(title="Save flash image", defaultextension=".bin",
                                           initialdir=last_dir(),
                                           initialfile=Path(self.output.get()).name or "firmware.full.bin",
                                           filetypes=[("Flash binary", "*.bin")])
        if path:
            save_settings(last_dir=str(Path(path).parent))
            self.output.set(path)

    def choose_table(self):
        path = filedialog.askopenfilename(title="Choose 256-byte family table", initialdir=last_dir(), filetypes=[("Binary", "*.bin"), ("All files", "*.*")])
        if path:
            save_settings(last_dir=str(Path(path).parent))
            self.table.set(path)

    def choose_reference(self):
        path = filedialog.askopenfilename(title="Choose full flash read", initialdir=last_dir(), filetypes=[("Flash binary", "*.bin"), ("All files", "*.*")])
        if path:
            save_settings(last_dir=str(Path(path).parent))
            self.reference.set(path)

    def about(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("About")
        dialog.transient(self.root)
        dialog.resizable(False, False)
        dialog.grab_set()
        frame = ttk.Frame(dialog, padding=14)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="TCU SGO / FRF Unpacker",
                  font=("Segoe UI", 12, "bold")).pack(anchor="w")
        ttk.Label(
            frame, wraplength=560, justify="left", font=("Segoe UI", 10),
            text=(
                "Turns a factory VAG transmission update into a full flash image, "
                "and puts a tuned read back to stock using the closest factory "
                "calibration.\n\n"
                "Unpacking: open a factory container (FRF, ODX or SGO). Its blocks "
                "are decrypted and decompressed with the family's key and cipher, "
                "then placed at their known addresses, producing the complete stock "
                "flash (typically 1.5–2 MB) rather than a single member.\n\n"
                "Restoring: open a tuned dump and press Restore ORI. The library is "
                "searched and every candidate is compared over the calibration "
                "window; the best CAL fit is offered, with its own Match (same "
                "offset) and Cal fit (sections may move) scores. Only the "
                "calibration bytes you tick are copied into a copy of your read — "
                "application/boot regions and the SW part-number markings are never "
                "written. Saving writes a new file plus a change report.\n\n"
                "Families: DQ200, DQ250, DQ381, DQ400e, DQ500, DL382, DL501, ZF 8HP, "
                "Aisin AL1000 and plain SGO containers.\n\n"
                "AL numbers are VAG designations for longitudinal automatics by "
                "torque class, not a supplier: AL551 ≈ 550 Nm (ZF 8HP55), "
                "AL951 ≈ 950 Nm (ZF 8HP95 range), AL1000 ≈ 1000 Nm (Aisin 8-speed, "
                "0C8 927 750/769). ZF and Aisin units share the naming only; their "
                "TCUs, ciphers and block layouts are different."
            )).pack(anchor="w", pady=(8, 12))
        ttk.Button(frame, text="OK", command=dialog.destroy).pack(side="right")
        dialog.bind("<Escape>", lambda _: dialog.destroy())
        dialog.bind("<Return>", lambda _: dialog.destroy())
        self.root.wait_window(dialog)

    def choose_library(self):
        path = filedialog.askdirectory(title="Stock file library",
                                       initialdir=last_dir() or self.library.get())
        if path:
            save_settings(last_dir=path, library=path)
            self.library.set(path)

    def open_flash(self):
        path = filedialog.askopenfilename(title="Open full flash read", initialdir=last_dir(), filetypes=[("All files", "*.*"), ("Flash binary", "*.bin")])
        if path:
            save_settings(last_dir=str(Path(path).parent))
            self.load_flash(path)

    def load_flash(self, path):
        try:
            self.remember_library()
            from sgo_hex import HexWindow
            profile = self.profile_key()
            table = Path(self.table.get()).read_bytes() if profile == "custom" and self.table.get() else None
            program_folder = Path(sys.executable).parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent
            extra_sgos = list(program_folder.glob("*.sgo"))
            # A local dist/ build can reuse the investigation's adjacent source
            # fixtures without bundling firmware into a portable executable.
            if (program_folder.parent / "datflash_gui.py").is_file() and (program_folder.parent / "sgo_unpack.py").is_file():
                extra_sgos.extend(program_folder.parent.glob("*.sgo"))
            if self.source.get():
                extra_sgos.append(Path(self.source.get()))
            library_root, index_path = self.catalogue_location()
            window = HexWindow(self.root, path, self.library.get(), profile, table, extra_sgos, index_path,
                               data=getattr(self, "_frf_image", None))
            return window
        except (OSError, ValueError) as exc:
            self.write(f"\n*** CANNOT OPEN FLASH: {Path(path).name}")
            self.write(f"    {exc}")
            messagebox.showerror("Cannot open flash", str(exc))

    def clear_index(self):
        """Delete this library's index/catalogue so the next rescan rebuilds it."""
        library_root, index_path = self.catalogue_location()
        program_folder = (Path(sys.executable).parent
                          if getattr(sys, "frozen", False)
                          else Path(__file__).resolve().parent)
        targets = {index_path}
        targets.update(library_root.glob("catalogue.json.*.tmp"))
        targets.update(library_root.glob(".write_probe_*"))
        cache = index_cache_root(program_folder)
        if cache.is_dir():
            targets.update(cache.glob("catalogue*.json"))
            targets.update(cache.glob("catalogue*.json.*.tmp"))
        existing = sorted(p for p in targets if p.is_file())
        if not existing:
            self.write("Index: nothing to clear (no catalogue files found).")
            return
        total = sum(p.stat().st_size for p in existing)
        listing = "\n".join(f"  {p}" for p in existing[:8])
        more = "" if len(existing) <= 8 else f"\n  … and {len(existing) - 8} more"
        if not messagebox.askyesno(
                "Clear index",
                f"Delete {len(existing)} index file(s), {total / 1048576:.2f} MB?\n"
                f"{listing}{more}\n\nThe next Rescan folder rebuilds them; "
                "the stock files themselves are not touched.",
                parent=self.root):
            return
        removed = 0
        freed = 0
        failures = []
        for path in existing:
            size = path.stat().st_size
            try:
                path.unlink()
                removed += 1
                freed += size
            except OSError as exc:
                failures.append(f"{path.name}: {exc}")
        self.write(f"Index cleared: {removed} file(s), {freed / 1048576:.2f} MB. "
                   "Press Rescan folder to rebuild.")
        for line in failures:
            self.write("  could not remove " + line)

    def catalogue_location(self):
        """(library folder, catalogue json inside it) for this session.

        The catalogue describes one library and must travel with it, because
        two people's datflash folders hold different files. Only when the
        library folder is not writable does it fall back to the app cache.
        """
        library_root = Path(self.library.get()).resolve()
        in_library = library_root / "catalogue.json"
        try:
            library_root.mkdir(parents=True, exist_ok=True)
            # Probe the same operation the rescan will perform: create and
            # replace a temp file next to the catalogue. A plain dot-file probe
            # can pass while the atomic replace is still denied.
            probe = library_root / f".write_probe_{os.getpid()}"
            probe.write_bytes(b"")
            probe.unlink()
            return library_root, in_library
        except OSError:
            program_folder = (Path(sys.executable).parent
                              if getattr(sys, "frozen", False)
                              else Path(__file__).resolve().parent)
            digest = hashlib.sha256(
                str(library_root).casefold().encode("utf-8")).hexdigest()[:6]
            return library_root, index_cache_root(program_folder) / f"catalogue_{digest}.json"

    def _probe_library_writes(self, library_root):
        self.write("Library write probe: "
                   + "; ".join(library_write_probe(library_root)))

    def _process_diagnostics(self, library_root):
        self.write("Process probe: "
                   + "; ".join(process_diagnostics(library_root)))

    def remember_library(self):
        """Persist the donor library whenever it is actually used or the app closes.

        It used to be saved only by the Browse button, so typing a path (or
        accepting the default) forgot it on the next start.
        """
        library = self.library.get().strip()
        if not library or library == self._saved_library:
            return
        try:
            if not Path(library).is_dir():
                return
        except OSError:
            return
        save_settings(library=library, last_dir=library)
        self._saved_library = library

    def on_close(self):
        self.remember_library()
        self.root.destroy()

    def rescan_library(self):
        """Add new FRFs to the catalogue and fill in their CAL CRCs.

        Runs on a worker thread: decoding every new container can take minutes
        and must never freeze the window. One counter, two labelled phases.
        """
        import json

        import sgo_index

        self.remember_library()

        if getattr(self, "_rescan_thread", None) and self._rescan_thread.is_alive():
            self._rescan_cancel.set()
            return
        library_root, index_path = self.catalogue_location()
        if DEBUG:
            self._process_diagnostics(library_root)
            self._probe_library_writes(library_root)
        if index_path.parent != library_root:
            self.write(f"Library folder is not writable by this app; "
                       f"using cache index: {index_path}")
        if not library_root.is_dir():
            messagebox.showerror("Rescan folder",
                                 "Choose an existing library folder first.")
            return
        if not index_path.exists():
            index_path.parent.mkdir(parents=True, exist_ok=True)
            index_path.write_text(json.dumps({
                "schema": sgo_index.INDEX_SCHEMA,
                "source_root": str(library_root),
                "chunk_size": sgo_index.CHUNK,
                "source_count": 0, "unique_sgo_count": 0, "counts": {},
                "sources": [], "sgos": [], "frfs": []}), encoding="utf-8")
        names = sorted(p.name for p in library_root.glob("*")
                       if p.suffix.lower() in (".frf", ".odx")
                       if p.stat().st_size > 0)
        plan = sgo_index.rescan_plan(library_root, index_path)
        total_work = plan["total"]
        inventory = sgo_index.format_extension_counts(plan)
        if inventory:
            self.write(f"Folder : {inventory}")
        try:
            indexed = json.loads(index_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            indexed = {}
        self.write(f"Indexed: {sgo_index.format_index_counts(indexed)}")
        import sgo_frf
        if DEBUG:
            self.write(f"Index: {index_path}")
            self.write(f"Decoder: {getattr(sgo_frf, 'FAST_PATH', None) or 'Python fallback'}")
        mix = sgo_index.format_library_mix(plan) or f"{len(names):,} FRFs"
        self.write(f"\nRescanning {library_root}: {mix}, "
                   f"{total_work:,} work items "
                   f"({plan['new_sgo']:,} new stock, {plan['new_frf']:,} new FRF, "
                   f"{plan['missing_crc']:,} CAL CRCs)")
        self._rescan_cancel = threading.Event()
        events = queue.Queue()
        self.rescan_button.configure(text="Cancel", state="normal")
        def progress(phase, done, total, name):
            if self._rescan_cancel.is_set():
                raise RuntimeError("cancelled")
            events.put(("progress", (phase, done, total, name)))

        def worker():
            try:
                # Batched passes; the wrapper turns their per-batch counters
                # into one folder-wide figure so the status cannot oscillate.
                sgo_index.run_rescan(library_root, index_path, progress, plan=plan)
                document = json.loads(index_path.read_text(encoding="utf-8"))
                crcs = sum(1 for entry in document.get("frfs", ())
                           if entry.get("cal_crc"))
                events.put(("done", (len(names), len(document.get("frfs", ())),
                                     crcs, len(document.get("sgos", ())))))
            except Exception as exc:
                events.put(("error", str(exc)))

        def poll():
            try:
                while True:
                    kind, value = events.get_nowait()
                    if kind == "progress":
                        phase, done, total, name = value
                        share = (f"{done:,}/{total:,} ({100 * done // total}%)"
                                 if total else "")
                        self.status.set(f"{phase}: {name}  {share}".strip())
                    else:
                        self.rescan_button.configure(text="Rescan folder",
                                                     state="normal")
                        self._rescan_thread = None
                        if kind == "error":
                            if "cancelled" in value:
                                self.status.set("Rescan cancelled.")
                                self.write("Rescan cancelled.")
                            else:
                                self.status.set(f"Rescan failed: {value}")
                                messagebox.showerror("Rescan folder", value)
                        else:
                            count, entries, crcs, sgos = value
                            removed = (plan.get("removed_sgo", 0),
                                       plan.get("removed_frf", 0))
                            if any(removed):
                                self.write(f"Removed {removed[0]:,} missing SGO and "
                                           f"{removed[1]:,} missing FRF record(s).")
                            if plan.get("tcu_labelled"):
                                self.write(f"Labelled {plan['tcu_labelled']:,} SGO "
                                           f"record(s) with their TCU.")
                            total_files = plan.get("files", 0)
                            self.write(f"Rescan done: {total_files:,} files · "
                                       f"{mix} · {entries:,} FRFs in catalogue, "
                                       f"{crcs:,} with CAL CRCs.")
                            if DEBUG:
                                self.write(f"Decode workers: {sgo_index.pool_status()}")
                            self.status.set("Rescan complete.")
                        return
            except queue.Empty:
                pass
            self.root.after(100, poll)

        self._rescan_thread = threading.Thread(target=worker, daemon=True)
        self._rescan_thread.start()
        self.root.after(100, poll)

    def inspect(self):
        if self.busy or not self.source.get():
            return
        if getattr(self, "_frf_family", None):
            size = Path(self.source.get()).stat().st_size
            self.info.set(f"FRF family: {self._frf_family} · {size:,} bytes · extracted image")
            self.status.set("Ready to unpack.")
            self.write(f"FRF extracted: {self.source.get()} ({size:,} bytes, family {self._frf_family})")
            return
        try:
            sgo = SGO(self.source.get()).parse()
            total = sum(b["decomp_be"] for b in sgo.blocks)
            formats = ", ".join(f"{b['format']:02X}" for b in sgo.blocks)
            self.info.set(f"SW {sgo.version or '—'} · {len(sgo.blocks)} block(s) · {total:,} bytes · format {formats}")
            self.write(sgo.summary())
            reason = unsupported_reason(sgo)
            if reason:
                self.status.set("Cannot decode this SGO: " + reason)
                self.write("")
                self.write("*** CANNOT DECODE THIS SGO")
                self.write("    " + reason)
                self.write("    Unpacking and Open flash would fail with this message.")
                return
            self.status.set("Ready to unpack.")
        except (OSError, ValueError) as exc:
            self.status.set(str(exc))
            self.write("Cannot inspect: " + str(exc))

    def options(self):
        if not self.source.get() or not self.output.get():
            raise ValueError("Choose a stock file and an output filename first.")
        # auto-profile from FRF family when the user left AUTO
        if getattr(self, "_frf_family", None) and self.profile_key() == "auto":
            family_map = {"dq381": "dq381", "dq200mqb": "dq200mqb",
                          "dq500temic": "dq500temic", "dl382": "dl382",
                          "dl501": "dl501", "vl381": "vl381",
                          "zf8hp": "zf8hp", "dq400e": "dq400e"}
            frf_profile = family_map.get(self._frf_family)
            if frf_profile:
                self.profile.set(PROFILES[frf_profile])
        size_text = self.size.get().strip()
        size = SIZE_CHOICES.get(size_text) if size_text in SIZE_CHOICES else number(size_text)
        profile = self.profile_key()
        table = Path(self.table.get()).read_bytes() if profile == "custom" and self.table.get() else None
        if self.preserve.get() and not self.reference.get():
            raise ValueError("Choose a full read to preserve missing regions from.")
        return dict(filename=self.source.get(), output=self.output.get(), profile=profile,
                    table=table, size=size, fill=int(self.fill.get(), 16),
                    base_path=self.reference.get() if self.preserve.get() else None,
                    reference_path=self.reference.get() or None)

    def run(self):
        # Log the press itself: if this line never appears, the click never
        # reached this button (disabled, or a different button was pressed).
        self.write("\nUnpack requested: " + (self.source.get() or "(no stock file)"))
        if self.busy:
            self.write("    ignored: a decode is already running")
            return
        try:
            options = self.options()
            if not getattr(self, "_frf_family", None):
                reason = unsupported_reason(SGO(options["filename"]).parse())
                if reason:
                    raise ValueError(reason)
            target = Path(options["output"])
            # This GUI confirmation protects existing output; no source is overwritten.
            candidates = [target, target.with_suffix(target.suffix + ".json")]
            if options["profile"] in ("edc16-1m", "edc16-2m"):
                candidates += [target.with_name(f"{target.stem}.{part}.bin") for part in ("flash", "mcu")]
            if any(p.exists() for p in candidates) and not messagebox.askyesno(
                    "Replace output?", "One or more output files already exist. Replace those output files?"):
                self.write("    cancelled: output already exists")
                return
        except BaseException as exc:
            self.write("\n*** CANNOT UNPACK: " + Path(self.source.get()).name)
            self.write("    {}: {}".format(type(exc).__name__, exc))
            self.status.set("Cannot unpack: " + str(exc))
            messagebox.showerror("Cannot unpack", str(exc))
            return
        self.busy = True
        self.go.configure(state="disabled")
        self.progress.start(12)
        self.status.set("Decoding and assembling flash image…")
        self.write("\nUnpacking " + options["filename"])

        def worker():
            try:
                if getattr(self, "_frf_family", None):
                    import shutil
                    shutil.copyfile(options["filename"], options["output"])
                    manifest = {"output": options["output"],
                                "output_size": Path(options["output"]).stat().st_size,
                                "profile": self._frf_family,
                                "source": options["filename"]}
                    self.events.put((True, manifest))
                else:
                    self.events.put((True, build_image(**options)))
            except BaseException as exc:
                # BaseException too: a worker that dies silently used to leave
                # the button disabled with nothing in the log.
                self.events.put((False, "{}: {}".format(type(exc).__name__, exc)))

        threading.Thread(target=worker, daemon=True).start()

    def poll(self):
        try:
            ok, result = self.events.get_nowait()
        except queue.Empty:
            pass
        else:
            self.busy = False
            self.go.configure(state="normal")
            self.progress.stop()
            self.progress.configure(value=0)
            if ok:
                self.last_manifest = result
                self.show_result(result)
            else:
                self.status.set("Unpacking failed: " + result)
                self.write("ERROR: " + result)
                messagebox.showerror("Unpacking failed", result)
        self.root.after(100, self.poll)

    def show_result(self, m):
        self.status.set("BIN EXPORTED")
        self.write(f"Saved: {m['output']}\n"
                   f"Size: {m['output_size']:,} bytes ({m['output_size']:#x})\n"
                   f"Decoded: {m['decoded_bytes']:,} bytes; missing: {m['missing_bytes']:,} bytes\n"
                   f"Missing regions: {m['missing_region_source']}\nSHA-256: {m['output_sha256']}")
        comparison = m.get("comparison")
        if comparison:
            if comparison["exact_match"]:
                text = f"EXACT MATCH — all {m['output_size']:,} output bytes equal the full read."
            elif comparison["decoded_regions_match"]:
                text = (f"Decoded regions match. Full image differs by {comparison['different_bytes']:,} bytes "
                        "in size or missing regions.")
            else:
                text = f"MISMATCH — {comparison['decoded_different_bytes']:,} decoded bytes differ from the full read."
            if comparison["reference_used_as_base"]:
                text += " Missing bytes were preserved from that read."
            self.write(text)
        for part in m["part_exports"]:
            self.write("Part export: " + part["output"])

    def open_output(self):
        path = Path(self.output.get()).parent if self.output.get() else Path.cwd()
        if path.is_dir():
            os.startfile(str(path))

def index_cache_root(program_folder):
    """Portable first: the index cache lives beside the executable.

    Only if that folder cannot be written (Program Files, a policy-protected
    Downloads folder) fall back to the per-user profile, so a restore still
    works instead of dying on a permission error.
    """
    candidates = [Path(program_folder) / "index",
                  Path(os.environ.get("LOCALAPPDATA") or Path.home())
                  / "TCU SGO FRF Unpacker" / "index"]
    for root in candidates:
        try:
            root.mkdir(parents=True, exist_ok=True)
            probe = root / f".probe_{os.getpid()}"
            probe.write_bytes(b"")
            probe.unlink()
            return root
        except OSError:
            continue
    raise OSError("no writable folder for the index cache")


def main():
    # A frozen (PyInstaller) build must install the multiprocessing hook before
    # any process pool is created. Without it, worker spawn re-executes the exe
    # and ProcessPoolExecutor fails, so every decode silently ran serially.
    import multiprocessing

    multiprocessing.freeze_support()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sgo", nargs="?")
    parser.add_argument("--reference")
    parser.add_argument("--smoke-test", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--write-probe", metavar="DIR",
                        help="headless: report write access to DIR and exit")
    args = parser.parse_args()
    if args.write_probe:
        import tempfile

        notes = process_diagnostics(args.write_probe)
        notes += library_write_probe(args.write_probe)
        report = Path(tempfile.gettempdir()) / "tcu_write_probe.txt"
        report.write_text("\n".join(notes), encoding="utf-8")
        try:
            print("\n".join(notes))
        except Exception:
            pass
        return 0
    aware = enable_dpi_awareness()
    root = tk.Tk()
    app = App(root)
    app.dpi_mode = aware
    if args.smoke_test:
        root.withdraw()
        root.update()
        assert app.profile.get() == "AUTO"
        assert list(PROFILES.values()).count("DQ250") == 1
        assert PROFILES["dq200"] == "DQ200"
        app.profile.set("DQ250")
        assert app.profile_key() == "dq250"
        from sgo_hex import HexWindow
        from sgo_restore import find_matches
        from sgo_unpack import decrypt_table
        from sgo_early import EARLY_TABLE, EARLY_TABLE_SHA256, decrypt_feedback
        assert hashlib.sha256(EARLY_TABLE).hexdigest() == EARLY_TABLE_SHA256
        assert decrypt_feedback(bytes.fromhex("8fde6fca")) == bytes.fromhex("48008116")
        key = sgo_tables.table("dq250_pq")
        dq250c = sgo_tables.table("dq250c_pq")
        dq200 = sgo_tables.table("dq200_pq")
        assert len(dq200) == 256 and hashlib.sha256(dq200).hexdigest() == "c6ec43b6fe5ffb28a55b3db7d3a06e10f46cae3b24c66fb99927b448d3f061e2"
        assert len(dq250c) == 256 and hashlib.sha256(dq250c).hexdigest() == "3cb44b95ed4138f29efbd6fc8c002731bcb5cfcff9719f810e7128a0897c4c26"
        assert len(key) == 256 and decrypt_table(b"\xb1", key) == b"\xa8"
        assert app.go.cget("text") == "Unpack"
        from sgo_scratch import scratch
        with scratch() as folder:
            sample = Path(folder) / "flash.bin"
            sample.write_bytes(b"02E927770AJ\x0002E300051S\x00"
                               b"v0691b5702ea__getriebe_DSG_RN1b E19R1\x00")
            view = HexWindow(root, sample, folder)
            view.window.withdraw()
            root.update_idletasks()
            assert "HW: 02E927770AJ" in view.identity_text.get()
            assert "SW: 02E300051S" in view.identity_text.get()
            assert "Getriebe: DSG RN1b" in view.identity_text.get()
            assert int(view.identity_label.grid_info()["row"]) == 1
            assert int(view.text.grid_info()["row"]) == 3
            view.close()
        root.destroy()
        return
    if args.sgo:
        app.load_source(args.sgo)
    if args.reference:
        app.reference.set(args.reference)
    root.mainloop()


if __name__ == "__main__":
    main()
