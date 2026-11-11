"""Compact virtualized hex editor and stock-file restore window."""

import bisect
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk
from tkinter.font import Font

from sgo_image import MAX_IMAGE
from sgo_identity import flash_identity, identity_text
from sgo_restore import (apply_writes, candidate_for, changed_ranges,
                         find_matches, outside_cal_ranges, plan_writes,
                         raw_image_candidate, refine_match, restore_plan,
                         save_flash, software_parts, sw_marking_ranges)

# Donor acceptance bar: a candidate whose calibration only matches under 50%
# sectioned best-fit is a different calibration, not an original for this box.
MIN_CAL_FIT = 0.50

# A TCU flash read is at least 256 KiB. Anything smaller is an EEPROM/micro
# dump (E2P) or a partial read, and no FRF donor can match it.
MIN_FLASH_BYTES = 0x40000

# Donor rows offered in the dialog (the list scrolls past this).
MAX_DONORS = 20


class HexWindow:
    def __init__(self, parent, path, library, profile="auto", table=None, extra_sgos=(), index_path=None, data=None):
        self.path = Path(path)
        if data is None:
            if not 0 < self.path.stat().st_size <= MAX_IMAGE:
                raise ValueError("flash must be between 1 byte and 32 MiB")
            self.original = self.path.read_bytes()
        else:
            if not 0 < len(data) <= MAX_IMAGE:
                raise ValueError("flash must be between 1 byte and 32 MiB")
            self.original = bytes(data)
        self.data = bytearray(self.original)
        self.small_dump = len(self.data) < MIN_FLASH_BYTES
        stem = self.path.stem.lower()
        self.is_eeprom = (self.small_dump
                          or (len(self.data) <= 0x10000
                              and ("eeprom" in stem or "e2p" in stem
                                   or "epp" in stem or "micro" in stem
                                   or self.path.suffix.lower() in (".eep", ".e2p"))))
        self.library, self.profile, self.table = Path(library), profile, table
        self.extra_sgos = list(extra_sgos)
        self.index_path = Path(index_path) if index_path else None
        self.ranges, self.starts = [], []
        self.top = 0
        self.position = 0
        self.selected_match = None
        self.busy = False
        self.events = queue.Queue()
        self.last_scan = None
        self.window = tk.Toplevel(parent)
        self.window.title(("EEPROM · " if self.is_eeprom else "Flash · ") + self.path.name)
        # Geometry is in real pixels; these sizes are 96-dpi units.
        try:
            scale = float(self.window.tk.call("tk", "scaling")) * 72.0 / 96.0
        except Exception:
            scale = 1.0
        self.ui_scale = scale
        width = round(720 * scale)
        height = round(713 * scale)
        # Keep the window on screen: at 125% the 96-dpi height would exceed a
        # 1366x768-class display once DPI is honoured.
        screen_w = self.window.winfo_screenwidth()
        screen_h = self.window.winfo_screenheight()
        width = min(width, screen_w - round(80 * scale))
        height = min(height, screen_h - round(60 * scale))
        self.window.geometry(f"{width}x{height}")
        self.window.minsize(560, 520)
        self.window.protocol("WM_DELETE_WINDOW", self.close)
        frame = ttk.Frame(self.window, padding=8)
        frame.pack(fill="both", expand=True)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(5, weight=1)
        toolbar = ttk.Frame(frame)
        toolbar.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 5))
        self.restore_button = ttk.Button(toolbar, text="Restore ORI", command=self.search)
        self.restore_button.pack(side="left")
        self.save_button = ttk.Button(toolbar, text="Save as…", command=self.save)
        self.save_button.pack(side="left", padx=(5, 0))
        self.view_original = False
        self.hide_changes = tk.BooleanVar(value=False)
        self.view_button = ttk.Checkbutton(
            toolbar, text="Hide changes", variable=self.hide_changes,
            command=self.toggle_view)
        self.view_button.pack(side="left", padx=(5, 12))
        if self.is_eeprom:
            self.restore_button.configure(state="disabled")
        ttk.Button(toolbar, text="|◀", width=3,
                   command=self.first_change).pack(side="left")
        ttk.Button(toolbar, text="◀", width=3,
                   command=self.previous_change).pack(side="left", padx=(3, 0))
        ttk.Button(toolbar, text="▶", width=3,
                   command=self.next_change_forward).pack(side="left", padx=(3, 0))
        ttk.Button(toolbar, text="▶|", width=3,
                   command=self.last_change).pack(side="left", padx=(3, 10))
        self.offset = tk.StringVar(value="00000000")
        entry = ttk.Entry(toolbar, textvariable=self.offset, width=9, font=("Consolas", 10))
        entry.pack(side="left")
        entry.bind("<Return>", lambda _: self.jump())
        ttk.Button(toolbar, text="Go", width=3, command=self.jump).pack(side="left", padx=3)
        ttk.Button(toolbar, text="Library…", command=self.choose_library).pack(side="right")
        self.identifiers = flash_identity(self.data)
        self.identity_text = tk.StringVar(value=identity_text(self.identifiers))
        self.identity_label = ttk.Label(frame, textvariable=self.identity_text,
                                        font=("Segoe UI", 9), wraplength=535, justify="left")
        self.identity_label.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, 6))
        frame.bind("<Configure>", lambda event: self.identity_label.configure(
            wraplength=max(250, event.width - 16)))
        ttk.Label(frame, text="Offset     00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F   ASCII",
                  font=("Consolas", 9)).grid(row=2, column=0, sticky="w")
        self.text = tk.Text(frame, wrap="none", font=("Consolas", 10), width=76, height=16,
                            padx=2, pady=2, relief="sunken", cursor="arrow", takefocus=True)
        # Fixed 16-line hex pane: the 2D plot below takes the spare height.
        self.text.grid(row=3, column=0, sticky="new")
        self.scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.scroll)
        self.scrollbar.grid(row=3, column=1, sticky="ns")
        self.text.tag_configure("changed", background="#b3261e", foreground="#ffe6e6")
        self.text.tag_configure("cursor", background="#264f78", foreground="#ffffff")
        self.nibble = 0
        self.nibble_value = 0
        self.text.bind("<Key>", self.key_press)
        self.text.bind("<MouseWheel>", self.wheel)
        self.text.bind("<Button-4>", lambda _: self.move(-3))
        self.text.bind("<Button-5>", lambda _: self.move(3))
        self.text.bind("<Double-Button-1>", self.edit_click)
        self.text.bind("<ButtonRelease-1>", self.click_cursor)
        self.text.bind("<FocusIn>", lambda _: self.render())
        self.text.bind("<Configure>", lambda _: self.render())
        self.status = tk.StringVar(value=(
            (f"{len(self.data):,} bytes is smaller than a flash image "
             f"(minimum {MIN_FLASH_BYTES:,} B / 256 KiB) — this looks like an "
             f"EEPROM/micro dump, so no FRF donor can match it. "
             f"Open the full flash read to restore ORI.")
            if self.is_eeprom else
            f"{len(self.data):,} bytes · Double-click a hex byte to edit."))
        # 2D value map under the hex dump: one cell per 8/16/32-bit word.
        map_row = ttk.Frame(frame)
        map_row.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(6, 0))
        ttk.Label(map_row, text="Map:").pack(side="left")
        self.map_bits = tk.IntVar(value=16)
        ttk.Combobox(map_row, textvariable=self.map_bits, state="readonly",
                     width=4, values=(8, 16, 32)).pack(side="left", padx=(3, 8))
        self.map_order = tk.StringVar(value="lo-hi")
        ttk.Combobox(map_row, textvariable=self.map_order, state="readonly",
                     width=6, values=("lo-hi", "hi-lo")).pack(side="left")
        ttk.Label(map_row, text="  zoom:").pack(side="left")
        self.map_zoom = tk.StringVar(value="200")
        ttk.Combobox(map_row, textvariable=self.map_zoom, state="readonly",
                     width=5, values=(25, 50, 100, 200, 400)).pack(
            side="left", padx=(3, 0))
        ttk.Label(map_row, text="%").pack(side="left")
        self.map_bits.trace_add("write", lambda *_: self.map_recentre())
        self.map_order.trace_add("write", lambda *_: self.draw_map())
        self.map_zoom.trace_add("write", lambda *_: self.map_recentre())
        map_frame = ttk.Frame(frame)
        map_frame.grid(row=5, column=0, columnspan=2, sticky="nsew", pady=(2, 0))
        self.map = tk.Canvas(map_frame, height=150, highlightthickness=1,
                            background="#000000")
        self.map.pack(fill="both", expand=True)
        self.map_scroll = ttk.Scrollbar(map_frame, orient="horizontal",
                                        command=self.scroll_map)
        self.map_scroll.pack(fill="x")
        self.map_offset = 0
        self.map.bind("<Button-1>", self.map_press)
        self.map.bind("<B1-Motion>", self.map_drag)
        self.map.bind("<ButtonRelease-1>", self.map_release)
        self.map.bind("<MouseWheel>", self.map_wheel)
        self.map.bind("<Configure>", lambda _: self.draw_map())
        # WinOLS-style View accelerators on the 2D pane: plain E/V/N/L while it
        # has focus, so the hex editor keeps E as a nibble.
        for key, action in (("e", self.first_change), ("v", self.previous_change),
                            ("n", self.next_change_forward),
                            ("l", self.last_change)):
            self.map.bind(f"<KeyPress-{key}>",
                          lambda _e, a=action: (a(), "break")[1])
        ttk.Label(frame, textvariable=self.status, wraplength=535,
                  justify="left", anchor="nw").grid(
            row=6, column=0, columnspan=2, sticky="nw", pady=(5, 0))
        # Reserve room for four status lines so the hex view keeps a constant
        # number of rows whether the message is short or long.
        frame.rowconfigure(6, minsize=64)
        self.window.after_idle(self.render)
        self.window.bind("<Escape>", lambda _: self.close())
        self.window.after(100, self.poll)

    def close(self):
        # Files are only written through Save as. Closing discards the buffer.
        self.window.destroy()

    def visible_rows(self):
        height = Font(font=self.text.cget("font")).metrics("linespace")
        return max(1, (self.text.winfo_height() - 6) // height)

    def view_data(self):
        """Bytes currently shown: the read as opened, or as edited."""
        return self.original if self.view_original else self.data

    def toggle_view(self):
        self.view_original = bool(self.hide_changes.get())
        self.render()

    def render(self):
        if not self.window.winfo_exists():
            return
        shown = self.view_data()
        rows = self.visible_rows()
        total = (len(shown) + 15) // 16
        self.top = max(0, min(self.top, max(0, total - rows)))
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        for row in range(min(rows, total - self.top)):
            address = (self.top + row) * 16
            chunk = shown[address:address + 16]
            hexes = " ".join(f"{value:02X}" for value in chunk).ljust(47)
            ascii_text = "".join(chr(value) if 32 <= value < 127 else "." for value in chunk)
            self.text.insert("end", f"{address:08X}  {hexes}  {ascii_text}\n")
            for index in range(len(chunk)):
                offset = address + index
                change = bisect.bisect_right(self.starts, offset) - 1
                if change >= 0 and offset < self.ranges[change][1]:
                    self.text.tag_add("changed", f"{row + 1}.{10 + index * 3}", f"{row + 1}.{12 + index * 3}")
                    self.text.tag_add("changed", f"{row + 1}.{59 + index}", f"{row + 1}.{60 + index}")
                if offset == self.position:
                    self.text.tag_add("cursor", f"{row + 1}.{10 + index * 3}", f"{row + 1}.{12 + index * 3}")
                    self.text.tag_add("cursor", f"{row + 1}.{59 + index}", f"{row + 1}.{60 + index}")
        self.text.configure(state="disabled")
        self.scrollbar.set(self.top / total, min(1, (self.top + rows) / total))
        self.offset.set(f"{self.top * 16:08X}")
        self.draw_map()

    def map_word(self, offset, size):
        shown = self.view_data()
        if offset + size > len(shown):
            return None
        chunk = bytes(shown[offset:offset + size])
        return int.from_bytes(chunk, "big" if self.map_order.get() == "hi-lo"
                              else "little")

    MAP_LEFT = 4
    MAP_BOTTOM = 26
    MAP_RIGHT = 56

    def _map_geometry(self):
        bits = int(self.map_bits.get())
        size = max(1, bits // 8)
        percent = max(25, int(self.map_zoom.get() or 100))
        if percent >= 100:
            px = percent / 100.0      # pixels per sample
            pooling = 1
        else:
            px = 1.0                  # one pixel per group of samples
            pooling = max(1, 100 // percent)
        width = max(1, self.map.winfo_width())
        height = max(1, self.map.winfo_height())
        plot_w = max(1, width - self.MAP_LEFT - self.MAP_RIGHT)
        plot_h = max(1, height - self.MAP_BOTTOM - 8)
        count = max(1, int(plot_w // px))
        return size, px, pooling, plot_w, plot_h, count

    def draw_map(self):
        if not hasattr(self, "map") or not self.window.winfo_exists():
            return
        size, px, pooling, plot_w, plot_h, count = self._map_geometry()
        self.map.delete("all")
        total = len(self.data)
        start = self.map_offset - (self.map_offset % size)
        left, top = self.MAP_LEFT, 8
        bottom = top + plot_h
        values = []
        for index in range(count):
            base = start + index * pooling * size
            group = [self.map_word(base + i * size, size)
                     for i in range(pooling)]
            group = [value for value in group if value is not None]
            if not group:
                break
            values.append(max(group))
        if not values:
            return
        # Vertical scale is fixed: the axis always spans the full numeric range
        # of the selected grouping (0 .. max), so the trace keeps its real
        # proportions instead of being normalised to the visible window.
        vmax = (1 << (size * 8)) - 1
        scale = (plot_h - 2) / max(1, vmax)
        # Grid and axes.
        for frac in (0.0, 0.25, 0.5, 0.75, 1.0):
            y = bottom - frac * (plot_h - 2)
            self.map.create_line(left, y, left + plot_w, y, fill="#203020")
            label = int(vmax * frac)
            self.map.create_text(left + plot_w + 4, y, anchor="w",
                                 text=f"{label:0{size * 2}X}",
                                 fill="#5ad45a", font=("Consolas", 7))
        tick = max(1, int(90 // px))
        for index in range(0, len(values), tick):
            offset = start + index * pooling * size
            x = left + index * px
            self.map.create_line(x, top, x, bottom, fill="#203020")
            self.map.create_text(x, bottom + 4, anchor="nw",
                                 text=f"{offset:05X}", fill="#5ad45a",
                                 font=("Consolas", 7))
        # Changed ranges as thin ticks along the top edge, coloured like the
        # trace: red where the value rose, blue where it fell, amber if the
        # bytes changed without moving the value.
        sample = pooling * size
        span = count * sample

        def change_colour(offset):
            if offset + size > len(self.data) or offset + size > len(self.original):
                return "#ffd24a"
            order = "big" if self.map_order.get() == "hi-lo" else "little"
            current = int.from_bytes(self.data[offset:offset + size], order)
            original = int.from_bytes(self.original[offset:offset + size], order)
            if current > original:
                return "#ff5555"
            if current < original:
                return "#5aa9ff"
            return "#ffd24a"

        for range_start, range_end in self.ranges:
            if range_end <= start or range_start >= start + span:
                continue
            x1 = left + max(0, (range_start - start) // sample) * px
            x2 = left + max(1, (min(range_end, start + span) - start) // sample) * px
            self.map.create_rectangle(x1, top, max(x2, x1 + px), top + 5,
                                      fill=change_colour(range_start),
                                      outline="")
        # Trace: green normally, coloured only where bytes differ from the
        # original read — red when the value rose, blue when it fell.
        def sample_changed(offset):
            index = bisect.bisect_right(self.starts, offset) - 1
            return (index >= 0 and offset < self.ranges[index][1]
                    and self.ranges[index][0] < offset + sample)

        def direction(offset):
            current = self.map_word(offset, size)
            if current is None or offset + size > len(self.original):
                return 0
            original = int.from_bytes(
                self.original[offset:offset + size],
                "big" if self.map_order.get() == "hi-lo" else "little")
            return (current > original) - (current < original)

        previous = None
        for index, value in enumerate(values):
            y = bottom - value * scale
            px_now = left + index * px
            offset_now = start + index * sample
            if sample_changed(offset_now):
                step = direction(offset_now)
                colour = "#ff5555" if step > 0 else "#5aa9ff" if step < 0 else "#ffd24a"
            else:
                colour = "#00ff00"
            if previous is not None:
                self.map.create_line(px_now - px, previous_y, px_now, y,
                                     fill=colour, width=1)
            previous, previous_y = value, y
        self.map.create_line(left, bottom, left + plot_w, bottom, fill="#3f7f3f")
        # Cursor marker: the hex view's cursor offset, when it is in view.
        if start <= self.position < start + span:
            x = left + ((self.position - start) // sample) * px
            self.map.create_line(x, top, x, bottom, fill="#ffcc00", width=1)
        if total:
            self._map_centre = start + span // 2
            self.map_scroll.set(min(1.0, start / total),
                                min(1.0, (start + span) / total))

    def map_recentre(self):
        """Keep the byte under the middle of the plot centred across a zoom."""
        centre = getattr(self, "_map_centre", None)
        if centre is None:
            self.draw_map()
            return
        size, _px, pooling, _pw, _ph, count = self._map_geometry()
        span = count * pooling * size
        self.map_offset = max(0, min(centre - span // 2,
                                     max(0, len(self.data) - span)))
        self.map_offset -= self.map_offset % size
        self.draw_map()

    def scroll_map(self, *args):
        size, _px, pooling, _pw, _ph, count = self._map_geometry()
        span = count * pooling * size
        total = len(self.data)
        if args and args[0] == "moveto":
            self.map_offset = int(float(args[1]) * total)
        elif args and args[0] == "scroll":
            step_bytes = max(size, span // 8)
            self.map_offset += (span // 2 if args[2] == "pages"
                                else step_bytes * int(args[1]))
        self.map_offset = max(0, min(self.map_offset, max(0, total - span)))
        self.map_offset -= self.map_offset % size
        self.map_sync_hex()
        self.render()

    def map_wheel(self, event):
        size, _px, pooling, _pw, _ph, count = self._map_geometry()
        direction = -1 if event.delta > 0 else 1
        self.map_offset += direction * max(size, count * pooling * size // 8)
        self.map_offset = max(0, min(self.map_offset, max(0, len(self.data) - 1)))
        self.map_sync_hex()
        self.render()
        return "break"

    def map_press(self, event):
        self.map.focus_set()          # so E/V/N/L reach the pane's bindings
        size, _px, _pooling, _pw, _ph, _count = self._map_geometry()
        self.map_offset -= self.map_offset % size
        self._drag = {"x": event.x, "offset": self.map_offset, "moved": False}
        self.map.configure(cursor="fleur")
        return "break"

    def map_drag(self, event):
        if not getattr(self, "_drag", None):
            return "break"
        size, px, pooling, _pw, _ph, count = self._map_geometry()
        dx = event.x - self._drag["x"]
        if abs(dx) >= 2:
            self._drag["moved"] = True
        shift = int(dx / px) * pooling * size
        self.map_offset = self._drag["offset"] - shift
        span = count * pooling * size
        self.map_offset = max(0, min(self.map_offset, max(0, len(self.data) - span)))
        self.map_offset -= self.map_offset % size
        self.map_sync_hex()
        self.render()
        return "break"

    def map_release(self, event):
        drag = getattr(self, "_drag", None)
        self._drag = None
        self.map.configure(cursor="")
        if drag and not drag["moved"]:
            self.map_click(event)
        return "break"

    def map_click(self, event):
        size, px, pooling, plot_w, plot_h, _count = self._map_geometry()
        if event.x < self.MAP_LEFT or event.y > 8 + plot_h:
            return "break"
        index = max(0, min(int((event.x - self.MAP_LEFT) / px), 1 << 30))
        offset = (self.map_offset - (self.map_offset % size)) + index * pooling * size
        if 0 <= offset < len(self.data):
            self.goto(offset)
        return "break"

    def map_align_to_top(self):
        """Point the plot at the first line currently shown in the hex view."""
        if not hasattr(self, "map"):
            return
        size, _px, _pooling, _pw, _ph, _count = self._map_geometry()
        offset = self.top * 16
        self.map_offset = offset - (offset % size)

    def map_sync_hex(self):
        """Scroll the hex view to the region the plot is showing."""
        if not hasattr(self, "map"):
            return
        rows = max(1, (len(self.data) + 15) // 16)
        self.top = max(0, min(self.map_offset // 16, rows - 1))

    def move(self, rows):
        total = (len(self.data) + 15) // 16
        self.top = max(0, min(self.top + rows, max(0, total - self.visible_rows())))
        self.position = self.top * 16
        self.map_align_to_top()
        self.render()
        return "break"

    def wheel(self, event):
        return self.move(-3 * (1 if event.delta > 0 else -1))

    def scroll(self, command, value, units=None):
        if command == "moveto":
            self.top = int(float(value) * ((len(self.data) + 15) // 16))
            self.position = self.top * 16
            self.map_align_to_top()
            self.render()
        else:
            self.move(int(value) * (self.visible_rows() if units == "pages" else 1))

    def map_follow_cursor(self):
        """Scroll the plot so the hex cursor stays visible."""
        if not hasattr(self, "map"):
            return
        size, _px, pooling, _pw, _ph, count = self._map_geometry()
        span = count * pooling * size
        start = self.map_offset - (self.map_offset % size)
        sample = pooling * size
        if start <= self.position < start + span:
            return
        self.map_offset = max(0, min(self.position - span // 2,
                                     max(0, len(self.data) - span)))
        self.map_offset -= self.map_offset % size

    def ensure_visible(self):
        rows = self.visible_rows()
        row = self.position // 16
        if row < self.top:
            self.top = row
        elif row >= self.top + rows:
            self.top = row - rows + 1
        self.top = max(0, self.top)

    def move_cursor(self, delta):
        self.position = max(0, min(len(self.data) - 1, self.position + delta))
        self.nibble = 0
        self.ensure_visible()
        self.map_follow_cursor()
        self.render()
        return "break"

    def key_press(self, event):
        if event.state & 0x0004:          # Ctrl+... keeps its normal meaning
            return None
        char = (event.char or "").upper()
        if len(char) == 1 and char in "0123456789ABCDEF":
            self.type_nibble(int(char, 16))
            return "break"
        steps = {"Left": -1, "Right": 1, "Up": -16, "Down": 16}
        if event.keysym in steps:
            return self.move_cursor(steps[event.keysym])
        page = 16 * max(1, self.visible_rows())
        if event.keysym == "Prior":
            return self.move_cursor(-page)
        if event.keysym == "Next":
            return self.move_cursor(page)
        if event.keysym == "Home":
            self.position = 0
            self.nibble = 0
            self.ensure_visible()
            self.render()
            return "break"
        if event.keysym == "End":
            self.position = len(self.data) - 1
            self.nibble = 0
            self.ensure_visible()
            self.render()
            return "break"
        if event.keysym == "Escape":
            if self.nibble:
                self.nibble = 0
                self.render()
            else:
                self.close()
            return "break"
        return "break"

    def index_to_offset(self, index):
        line, column = map(int, str(index).split("."))
        row = max(0, line - 1)
        if column >= 59:
            byte = column - 59
        else:
            byte = (column - 10) // 3
        byte = max(0, min(15, byte))
        return min(len(self.data) - 1, (self.top + row) * 16 + byte)

    def selection_span(self):
        ranges = self.text.tag_ranges("sel")
        if len(ranges) != 2:
            return None
        start = self.index_to_offset(ranges[0])
        end = self.index_to_offset(ranges[1])
        if end < start:
            start, end = end, start
        return start, end

    def type_nibble(self, value):
        if self.view_original:
            self.status.set("Changes are hidden — untick Hide changes to edit.")
            return
        if not 0 <= self.position < len(self.data):
            return
        span = self.selection_span()
        if span is not None and span[1] > span[0]:
            # Typing over a selection writes that byte to every selected byte.
            if self.nibble == 0:
                self.nibble_value = value
                self.nibble = 1
                self.status.set(f"Selection of {span[1] - span[0] + 1:,} bytes "
                                f"· type the low nibble to fill")
                return
            self.nibble = 0
            byte = (self.nibble_value << 4) | value
            start, end = span
            for offset in range(start, end + 1):
                self.data[offset] = byte
            self.text.tag_remove("sel", "1.0", "end")
            self.refresh_changes()
            self.position = min(end + 1, len(self.data) - 1)
            self.ensure_visible()
            self.render()
            self.status.set(f"Filled {end - start + 1:,} bytes with "
                            f"0x{byte:02X}")
            return
        current = self.data[self.position]
        if self.nibble == 0:
            # Show the high nibble now, keep the low nibble until the next key.
            self.nibble_value = value
            self.nibble = 1
            self.data[self.position] = (value << 4) | (current & 0x0F)
            self.refresh_changes()
            self.render()
        else:
            self.nibble = 0
            self.data[self.position] = (self.nibble_value << 4) | value
            self.refresh_changes()
            self.move_cursor(1)

    def goto(self, offset):
        self.position = max(0, min(offset, len(self.data) - 1))
        self.nibble = 0
        self.ensure_visible()
        self.map_follow_cursor()
        self.render()
        return "break"

    def jump(self):
        try:
            self.goto(int(self.offset.get(), 16))
        except ValueError:
            self.status.set("Enter a hexadecimal offset.")

    def first_change(self):
        if not self.ranges:
            self.status.set("No changed bytes.")
            return
        start = self.ranges[0][0]
        self.goto(start)
        self.status.set(f"First change · 0x{start:08X}")

    def last_change(self):
        if not self.ranges:
            self.status.set("No changed bytes.")
            return
        start = self.ranges[-1][0]
        self.goto(start)
        self.status.set(f"Last change · 0x{start:08X}")

    def previous_change(self):
        self.next_change(-1)

    def next_change_forward(self):
        self.next_change(1)

    def next_change(self, direction):
        if not self.ranges:
            self.status.set("No changed bytes.")
            return
        offset = self.position
        if direction > 0:
            index = bisect.bisect_right(self.starts, offset)
            if index >= len(self.ranges):
                self.status.set("Last change reached.")
                return
        else:
            index = bisect.bisect_left(self.starts, offset) - 1
            if index < 0:
                self.status.set("First change reached.")
                return
        start, end = self.ranges[index]
        self.goto(start)
        self.status.set(f"Change {index + 1}/{len(self.ranges)} · 0x{start:08X}–0x{end - 1:08X} · {end - start:,} bytes")

    def refresh_changes(self):
        self.ranges = changed_ranges(self.original, self.data)
        self.starts = [start for start, _ in self.ranges]
        self.identifiers = flash_identity(self.data)
        self.identity_text.set(identity_text(self.identifiers))
        self.render()

    def edit_byte(self, offset, value):
        if self.busy:
            raise ValueError("wait for the stock search to finish")
        if not 0 <= offset < len(self.data) or not 0 <= value <= 255:
            raise ValueError("invalid byte or offset")
        self.data[offset] = value
        self.refresh_changes()
        self.status.set(f"{sum(end - start for start, end in self.ranges):,} changed bytes in {len(self.ranges):,} ranges")

    def click_cursor(self, event):
        self.text.focus_set()
        try:
            line, column = map(int, self.text.index(f"@{event.x},{event.y}").split("."))
        except (ValueError, tk.TclError):
            return "break"
        if column >= 59:
            byte = column - 59
        else:
            byte = (column - 10) // 3
        if 0 <= byte < 16:
            self.goto((self.top + line - 1) * 16 + byte)
        return "break"

    def ask_byte(self, offset):
        """Small hex byte dialog with Accept/Cancel, Enter and Escape."""
        dialog = tk.Toplevel(self.window)
        dialog.title("Edit byte")
        dialog.transient(self.window)
        dialog.grab_set()
        dialog.resizable(False, False)
        frame = ttk.Frame(dialog, padding=10)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text=f"0x{offset:08X} — new byte (hex):").pack(anchor="w")
        text = tk.StringVar(value=f"{self.data[offset]:02X}")
        entry = ttk.Entry(frame, textvariable=text, width=6, font=("Consolas", 10))
        entry.pack(anchor="w", pady=(4, 8))
        entry.selection_range(0, "end")
        result = {"value": None}

        def accept(_event=None):
            try:
                value = int(text.get(), 16)
            except ValueError:
                self.status.set("Enter a hexadecimal byte.")
                return "break"
            if not 0 <= value <= 255:
                self.status.set("Byte must be 00–FF.")
                return "break"
            result["value"] = value
            dialog.destroy()
            return "break"

        buttons = ttk.Frame(frame)
        buttons.pack(fill="x")
        ttk.Button(buttons, text="Accept", command=accept).pack(side="right")
        ttk.Button(buttons, text="Cancel", command=dialog.destroy).pack(
            side="right", padx=(0, 6))
        entry.bind("<Return>", accept)
        dialog.bind("<Return>", accept)
        dialog.bind("<Escape>", lambda _: dialog.destroy())
        entry.focus_set()
        self.window.wait_window(dialog)
        return result["value"]

    def edit_click(self, event):
        if self.busy:
            return "break"
        row, column = map(int, self.text.index(f"@{event.x},{event.y}").split("."))
        if not 10 <= column < 57 or (column - 10) % 3 == 2:
            return "break"
        offset = (self.top + row - 1) * 16 + (column - 10) // 3
        if offset >= len(self.data):
            return "break"
        value = self.ask_byte(offset)
        if value is not None:
            try:
                self.edit_byte(offset, value)
            except ValueError as exc:
                self.status.set(str(exc))
        return "break"

    def choose_library(self):
        path = filedialog.askdirectory(title="Folder containing stock files",
                                       initialdir=str(self.library), parent=self.window)
        if path:
            self.library = Path(path)
            self.status.set("Stock library: " + str(self.library))

    def search(self):
        if self.busy:
            return
        if self.is_eeprom:
            self.status.set(
                f"{len(self.data):,} bytes is an EEPROM/micro dump, not a flash read "
                f"(minimum {MIN_FLASH_BYTES:,} B / 256 KiB). Open the full flash "
                f"read to restore ORI.")
            return
        if not self.library.is_dir():
            self.choose_library()
            if not self.library.is_dir():
                return
        self.busy = True
        self.restore_button.configure(state="disabled")
        self.save_button.configure(state="disabled")
        # The donor search always runs against the file as it was opened, so a
        # previous restore or a manual edit cannot change which original is
        # chosen.
        snapshot = bytes(self.original)
        self.status.set("Searching for a matching original…")

        def progress(index, total, name=""):
            # Only the main thread accesses Tk widgets.
            if index % 8 == 0 or index == total:
                self.events.put(("progress", (index, total, name)))

        def worker():
            try:
                matches, scan = find_matches(snapshot, self.library, self.profile, self.table, progress,
                                             extra_files=self.extra_sgos, index_path=self.index_path,
                                             allow_build=True, limit=MAX_DONORS)
                self.events.put(("matches", (matches, scan)))
            except Exception as exc:
                self.events.put(("error", str(exc)))

        threading.Thread(target=worker, daemon=True).start()

    def poll(self):
        if not self.window.winfo_exists():
            return
        try:
            while True:
                kind, value = self.events.get_nowait()
                if kind == "progress":
                    index, total, name = value
                    if name:
                        # Report the step that is actually running (catalogue,
                        # CRC build, FRF compare, ...), never a generic SGO
                        # wording that hides which family is being searched.
                        self.status.set(f"{name}  ({index:,}/{total:,})")
                    else:
                        self.status.set(f"Searching for a matching original… {index:,}/{total:,}")
                else:
                    self.busy = False
                    self.restore_button.configure(state="normal")
                    self.save_button.configure(state="normal")
                    if kind == "error":
                        self.status.set(value)
                    else:
                        matches, self.last_scan = value
                        if matches:
                            self.choose_match(matches, self.last_scan)
                        else:
                            self.status.set("No matching original found for this flash read.")
        except queue.Empty:
            pass
        self.window.after(100, self.poll)

    def choose_match(self, matches, scan=None):
        # Only donors whose calibration actually lines up are worth offering: a
        # 4% CAL fit is a different calibration, and restoring from it would
        # overwrite working data with unrelated bytes.
        present = [match for match in matches if Path(match.path).exists()]
        ghosts = len(matches) - len(present)
        matches = present
        scored = [match for match in matches
                  if match.exact_dataset
                  or (match.fit_compared and match.fit_similarity >= MIN_CAL_FIT)]
        if not scored:
            best = max((match.fit_similarity for match in matches
                        if match.fit_compared), default=0.0)
            self.status.set(
                f"No donor with CAL fit >= {MIN_CAL_FIT:.0%} "
                f"({len(matches)} candidate(s) compared, best {best:.1%}).")
            return
        matches = scored
        window = tk.Toplevel(self.window)
        window.title("Select original donor")
        window.geometry("780x400")
        window.transient(self.window)
        window.grab_set()
        frame = ttk.Frame(window, padding=8)
        frame.pack(fill="both", expand=True)
        scan = scan or {}
        indexed = scan.get("indexed_source_count", scan.get("files_scanned", 0))
        compared = scan.get("byte_compared_candidates", len(matches))
        ttk.Label(frame,
                  text=f"{indexed:,} stock files indexed · {compared:,} byte-compared candidates · "
                       f"{len(matches):,} with CAL fit >= {MIN_CAL_FIT:.0%}. "
                       f"Match = bytes equal at the same offset; "
                       f"Cal fit = best score when calibration sections may move "
                       f"(both over the CAL window only). "
                       f"Index: {Path(self.index_path).name if self.index_path else 'auto'}.",
                  wraplength=670).pack(anchor="w")
        tree = ttk.Treeview(frame, columns=("name", "part", "version", "kind", "diff", "fit", "match"), show="headings", height=10)
        for key, label, width in [("name", "Stock file", 230), ("part", "SW part", 105),
                                  ("version", "Version", 55), ("kind", "Type", 55),
                                  ("diff", "Cal diff", 70),
                                  ("fit", "Cal fit (moved)", 95),
                                  ("match", "Match (in place)", 95)]:
            tree.heading(key, text=label)
            tree.column(key, width=width, stretch=key == "name")
        for index, match in enumerate(matches):
            markings = ", ".join(sorted(software_parts(match.part_markings)) or match.ecu_families[:2])
            fit = f"{match.fit_similarity:.1%}" if match.fit_compared else "-"
            tree.insert("", "end", iid=str(index), values=(match.path.name, markings, match.version,
                        "Exact" if match.exact_dataset else "Similar",
                        f"{match.differences:,}", fit, f"{match.similarity:.2%}"))
        tree.pack(fill="both", expand=True, pady=6)
        tree.selection_set("0")
        tree.bind("<Return>", lambda _: selected(True))
        tree.bind("<Double-Button-1>", lambda _: selected(True))
        window.bind("<Return>", lambda _: selected(True))
        window.bind("<Escape>", lambda _: window.destroy())
        window.protocol("WM_DELETE_WINDOW", window.destroy)
        top = matches[0]
        label = "Exact dataset" if top.exact_dataset else "Closest ori"
        self.status.set(
            f"{label}: SW {top.version} · Match {top.similarity:.1%} at same offset · "
            f"Cal fit {top.fit_similarity:.1%} moved · {top.differences:,} differing bytes "
            f"of {top.match_denominator:,} CAL bytes.")

        def selected(apply):
            chosen = tree.selection()
            if not chosen:
                return
            match = matches[int(chosen[0])]
            window.destroy()
            if apply:
                self.apply_match(match)
            else:
                self.status.set(f"{match.path.name}: {match.differences:,} differences / {match.compared_bytes:,} compared bytes. File unchanged.")

        buttons = ttk.Frame(frame)
        buttons.pack(fill="x")
        ttk.Button(buttons, text="Accept", command=lambda: selected(True)).pack(side="left")
        ttk.Button(buttons, text="Accept (report only)", command=lambda: selected(False)).pack(side="left", padx=6)
        ttk.Button(buttons, text="Cancel", command=window.destroy).pack(side="right")
        def browse_sgo():
            path = filedialog.askopenfilename(title="Choose ORI source", parent=window,
                        filetypes=[("Stock file / FRF / ODX / flash image", "*.sgo *.frf *.odx *.bin"),
                                   ("All files", "*.*")])
            if not path:
                return
            try:
                new_matches = []
                # Trust the bytes, not the name: a read renamed to .frf (or a
                # container renamed to .bin) must still be handled correctly.
                with open(path, "rb") as handle:
                    head = handle.read(64)
                is_zip = head[:2] == b"PK"
                is_xml = head.lstrip()[:1] == b"<"
                if path.lower().endswith((".frf", ".odx")) and (is_zip or is_xml):
                    import sgo_frf
                    if path.lower().endswith(".odx"):
                        members, image, _blocks, family = sgo_frf.load_odx(path)
                    else:
                        members, image, _blocks, family = sgo_frf.load(path)
                    # map the frf family to the restore profile so the
                    # calibration window matches the image layout
                    cand_profile = {"dq381": "dq381", "dq200mqb": "dq200mqb",
                                    "dq500temic": "dq500temic",
                                    "dl382": "dl382", "zf8hp": "zf8hp",
                                    "dl501": "dl501",
                                    }.get(family, "dq250")
                    base = Path(path).parent
                    stem = Path(path).stem
                    for member_name in sorted(members):
                        if not member_name.lower().endswith(".sgo"):
                            continue
                        extracted = base / f"{stem}.{Path(member_name).name}"
                        if not extracted.exists():
                            extracted.write_bytes(members[member_name])
                        new_matches.append(candidate_for(
                            bytes(self.original), extracted,
                            self.profile if self.profile != "auto" else cand_profile,
                            self.table))
                    if image is not None:
                        extracted = base / f"{stem}.image.bin"
                        if not extracted.exists():
                            extracted.write_bytes(image)
                        new_matches.append(raw_image_candidate(
                            bytes(self.original), extracted, cand_profile))
                elif path.lower().endswith(".sgo") and not (is_zip or is_xml):
                    new_matches.append(candidate_for(
                        bytes(self.original), path, self.profile, self.table))
                else:
                    # Plain flash image, whatever extension it carries.
                    new_matches.append(raw_image_candidate(
                        bytes(self.original), path, self.profile))
                if not new_matches:
                    messagebox.showinfo(
                        "No flash content",
                        "This FRF contains no SGO or DQ250 flash members.",
                        parent=window)
                    return
                window.destroy()
                self.choose_match(new_matches, {
                    "indexed_source_count": len(new_matches),
                    "byte_compared_candidates": len(new_matches)})
            except (OSError, ValueError) as exc:
                messagebox.showerror("Cannot compare stock file", str(exc), parent=window)
        ttk.Button(buttons, text="Choose ORI source…", command=browse_sgo).pack(side="left")

    def apply_match(self, match):
        # Refine and plan against the file as opened: the donor was chosen from
        # that snapshot, and hex edits must not shift the comparison.
        snapshot = bytes(self.original)
        if not Path(match.path).exists():
            messagebox.showinfo(
                "Donor file missing",
                f"{Path(match.path).name} is no longer in the library.\n"
                f"The donor list came from an older search; run Restore ORI "
                f"again to refresh it.",
                parent=self.window)
            return None
        if not match.fit_compared:
            # Search ranked candidates by whole-window comparison only; the
            # per-section placement fit runs now, for the match you picked.
            self.status.set("Placing calibration sections…")
            self.window.update_idletasks()
            match = refine_match(snapshot, match, self.table)
        stock, plan = restore_plan(snapshot, match)
        pieces = plan.get("pieces", [])
        ranges = plan.get("ranges", [])
        restorable = (sum(sum(e - s for s, e in piece["ranges"]) for piece in pieces)
                      if pieces else sum(e - s for s, e in ranges))
        compared = match.fit_compared or 0
        fit_text = f"{match.fit_similarity:.3%}" if compared else "n/a"
        self.status.set(
            f"Preview: {match.path.name} · fit {fit_text} ({compared:,} B) · "
            f"plan {plan.get('mode')} · {len(pieces):,} piece(s) · "
            f"{len(ranges):,} range(s) · {restorable:,} byte(s) restorable")
        protected = sw_marking_ranges(snapshot)
        skipped = outside_cal_ranges(snapshot, match)
        self._show_restore_preview(match, snapshot, stock, plan, skipped,
                                   protected)
        return plan

    def _show_restore_preview(self, match, snapshot, stock, plan, skipped,
                              protected):
        window = tk.Toplevel(self.window)
        window.title("Restore preview")
        window.geometry("780x560")
        window.transient(self.window)
        frame = ttk.Frame(window, padding=8)
        frame.pack(fill="both", expand=True)
        frame.columnconfigure(0, weight=1)
        fit = f"{match.fit_similarity:.1%}" if match.fit_compared else "-"
        skipped_note = ""
        if skipped:
            skipped_note = (f"  ·  {sum(e - s for s, e in skipped):,} differing "
                            "bytes outside the calibration area left untouched")
        ttk.Label(frame, wraplength=740, justify="left", text=(
            f"{match.path.name}  ·  SW {match.version}  ·  calibration fit {fit}"
            f"{skipped_note}\n"
            f"SW part numbers and checksum cells are protected and never written "
            f"({len(protected)} region(s)"
            + (f", CRC profile {plan['crc_profile']}" if plan.get("crc_profile") else "")
            + "). Only pieces passing the minimum match and block size are "
            "applied. Nothing is written until you press Apply.")).pack(anchor="w")

        ranges_mode = plan.get("mode") != "pieces"
        row = ttk.Frame(frame)
        row.pack(fill="x", pady=(6, 2))
        ttk.Label(row, text="Min match %:").pack(side="left")
        min_pct = tk.IntVar(value=50)
        slider = ttk.Scale(row, from_=50, to=100, variable=min_pct,
                           orient="horizontal", length=130)
        slider.pack(side="left", padx=(4, 2))
        pct_label = ttk.Label(row, text="50", width=3)
        pct_label.pack(side="left")
        ttk.Label(row, text="  Min run:").pack(side="left")
        min_run = tk.IntVar(value=4)
        run_slider = ttk.Scale(row, from_=1, to=16, variable=min_run,
                               orient="horizontal", length=90)
        run_slider.pack(side="left", padx=(4, 2))
        run_label = ttk.Label(row, text="4", width=2)
        run_label.pack(side="left")
        ttk.Label(row, text="  Min block:").pack(side="left")
        min_var = tk.StringVar(value="8")
        combo = ttk.Combobox(row, textvariable=min_var, state="readonly",
                             width=6, values=("8", "16", "32", "64", "128",
                                              "256", "512", "1024"))
        if ranges_mode:
            # Runs carry no block size: only Min run can filter them.
            combo.configure(state="disabled")
            ttk.Label(row, text="(placement blocks only)").pack(side="left")
        combo.pack(side="left", padx=(4, 12))
        totals = tk.StringVar()
        ttk.Label(row, textvariable=totals, font=("", 9, "bold")).pack(
            side="left", padx=(0, 12))

        columns = ("tick", "start", "diff", "offset", "pct")
        tree = ttk.Treeview(frame, columns=columns, show="headings", height=16)
        for key, label, width, anchor in (("tick", "restore", 60, "center"),
                                          ("start", "cal offset", 115, "w"),
                                          ("diff", "tbr / diff / total", 140, "e"),
                                          ("offset", "offset", 70, "e"),
                                          ("pct", "match", 65, "e")):
            tree.heading(key, text=label)
            tree.column(key, width=width, anchor=anchor)
        tree.pack(fill="both", expand=True)
        tree.tag_configure("dim", foreground="#808080")

        if ranges_mode:
            # Whole-region plans (no placement pieces) carry "ranges" instead;
            # ignoring them made a donor with real CAL differences look empty.
            pieces = [{"read_offset": start, "size": end - start,
                       "changed": end - start, "matched": end - start,
                       "fit_offset": None, "ranges": [(start, end)]}
                      for start, end in plan.get("ranges", [])]
        else:
            pieces = plan.get("pieces", [])
        state = {"ticked": [True] * len(pieces),
                 "manual": [False] * len(pieces)}

        def piece_pct(piece):
            if ranges_mode:
                return 100.0
            return piece["matched"] * 100.0 / piece["size"] if piece["size"] else 0

        def piece_tbr(piece, minimum_run):
            return sum(e - s for s, e in piece["ranges"]
                       if e - s >= minimum_run)

        def piece_keeps(piece, minimum, minimum_pct, minimum_run):
            # Ticked when the piece contains a run of at least min run bytes;
            # that run is what gets restored, shorter runs in the same piece
            # stay untouched (the row shows as half ticked).
            if ranges_mode:
                return piece_tbr(piece, minimum_run) > 0
            return (piece["size"] >= minimum
                    and piece_pct(piece) >= minimum_pct
                    and piece_tbr(piece, minimum_run) > 0)

        def refresh(_event=None):
            minimum = int(min_var.get())
            minimum_pct = int(min_pct.get())
            minimum_run = int(min_run.get())
            pct_label.config(text=str(minimum_pct))
            run_label.config(text=str(minimum_run))
            tree.delete(*tree.get_children())
            total = 0
            count = 0
            for index, piece in enumerate(pieces):
                # A piece with no differing byte can never be restored, so it
                # is not listed. Everything that does differ stays listed and
                # is ticked or unticked by the filters.
                if not piece["changed"]:
                    continue
                qualifies = piece_keeps(piece, minimum, minimum_pct, minimum_run)
                # Ticked rows restore the runs passing min run; a hand tick
                # means restore every differing byte of that piece.
                qualifying = piece_tbr(piece, minimum_run)
                manual = state["manual"][index]
                tbr = piece["changed"] if manual else (
                    qualifying if qualifying else piece["changed"])
                if state["ticked"][index]:
                    total += tbr
                    count += 1
                if not state["ticked"][index]:
                    mark = "☐"
                elif manual or qualifying >= piece["changed"]:
                    mark = "✓"
                else:
                    mark = "◩"
                if ranges_mode:
                    # Same-offset write: the donor offset equals the read offset.
                    delta_text = "0"
                elif piece["fit_offset"] is None:
                    delta_text = "no match"
                else:
                    delta_text = str(piece["fit_offset"] - piece["read_offset"])
                tree.insert("", "end", iid=str(index),
                            tags=() if state["ticked"][index] else ("dim",),
                            values=(
                                mark,
                                f"0x{piece['read_offset']:08X}",
                                f"{tbr:,} / {piece['changed']:,} / {piece['size']:,}",
                                delta_text,
                                f"{piece_pct(piece):.0f}%"))
            if count:
                totals.set(f"will restore: {total:,} bytes / {count:,} pieces")
            else:
                totals.set("will restore: nothing — no listed piece is ticked "
                           "at the current filters")

        def filters_changed(_event=None):
            # Moving any filter re-selects everything that qualifies.
            minimum = int(min_var.get())
            minimum_pct = int(min_pct.get())
            minimum_run = int(min_run.get())
            for index, piece in enumerate(pieces):
                state["ticked"][index] = piece_keeps(piece, minimum,
                                                     minimum_pct, minimum_run)
                state["manual"][index] = False
            refresh()

        def toggle(_event=None, row=None):
            selected = tree.selection() if row is None else [row]
            for iid in selected:
                index = int(iid)
                if not state["ticked"][index]:
                    # unticked -> ticked by hand
                    state["ticked"][index] = True
                    state["manual"][index] = True
                elif state["manual"][index]:
                    # a hand tick removes again
                    state["ticked"][index] = False
                    state["manual"][index] = False
                else:
                    # automatic/partial tick -> make it a full hand tick
                    state["manual"][index] = True
            refresh()

        def set_all(value):
            for index, piece in enumerate(pieces):
                if piece["changed"]:
                    state["ticked"][index] = value
                    state["manual"][index] = value
            refresh()

        def on_click(event):
            if tree.identify_column(event.x) == "#1":
                row = tree.identify_row(event.y)
                if row:
                    toggle(row=row)

        tree.bind("<Button-1>", on_click)
        combo.bind("<<ComboboxSelected>>", filters_changed)
        slider.configure(command=filters_changed)
        run_slider.configure(command=filters_changed)
        ttk.Button(row, text="Tick all", width=8,
                   command=lambda: set_all(True)).pack(side="left")
        ttk.Button(row, text="Tick none", width=9,
                   command=lambda: set_all(False)).pack(side="left", padx=(4, 0))

        def apply(_event=None):
            minimum = int(min_var.get())
            minimum_pct = int(min_pct.get())
            minimum_run = int(min_run.get())
            chosen = [piece for index, piece in enumerate(pieces)
                      if state["ticked"][index] and piece["changed"]]
            chosen_writes = []
            for index, piece in enumerate(pieces):
                if not (state["ticked"][index] and piece["changed"]):
                    continue
                # A hand tick restores the whole piece; automatic ticks keep the
                # min-run filter (they qualified because of a long run).
                per_piece = 1 if state["manual"][index] else minimum_run
                chosen_writes.extend(plan_writes(plan, [piece], per_piece))
            if not chosen_writes:
                messagebox.showinfo("Restore preview",
                                    "Nothing ticked to restore.", parent=window)
                return
            self.data = bytearray(apply_writes(snapshot, stock, chosen_writes))
            self.selected_match = match
            self.refresh_changes()
            if self.ranges:
                self.goto(self.ranges[0][0])
            changed = sum(n for _s, _src, n in chosen_writes)
            self.status.set(
                f"ORI (calibration area only): {match.path.name}\n"
                f"Applied {changed:,} bytes from {len(chosen):,} pieces "
                f"(min match {minimum_pct}%, min run {minimum_run} B, "
                f"min block {minimum} B) using the detected offsets. "
                "SW numbers untouched.\n"
                "Highlighted changes are unsaved; use Save as.")
            window.destroy()

        buttons = ttk.Frame(frame)
        buttons.pack(fill="x", pady=(6, 0))
        ttk.Button(buttons, text="Accept", command=apply).pack(side="right")
        ttk.Button(buttons, text="Cancel",
                   command=window.destroy).pack(side="right", padx=(0, 6))
        window.bind("<Return>", lambda _: apply())
        window.bind("<Escape>", lambda _: window.destroy())
        # Start with the filters' automatic choice, not everything ticked.
        filters_changed()

    def save(self):
        if self.busy:
            return
        path = filedialog.asksaveasfilename(title="Save restored flash as", parent=self.window,
                    initialdir=str(self.path.parent), initialfile=self.path.stem + ".ori.bin",
                    defaultextension=".bin", filetypes=[("Flash binary", "*.bin")])
        if not path:
            return
        try:
            report_path = Path(path).with_suffix(Path(path).suffix + ".changes.json")
            if report_path.exists() and not messagebox.askyesno("Replace report?", "Replace the existing change report?", parent=self.window):
                return
            report = save_flash(self.path, self.original, bytes(self.data), path,
                                self.selected_match, overwrite=True)
            self.status.set(f"Saved {Path(path).name} · {report['changed_bytes']:,} changed bytes / {report['changed_range_count']:,} ranges.\nAddress report: {report_path.name}")
        except (OSError, ValueError) as exc:
            messagebox.showerror("Cannot save", str(exc), parent=self.window)
