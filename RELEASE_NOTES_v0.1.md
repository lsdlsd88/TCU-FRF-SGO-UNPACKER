First public release.

Windows GUI to unpack VAG transmission update containers and restore factory
calibration into a tuned TCU dump.

- Unpack FRF / ODX / SGO to a complete stock flash image.
- Restore ORI: compare a tuned read against a stock library, tick the
  calibration bytes to restore, keep application/boot areas, SW markings and
  per-TCU checksum cells untouched.
- Hex editor with change highlighting, ORI/MOD toggle, 2D value plot with
  change navigation (E/V/N/L on the plot, mouse wheel zoom, drag to scroll).
- Stock library index with CAL CRCs for both FRF and SGO donors; rescan retries
  truncated containers once per pass.

Supported: DQ200, DQ250, DQ381, DQ400e, DQ500 (0BH/0DL), DL382, DL501, VL381,
ZF 8HP (AL551/AL951), Aisin AL1000.

Known limitations: a handful of containers still need keys/tables that are not
recovered (0DL method-11 Temic layout, some AES generations), and engine ECUs
are intentionally not decoded.

Requires Windows 10/11 x64; no installation, no network access.

SHA-256 of the attached exe:
BDDF495D3371E7BA913C2F8D0301E546D86821EB65AC39CB9FFCE34D3AD09D96
