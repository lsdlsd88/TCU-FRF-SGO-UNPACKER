"""One vocabulary for FRF container families.

The catalogue pass (frf_catalogue.py), the restore lookup (sgo_restore.py) and
the content decoder (sgo_frf.load) all name families with these identifiers.
sgo_frf.load already returns the donor names; everything else is a label for
containers a restore can never use.
"""

# Families that carry a TCU image and can be shortlisted as donors.
DONOR_FAMILIES = frozenset({"dq250mqb", "dq381", "dq200mqb", "dq500temic",
                            "dl382", "dl501", "vl381", "zf8hp", "dq400e"})

# Non-donor labels.
SGO = "sgo"                # FRF wrapping plain .sgo members
ENGINE_ECU = "engine-ecu"  # ODX with ECU-MEM but not an EV_TCM (gearbox) image
OTHER = "other"            # no ODX, or ODX without ECU-MEM
UNREADABLE = "unreadable"  # not a ZIP, or a TCU container that will not decode

# The ODX ENCRYPT-COMPRESS-METHOD picks the cipher family (sgo_frf.extract_odx_auto).
BY_METHOD = {"22": "zf8hp", "AA": "dq381"}
PLAIN_METHODS = frozenset({"", "00"})
# 11/01 (table cipher) cannot be told apart from the ODX alone.
TABLE_METHODS = frozenset({"11", "01"})

# Labels written by catalogues built before the vocabulary was unified.
LEGACY = {"Bosch-DQ380/381": "dq381", "DQ500-Temic": "dq500temic",
          "DQ200-MQB": "dq200mqb", "DQ250-MQB": "dq250mqb",
          "DL382": "dl382", "DL501-0B5": "dl501", "ZF-8HP": "zf8hp",
          "frf(sgo)": SGO, "frf(other)": OTHER}


def canonical(label):
    """Map any label (current or legacy) onto the shared identifier set."""
    if label in DONOR_FAMILIES:
        return label
    if label in (SGO, ENGINE_ECU, OTHER, UNREADABLE):
        return label
    if label in LEGACY:
        return LEGACY[label]
    if not isinstance(label, str):
        return OTHER
    if label.startswith("ERROR("):
        return UNREADABLE
    if label.startswith("engine-ECU"):
        return ENGINE_ECU
    return OTHER
