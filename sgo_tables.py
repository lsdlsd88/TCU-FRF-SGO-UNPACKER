"""Embedded cipher tables.

These are 256-byte permutations recovered from TCU firmware; each one defines
one family's substitution cipher (the rolling-offset recurrence lives in
sgo_unpack/sgo_frf). They are embedded so a packaged build cannot lose them,
and a table file next to this module (or the executable) still overrides the
constant, which lets a new family be dropped in without a rebuild.
"""
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent

TABLES = {
    # Temic VL381/0CK (DL382, method 11) and 0B5/DL501 (method 01 and 11).
    "temic": bytes.fromhex(
        "d311f7943d7139e740be96440bf567b3587dc4f9a95ced6bd1abe801b7476c57"
        "cafe09ba5a060014289b7f4af195cee4cf3679769ee3eb6fbcc588bb9db4acbf"
        "849c13a2ddb87391599081f3fb3f0c4c03dc45626ecd1c20ea7e07e1b64db22f"
        "c072a621a14e4bfc0e2b12e6c256931e55506a300a0586ffcb1925c87befd851"
        "8963dee964e53ab1e034231da77443d738ee3754291bbd2731c670835d33ad65"
        "aada419a698af82ddfd95f48d05e167c61982cb51aa81f0d088f15c94292c180"
        "b93b8e993578b052534f68d65b87ec043e6da08c8da3f42a0f3cf2fa85d477c7"
        "7ad5a49ffd174966c360dbcc24f018d2aea526028b22e22e8297f6af10467532"),
    # DQ250-MQB (5/11 LZZ containers and MQB SGO blocks).
    "mqb_dsg": bytes.fromhex(
        "4593ca72845d11e978b99fa265e28be5c977cd59f78901bf02f368e0dc30c4d4"
        "f525cc8723c8ee3a12ab70610041d30dc0f422afd1cbb0b715278fd909ac5cf2"
        "f1c72a21568c063508e7c3734939cf40436bc66eea906d1bb453d25fb67416d7"
        "2b975a8a58c53375fcad3b60ce62912d0c3cda42269283fa182832074abb542c"
        "b89d4ce4a4715ea7ed2f377634d8c18e44636451f61ec2f8690adfe6f99e4ea8"
        "ff889a5b0f1f3f24e3fe9bb3a58086961d50de04a6553d059ceb8db5ef946c31"
        "a02014134f66f02946bdd64bdbbe360b85a1b2b11910fd1c81e10e7da9e847d5"
        "1a035738bcae98fbaa7e6a526f17a3677a7bddec2e3e7f7c48d099ba79954d82"),
    # DQ200-MQB 0CW, software 5xxx/6xxx.
    "dq200mqb": bytes.fromhex(
        "be0eb8584ce6ead4e9223e002801cad37c66dd041e9398492131ebb0380b82ba"
        "571516f330ac8f1467797513331a0581b3f0703c642f17f9d62cda6fc3bd6072"
        "40facc07363a4d4255a7c2eee5c05c41201d0a926e5e459761e3abbc9cd0068e"
        "ad9f8a73ed77445ab1194a630f2dff9a39f46c90592e53a8629b5ffe2bfd2978"
        "4e8d37e27f02b7d2decb7eae52e8fb802aef0d4fec5b468c7b832748517a096a"
        "23266da9c8b5108b0887aa1256c1346b183f886965afd885df9de01cb9d7a51f"
        "c5991143dba6f53591e11be7f25095bba371b2c6ce9e3d3b47dc84c47df7f15d"
        "68b40cc9d1f85489f6fc0374cdcfd9d586b6bf76a424a196a2e494c7a04b2532"),
    # DQ200-MQB 0CW, software 09xx-19xx (read at flash 0x169A0).
    "dq200mqb_gen2": bytes.fromhex(
        "b0fbc45de4cc4d121779b5c963820ea07c9fc1a74002c84590dc1ed75f227499"
        "089126cae5f06d0b1d95d609bd2af35bb150aec6a81f922459e8e36b163f7821"
        "7b5af627054c653e76abdd859b7530520c131cbf0fceb86c67e223a64a6f9eee"
        "9355b984dfdeecbed343d219acaaa31b3456f74f18b77adac0d8c55106f5fa4e"
        "9670680a2ea43cd042cffff2bc8628942b32eac20166f9ad36e060629d00a2cd"
        "bb115c8714afc7737f4647fcf1b477d9a18df4cb07353983eb800d44fe413a9c"
        "4964d5726aef58d18fc3312d20892ce988a58b7e25572f33f88e61d4154b10e7"
        "5e69b6dbe6ed4897b2378a5438988c299ae103048153fd6e71ba3d7d3ba9b31a"),
    # Legacy PQ SGO format-1 tables.
    "dq200_pq": bytes.fromhex(
        "657f83ad0040c49f4e30a910d6469cd5eb192c52314faf905d593c5e78dff774"
        "9e6b951684c1d3cc87ce43f9c8f83f0ded510c538c6a232aec8954a066038e39"
        "feae0aee37d18817a7bc969991bae7bdbff5e011b9a52b1ae96d28076fa65097"
        "24c6b55733c7e2d0a421e84df67e61155c793ab31c5582e1222fda703bead258"
        "933402d4ff0fb1c58f7bdc7cc2738bd90627a8a28056b7f2c3e32d6cde29f301"
        "44bbe58dcb4114c0becac9aa863d67491d7a205b9b9db2421277640b8a051b9a"
        "3ef0d8dbfd04f47d98cd60acb6b81ffa5acf3813724ae6a1b069fb7581a3f126"
        "efdd94451e32920e35b448fc4768082509632e6e5f364b18d785ab6276e44c71"),
    "dq250_pq": bytes.fromhex(
        "fab6c9aae801ea7f031c93dd22575e45d05fe6f05b70607636dc69b5ab2ab840"
        "1a1fc178614a9ae5d292914706242db75d0bcb37e056d52194a7bee988f7b48e"
        "3e34eb7e19a653d9684be386ca10a8466c67df30426b837426ec5cf2edfece7a"
        "9c7154f5aecf316a8f15d43577b3087cbd2e3f96114179fb8bc00aa309e26528"
        "14d152cc55395a27fdcdc70ef3899b8564828d9f59ac2f3af67db9af73480595"
        "2b1d4cdec432dbf9f43b1b026681ada4bf4f6313c6f100f80787973d12e1ee17"
        "a5b144dad8a98a72e46e84c3d66d51d775b24d58a19e25621820c81e980c80ba"
        "7b6f9d90b02950ef492c04c24ea2fca00fbcd3c53c16bb433833998cff0de723"),
    "dq250c_pq": bytes.fromhex(
        "10f8754fffa831fb9e2008f76cb58ed5bf32f2595c1cde453b8bf6d255345103"
        "3d4be0150d3953af3e2fa225f991faddcb6fa938c6fed657e86bef285e44637d"
        "3ae9d80ba1c25f9f50605bec9770624082bac8ebc5b7358d85a5a090476e1889"
        "9a8754cfea927e4156c15dc4ce0f991283849558cd1baa663364f1bd4dca0768"
        "f5b627b15ae52181c749b82bb3ee2dfce11e6d9cd74e22a60abee4c07411da93"
        "ab6a2cd07a16e700ed9d5261a30cf32a8c484c131772f4b2361ac3d97f049b8a"
        "7914057896427329d371b088373f65022ee306e630b9fdad98a41d8f24dbc943"
        "7c26dc1f947bb4f01980690109df86763caeacccbb0e23bcd4d14a7746e267a7"),
    # DQ400e (0DD): recovered from the firmware at 0x1698C, immediately after
    # the 'EV_TCM' descriptor - the same slot DQ250 keeps its table at 0x117B8.
    "dq400e": bytes.fromhex(
        "feaa038c1f0ebaff4661ae9d3a588df1adef36ec1eb9c0d774be12e1c1e618d3"
        "7685f3776e3065045edd2c89887851e527353d7fdad573224d849b7e94a6c45a"
        "f50fd8e01057f200a7eb6847137519f8ac8b39e2cd52d682874cb4c36b4ffb0d"
        "edc8016dcad4c7977a9e7256cc86fa96a391dc205bc6cb9af0a16390b308dff7"
        "92a23e625434ce05ee5c605009805317328a931b2a7c4544b66948b859286ac9"
        "b1d241641ce83bd9291d1ab25fe7407b23c5cf4a6c33e42fb00abd3cd04eab2b"
        "98a9211566d1a007f62e16e9af9f26de67e3db8e0295fc8155f4ea0b3fb7fda5"
        "49bb38c2a87031bc8ff943839c0c2d112414a47942375dbf7d25b50699714b6f"),
    # VL381/0CK method-01 containers (8K0927155...): table found in the VL381
    # image boot area at flash 0xA001017C; same rolling recurrence as Temic.
    "vl381_01": bytes.fromhex(
        "6affc747f065ea1cf510fceda7c33c199bf7aaf2015f848d7855d05b33f4c258"
        "0a468eef8b2bdf38429631c9f97bcfb9fe125d5aca033b995ea38a8048669850a"
        "22e3495bdabb40dd1890b744ec0d6402c5ca4ba458c72186e289d26a1e1a0af0"
        "98f753f9fb17ca9636b1767210f9302dc2391253eb7eee9d314222011bfbb2de20"
        "57dbef81d076f6c94f3c144e8eb3a73a5cc9262292470b2d9ae3654cdb6434bb0"
        "b8089c4186c43037f14ae31f837ea852bc57ace7d2154c8800713927fd61db59da"
        "903d069a4fadd787e4492a51fae01b697735e6327f7a7985d8c50cc60e1eec68de"
        "1613f6e51ab5d46d82cb5697b353d5fbce2f9edd64a676604dc80481"),
}

# File names that may override an embedded table, in priority order.
OVERRIDES = {
    "temic": ("temic_frf_key.bin", "dl382_frf_key.bin"),
    "mqb_dsg": ("mqb_dsg_key.bin",),
    "dq200mqb": ("dq200mqb_frf_key.bin",),
    "dq200mqb_gen2": ("dq200mqb_frf_key_gen2.bin",),
    "dq200_pq": ("dq200_pq_table.bin",),
    "dq250_pq": ("dq250_pq_table.bin",),
    "dq250c_pq": ("dq250c_pq_table.bin",),
    "dq400e": ("dq400e_frf_key.bin",),
    "vl381_01": ("vl381_01_table.bin",),
}


def _roots():
    yield HERE
    if getattr(sys, "frozen", False):
        yield Path(sys.executable).resolve().parent


def table(name):
    """Table bytes for a family, preferring an on-disk override."""
    for root in _roots():
        for filename in OVERRIDES.get(name, ()):
            path = root / filename
            if path.is_file():
                return path.read_bytes()
    try:
        return TABLES[name]
    except KeyError:
        raise ValueError(f"unknown cipher table {name!r}") from None
