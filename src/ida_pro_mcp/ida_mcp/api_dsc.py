"""DYLD Shared Cache Utilities.

This module exposes IDA's dscu (dyld shared cache utils) plugin functionality,
allowing callers to load modules and sections from a dyld shared cache that
was opened with the "single module" option.

Plugin run modes (from reverse engineering dscu.dylib):
  0 - dump all regions to file (internal diagnostic)
  1 - load module by path          (supset key 2)
  2 - load section/region by addr  (altset key 3) — auto-detects type
  3 - print region info by addr    (altset key 3, informational)
  4 - load branch island(s)        (chooser / tag 'g'=103)
  5 - load dependency(ies)         (chooser / altset key 4)
  6 - load dyld header             (no input)
  7 - load branch mapping(s)       (chooser / tag 'h'=104)
  8 - load gap(s)                  (chooser / tag 'p'=112)
  9 - load GOT(s)                  (chooser / tag 'f'=102)

Chooser bypass (headless support):
  Modes 4/7/8/9 check (via netnode_supfirst) if their netnode tag already
  has entries.  If so, the chooser is skipped and the pre-populated items
  are loaded directly.  The dsc_load_all tool exploits this by reading the
  region table (tag 'r'=114) from the '$ dscu' netnode to enumerate all
  items of a given type, pre-populating the mode-specific tag, then
  triggering the mode.

Region info format in tag 'r' (IDA packed integers, all big-endian):
  pack_dd(1)    — format version
  pack_dq(addr) — region start address  (pack_dq = pack_dd(lo32) + pack_dd(hi32))
  pack_dq(size) — region size
  pack_dd(type) — region type (0=MODULE,1=ISLAND,2=HEADER,3=MAPPING,4=GAP,5=GOT)
  pack_dd(...)  — additional fields (ignored by this module)
"""

from __future__ import annotations

import struct
from typing import Annotated

import idaapi
import ida_nalt
import ida_segment
import idautils

from .rpc import tool
from .sync import idasync, IDAError, tool_timeout
from .utils import parse_address, normalize_list_input


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DSCU_NETNODE = "$ dscu"
_DSCU_PLUGIN = "dscu"

# dscu plugin run modes
_MODE_LOAD_MODULE = 1
_MODE_LOAD_SECTION = 2
_MODE_LOAD_ISLAND = 4
_MODE_LOAD_DEPENDENCY = 5
_MODE_LOAD_HEADER = 6
_MODE_LOAD_MAPPING = 7
_MODE_LOAD_GAP = 8
_MODE_LOAD_GOT = 9

# Netnode tag chars used by the Mach-O DSC loader during reload_file_ex.
# Pre-populating these tags before calling the corresponding mode makes the
# dscu handler skip the GUI chooser and load the items directly.
_TAG_MODULE = ord("t")  # 116 — module indices
_TAG_ISLAND = ord("g")  # 103 — branch island indices
_TAG_MAPPING = ord("h")  # 104 — branch mapping addresses
_TAG_GOT = ord("f")  # 102 — GOT (start_addr → end_addr)
_TAG_GAP = ord("p")  # 112 — gap (start_addr → end_addr)
_TAG_REGION = ord("r")  # 114 — region info (packed: ver, addr, size, type, ...)

# Region types stored in tag 'r' entries (from dscu.dylib string table).
_RT_MODULE = 0
_RT_ISLAND = 1
_RT_HEADER = 2
_RT_MAPPING = 3
_RT_GAP = 4
_RT_GOT = 5


# ---------------------------------------------------------------------------
# Helpers — plugin interaction
# ---------------------------------------------------------------------------


def _ensure_dscu() -> None:
    """Raise if the dscu plugin is not available."""
    plg = idaapi.find_plugin(_DSCU_PLUGIN, True)
    if plg is None:
        raise IDAError(
            "dscu plugin not available. "
            "Ensure the database was opened from a dyld shared cache "
            "with the 'single module' option."
        )


def _run_dscu(mode: int) -> None:
    """Run the dscu plugin with the given mode.

    Raises IDAError if the plugin could not be loaded.
    """
    if not idaapi.load_and_run_plugin(_DSCU_PLUGIN, mode):
        raise IDAError(f"dscu plugin failed to execute (mode {mode})")


def _dscu_node() -> "idaapi.netnode":
    """Get or create the dscu communication netnode (open-or-create semantics)."""
    node = idaapi.netnode()
    node.create(_DSCU_NETNODE)
    return node


# ---------------------------------------------------------------------------
# Helpers — IDA packed integer decoding (matches ida_netnode pack_dd/pack_dq)
# ---------------------------------------------------------------------------


def _unpack_dd(data: bytes, offset: int) -> tuple[int, int]:
    """Decode a packed uint32 (IDA varint) and return (value, new_offset).

    IDA stores all multi-byte cases in big-endian (network) byte order
    via mfhtonl / mfhtons in the SDK.
    """
    first_byte = data[offset]
    if first_byte < 0x80:
        return first_byte, offset + 1
    if first_byte < 0xC0:
        # 2 bytes BE, mask off tag bits
        return ((data[offset] << 8) | data[offset + 1]) & 0x3FFF, offset + 2
    if first_byte < 0xE0:
        # 3 bytes BE, mask off tag bits
        return (
            ((data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2])
            & 0x1FFFFF
        ), offset + 3
    if first_byte < 0xFF:
        # 4 bytes BE, mask off tag bits
        return (
            (
                (data[offset] << 24)
                | (data[offset + 1] << 16)
                | (data[offset + 2] << 8)
                | data[offset + 3]
            )
            & 0x0FFFFFFF
        ), offset + 4
    # 0xFF prefix → next 4 bytes big-endian
    return (
        (data[offset + 1] << 24)
        | (data[offset + 2] << 16)
        | (data[offset + 3] << 8)
        | data[offset + 4]
    ), offset + 5


def _unpack_dq(data: bytes, offset: int) -> tuple[int, int]:
    """Decode a packed uint64 and return (value, new_offset).

    IDA encodes uint64 as two consecutive pack_dd values (lo32 then hi32).
    """
    low32, offset = _unpack_dd(data, offset)
    high32, offset = _unpack_dd(data, offset)
    return low32 | (high32 << 32), offset


# ---------------------------------------------------------------------------
# Helpers — dscu region enumeration from netnode tag 'r'
# ---------------------------------------------------------------------------
#
# The Mach-O DSC loader stores per-region metadata in the '$ dscu' netnode
# under tag 'r' (114).  Each entry is packed:
#   pack_dd(1)           — format version (always 1)
#   pack_dq(start_addr)  — region start address
#   pack_dq(size)         — region size in bytes
#   pack_dd(type)         — region type (_RT_* constant)
#   ...                   — additional fields (ignored here)
#
# The dscu choosers enumerate these entries and filter by type.  We replicate
# this to correctly identify GOT / gap / mapping / island regions without
# relying on heuristics from the DSC file header.


def _parse_region_entry(data: bytes, netnode_index: int) -> dict | None:
    """Parse a single region info blob from tag 'r'.

    The *netnode_index* is the key under which the entry is stored; it
    equals (end_address - 1) for the region, so the true end address is
    ``netnode_index + 1``.

    Returns {"start": int, "end": int, "type": int} or None if the entry
    cannot be parsed.
    """
    # Region entry tail format (confirmed from dscu.dylib reverse engineering):
    #   pack_dd(type) pack_dd(f2) pack_dd(f3) pack_ds(name)
    #
    # For entries without a name (common for GOT/GAP/MAPPING/ISLAND),
    # the tail is: [type] 00 [f3_bytes] 00
    # where f3 is typically 0 (1 byte) or 0xFFFFFFFF (5 bytes: FF+4 BE).
    #
    # We extract the type from the tail rather than trying to skip the
    # variable-length pack_dq size field whose encoding differs between
    # IDA versions.
    try:
        if len(data) < 5:
            return None
        # Verify version = 1.
        if data[0] >= 0x80 or data[0] != 1:
            return None
        # Parse start address: pack_dd(lo32) + pack_dd(hi32).
        offset = 1
        start_lo, offset = _unpack_dd(data, offset)
        start_hi, offset = _unpack_dd(data, offset)
        start_addr = start_lo | (start_hi << 32)
        end_addr = netnode_index + 1
        # Extract region type from the tail.
        region_type = _extract_type_from_tail(data)
        if region_type is None:
            return None
        return {
            "start": start_addr,
            "end": end_addr,
            "type": region_type,
        }
    except (IndexError, struct.error):
        return None


def _extract_type_from_tail(data: bytes) -> int | None:
    """Extract the region type by parsing the entry tail backwards.

    Tail layout: pack_dd(type) pack_dd(f2) pack_dd(f3) pack_ds(name)

    Common tail patterns (from the end of the blob):
      - No name, f3=0xFFFFFFFF:  [type] 00 FF FF FF FF FF 00  (8 bytes)
      - No name, f3=0:           [type] 00 00 00              (4 bytes)
      - With name of length N:   [type] ... pack_dd(N) <N bytes>
    """
    length = len(data)
    # Pattern 1: tail = [type] 00 FF FF FF FF FF 00 (8 bytes, no name, f3=max)
    if length >= 8 and data[-7:] == b"\x00\xff\xff\xff\xff\xff\x00":
        candidate = data[-8]
        if candidate <= _RT_GOT:
            return candidate
    # Pattern 2: tail = [type] 00 00 00 (4 bytes, no name, f2=0, f3=0)
    if length >= 4 and data[-3:] == b"\x00\x00\x00":
        candidate = data[-4]
        if candidate <= _RT_GOT:
            return candidate
    # Pattern 3: named entry — parse pack_ds(name) from the end, then
    # work backwards through f3, f2, to reach type.
    # Find name: the last field is pack_ds = pack_dd(len) + len bytes.
    # We try small name lengths (most section names are < 40 bytes).
    for name_len in range(0, 60):
        # pack_dd(name_len) has known encoding size:
        if name_len < 0x80:
            dd_size = 1
        elif name_len < 0x4000:
            dd_size = 2
        else:
            dd_size = 3
        name_field_size = dd_size + name_len
        tail_start = length - name_field_size
        if tail_start < 4:
            break
        # Verify: decode pack_dd at tail_start should give name_len.
        try:
            decoded_len, _ = _unpack_dd(data, tail_start)
        except (IndexError, struct.error):
            continue
        if decoded_len != name_len:
            continue
        # Found valid name field. Now parse f3, f2, type backwards.
        # f3 is right before name. Try common f3 encodings.
        pos = tail_start
        # Try f3 = 0xFFFFFFFF (5 bytes: FF + 4 BE bytes all FF)
        if pos >= 5 and data[pos - 5 : pos] == b"\xff\xff\xff\xff\xff":
            pos -= 5
        # Try f3 as small value (1 byte, < 0x80)
        elif pos >= 1 and data[pos - 1] < 0x80:
            pos -= 1
        else:
            continue
        # f2: expect small value (1 byte)
        if pos >= 1 and data[pos - 1] < 0x80:
            pos -= 1
        else:
            continue
        # type: should be 0..5
        if pos >= 1 and data[pos - 1] <= _RT_GOT:
            return data[pos - 1]
    return None


def _enumerate_dscu_regions(type_filter: int) -> list[dict]:
    """Return all dscu region entries matching *type_filter*.

    Reads tag 'r' from the '$ dscu' netnode and returns regions whose
    type field equals *type_filter* (one of the _RT_* constants).
    """
    node = _dscu_node()
    regions: list[dict] = []
    index = node.supfirst(_TAG_REGION)
    while index != idaapi.BADNODE:
        data = node.supval(index, _TAG_REGION)
        if data:
            info = _parse_region_entry(data, index)
            if info is not None and info["type"] == type_filter:
                regions.append(info)
        index = node.supnext(index, _TAG_REGION)
    return regions


# ---------------------------------------------------------------------------
# Helpers — DSC file header parsing
# ---------------------------------------------------------------------------

# dyld_cache_header layout (stable across versions):
#   0x00  char     magic[16]
#   0x10  uint32   mappingOffset
#   0x14  uint32   mappingCount
#   0x18  uint32   imagesOffsetOld
#   0x1C  uint32   imagesCountOld
#   ...
#   0x70  uint32   branchPoolsOffset   (0 if absent)
#   0x74  uint32   branchPoolsCount
#
# dyld_cache_image_info (32 bytes each):
#   0x00  uint64   address
#   0x08  uint64   modTime
#   0x10  uint64   inode
#   0x18  uint32   pathFileOffset
#   0x1C  uint32   pad


def _dsc_path() -> str:
    """Return the filesystem path of the input dyld shared cache."""
    path = ida_nalt.get_input_file_path()
    if not path:
        raise IDAError("Cannot determine input file path")
    return path


def _parse_dsc_modules() -> list[dict]:
    """Parse the DSC header and return all cached images (modules)."""
    from ida_pro_mcp.dsc_parser import list_dsc_images

    try:
        return list_dsc_images(_dsc_path())
    except ValueError as exc:
        raise IDAError(str(exc)) from exc


def _parse_dsc_branch_pool_count() -> int:
    """Return the number of branch pools (islands) from the DSC header."""
    path = _dsc_path()
    with open(path, "rb") as f:
        header = f.read(0x78)
    if len(header) < 0x78 or not header[:4].startswith(b"dyld"):
        return 0
    return struct.unpack_from("<I", header, 0x74)[0]


def _parse_dsc_mappings() -> list[dict]:
    """Parse cache mapping entries from the DSC header.

    Returns basic mapping info (address, size, fileOffset, maxProt, initProt).
    """
    path = _dsc_path()
    with open(path, "rb") as f:
        f.seek(0x10)
        mapping_offset, mapping_count = struct.unpack("<II", f.read(8))
        if mapping_count == 0 or mapping_offset == 0:
            return []

        # dyld_cache_mapping_info: 32 bytes
        # address(8) + size(8) + fileOffset(8) + maxProt(4) + initProt(4)
        f.seek(mapping_offset)
        mappings: list[dict] = []
        for _ in range(mapping_count):
            data = f.read(32)
            if len(data) < 32:
                break
            addr, size, file_off, max_prot, init_prot = struct.unpack_from(
                "<QQQII", data
            )
            mappings.append(
                {
                    "address": hex(addr),
                    "size": hex(size),
                    "end": hex(addr + size),
                    "fileOffset": hex(file_off),
                    "maxProt": max_prot,
                    "initProt": init_prot,
                }
            )
        return mappings


# ---------------------------------------------------------------------------
# Tools — programmatic (no GUI chooser required)
# ---------------------------------------------------------------------------


@tool
@idasync
@tool_timeout(600.0)
def dsc_load_module(
    modules: Annotated[
        list[str] | str,
        "Module path(s) inside the shared cache, e.g. "
        '"/usr/lib/libobjc.A.dylib". '
        "Accepts a single path, a comma-separated string, or a list.",
    ],
) -> list[dict]:
    """Load one or more modules from the dyld shared cache into the database.

    The current database must have been opened from a dyld shared cache using
    the "single module" option.  Each module is identified by its full path
    inside the cache (e.g. "/usr/lib/libobjc.A.dylib").
    """
    _ensure_dscu()
    modules = normalize_list_input(modules)

    results = []
    for path in modules:
        path = path.strip()
        if not path:
            continue
        try:
            node = _dscu_node()
            node.supset(2, path)
            _run_dscu(_MODE_LOAD_MODULE)
            results.append({"module": path, "ok": True})
        except Exception as exc:
            results.append({"module": path, "error": str(exc)})
    return results


@tool
@idasync
@tool_timeout(600.0)
def dsc_load_section(
    addresses: Annotated[
        list[str] | str,
        "Address(es) that fall within the target region(s). "
        "Accepts a hex string, a comma-separated string, or a list.",
    ],
) -> list[dict]:
    """Load individual region(s) from a dyld shared cache by address.

    This is the most versatile dscu operation: it auto-detects the region type
    (module section, branch island, branch mapping, GOT, or gap) based on the
    given address and loads only that region.  This is much faster than loading
    an entire module and is especially useful for loading ObjC metadata sections
    (e.g. __objc_methname) without pulling in the full module code.

    The current database must have been opened from a dyld shared cache using
    the "single module" option.
    """
    _ensure_dscu()
    addresses = normalize_list_input(addresses)

    results = []
    for addr_str in addresses:
        addr_str = addr_str.strip()
        if not addr_str:
            continue
        try:
            ea = parse_address(addr_str)
            node = _dscu_node()
            node.altset(3, ea)
            _run_dscu(_MODE_LOAD_SECTION)
            results.append({"addr": hex(ea), "ok": True})
        except Exception as exc:
            results.append({"addr": addr_str, "error": str(exc)})
    return results


@tool
@idasync
def dsc_load_dyld_header() -> dict:
    """Load the formatted dyld shared cache header into the database.

    This loads the dyld_cache_header structure, making its fields visible
    and annotated in the disassembly.  No input is required.

    The current database must have been opened from a dyld shared cache using
    the "single module" option.
    """
    _ensure_dscu()
    try:
        _run_dscu(_MODE_LOAD_HEADER)
        return {"ok": True}
    except Exception as exc:
        return {"error": str(exc)}


# ---------------------------------------------------------------------------
# Tools — resolve unmapped references (MEMORY[0x...])
# ---------------------------------------------------------------------------


@tool
@idasync
@tool_timeout(600.0)
def dsc_resolve_unmapped(
    limit: Annotated[
        int,
        "Maximum number of regions to load (default 100, 0 for unlimited).",
    ] = 100,
) -> dict:
    """Scan the database for references to unmapped addresses and load them.

    Iterates all cross-references in the current database, collects target
    addresses that do not belong to any known segment (these appear as
    MEMORY[0x...] in the disassembly/decompiler), and loads the
    corresponding shared cache sections via dscu mode 2.

    Each unique unmapped address is loaded only once (de-duplicated by
    page alignment to avoid redundant loads for nearby references).

    The current database must have been opened from a dyld shared cache using
    the "single module" option.
    """
    _ensure_dscu()

    # Collect unmapped xref targets, de-duplicate by 16 KB page.
    page_mask = ~0x3FFF  # 16 KB page alignment (arm64)
    seen_pages: set[int] = set()
    unmapped_addrs: list[int] = []

    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if seg is None:
            continue
        for head in idautils.Heads(seg.start_ea, seg.end_ea):
            for xref in idautils.XrefsFrom(head, 0):
                target = xref.to
                if target == idaapi.BADADDR:
                    continue
                if ida_segment.getseg(target) is not None:
                    continue  # already mapped
                page = target & page_mask
                if page in seen_pages:
                    continue
                seen_pages.add(page)
                unmapped_addrs.append(target)
                if limit and len(unmapped_addrs) >= limit:
                    break
            if limit and len(unmapped_addrs) >= limit:
                break
        if limit and len(unmapped_addrs) >= limit:
            break

    if not unmapped_addrs:
        return {"ok": True, "loaded": 0, "message": "No unmapped references found"}

    # Load each unmapped region via mode 2 (auto-detect type).
    results: list[dict] = []
    for ea in unmapped_addrs:
        try:
            node = _dscu_node()
            node.altset(3, ea)
            _run_dscu(_MODE_LOAD_SECTION)
            results.append({"addr": hex(ea), "ok": True})
        except Exception as exc:
            results.append({"addr": hex(ea), "error": str(exc)})

    ok_count = sum(1 for r in results if r.get("ok"))
    return {
        "ok": True,
        "loaded": ok_count,
        "total_unmapped": len(unmapped_addrs),
        "details": results,
    }


# ---------------------------------------------------------------------------
# Tools — headless "load all" (bypass chooser via netnode pre-population)
# ---------------------------------------------------------------------------


@tool
@idasync
def dsc_list_modules() -> dict:
    """List all modules (images) available in the dyld shared cache.

    Parses the dyld_cache_header from the input file and returns every
    cached image with its path and load address.  Use the paths with
    dsc_load_module to load specific modules.
    """
    try:
        modules = _parse_dsc_modules()
        return {"count": len(modules), "modules": modules}
    except Exception as exc:
        return {"error": str(exc)}


@tool
@idasync
@tool_timeout(600.0)
def dsc_load_all(
    region_type: Annotated[
        str,
        'Region type to load: "module", "island", "mapping", "got", or "gap". '
        "All items of the specified type will be loaded without a GUI chooser.",
    ],
) -> dict:
    """Load ALL regions of a given type from the dyld shared cache (headless).

    This bypasses the GUI chooser by pre-populating the dscu netnode with all
    items of the requested type, then triggering the corresponding plugin mode.
    The Mach-O loader reads the pre-populated tags during reload and loads
    every marked item.

    Supported types:
    - "module"  — load every module in the cache (can be very large!)
    - "island"  — load all branch islands (stub trampolines)
    - "mapping" — load all branch mappings (iOS 16+ stubs regions)
    - "got"     — load all global offset tables (iOS 16+)
    - "gap"     — load all gap regions

    The current database must have been opened from a dyld shared cache using
    the "single module" option.
    """
    _ensure_dscu()
    region_type = region_type.strip().lower()

    try:
        if region_type == "module":
            return _load_all_modules()
        elif region_type == "island":
            return _load_all_islands()
        elif region_type == "mapping":
            return _load_all_mappings()
        elif region_type == "got":
            return _load_all_gots()
        elif region_type == "gap":
            return _load_all_gaps()
        else:
            return {
                "error": f"Unknown region type: {region_type!r}. "
                "Use: module, island, mapping, got, gap"
            }
    except Exception as exc:
        return {"error": str(exc)}


def _load_all_modules() -> dict:
    """Load every module in the cache via tag 't' pre-population."""
    modules = _parse_dsc_modules()
    if not modules:
        return {"error": "No modules found in DSC header"}

    node = _dscu_node()
    val = struct.pack("<Q", 1)
    for mod in modules:
        node.supset(mod["index"], val, _TAG_MODULE)
    _run_dscu(_MODE_LOAD_MODULE)
    return {"ok": True, "loaded": len(modules)}


def _load_all_islands() -> dict:
    """Load every branch island via tag 'g' pre-population."""
    count = _parse_dsc_branch_pool_count()
    if count == 0:
        return {"error": "No branch pools found in DSC header"}

    node = _dscu_node()
    val = struct.pack("<Q", 1)
    for i in range(count):
        node.supset(i, val, _TAG_ISLAND)
    _run_dscu(_MODE_LOAD_ISLAND)
    return {"ok": True, "loaded": count}


def _load_all_mappings() -> dict:
    """Load all branch mappings via tag 'h' pre-population.

    Reads the '$ dscu' netnode tag 'r' to find regions with type RT_MAPPING,
    then pre-populates tag 'h' (start_addr → flag=1) and triggers mode 7.
    """
    regions = _enumerate_dscu_regions(_RT_MAPPING)
    if not regions:
        return {"error": "No branch mapping regions found in dscu region table"}

    node = _dscu_node()
    flag_value = struct.pack("<Q", 1)
    for region in regions:
        node.supset(region["start"], flag_value, _TAG_MAPPING)
    _run_dscu(_MODE_LOAD_MAPPING)
    return {"ok": True, "loaded": len(regions)}


def _load_all_gots() -> dict:
    """Load all GOTs via tag 'f' pre-population.

    Reads the '$ dscu' netnode tag 'r' to find regions with type RT_GOT,
    then pre-populates tag 'f' (start_addr → end_addr) and triggers mode 9.
    """
    regions = _enumerate_dscu_regions(_RT_GOT)
    if not regions:
        return {"error": "No GOT regions found in dscu region table"}

    region_details = [
        {"start": hex(r["start"]), "end": hex(r["end"]), "size": hex(r["size"])}
        for r in regions
    ]
    node = _dscu_node()
    for region in regions:
        node.supset(
            region["start"], struct.pack("<Q", region["end"]), _TAG_GOT
        )
    try:
        _run_dscu(_MODE_LOAD_GOT)
    except Exception as exc:
        return {
            "error": f"reload_file_ex failed after pre-populating "
            f"{len(regions)} GOT region(s): {exc}",
            "regions": region_details,
        }
    return {"ok": True, "loaded": len(regions)}


def _load_all_gaps() -> dict:
    """Load all gaps via tag 'p' pre-population.

    Reads the '$ dscu' netnode tag 'r' to find regions with type RT_GAP,
    then pre-populates tag 'p' (start_addr → end_addr) and triggers mode 8.
    """
    regions = _enumerate_dscu_regions(_RT_GAP)
    if not regions:
        return {"error": "No gap regions found in dscu region table"}

    node = _dscu_node()
    for region in regions:
        node.supset(
            region["start"], struct.pack("<Q", region["end"]), _TAG_GAP
        )
    try:
        _run_dscu(_MODE_LOAD_GAP)
    except Exception as exc:
        return {
            "error": f"reload_file_ex failed after pre-populating "
            f"{len(regions)} gap region(s): {exc}",
        }
    return {"ok": True, "loaded": len(regions)}


# ---------------------------------------------------------------------------
# Tools — GUI chooser based (require IDA GUI interaction)
#
# These tools trigger IDA's built-in chooser dialogs so the user can
# interactively select which items to load.  They are designed for use
# inside IDA's GUI — in headless mode the chooser will not appear and
# the call will return without loading anything.
#
# For headless/automated workflows, use dsc_load_all(type) instead.
# ---------------------------------------------------------------------------


@tool
@idasync
def dsc_load_dependency() -> dict:
    """Open the dependency chooser to load modules that the current module depends on.

    Shows a two-step chooser dialog in IDA: first select a base module,
    then select which of its dependencies to load.  Requires IDA GUI.
    For headless use, find dependency paths and use dsc_load_module instead.

    The current database must have been opened from a dyld shared cache using
    the "single module" option.
    """
    _ensure_dscu()
    try:
        _run_dscu(_MODE_LOAD_DEPENDENCY)
        return {"ok": True}
    except Exception as exc:
        return {"error": str(exc)}


@tool
@idasync
@tool_timeout(600.0)
def dsc_load_branch_island() -> dict:
    """Load all branch island regions from the shared cache.

    Branch islands are intermediate stub sequences used by the dyld shared
    cache to bridge calls between distant modules.  Loading them resolves
    indirect branches (e.g. turns 'BL loc_...' into 'BL _objc_msgSend').

    In GUI mode this shows a multi-select chooser; in headless mode it
    automatically loads all available branch islands.

    The current database must have been opened from a dyld shared cache using
    the "single module" option.
    """
    _ensure_dscu()
    try:
        _run_dscu(_MODE_LOAD_ISLAND)
        return {"ok": True}
    except Exception:
        pass
    # Chooser failed (headless mode) — load all islands instead.
    return _load_all_islands()


@tool
@idasync
@tool_timeout(600.0)
def dsc_load_branch_mapping() -> dict:
    """Load all branch stub mapping regions from the shared cache.

    Branch mappings (iOS 16+) contain stub code that routes calls between
    modules in the shared cache.  Loading them is essential for resolving
    cross-module function calls.

    In GUI mode this shows a multi-select chooser; in headless mode it
    automatically loads all available branch mappings.

    The current database must have been opened from a dyld shared cache using
    the "single module" option.
    """
    _ensure_dscu()
    try:
        _run_dscu(_MODE_LOAD_MAPPING)
        return {"ok": True}
    except Exception:
        pass
    # Chooser failed (headless mode) — load all mappings instead.
    return _load_all_mappings()


@tool
@idasync
@tool_timeout(600.0)
def dsc_load_got() -> dict:
    """Load all global offset table regions from the shared cache.

    Global offset tables (iOS 16+) contain pointers used for inter-module
    symbol resolution.  Loading and symbolicating them helps IDA resolve
    indirect data references.

    In GUI mode this shows a multi-select chooser; in headless mode it
    automatically loads all available GOTs.

    The current database must have been opened from a dyld shared cache using
    the "single module" option.
    """
    _ensure_dscu()
    try:
        _run_dscu(_MODE_LOAD_GOT)
        return {"ok": True}
    except Exception:
        pass
    # Chooser failed (headless mode) — load all GOTs instead.
    return _load_all_gots()


@tool
@idasync
@tool_timeout(600.0)
def dsc_load_gap() -> dict:
    """Load all gap regions from the shared cache.

    Gaps are unmapped regions between modules in the dyld shared cache.
    Loading them can reveal data or code that IDA did not initially map.

    In GUI mode this shows a multi-select chooser; in headless mode it
    automatically loads all available gap regions.

    The current database must have been opened from a dyld shared cache using
    the "single module" option.
    """
    _ensure_dscu()
    try:
        _run_dscu(_MODE_LOAD_GAP)
        return {"ok": True}
    except Exception:
        pass
    # Chooser failed (headless mode) — load all gaps instead.
    return _load_all_gaps()
