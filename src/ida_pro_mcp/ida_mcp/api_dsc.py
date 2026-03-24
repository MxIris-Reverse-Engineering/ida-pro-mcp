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
  Modes 4/7/8/9 check if their netnode tag already has entries.  If so, the
  chooser is skipped and the pre-populated items are loaded directly.  The
  dsc_load_all tool exploits this by parsing the DSC file header to enumerate
  all items of a given type, pre-populating the netnode, then triggering the
  mode.
"""

from __future__ import annotations

import struct
from typing import Annotated

import idaapi
import ida_nalt
import ida_segment
import idautils

from .rpc import tool
from .sync import idasync, IDAError
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


def _read_cstring(f, offset: int) -> str:
    """Read a null-terminated UTF-8 string from file at *offset*."""
    saved = f.tell()
    f.seek(offset)
    parts: list[bytes] = []
    while True:
        c = f.read(1)
        if not c or c == b"\x00":
            break
        parts.append(c)
    f.seek(saved)
    return b"".join(parts).decode("utf-8", errors="replace")


def _dsc_path() -> str:
    """Return the filesystem path of the input dyld shared cache."""
    path = ida_nalt.get_input_file_path()
    if not path:
        raise IDAError("Cannot determine input file path")
    return path


def _parse_dsc_modules() -> list[dict]:
    """Parse the DSC header and return all cached images (modules)."""
    path = _dsc_path()
    with open(path, "rb") as f:
        magic = f.read(16)
        if not magic.startswith(b"dyld_v"):
            raise IDAError("Input file is not a dyld shared cache")

        f.seek(0x18)
        images_offset, images_count = struct.unpack("<II", f.read(8))
        if images_count == 0 or images_offset == 0:
            raise IDAError("No images found in DSC header")

        modules: list[dict] = []
        f.seek(images_offset)
        for i in range(images_count):
            entry = f.read(32)
            if len(entry) < 32:
                break
            addr = struct.unpack_from("<Q", entry, 0)[0]
            path_off = struct.unpack_from("<I", entry, 0x18)[0]
            mod_path = _read_cstring(f, path_off)
            modules.append({"index": i, "address": hex(addr), "path": mod_path})
        return modules


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

    Enumerates mappings from the DSC header and marks all executable
    non-primary mappings as branch mapping candidates.
    """
    mappings = _parse_dsc_mappings()
    if not mappings:
        return {"error": "No mappings found in DSC header"}

    # Branch mappings are executable (maxProt & 4 == PROT_EXEC) non-primary
    # mappings.  The first mapping is always the primary __TEXT mapping.
    node = _dscu_node()
    val = struct.pack("<Q", 1)
    loaded = 0
    for m in mappings[1:]:  # skip primary __TEXT mapping
        if m["maxProt"] & 4:  # VM_PROT_EXECUTE
            addr = int(m["address"], 16)
            node.supset(addr, val, _TAG_MAPPING)
            loaded += 1

    if loaded == 0:
        return {"error": "No branch mappings detected in mappings table"}
    _run_dscu(_MODE_LOAD_MAPPING)
    return {"ok": True, "loaded": loaded}


def _load_all_gots() -> dict:
    """Load all GOTs via tag 'f' pre-population.

    Enumerates mappings from the DSC header and marks all non-executable
    data mappings as GOT candidates (address → end address).
    """
    mappings = _parse_dsc_mappings()
    if not mappings:
        return {"error": "No mappings found in DSC header"}

    # GOT regions are data mappings (no PROT_EXEC, but with PROT_READ)
    # that are not the primary __TEXT mapping.
    node = _dscu_node()
    loaded = 0
    for m in mappings[1:]:  # skip primary __TEXT mapping
        if not (m["maxProt"] & 4):  # not VM_PROT_EXECUTE → data mapping
            addr = int(m["address"], 16)
            end = int(m["end"], 16)
            node.supset(addr, struct.pack("<Q", end), _TAG_GOT)
            loaded += 1

    if loaded == 0:
        return {"error": "No GOT regions detected in mappings table"}
    _run_dscu(_MODE_LOAD_GOT)
    return {"ok": True, "loaded": loaded}


def _load_all_gaps() -> dict:
    """Load all gaps via tag 'p' pre-population.

    Gaps are unmapped address ranges between consecutive mappings.
    """
    mappings = _parse_dsc_mappings()
    if len(mappings) < 2:
        return {"error": "Not enough mappings to detect gaps"}

    node = _dscu_node()
    loaded = 0
    for i in range(len(mappings) - 1):
        cur_end = int(mappings[i]["address"], 16) + int(mappings[i]["size"], 16)
        next_start = int(mappings[i + 1]["address"], 16)
        if next_start > cur_end:
            node.supset(cur_end, struct.pack("<Q", next_start), _TAG_GAP)
            loaded += 1

    if loaded == 0:
        return {"error": "No gaps detected between mappings"}
    _run_dscu(_MODE_LOAD_GAP)
    return {"ok": True, "loaded": loaded}


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
def dsc_load_branch_island() -> dict:
    """Open the branch island chooser to load branch island regions.

    Branch islands are intermediate stub sequences used by the dyld shared
    cache to bridge calls between distant modules.  Loading them resolves
    indirect branches (e.g. turns 'BL loc_...' into 'BL _objc_msgSend').

    Shows a multi-select chooser in IDA.  For headless use, call
    dsc_load_all("island") instead.

    The current database must have been opened from a dyld shared cache using
    the "single module" option.
    """
    _ensure_dscu()
    try:
        _run_dscu(_MODE_LOAD_ISLAND)
        return {"ok": True}
    except Exception as exc:
        return {"error": str(exc)}


@tool
@idasync
def dsc_load_branch_mapping() -> dict:
    """Open the branch mapping chooser to load branch stub mapping regions.

    Branch mappings (iOS 16+) contain stub code that routes calls between
    modules in the shared cache.  Loading them is essential for resolving
    cross-module function calls.

    Shows a multi-select chooser in IDA.  For headless use, call
    dsc_load_all("mapping") instead.

    The current database must have been opened from a dyld shared cache using
    the "single module" option.
    """
    _ensure_dscu()
    try:
        _run_dscu(_MODE_LOAD_MAPPING)
        return {"ok": True}
    except Exception as exc:
        return {"error": str(exc)}


@tool
@idasync
def dsc_load_got() -> dict:
    """Open the GOT chooser to load global offset table regions.

    Global offset tables (iOS 16+) contain pointers used for inter-module
    symbol resolution.  Loading and symbolicating them helps IDA resolve
    indirect data references.

    Shows a multi-select chooser in IDA.  For headless use, call
    dsc_load_all("got") instead.

    The current database must have been opened from a dyld shared cache using
    the "single module" option.
    """
    _ensure_dscu()
    try:
        _run_dscu(_MODE_LOAD_GOT)
        return {"ok": True}
    except Exception as exc:
        return {"error": str(exc)}


@tool
@idasync
def dsc_load_gap() -> dict:
    """Open the gap chooser to load gap regions from the shared cache.

    Gaps are unmapped regions between modules in the dyld shared cache.
    Loading them can reveal data or code that IDA did not initially map.

    Shows a multi-select chooser in IDA.  For headless use, call
    dsc_load_all("gap") instead.

    The current database must have been opened from a dyld shared cache using
    the "single module" option.
    """
    _ensure_dscu()
    try:
        _run_dscu(_MODE_LOAD_GAP)
        return {"ok": True}
    except Exception as exc:
        return {"error": str(exc)}
