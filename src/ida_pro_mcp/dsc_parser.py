"""Pure-Python parser for dyld shared cache (DSC) headers.

No IDA dependency — usable both inside IDA (api_dsc.py) and standalone
(idalib_server.py / idalib_dsc_info tool).
"""

from __future__ import annotations

import struct


def read_cstring(file_object, offset: int, max_length: int = 4096) -> str:
    """Read a null-terminated UTF-8 string from *file_object* at *offset*."""
    saved = file_object.tell()
    file_object.seek(offset)
    parts: list[bytes] = []
    for _ in range(max_length):
        byte = file_object.read(1)
        if not byte or byte == b"\x00":
            break
        parts.append(byte)
    file_object.seek(saved)
    return b"".join(parts).decode("utf-8", errors="replace")


def list_dsc_images(dsc_path: str) -> list[dict]:
    """Return every image in a dyld shared cache file.

    Each entry is ``{"index": int, "address": str, "path": str}``.

    Supports both the old ``dyld_cache_image_info`` array (offset 0x18) and
    the newer ``dyld_cache_image_text_info`` array (offset 0x88) introduced
    in macOS 10.12+ / iOS 10+.  Newer caches (macOS 12+ / iOS 15+) set the
    old fields to zero.
    """
    with open(dsc_path, "rb") as file_object:
        header = file_object.read(0x98)
        if len(header) < 0x20:
            raise ValueError("File too small to be a dyld shared cache")
        if not header[:16].startswith(b"dyld_v"):
            raise ValueError("Not a dyld shared cache (bad magic)")

        # Strategy 1: old dyld_cache_image_info at 0x18/0x1C
        #   Layout (32 B): address(8) + modTime(8) + inode(8) + pathFileOffset(4) + pad(4)
        images_offset, images_count = struct.unpack_from("<II", header, 0x18)
        if images_count > 0 and images_offset > 0:
            return _parse_image_info(file_object, images_offset, images_count)

        # Strategy 2: dyld_cache_image_text_info at 0x88/0x90
        #   Layout (32 B): uuid(16) + loadAddress(8) + textSegmentSize(4) + pathOffset(4)
        if len(header) >= 0x98:
            text_offset, text_count = struct.unpack_from("<QQ", header, 0x88)
            if text_count > 0 and text_offset > 0 and text_count < 0x100000:
                return _parse_image_text_info(file_object, text_offset, text_count)

        raise ValueError(
            "No images found in DSC header (neither old nor text format)"
        )


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------

def _parse_image_info(
    file_object, images_offset: int, images_count: int
) -> list[dict]:
    """Parse old-format ``dyld_cache_image_info`` entries."""
    modules: list[dict] = []
    file_object.seek(images_offset)
    for index in range(images_count):
        entry = file_object.read(32)
        if len(entry) < 32:
            break
        address = struct.unpack_from("<Q", entry, 0)[0]
        path_offset = struct.unpack_from("<I", entry, 0x18)[0]
        module_path = read_cstring(file_object, path_offset)
        modules.append({"index": index, "address": hex(address), "path": module_path})
    return modules


def _parse_image_text_info(
    file_object, text_offset: int, text_count: int
) -> list[dict]:
    """Parse newer ``dyld_cache_image_text_info`` entries."""
    modules: list[dict] = []
    file_object.seek(text_offset)
    for index in range(text_count):
        entry = file_object.read(32)
        if len(entry) < 32:
            break
        address = struct.unpack_from("<Q", entry, 0x10)[0]
        path_offset = struct.unpack_from("<I", entry, 0x1C)[0]
        module_path = read_cstring(file_object, path_offset)
        modules.append({"index": index, "address": hex(address), "path": module_path})
    return modules
