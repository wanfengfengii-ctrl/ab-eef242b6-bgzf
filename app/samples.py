"""Deterministic BGZF sample builder used by tests and smoke checks.

This is not part of the service code path; it produces well-formed BGZF
members and byte-level mutations so the test suite can exercise every
validation error without depending on an external bgzip binary.
"""

from __future__ import annotations

import struct
import zlib

from .bgzf import BGZF_EOF_MEMBER


def make_block(data: bytes, level: int = 6) -> bytes:
    """Build one complete BGZF member wrapping ``data``."""
    comp = zlib.compressobj(level, zlib.DEFLATED, -15)
    cdata = comp.compress(data) + comp.flush()

    xlen = 6
    total = 12 + xlen + len(cdata) + 8
    bsize = total - 1
    header = b"".join(
        [
            b"\x1f\x8b",  # gzip magic
            b"\x08",  # CM = deflate
            b"\x04",  # FLG = FEXTRA
            b"\x00\x00\x00\x00",  # MTIME
            b"\x00",  # XFL
            b"\xff",  # OS = unknown
            struct.pack("<H", xlen),
            b"BC",
            struct.pack("<H", 2),
            struct.pack("<H", bsize),
        ]
    )
    trailer = struct.pack("<II", zlib.crc32(data) & 0xFFFFFFFF, len(data) & 0xFFFFFFFF)
    return header + cdata + trailer


def make_archive(payloads: list[bytes], *, eof: bool = True) -> bytes:
    """Concatenate BGZF data members and append the canonical EOF member."""
    out = b"".join(make_block(p) for p in payloads)
    if eof:
        out += BGZF_EOF_MEMBER
    return out


def make_index(archive: bytes, payloads: list[bytes]) -> bytes:
    """Build the canonical little-endian uint64 pair index for an archive."""
    entries = bytearray()
    comp_off = 0
    unc_off = 0
    for i, payload in enumerate(payloads):
        if i > 0:
            entries += struct.pack("<QQ", comp_off, unc_off)
        comp_off += len(make_block(payload))
        unc_off += len(payload)
    return bytes(entries)


def make_valid_case(
    payloads: list[bytes] | None = None,
) -> tuple[bytes, bytes, bytes]:
    """Return (archive, index, expected_payload) for a valid submission."""
    if payloads is None:
        payloads = [
            b"first block: genome archive audit\n",
            b"second block\ndifferent compression member\n" * 4,
            b"third block" * 64,
        ]
    archive = make_archive(payloads)
    index = make_index(archive, payloads)
    return archive, index, b"".join(payloads)
