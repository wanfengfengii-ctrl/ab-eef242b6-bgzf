"""BGZF archive and block-offset index validation.

The validator walks a BGZF file as a sequence of complete gzip (RFC 1952)
members.  Every data member must carry exactly one ``BC`` subfield
(SI1='B', SI2='C') in its FEXTRA block.  For each member it cross-checks:

* the declared block size (BSIZE in the BC subfield) against the bytes
  available and the raw Deflate boundary,
* CRC32 and ISIZE against the decompressed payload,

and enforces exactly one canonical 28-byte empty EOF member at the very end
with no trailing bytes.

The companion index is a little-endian sequence of ``uint64`` pairs
``(compressed_offset, uncompressed_offset)`` with one entry per non-first
*data* block.

Everything here is pure standard library so the same code runs under the
test suite and inside the one-shot verification container.
"""

from __future__ import annotations

import hashlib
import struct
import zlib
from dataclasses import dataclass

# Hard limits mandated by the ingestion contract.
MAX_ARCHIVE_BYTES = 8 * 1024 * 1024
MAX_DATA_BLOCKS = 4096
# BGZF members may hold at most 65280 decompressed bytes (spec block limit).
MAX_BLOCK_DATA = 65280

# Standard BGZF EOF member: an empty deflate block with the BGZF BC field.
BGZF_EOF_MEMBER = bytes.fromhex(
    "1f8b08040000000000ff0600424302001b0003000000000000000000"
)

# Stable error codes returned with HTTP 422.  ``offset`` always points at the
# first compressed-file position where the problem is locatable; for index
# problems it is the offending compressed offset named by the index.
ERR_EMPTY = "EMPTY_ARCHIVE"
ERR_TOO_LARGE = "ARCHIVE_TOO_LARGE"
ERR_TRAILING = "TRUNCATED_MEMBER"
ERR_MEMBER_HEADER = "MALFORMED_MEMBER_HEADER"
ERR_FLAGS = "UNSUPPORTED_MEMBER_FLAGS"
ERR_EXTRA_LEN = "MALFORMED_EXTRA_HEADER"
ERR_BC_MISSING = "MISSING_BC_SUBFIELD"
ERR_BC_DUPLICATE = "DUPLICATE_BC_SUBFIELD"
ERR_BSIZE = "BSIZE_OUT_OF_RANGE"
ERR_BLOCK_SIZE = "BLOCK_SIZE_MISMATCH"
ERR_DEFLATE = "DEFLATE_BOUNDARY_MISMATCH"
ERR_CRC = "CRC32_MISMATCH"
ERR_ISIZE = "ISIZE_MISMATCH"
ERR_EOF_MISSING = "MISSING_EOF_MEMBER"
ERR_EOF_TRAILING = "BYTES_AFTER_EOF_MEMBER"
ERR_EOF_INVALID = "INVALID_EOF_MEMBER"
ERR_TOO_MANY_BLOCKS = "TOO_MANY_DATA_BLOCKS"
ERR_INDEX_TOO_LARGE = "INDEX_TOO_LARGE"
ERR_INDEX_LENGTH = "INDEX_LENGTH_MISMATCH"
ERR_INDEX_COMP_OFFSET = "INDEX_COMPRESSED_OFFSET_MISMATCH"
ERR_INDEX_UNC_OFFSET = "INDEX_UNCOMPRESSED_OFFSET_MISMATCH"


class AuditError(ValueError):
    """A validation failure with a stable code and a locatable offset."""

    def __init__(self, code: str, message: str, offset: int = 0):
        super().__init__(message)
        self.code = code
        self.message = message
        # Offset into the compressed archive where the problem is first seen.
        self.offset = offset


@dataclass(frozen=True)
class AuditResult:
    block_count: int
    uncompressed_size: int
    sha256: str


@dataclass(frozen=True)
class _Member:
    start: int
    end: int  # exclusive
    size: int  # decompressed payload length


def _parse_extra(extra: bytes, member_start: int) -> int:
    """Parse gzip extra subfields; return the BC/BSIZE value.

    Requires exactly one BC subfield in the member and well-formed framing
    for every subfield present.
    """
    bsize: int | None = None
    i = 0
    while i < len(extra):
        if i + 4 > len(extra):
            raise AuditError(
                ERR_EXTRA_LEN,
                "extra field contains a truncated subfield header",
                member_start,
            )
        si = extra[i : i + 2]
        slen = extra[i + 2] | (extra[i + 3] << 8)
        i += 4
        if i + slen > len(extra):
            raise AuditError(
                ERR_EXTRA_LEN,
                "extra subfield length runs past the extra field",
                member_start,
            )
        payload = extra[i : i + slen]
        i += slen
        if si == b"BC":
            if bsize is not None:
                raise AuditError(
                    ERR_BC_DUPLICATE,
                    "member header contains more than one BC subfield",
                    member_start,
                )
            if slen != 2:
                raise AuditError(
                    ERR_BC_MISSING,
                    "BC subfield must carry a 2-byte BSIZE value",
                    member_start,
                )
            bsize = payload[0] | (payload[1] << 8)
    if bsize is None:
        raise AuditError(
            ERR_BC_MISSING, "member header lacks the BGZF BC subfield", member_start
        )
    return bsize


def _parse_member(buf: bytes, start: int) -> tuple[_Member, bytes]:
    """Parse and fully verify one gzip member; return (member, payload)."""
    remaining = len(buf) - start
    if remaining < 18:
        raise AuditError(
            ERR_TRAILING,
            "trailing bytes are shorter than a complete gzip member",
            start,
        )

    if buf[start : start + 2] != b"\x1f\x8b":
        raise AuditError(
            ERR_MEMBER_HEADER, "missing gzip magic number (1f 8b)", start
        )
    if buf[start + 2] != 8:
        raise AuditError(
            ERR_MEMBER_HEADER, "unsupported compression method (not deflate)", start
        )

    flg = buf[start + 3]
    # FTEXT (0x01) is harmless; FEXTRA (0x04) is mandatory for BGZF.
    # FNAME/FCOMMENT/FHCRC are rejected because they would move the deflate
    # boundary in ways a strict BGZF member must not use.
    if flg & ~0x05:
        raise AuditError(
            ERR_FLAGS,
            "member uses gzip header flags other than FEXTRA/FTEXT",
            start,
        )
    if not (flg & 0x04):
        raise AuditError(
            ERR_BC_MISSING,
            "member has no FEXTRA field and therefore no BC subfield",
            start,
        )

    xlen = buf[start + 10] | (buf[start + 11] << 8)
    header_end = start + 12 + xlen
    if xlen < 6 or header_end + 8 > len(buf) or header_end - start > remaining:
        raise AuditError(
            ERR_EXTRA_LEN,
            "XLEN cannot frame a BC subfield inside this member",
            start,
        )

    bsize = _parse_extra(buf[start + 12 : header_end], start)
    block_size = bsize + 1
    if bsize < 27 or block_size > 65536:
        raise AuditError(
            ERR_BSIZE,
            f"BSIZE value {bsize} cannot describe a BGZF member",
            start,
        )
    if block_size > remaining:
        raise AuditError(
            ERR_BLOCK_SIZE,
            "BSIZE declares %d bytes but only %d remain in the archive"
            % (block_size, remaining),
            start,
        )

    end = start + block_size
    crc_stored, isize_stored = struct.unpack_from("<II", buf, end - 8)

    # Reject BGZF-spec-impossible ISIZE values before any decompression.
    if isize_stored > MAX_BLOCK_DATA:
        raise AuditError(
            ERR_ISIZE,
            "ISIZE %d exceeds the BGZF per-block payload limit of %d bytes"
            % (isize_stored, MAX_BLOCK_DATA),
            start,
        )

    # Decompress the raw Deflate stream and require zlib to consume exactly
    # the bytes between the extra header and the 8-byte gzip trailer; this is
    # what ties BSIZE to the Deflate boundary.  Output is capped while
    # streaming so a malicious block cannot inflate memory use.
    payload_start = header_end
    payload_end = end - 8
    dec = zlib.decompressobj(-15)
    payload = b""
    src = memoryview(buf)[payload_start:payload_end]
    fed = 0
    try:
        for i in range(0, len(src), 4096):
            chunk = src[i : i + 4096]
            payload += dec.decompress(bytes(chunk), MAX_BLOCK_DATA + 1)
            fed += len(chunk)
            if len(payload) > MAX_BLOCK_DATA:
                raise AuditError(
                    ERR_ISIZE,
                    "decompressed block exceeds the BGZF limit of %d bytes"
                    % MAX_BLOCK_DATA,
                    start,
                )
            if dec.eof:
                break
        if dec.eof:
            payload += dec.flush(MAX_BLOCK_DATA + 1)
    except AuditError:
        raise
    except zlib.error as exc:
        raise AuditError(
            ERR_DEFLATE, f"invalid deflate stream: {exc}", start
        ) from exc

    if len(payload) > MAX_BLOCK_DATA:
        raise AuditError(
            ERR_ISIZE,
            "decompressed block exceeds the BGZF limit of %d bytes" % MAX_BLOCK_DATA,
            start,
        )
    if not dec.eof:
        raise AuditError(
            ERR_DEFLATE,
            "deflate stream does not terminate within the block declared by BSIZE",
            start,
        )
    total_deflate = payload_end - payload_start
    consumed = fed - len(dec.unused_data)
    if consumed != total_deflate:
        raise AuditError(
            ERR_DEFLATE,
            "deflate stream ended %d byte(s) before the declared block trailer"
            % (total_deflate - consumed),
            start,
        )

    actual_crc = zlib.crc32(payload) & 0xFFFFFFFF
    if actual_crc != crc_stored:
        raise AuditError(
            ERR_CRC,
            "stored CRC32 %08x does not match decompressed data %08x"
            % (crc_stored, actual_crc),
            start,
        )
    if (len(payload) & 0xFFFFFFFF) != isize_stored:
        raise AuditError(
            ERR_ISIZE,
            "ISIZE %d does not match decompressed length %d"
            % (isize_stored, len(payload)),
            start,
        )

    return _Member(start=start, end=end, size=len(payload)), payload


def parse_bgzf(buf: bytes) -> tuple[list[_Member], "hashlib._Hash", int]:
    """Parse every member; return (members, running SHA-256, total payload size)."""
    if not buf:
        raise AuditError(ERR_EMPTY, "archive contains no bytes")
    if len(buf) > MAX_ARCHIVE_BYTES:
        raise AuditError(
            ERR_TOO_LARGE,
            "archive is %d bytes, limit is %d" % (len(buf), MAX_ARCHIVE_BYTES),
        )

    members: list[_Member] = []
    digest = hashlib.sha256()
    pos = 0
    while pos < len(buf):
        # The canonical empty EOF member may only appear as the final member.
        if buf[pos : pos + len(BGZF_EOF_MEMBER)] == BGZF_EOF_MEMBER:
            if pos + len(BGZF_EOF_MEMBER) != len(buf):
                raise AuditError(
                    ERR_EOF_TRAILING,
                    "bytes follow the EOF member",
                    pos + len(BGZF_EOF_MEMBER),
                )
            if not members:
                raise AuditError(
                    ERR_EOF_INVALID,
                    "archive contains only the EOF member and no data blocks",
                    pos,
                )
            break

        member, payload = _parse_member(buf, pos)
        # Hash immediately and drop the payload so the whole decompressed
        # stream is never held in memory at once.
        digest.update(payload)
        if member.size == 0:
            # An empty BGZF block is the EOF marker by convention; any empty
            # member that is not byte-identical to the canonical marker is invalid.
            raise AuditError(
                ERR_EOF_INVALID,
                "empty member at offset %d is not the standard EOF member" % pos,
                pos,
            )
        members.append(member)
        if len(members) > MAX_DATA_BLOCKS:
            raise AuditError(
                ERR_TOO_MANY_BLOCKS,
                "archive exceeds the limit of %d data blocks" % MAX_DATA_BLOCKS,
                member.start,
            )
        pos = member.end

        if pos == len(buf):
            raise AuditError(
                ERR_EOF_MISSING,
                "archive ends after a data member without the EOF member",
                pos,
            )

    total_size = sum(m.size for m in members)
    return members, digest, total_size


def audit_index(index: bytes, members: list[_Member]) -> None:
    """Validate little-endian uint64 (compressed, uncompressed) offset pairs.

    One entry is required per non-first data block.  Compressed offsets must
    equal each data block's member start; uncompressed offsets must equal the
    cumulative decompressed length of all preceding blocks.
    """
    expected_pairs = len(members) - 1
    expected_bytes = expected_pairs * 16
    if len(index) > MAX_DATA_BLOCKS * 16:
        raise AuditError(
            ERR_INDEX_TOO_LARGE,
            "index is larger than the %d-byte maximum" % (MAX_DATA_BLOCKS * 16),
            0,
        )
    if len(index) != expected_bytes:
        raise AuditError(
            ERR_INDEX_LENGTH,
            "index holds %d byte(s) (%s pair(s)); %d pair(s) are required for "
            "%d data block(s)"
            % (
                len(index),
                str(len(index) // 16) if len(index) % 16 == 0 else "unaligned",
                expected_pairs,
                len(members),
            ),
            members[1].start if expected_pairs else 0,
        )

    cumulative = members[0].size
    for i in range(expected_pairs):
        comp_off, unc_off = struct.unpack_from("<QQ", index, i * 16)
        member = members[i + 1]
        if comp_off != member.start:
            raise AuditError(
                ERR_INDEX_COMP_OFFSET,
                "index entry %d names compressed offset %d but block %d starts "
                "at %d" % (i, comp_off, i + 1, member.start),
                comp_off,
            )
        if unc_off != cumulative:
            raise AuditError(
                ERR_INDEX_UNC_OFFSET,
                "index entry %d names uncompressed offset %d but cumulative "
                "length before block %d is %d"
                % (i, unc_off, i + 1, cumulative),
                comp_off,
            )
        cumulative += member.size


def audit(archive: bytes, index: bytes) -> AuditResult:
    """Validate archive and index atomically and return the audit summary."""
    members, digest, total_size = parse_bgzf(archive)
    audit_index(index, members)
    return AuditResult(
        block_count=len(members),
        uncompressed_size=total_size,
        sha256=digest.hexdigest(),
    )
