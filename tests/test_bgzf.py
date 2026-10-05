"""Unit tests for the BGZF validator and HTTP integration tests."""

from __future__ import annotations

import hashlib
import struct
import zlib

import pytest
from fastapi.testclient import TestClient

from app.bgzf import (
    BGZF_EOF_MEMBER,
    MAX_ARCHIVE_BYTES,
    MAX_DATA_BLOCKS,
    AuditError,
    audit,
)
from app.main import app
from app.samples import make_archive, make_block, make_index, make_valid_case

client = TestClient(app)


# --------------------------------------------------------------------------
# Valid cases
# --------------------------------------------------------------------------


def test_valid_archive_and_index():
    archive, index, payload = make_valid_case()
    result = audit(archive, index)
    assert result.block_count == 3
    assert result.uncompressed_size == len(payload)
    assert result.sha256 == hashlib.sha256(payload).hexdigest()


def test_single_block_has_empty_index():
    archive, index, payload = make_valid_case([b"only one block" * 10])
    result = audit(archive, index)
    assert result.block_count == 1
    assert index == b""
    assert result.sha256 == hashlib.sha256(payload).hexdigest()


def test_equal_sized_blocks_share_bsize_but_pass():
    # BSIZE values naturally repeat when blocks compress to the same size;
    # the uniqueness requirement applies to the BC subfield per member.
    payloads = [b"same" * 8, b"data" * 8, b"xxxx" * 8]
    archive, index, payload = make_valid_case(payloads)
    result = audit(archive, index)
    assert result.block_count == 3


def test_block_payload_over_bgzf_limit_rejected():
    # A real member carrying 70 kB of zeros, but ISIZE is forged to 65281:
    # the oversized ISIZE is rejected before deflate runs.
    big = b"\x00" * 70000
    member = make_block(big)
    forged = member[:-4] + struct.pack("<I", 65281)
    _expect_code(forged + BGZF_EOF_MEMBER, b"", "ISIZE_MISMATCH")

    # Honest 70 kB member (ISIZE 70000) is rejected by the same bound.
    honest = make_block(big) + BGZF_EOF_MEMBER
    _expect_code(honest, b"", "ISIZE_MISMATCH")


def test_maximum_block_count_boundary():
    payloads = [b"x"] * MAX_DATA_BLOCKS
    archive = make_archive(payloads)
    index = make_index(archive, payloads)
    result = audit(archive, index)
    assert result.block_count == MAX_DATA_BLOCKS


# --------------------------------------------------------------------------
# Member-level corruption
# --------------------------------------------------------------------------


def _expect_code(archive: bytes, index: bytes, code: str):
    with pytest.raises(AuditError) as exc:
        audit(archive, index)
    assert exc.value.code == code
    return exc.value


def test_empty_archive():
    exc = _expect_code(b"", b"", "EMPTY_ARCHIVE")
    assert exc.offset == 0


def test_truncated_member_offset_points_at_member_start():
    # Remove the EOF member and all but a few header bytes of the only data
    # member: the stub is shorter than the 18-byte minimum.
    archive = make_archive([b"x" * 200])
    cut = archive[:10]
    exc = _expect_code(cut, b"", "TRUNCATED_MEMBER")
    assert exc.offset == 0


def test_bad_magic():
    archive, index, _ = make_valid_case()
    bad = bytearray(archive)
    second_block_start = len(make_block(b"first block: genome archive audit\n"))
    bad[second_block_start] ^= 0xFF
    exc = _expect_code(bytes(bad), index, "MALFORMED_MEMBER_HEADER")
    assert exc.offset == second_block_start


def test_missing_bc_subfield():
    payload = b"no bc field here"
    comp = zlib.compressobj(6, zlib.DEFLATED, -15)
    cdata = comp.compress(payload) + comp.flush()
    # gzip member with FEXTRA but no BC subfield (a different SI id instead)
    extra = b"XX\x02\x00\x00\x00"
    header = b"\x1f\x8b\x08\x04\x00\x00\x00\x00\x00\xff" + struct.pack(
        "<H", len(extra)
    ) + extra
    total = len(header) + len(cdata) + 8
    member = (
        header
        + cdata
        + struct.pack("<II", zlib.crc32(payload) & 0xFFFFFFFF, len(payload))
    )
    archive = member + BGZF_EOF_MEMBER
    assert total == len(member)
    exc = _expect_code(archive, b"", "MISSING_BC_SUBFIELD")
    assert exc.offset == 0


def test_duplicate_bc_subfield_rejected():
    payload = b"dup bc"
    comp = zlib.compressobj(6, zlib.DEFLATED, -15)
    cdata = comp.compress(payload) + comp.flush()
    xlen = 6 + 6
    bsize = 12 + xlen + len(cdata) + 8 - 1
    extra = b"BC" + struct.pack("<HH", 2, bsize) + b"BC" + struct.pack("<HH", 2, bsize)
    header = b"\x1f\x8b\x08\x04\x00\x00\x00\x00\x00\xff" + struct.pack(
        "<H", xlen
    ) + extra
    member = (
        header
        + cdata
        + struct.pack("<II", zlib.crc32(payload) & 0xFFFFFFFF, len(payload))
    )
    _expect_code(member + BGZF_EOF_MEMBER, b"", "DUPLICATE_BC_SUBFIELD")


def test_bsize_runs_past_end_of_file():
    archive, index, _ = make_valid_case()
    # enlarge BSIZE in the second block header without adding bytes
    first = len(make_block(b"first block: genome archive audit\n"))
    bad = bytearray(archive)
    off = first + 16  # BSIZE sits inside the BC subfield
    bsize = bad[off] | (bad[off + 1] << 8)
    bsize += 100
    bad[off] = bsize & 0xFF
    bad[off + 1] = (bsize >> 8) & 0xFF
    exc = _expect_code(bytes(bad), index, "BLOCK_SIZE_MISMATCH")
    assert exc.offset == first


def test_bsize_smaller_than_deflate_boundary():
    payloads = [b"first block: genome archive audit\n", b"second" * 100]
    archive = make_archive(payloads)
    index = make_index(archive, payloads)
    first_len = len(make_block(payloads[0]))
    bad = bytearray(archive)
    off = first_len + 16
    bsize = (bad[off] | (bad[off + 1] << 8)) - 2
    bad[off] = bsize & 0xFF
    bad[off + 1] = (bsize >> 8) & 0xFF
    # Shrink BSIZE: zlib either fails or stops before the real trailer,
    # so the deflate boundary / CRC check must flag block two.
    with pytest.raises(AuditError) as exc:
        audit(bytes(bad), index)
    assert exc.value.code in {"DEFLATE_BOUNDARY_MISMATCH", "CRC32_MISMATCH", "ISIZE_MISMATCH"}
    assert exc.value.offset == first_len


def test_crc_corruption_offset_locates_member():
    archive, index, _ = make_valid_case()
    first_len = len(make_block(b"first block: genome archive audit\n"))
    second_len = len(make_block(b"second block\ndifferent compression member\n" * 4))
    start2 = first_len
    # Flipping a payload byte corrupts either the deflate stream or the
    # CRC32; either way block two must be pinpointed at its member start.
    bad = bytearray(archive)
    bad[start2 + 20] ^= 0x01
    with pytest.raises(AuditError) as exc_info:
        audit(bytes(bad), index)
    assert exc_info.value.code in {"DEFLATE_BOUNDARY_MISMATCH", "CRC32_MISMATCH"}
    assert exc_info.value.offset == start2
    # CRC-only tampering (valid deflate, wrong CRC):
    good = make_archive([b"abc", b"def"])
    good_index = make_index(good, [b"abc", b"def"])
    b2off = len(make_block(b"abc"))
    tampered = bytearray(good)
    tampered[b2off + len(make_block(b"def")) - 5] ^= 0xFF
    exc = _expect_code(bytes(tampered), good_index, "CRC32_MISMATCH")
    assert exc.offset == b2off


def test_isize_mismatch():
    payloads = [b"abc", b"def"]
    archive, index, _ = make_valid_case(payloads)
    b2off = len(make_block(payloads[0]))
    bad = bytearray(archive)
    # set the highest ISIZE byte of block two (normally zero) to 1
    bad[b2off + len(make_block(payloads[1])) - 1] = 0x01
    _expect_code(bytes(bad), index, "ISIZE_MISMATCH")


def test_missing_eof_member():
    archive = make_archive([b"abc"], eof=False)
    _expect_code(archive, b"", "MISSING_EOF_MEMBER")


def test_bytes_appended_after_eof():
    archive = make_archive([b"abc"]) + b"\x00"
    exc = _expect_code(archive, b"", "BYTES_AFTER_EOF_MEMBER")
    assert exc.offset == len(archive) - 1


def test_only_eof_member_rejected():
    _expect_code(BGZF_EOF_MEMBER, b"", "INVALID_EOF_MEMBER")


def test_too_many_blocks():
    payloads = [b"x"] * (MAX_DATA_BLOCKS + 1)
    archive = make_archive(payloads)
    index = make_index(archive, payloads)
    with pytest.raises(AuditError) as exc:
        audit(archive, index)
    assert exc.value.code == "TOO_MANY_DATA_BLOCKS"


# --------------------------------------------------------------------------
# Index validation
# --------------------------------------------------------------------------


def test_index_length_too_long():
    archive, _, _ = make_valid_case([b"abc"])
    _expect_code(archive, b"\x00" * 16, "INDEX_LENGTH_MISMATCH")


def test_index_length_unaligned():
    archive, _, _ = make_valid_case([b"abc", b"def"])
    _expect_code(archive, b"\x00" * 20, "INDEX_LENGTH_MISMATCH")


def test_index_compressed_offset_drift():
    payloads = [b"abc", b"defgh", b"ijklm"]
    archive = make_archive(payloads)
    index = make_index(archive, payloads)
    bad = bytearray(index)
    bad[0] += 1  # drift first compressed offset by one
    exc = _expect_code(archive, bytes(bad), "INDEX_COMPRESSED_OFFSET_MISMATCH")
    assert exc.offset == struct.unpack_from("<Q", bytes(bad), 0)[0]


def test_index_uncompressed_offset_drift():
    payloads = [b"abc", b"defgh", b"ijklm"]
    archive = make_archive(payloads)
    index = make_index(archive, payloads)
    bad = bytearray(index)
    bad[8] += 1  # drift first uncompressed offset
    _expect_code(archive, bytes(bad), "INDEX_UNCOMPRESSED_OFFSET_MISMATCH")


def test_index_wrong_entry_for_second_block():
    payloads = [b"abc", b"defgh", b"ijklm"]
    archive = make_archive(payloads)
    good = make_index(archive, payloads)
    # Point the second entry back at block two's compressed start.
    b1 = len(make_block(payloads[0]))
    bad = good[:16] + struct.pack("<QQ", b1, 8)
    exc = _expect_code(archive, bad, "INDEX_COMPRESSED_OFFSET_MISMATCH")
    assert exc.offset == b1


def test_index_uses_big_endian_fails():
    payloads = [b"abc", b"defgh"]
    archive = make_archive(payloads)
    b1 = len(make_block(payloads[0]))
    be_index = struct.pack(">Q Q", b1, len(payloads[0]))
    _expect_code(archive, be_index, "INDEX_COMPRESSED_OFFSET_MISMATCH")


# --------------------------------------------------------------------------
# HTTP layer
# --------------------------------------------------------------------------


def _post(archive: bytes, index: bytes):
    return client.post(
        "/api/bgzf/audit",
        files={
            "archive": ("a.bgzf", archive, "application/octet-stream"),
            "index": ("a.gzi", index, "application/octet-stream"),
        },
    )


def test_http_success_shape():
    archive, index, payload = make_valid_case()
    r = _post(archive, index)
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"block_count", "uncompressed_size", "sha256"}
    assert body["block_count"] == 3
    assert body["uncompressed_size"] == len(payload)
    assert body["sha256"] == hashlib.sha256(payload).hexdigest()


def test_http_422_stable_code_and_offset():
    archive, index, _ = make_valid_case([b"abc", b"def"])
    b1 = len(make_block(b"abc"))
    bad = bytearray(archive)
    bad[b1] ^= 0xFF
    r = _post(bytes(bad), index)
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["code"] == "MALFORMED_MEMBER_HEADER"
    assert err["offset"] == b1
    # no partial result fields leak into the error body
    assert "block_count" not in r.json()


def test_http_index_drift_422():
    payloads = [b"abc", b"def"]
    archive = make_archive(payloads)
    index = bytearray(make_index(archive, payloads))
    index[0] += 1
    r = _post(archive, bytes(index))
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "INDEX_COMPRESSED_OFFSET_MISMATCH"


def test_archive_over_size_limit():
    # No valid member is needed: the envelope check precedes parsing.
    with pytest.raises(AuditError) as exc:
        audit(b"\x1f\x8b" + b"\x00" * (MAX_ARCHIVE_BYTES), b"")
    assert exc.value.code == "ARCHIVE_TOO_LARGE"


def test_http_missing_file_is_422():
    r = client.post(
        "/api/bgzf/audit",
        files={"archive": ("a.bgzf", b"x", "application/octet-stream")},
    )
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["code"] == "MALFORMED_REQUEST"
    assert err["offset"] == 0


def test_http_malformed_content_type_is_422():
    r = client.post("/api/bgzf/audit", content=b"not multipart")
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "MALFORMED_REQUEST"


def test_health():
    assert client.get("/health").json() == {"status": "ok"}
