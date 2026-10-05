"""End-to-end smoke checks submitted over HTTP by the one-shot verify service.

Submits four samples:

1. a legal archive + index                 -> 200 with audit summary
2. a member whose CRC32 was tampered       -> 422 CRC32_MISMATCH
3. a member whose declared block size lies -> 422 BLOCK_SIZE_MISMATCH
4. an index whose offset pair drifted      -> 422 INDEX_COMPRESSED_OFFSET_MISMATCH

Exits 0 only when every response matches the contract (including the
locatable compressed offset).  Uses the standard library only.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.samples import make_archive, make_block, make_index, make_valid_case  # noqa: E402

BASE_URL = os.environ.get("BASE_URL", "http://127.0.0.1:8080")
TIMEOUT = 10


def wait_for_health(attempts: int = 30) -> None:
    for _ in range(attempts):
        try:
            with urllib.request.urlopen(f"{BASE_URL}/health", timeout=2) as r:
                if r.status == 200:
                    return
        except (urllib.error.URLError, ConnectionError, OSError):
            time.sleep(1)
    raise SystemExit("service never became healthy")


def post_multipart(path: str, fields: dict[str, tuple[str, bytes]]) -> tuple[int, dict]:
    boundary = "----bgzf-smoke-boundary-0123456789"
    body = bytearray()
    for name, (filename, content) in fields.items():
        body += f"--{boundary}\r\n".encode()
        body += (
            f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'
        ).encode()
        body += b"Content-Type: application/octet-stream\r\n\r\n"
        body += content
        body += b"\r\n"
    body += f"--{boundary}--\r\n".encode()

    req = urllib.request.Request(
        f"{BASE_URL}{path}",
        data=bytes(body),
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


failures: list[str] = []


def check(label: str, condition: bool, detail: str = "") -> None:
    print(f"{'PASS' if condition else 'FAIL'}: {label} {detail}")
    if not condition:
        failures.append(label)


def main() -> int:
    wait_for_health()

    # 1) legal submission --------------------------------------------------
    payloads = [
        b"smoke block one: aligned members\n",
        b"smoke block two" * 32,
        b"smoke block three" * 16,
    ]
    archive = make_archive(payloads)
    index = make_index(archive, payloads)
    status, body = post_multipart(
        "/api/bgzf/audit",
        {
            "archive": ("legal.bgzf", archive),
            "index": ("legal.gzi", index),
        },
    )
    payload = b"".join(payloads)
    check(
        "legal archive accepted",
        status == 200
        and body.get("block_count") == 3
        and body.get("uncompressed_size") == len(payload)
        and body.get("sha256") == hashlib.sha256(payload).hexdigest(),
        f"status={status} body={body}",
    )

    # 2) CRC32 corruption: flip a byte in block two's CRC trailer ----------
    payloads = [b"crc one", b"crc two payload" * 8]
    archive = make_archive(payloads)
    index = make_index(archive, payloads)
    block1_len = len(make_block(payloads[0]))
    bad = bytearray(archive)
    bad[block1_len + len(make_block(payloads[1])) - 8] ^= 0xFF  # CRC byte
    status, body = post_multipart(
        "/api/bgzf/audit",
        {"archive": ("crc.bgzf", bytes(bad)), "index": ("crc.gzi", index)},
    )
    check(
        "CRC32 corruption rejected",
        status == 422
        and body.get("error", {}).get("code") == "CRC32_MISMATCH"
        and body.get("error", {}).get("offset") == block1_len,
        f"status={status} body={body}",
    )

    # 3) Declared block length corruption: bump BSIZE of block two ---------
    payloads = [b"bsize one", b"bsize two payload" * 8]
    archive = make_archive(payloads)
    index = make_index(archive, payloads)
    block1_len = len(make_block(payloads[0]))
    bad = bytearray(archive)
    bsize_off = block1_len + 16  # BC 'B','C', len lo/hi, then BSIZE lo/hi
    bsize = bad[bsize_off] | (bad[bsize_off + 1] << 8)
    bsize += 64
    bad[bsize_off] = bsize & 0xFF
    bad[bsize_off + 1] = (bsize >> 8) & 0xFF
    status, body = post_multipart(
        "/api/bgzf/audit",
        {"archive": ("bsize.bgzf", bytes(bad)), "index": ("bsize.gzi", index)},
    )
    check(
        "declared block length mismatch rejected",
        status == 422
        and body.get("error", {}).get("code") == "BLOCK_SIZE_MISMATCH"
        and body.get("error", {}).get("offset") == block1_len,
        f"status={status} body={body}",
    )

    # 4) Index drift: compress second pair's compressed offset by -1 -------
    payloads = [b"index one", b"index two payload" * 8]
    archive = make_archive(payloads)
    index = bytearray(make_index(archive, payloads))
    drifted = struct.unpack_from("<Q", bytes(index), 0)[0] - 1
    struct.pack_into("<Q", index, 0, drifted)
    status, body = post_multipart(
        "/api/bgzf/audit",
        {"archive": ("idx.bgzf", archive), "index": ("idx.gzi", bytes(index))},
    )
    check(
        "index offset drift rejected",
        status == 422
        and body.get("error", {}).get("code") == "INDEX_COMPRESSED_OFFSET_MISMATCH"
        and body.get("error", {}).get("offset") == drifted,
        f"status={status} body={body}",
    )

    if failures:
        print(f"\n{len(failures)} smoke check(s) failed")
        return 1
    print("\nall smoke checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
