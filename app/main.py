"""FastAPI application exposing POST /api/bgzf/audit."""

from __future__ import annotations

import os

from fastapi import FastAPI, File, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from .bgzf import AuditError, audit

app = FastAPI(title="BGZF Archive Audit", version="1.0.0")

# Multipart uploads must stay in the 8 MiB envelope (plus index / overhead).
MAX_UPLOAD_BYTES = 16 * 1024 * 1024


def _error(code: str, message: str, offset: int, status: int = 422) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": {"code": code, "message": message, "offset": offset}},
    )


@app.exception_handler(RequestValidationError)
async def _malformed_request(_: Request, exc: RequestValidationError) -> JSONResponse:
    # Missing fields / wrong multipart shape: stable code, no partial result.
    return _error(
        "MALFORMED_REQUEST",
        "request must be multipart/form-data with 'archive' and 'index' files: "
        + "; ".join(e["msg"] for e in exc.errors()),
        0,
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/bgzf/audit")
async def audit_endpoint(
    archive: UploadFile = File(...),
    index: UploadFile = File(...),
) -> JSONResponse:
    archive_bytes = await archive.read(MAX_UPLOAD_BYTES + 1)
    index_bytes = await index.read(MAX_UPLOAD_BYTES + 1)
    if len(archive_bytes) > MAX_UPLOAD_BYTES or len(index_bytes) > MAX_UPLOAD_BYTES:
        return _error(
            "UPLOAD_TOO_LARGE",
            "uploaded file exceeds the accepted size limit",
            0,
            status=413,
        )

    try:
        result = audit(archive_bytes, index_bytes)
    except AuditError as exc:
        # Atomic failure: no partial results are ever returned.
        return _error(exc.code, exc.message, exc.offset)

    return JSONResponse(
        status_code=200,
        content={
            "block_count": result.block_count,
            "uncompressed_size": result.uncompressed_size,
            "sha256": result.sha256,
        },
    )


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", "8080"))
    uvicorn.run(app, host="0.0.0.0", port=port)
