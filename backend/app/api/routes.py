from __future__ import annotations

import os
import tempfile

from fastapi import APIRouter, File, HTTPException, UploadFile

from ..analyzers.inspector import InspectError
from ..analyzers.service import analyze_path
from ..core.config import settings

router = APIRouter(prefix="/api/v1")


@router.get("/health")
def health() -> dict:
    return {"status": "ok"}


@router.post("/analyze")
async def analyze(file: UploadFile = File(...)) -> dict:
    """Nhận file upload, lưu tạm dưới tên ngẫu nhiên (chống path traversal), phân tích, rồi xóa."""
    original_name = file.filename or "unnamed"
    fd, tmp_path = tempfile.mkstemp(prefix="sb_", dir=settings.tmp_dir)
    try:
        written = 0
        with os.fdopen(fd, "wb") as out:
            while chunk := await file.read(1024 * 1024):
                written += len(chunk)
                if written > settings.max_upload_bytes:
                    raise HTTPException(413, f"File vượt quá giới hạn {settings.max_upload_bytes // (1024 * 1024)} MB")
                out.write(chunk)
        try:
            return analyze_path(tmp_path, original_name=original_name).to_dict()
        except InspectError as e:
            raise HTTPException(400, str(e))
    finally:
        try:
            os.remove(tmp_path)
        except FileNotFoundError:
            pass
