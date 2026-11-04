# ShadowBox

**Know your files before you open them.**
AI-powered file security analyzer. Phân tích tĩnh file trước khi mở, nhận diện dấu hiệu đáng ngờ, giải thích rủi ro.

> Trạng thái: **MVP 2 (YARA-X + Script Analyzer)**. Đây không phải phần mềm chống malware hoàn chỉnh.

## Nguyên tắc
- Không thực thi file được kiểm tra, không sửa/xóa file gốc.
- Không tự tải file lên Internet.
- Điểm rủi ro do **rule engine** quyết định (rules/risk/default.json), AI chỉ giải thích.
- Mọi finding đều kèm bằng chứng. Không hiển thị "SAFE", chỉ "No threats detected".

## Chạy thử (không cần cài gì thêm, chỉ Python 3.10+)
```bash
cd backend
python -m app.cli /duong/dan/toi/file
cd .. && python -m unittest discover -s tests -v
```

## Chạy API
```bash
cd backend
python -m venv .venv && .venv\Scripts\activate    # Windows
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000
# Docs: http://127.0.0.1:8000/docs   |   POST /api/v1/analyze (multipart, field "file")
```
Biến môi trường: `SHADOWBOX_MAX_UPLOAD_MB` (mặc định 50), `SHADOWBOX_RULES`, `SHADOWBOX_TMP_DIR`.

## Cấu trúc
```
backend/app/analyzers/   File Inspector (hash, magic bytes, đuôi giả, ZIP/OOXML)
backend/app/analyzers/scripts/  Script Analyzer theo ngôn ngữ (bỏ comment, IOC, nhận diện từ nội dung)
backend/app/scanners/    Rule engine chấm điểm + tích hợp YARA-X (process con, timeout)
backend/app/api/         FastAPI routes
rules/risk/default.json  Quy tắc và trọng số (chỉnh không cần sửa code)
rules/yara/              Luật YARA-X (*.yar)
rules/scripts/           Luật theo ngôn ngữ: PowerShell, BAT/CMD, Python, JavaScript
apps/web, apps/desktop   (chưa khởi tạo: React + Vite, Tauri 2)
```

## Lộ trình
MVP 1: Inspector + hash + rule cơ bản (xong phần backend) · MVP 2: YARA, Script Analyzer, AI Explainer, Report · MVP 3: APK, PE nâng cao, VirusTotal, lịch sử, Desktop.
