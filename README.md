# ShadowBox

**Know your files before you open them.**

Công cụ phân tích tĩnh file trước khi mở: nhận diện dấu hiệu đáng ngờ, chấm điểm rủi ro bằng quy tắc có thể giải thích, và hiển thị bằng chứng cụ thể cho từng phát hiện.

> **Trạng thái: MVP 2** (File Inspector, YARA-X, Script Analyzer, giao diện web). Đây không phải phần mềm chống malware hoàn chỉnh.

## Nguyên tắc thiết kế

- Không bao giờ thực thi file được kiểm tra, không sửa hay xóa file gốc.
- Không tự tải file lên Internet.
- Điểm rủi ro do rule engine quyết định (`rules/`), AI sau này chỉ giải thích kết quả.
- Mọi phát hiện đều kèm bằng chứng (số dòng, offset). Giao diện không bao giờ hiển thị "SAFE", chỉ hiển thị "No threats detected".

## Tính năng hiện có

- **File Inspector:** SHA-256, MD5, nhận diện định dạng thật bằng magic bytes, phát hiện đuôi giả, đuôi kép (`invoice.pdf.exe`), ký tự đảo chiều Unicode trong tên file, macro Office, file thực thi nằm trong ZIP.
- **Script Analyzer** cho PowerShell, BAT/CMD, Python, JavaScript: bỏ qua dòng comment, nhận diện ngôn ngữ từ nội dung khi đuôi file không rõ, trích URL và IP làm IOC tham khảo.
- **YARA-X:** quét trong process riêng có giới hạn thời gian. Nếu chưa cài `yara-x`, các phân tích khác vẫn chạy bình thường.
- **Giao diện web** (React + TypeScript + Tailwind): Dashboard, File Scanner, Analysis, History, Settings. Có xuất kết quả ra JSON.

Các luật hiện là tập khởi đầu và cần hiệu chỉnh bằng file mẫu thật. Một số luật (ví dụ chạy PowerShell ẩn) cũng khớp với script quản trị hợp lệ.

## Yêu cầu

- Python 3.10 trở lên
- Node.js 20 trở lên (cho giao diện web)

## Chạy nhanh trên Windows

Bấm đúp `run-shadowbox.bat` ở thư mục gốc. File này tự tạo môi trường ảo, cài thư viện, mở backend (cổng 8000) và giao diện (cổng 5173) trong hai cửa sổ riêng, rồi mở trình duyệt. Đóng hai cửa sổ đó để dừng.

## Chạy thủ công

Mở hai terminal.

**Terminal 1: backend**
```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r backend\requirements.txt
cd backend
uvicorn app.main:app --host 127.0.0.1 --port 8000
```
Tài liệu API: http://127.0.0.1:8000/docs. Endpoint phân tích: `POST /api/v1/analyze` (multipart, trường `file`).

**Terminal 2: giao diện web**
```powershell
cd apps\web
npm install
npm run dev
```
Mở http://127.0.0.1:5173.

## Chạy bằng dòng lệnh, không cần giao diện

```powershell
cd backend
python -m app.cli C:\duong\dan\toi\file
```
Kết quả in ra dạng JSON.

## Kiểm thử

Từ thư mục gốc (đã kích hoạt môi trường ảo):
```powershell
python -m unittest discover -s tests -v
```
Các test dùng YARA-X thật sẽ tự bỏ qua nếu chưa cài `yara-x`. Test symlink bị bỏ qua trên Windows nếu chưa bật Developer Mode.

## Cấu hình

| Biến môi trường | Mặc định | Ý nghĩa |
|---|---|---|
| `SHADOWBOX_MAX_UPLOAD_MB` | 50 | Giới hạn dung lượng upload |
| `SHADOWBOX_RULES` | `rules/risk/default.json` | Mức rủi ro và luật tín hiệu |
| `SHADOWBOX_SCRIPT_RULES` | `rules/scripts` | Thư mục luật Script Analyzer |
| `SHADOWBOX_YARA_RULES` | `rules/yara` | Thư mục luật YARA |
| `SHADOWBOX_YARA_TIMEOUT` | 20 | Thời gian tối đa quét YARA (giây) |
| `SHADOWBOX_YARA_MAX_MB` | 64 | File lớn hơn mức này bỏ qua bước YARA |
| `SHADOWBOX_TMP_DIR` | thư mục tạm hệ thống | Nơi lưu file upload tạm |
| `VITE_API_URL` (web) | `http://127.0.0.1:8000` | Địa chỉ backend, đặt trong `apps/web/.env` |

## Cấu trúc thư mục

```
backend/app/analyzers/          File Inspector (hash, magic bytes, đuôi giả, ZIP/OOXML)
backend/app/analyzers/scripts/  Script Analyzer theo từng ngôn ngữ
backend/app/scanners/           Rule engine và tích hợp YARA-X
backend/app/api/                FastAPI routes
rules/risk/default.json         Mức rủi ro và luật tín hiệu từ Inspector
rules/scripts/                  Luật PowerShell, BAT/CMD, Python, JavaScript
rules/yara/                     Luật YARA-X (*.yar)
apps/web/                       Giao diện React + Vite + Tailwind
apps/desktop/                   Chưa khởi tạo (dự kiến Tauri 2)
docs/security-notes.md          Ghi chú bảo mật triển khai
tests/                          Unit test
```

## Giới hạn bảo mật đã biết

- Worker YARA chạy trong process riêng có timeout, nhưng trên Windows chưa giới hạn RAM và chưa chặn mạng.
- Lịch sử phân tích hiện lưu trong localStorage của trình duyệt (chỉ kết quả, không lưu file).
- Chi tiết xem `docs/security-notes.md`.

## Lộ trình

- [x] **MVP 1:** File Inspector, hash, rule engine cơ bản
- [x] **MVP 2 (một phần):** YARA-X, Script Analyzer, giao diện web
- [ ] **MVP 2 (còn lại):** AI Explainer (Ollama hoặc API tương thích), xuất báo cáo HTML/PDF
- [ ] **MVP 3:** phân tích APK và PE nâng cao, VirusTotal tùy chọn, lịch sử bằng SQLite, đóng gói Desktop bằng Tauri

## Giấy phép

MIT. Xem file `LICENSE`.
