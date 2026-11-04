# Ghi chú bảo mật triển khai

- Upload lưu bằng tên ngẫu nhiên (`mkstemp`), tên client chỉ dùng để hiển thị và tạo tín hiệu. File tạm luôn bị xóa trong `finally`.
- Giới hạn dung lượng upload theo luồng (mặc định 50 MB).
- Inspector dùng `lstat`, từ chối symlink; ZIP chỉ đọc danh sách entry, không giải nén.
- Ký tự điều khiển/bidi trong tên file bị escape khi trả ra.
- API chỉ bind 127.0.0.1 khi chạy local; CORS chỉ cho origin dev và Tauri.

## Việc cần làm ở MVP 2 (chưa có trong khung này)
- Chạy parser nặng (pefile, LIEF, PyMuPDF, Androguard, YARA) trong process con có giới hạn thời gian/RAM, không quyền mạng, không chạy bằng Administrator.
- Giới hạn tổng dung lượng giải nén của ZIP khi cần đọc nội dung.
- AI chỉ nhận bằng chứng đã chọn lọc; hỏi đồng ý trước khi gửi bất cứ gì lên Cloud.

## MVP 2: YARA-X và Script Analyzer (đã triển khai)
- YARA-X chạy trong process con (`app.scanners.yara_worker`) với timeout (`SHADOWBOX_YARA_TIMEOUT`, mặc định 20s), môi trường rút gọn, giới hạn dung lượng (`SHADOWBOX_YARA_MAX_MB`, mặc định 64). Trên Linux/macOS worker còn bị giới hạn RAM 1 GB.
- Chưa có: giới hạn RAM trên Windows (cần Job Object), chặn mạng cho worker, chạy dưới tài khoản hạn chế. Vẫn là việc cần làm trước khi coi parser là cách ly hoàn chỉnh.
- Script Analyzer chỉ đọc văn bản, bỏ qua dòng comment, không thực thi gì. URL và IP trích ra chỉ là IOC tham khảo, không tự tra cứu hay truy cập.
- Luật script nằm ở `rules/scripts/*.json`, luật YARA ở `rules/yara/*.yar`. Đều là tập khởi đầu cần hiệu chỉnh bằng file mẫu thật.
