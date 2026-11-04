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
- **Giao diện web** (React + TypeScript + Tailwind): Dashboard, File Scanner,
