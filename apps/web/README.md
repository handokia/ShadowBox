# apps/web

Giao diện Dark Cybersecurity Dashboard (React + TypeScript + Vite + Tailwind CSS 4).

```powershell
cd apps\web
npm install
npm run dev        # http://127.0.0.1:5173
npm run build      # kiểm tra kiểu + build production
```

Cần backend đang chạy (`uvicorn app.main:app --host 127.0.0.1 --port 8000` trong thư mục `backend`).
Đổi địa chỉ backend bằng `VITE_API_URL` trong `apps/web/.env`.

Màn hình: Dashboard, File Scanner, Analysis, History, Settings. AI Assistant là placeholder (MVP 2).
Lịch sử đang lưu trong localStorage của trình duyệt, sẽ chuyển sang SQLite ở MVP 3.
Chưa dùng shadcn/ui, có thể thêm sau khi giao diện ổn định.
