import { useState } from "react";
import { DropZone, Panel } from "../components/ui";
import { API_URL, checkHealth } from "../services/api";
import type { HistoryEntry } from "../types";
import { RecentList } from "./Dashboard";

export function Scanner({ busy, error, onFile }: { busy: boolean; error: string | null; onFile: (f: File) => void }) {
  return (
    <div className="space-y-4">
      <DropZone onFile={onFile} busy={busy} />
      {error && <p className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-300">{error}</p>}
      <p className="text-xs text-slate-500">
        File được gửi tới backend tại {API_URL}, lưu tạm dưới tên ngẫu nhiên và xóa ngay sau khi phân tích. Không có gì được tải lên Internet.
      </p>
    </div>
  );
}

export function History({ history, onOpen, onClear }: { history: HistoryEntry[]; onOpen: (e: HistoryEntry) => void; onClear: () => void }) {
  return (
    <Panel
      title="Lịch sử phân tích"
      action={
        history.length > 0 && (
          <button onClick={onClear} className="text-xs text-slate-500 hover:text-red-300">
            Xóa lịch sử
          </button>
        )
      }
    >
      <RecentList entries={history} onOpen={onOpen} />
      <p className="mt-4 text-[11px] text-slate-600">Lịch sử hiện lưu trong trình duyệt (chỉ kết quả, không lưu file). SQLite sẽ thay thế ở MVP 3.</p>
    </Panel>
  );
}

export function Assistant() {
  return (
    <Panel title="AI Assistant">
      <p className="text-sm text-slate-300">Sắp có ở MVP 2.</p>
      <p className="mt-2 text-sm text-slate-500">
        AI chỉ giải thích kết quả phân tích và trả lời câu hỏi về bằng chứng đã có. Điểm rủi ro luôn do rule engine quyết định, và chỉ dữ liệu bạn đồng ý mới được gửi lên Cloud.
      </p>
    </Panel>
  );
}

export function Settings() {
  const [status, setStatus] = useState<"idle" | "ok" | "fail" | "checking">("idle");
  const test = async () => {
    setStatus("checking");
    setStatus((await checkHealth()) ? "ok" : "fail");
  };
  return (
    <Panel title="Settings">
      <dl className="space-y-3 text-sm">
        <div>
          <dt className="text-[11px] uppercase tracking-widest text-slate-500">Backend URL</dt>
          <dd className="mt-0.5 font-mono text-xs text-slate-200">{API_URL}</dd>
        </div>
      </dl>
      <div className="mt-4 flex items-center gap-3">
        <button onClick={test} className="rounded-lg border border-edge px-3 py-1.5 text-xs text-slate-300 hover:border-cyan-400/50 hover:text-cyan-300">
          Kiểm tra kết nối
        </button>
        {status === "checking" && <span className="text-xs text-slate-500">Đang kiểm tra…</span>}
        {status === "ok" && <span className="text-xs text-cyan-300">Backend phản hồi bình thường</span>}
        {status === "fail" && <span className="text-xs text-red-300">Không kết nối được backend</span>}
      </div>
      <p className="mt-4 text-[11px] text-slate-600">Đổi địa chỉ bằng biến VITE_API_URL trong file .env của apps/web. Cấu hình AI sẽ có ở MVP 2.</p>
    </Panel>
  );
}
