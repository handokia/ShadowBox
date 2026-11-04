import type { AnalysisResult, HistoryEntry } from "../types";

export const API_URL: string = import.meta.env.VITE_API_URL ?? "http://127.0.0.1:8000";

export async function analyzeFile(file: File): Promise<AnalysisResult> {
  const body = new FormData();
  body.append("file", file, file.name);
  let res: Response;
  try {
    res = await fetch(`${API_URL}/api/v1/analyze`, { method: "POST", body });
  } catch {
    throw new Error(`Không kết nối được backend tại ${API_URL}. Hãy chạy uvicorn trong thư mục backend.`);
  }
  if (!res.ok) {
    let detail = `Lỗi ${res.status}`;
    try {
      const data = await res.json();
      if (typeof data.detail === "string") detail = data.detail;
    } catch {
      /* giữ thông báo mặc định */
    }
    throw new Error(detail);
  }
  return (await res.json()) as AnalysisResult;
}

export async function checkHealth(): Promise<boolean> {
  try {
    const res = await fetch(`${API_URL}/api/v1/health`);
    return res.ok;
  } catch {
    return false;
  }
}

const KEY = "shadowbox.history.v1";
const MAX_ENTRIES = 100;

export function loadHistory(): HistoryEntry[] {
  try {
    const raw = localStorage.getItem(KEY);
    return raw ? (JSON.parse(raw) as HistoryEntry[]) : [];
  } catch {
    return [];
  }
}

export function saveHistory(entries: HistoryEntry[]): void {
  try {
    localStorage.setItem(KEY, JSON.stringify(entries.slice(0, MAX_ENTRIES)));
  } catch {
    /* localStorage đầy hoặc bị chặn: bỏ qua, lịch sử chỉ còn trong phiên */
  }
}
