import { DropZone, LevelBadge, Panel, formatDate, formatSize } from "../components/ui";
import type { HistoryEntry } from "../types";

function Stat({ label, value, hint }: { label: string; value: number; hint: string }) {
  return (
    <div className="rounded-xl border border-edge bg-ink-900/80 p-5">
      <p className="text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">{label}</p>
      <p className="mt-2 text-3xl font-semibold text-slate-100">{value}</p>
      <p className="mt-1 text-xs text-slate-500">{hint}</p>
    </div>
  );
}

export function RecentList({ entries, onOpen }: { entries: HistoryEntry[]; onOpen: (e: HistoryEntry) => void }) {
  if (entries.length === 0) return <p className="text-sm text-slate-500">Chưa có lần phân tích nào.</p>;
  return (
    <ul className="divide-y divide-edge">
      {entries.map((e) => (
        <li key={e.id}>
          <button onClick={() => onOpen(e)} className="flex w-full items-center justify-between gap-4 py-3 text-left hover:bg-ink-800/50">
            <div className="min-w-0">
              <p className="truncate text-sm text-slate-200">{e.result.file.name}</p>
              <p className="text-xs text-slate-500">
                {e.result.file.detected.label} · {formatSize(e.result.file.size)} · {formatDate(e.analyzedAt)}
              </p>
            </div>
            <div className="flex shrink-0 items-center gap-3">
              <span className="font-mono text-sm text-slate-300">{e.result.score}</span>
              <LevelBadge level={e.result.level} label={e.result.verdict} />
            </div>
          </button>
        </li>
      ))}
    </ul>
  );
}

export function Dashboard({
  history,
  busy,
  error,
  onFile,
  onOpen,
}: {
  history: HistoryEntry[];
  busy: boolean;
  error: string | null;
  onFile: (f: File) => void;
  onOpen: (e: HistoryEntry) => void;
}) {
  const suspicious = history.filter((h) => h.result.level !== "none").length;
  const clean = history.length - suspicious;
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <Stat label="Total Scans" value={history.length} hint="Tổng số file đã quét" />
        <Stat label="Suspicious Files" value={suspicious} hint="Có ít nhất một dấu hiệu đáng ngờ" />
        <Stat label="Clean Indicators" value={clean} hint="No threats detected (không đồng nghĩa an toàn)" />
      </div>
      <Panel title="Quick Scan">
        <DropZone onFile={onFile} busy={busy} compact />
        {error && <p className="mt-3 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-300">{error}</p>}
      </Panel>
      <Panel title="Recent Analysis">
        <RecentList entries={history.slice(0, 5)} onOpen={onOpen} />
      </Panel>
    </div>
  );
}
