import { useRef, useState } from "react";
import type { DragEvent } from "react";
import type { Finding, Level, PageId } from "../types";

export const LEVEL_STYLE: Record<Level, { color: string; badge: string }> = {
  none: { color: "#22d3ee", badge: "border-cyan-400/30 bg-cyan-400/10 text-cyan-300" },
  low: { color: "#facc15", badge: "border-yellow-400/30 bg-yellow-400/10 text-yellow-300" },
  medium: { color: "#f59e0b", badge: "border-amber-500/30 bg-amber-500/10 text-amber-300" },
  high: { color: "#f97316", badge: "border-orange-500/30 bg-orange-500/10 text-orange-300" },
  critical: { color: "#ef4444", badge: "border-red-500/40 bg-red-500/10 text-red-300" },
};

const SEVERITY_STYLE: Record<string, string> = {
  low: "bg-yellow-400/10 text-yellow-300",
  medium: "bg-amber-500/10 text-amber-300",
  high: "bg-red-500/10 text-red-300",
};

export function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  let v = bytes / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v < 10 ? 2 : 1)} ${units[i]}`;
}

export function formatDate(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString("vi-VN");
}

export function Panel({ title, children, action }: { title?: string; children: React.ReactNode; action?: React.ReactNode }) {
  return (
    <section className="rounded-xl border border-edge bg-ink-900/80 p-5">
      {(title || action) && (
        <header className="mb-4 flex items-center justify-between">
          {title && <h2 className="text-xs font-semibold uppercase tracking-[0.14em] text-slate-400">{title}</h2>}
          {action}
        </header>
      )}
      {children}
    </section>
  );
}

export function LevelBadge({ level, label }: { level: Level; label: string }) {
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium ${LEVEL_STYLE[level].badge}`}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: LEVEL_STYLE[level].color }} />
      {label}
    </span>
  );
}

export function ScoreRing({ score, level, size = 120 }: { score: number; level: Level; size?: number }) {
  const r = size / 2 - 8;
  const c = 2 * Math.PI * r;
  const color = LEVEL_STYLE[level].color;
  return (
    <div className="relative shrink-0" style={{ width: size, height: size }} aria-label={`Điểm rủi ro ${score} trên 100`}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#172540" strokeWidth="8" />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={color}
          strokeWidth="8"
          strokeLinecap="round"
          strokeDasharray={c}
          strokeDashoffset={c * (1 - Math.min(score, 100) / 100)}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-3xl font-semibold text-slate-100">{score}</span>
        <span className="text-[10px] uppercase tracking-widest text-slate-500">/ 100</span>
      </div>
    </div>
  );
}

export function FindingCard({ finding }: { finding: Finding }) {
  return (
    <article className="rounded-lg border border-edge bg-ink-800/60 p-4">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <p className="text-sm font-medium text-slate-100">{finding.title}</p>
          <p className="mt-0.5 font-mono text-[11px] text-slate-500">{finding.rule_id}</p>
        </div>
        <div className="flex items-center gap-2">
          <span className={`rounded px-2 py-0.5 text-[11px] font-medium uppercase ${SEVERITY_STYLE[finding.severity] ?? "bg-slate-500/10 text-slate-300"}`}>
            {finding.severity}
          </span>
          <span className="font-mono text-xs text-cyan-300">+{finding.points}</span>
        </div>
      </div>
      <p className="mt-2 text-sm text-slate-400">{finding.description}</p>
      <ul className="mt-3 space-y-1">
        {finding.evidence.map((e, i) => (
          <li key={i} className="overflow-x-auto rounded border border-edge bg-ink-950 px-2.5 py-1.5 font-mono text-xs whitespace-pre text-slate-300">
            {e}
          </li>
        ))}
      </ul>
    </article>
  );
}

export function DropZone({ onFile, busy, compact = false }: { onFile: (f: File) => void; busy: boolean; compact?: boolean }) {
  const input = useRef<HTMLInputElement>(null);
  const [over, setOver] = useState(false);

  const handleDrop = (e: DragEvent) => {
    e.preventDefault();
    setOver(false);
    const f = e.dataTransfer.files?.[0];
    if (f && !busy) onFile(f);
  };

  return (
    <div
      onDragOver={(e) => {
        e.preventDefault();
        setOver(true);
      }}
      onDragLeave={() => setOver(false)}
      onDrop={handleDrop}
      onClick={() => !busy && input.current?.click()}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && !busy && input.current?.click()}
      className={`flex cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed text-center transition-colors ${
        compact ? "px-6 py-8" : "px-6 py-20"
      } ${over ? "border-cyan-400 bg-cyan-400/5" : "border-edge hover:border-cyan-400/60 hover:bg-ink-800/50"} ${busy ? "cursor-wait opacity-70" : ""}`}
    >
      <input
        ref={input}
        type="file"
        className="hidden"
        onChange={(e) => {
          const f = e.target.files?.[0];
          if (f) onFile(f);
          e.target.value = "";
        }}
      />
      <div className="mb-3 flex h-11 w-11 items-center justify-center rounded-full bg-cyan-400/10 text-cyan-300">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
          <path d="M12 16V4m0 0 4 4m-4-4-4 4M4 16v3a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-3" />
        </svg>
      </div>
      <p className="text-sm font-medium text-slate-200">{busy ? "Đang phân tích…" : "Kéo thả file vào đây hoặc bấm để chọn"}</p>
      <p className="mt-1 text-xs text-slate-500">File chỉ được đọc và phân tích tĩnh, không bao giờ được chạy.</p>
    </div>
  );
}

const NAV: { id: PageId; label: string }[] = [
  { id: "dashboard", label: "Dashboard" },
  { id: "scanner", label: "File Scanner" },
  { id: "analysis", label: "Analysis" },
  { id: "assistant", label: "AI Assistant" },
  { id: "history", label: "History" },
  { id: "settings", label: "Settings" },
];

export function Sidebar({ page, onNavigate }: { page: PageId; onNavigate: (p: PageId) => void }) {
  return (
    <aside className="flex w-56 shrink-0 flex-col border-r border-edge bg-ink-900">
      <div className="px-5 py-5">
        <p className="text-lg font-semibold tracking-tight text-slate-100">
          Shadow<span className="text-cyan-400">Box</span>
        </p>
        <p className="mt-0.5 text-[11px] text-slate-500">Know your files before you open them.</p>
      </div>
      <nav className="flex-1 space-y-0.5 px-3">
        {NAV.map((n) => (
          <button
            key={n.id}
            onClick={() => onNavigate(n.id)}
            className={`flex w-full items-center rounded-lg px-3 py-2 text-left text-sm transition-colors ${
              page === n.id ? "bg-cyan-400/10 text-cyan-300" : "text-slate-400 hover:bg-ink-800 hover:text-slate-200"
            }`}
          >
            {n.label}
          </button>
        ))}
      </nav>
      <p className="px-5 py-4 text-[11px] leading-snug text-slate-600">Phân tích tĩnh · MVP 1</p>
    </aside>
  );
}
