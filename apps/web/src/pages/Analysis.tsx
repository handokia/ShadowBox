import { FindingCard, LevelBadge, Panel, ScoreRing, formatDate, formatSize } from "../components/ui";
import type { AnalysisResult } from "../types";

interface ScriptInfo {
  language: string;
  display_name: string;
  language_source: "extension" | "content";
  iocs: { urls: string[]; ips: string[] };
}

interface YaraInfo {
  status: "ok" | "unavailable" | "timeout" | "skipped_too_large" | "error";
  rules_loaded?: number;
  rule_errors?: string[];
  error?: string;
}

const YARA_TEXT: Record<YaraInfo["status"], (i: YaraInfo) => string> = {
  ok: (i) => `Đã quét bằng YARA-X với ${i.rules_loaded ?? 0} luật.`,
  unavailable: () => "YARA-X chưa được cài trên backend (pip install yara-x). Các phân tích khác vẫn chạy bình thường.",
  timeout: () => "Quét YARA vượt quá thời gian cho phép và đã bị dừng.",
  skipped_too_large: () => "File quá lớn nên bỏ qua bước YARA.",
  error: (i) => `Quét YARA gặp lỗi: ${i.error ?? "không rõ"}`,
};

function Field({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="text-[11px] uppercase tracking-widest text-slate-500">{label}</dt>
      <dd className={`mt-0.5 break-all text-sm text-slate-200 ${mono ? "font-mono text-xs" : ""}`}>{value}</dd>
    </div>
  );
}

function IocList({ label, items }: { label: string; items: string[] }) {
  if (items.length === 0) return null;
  return (
    <div>
      <p className="text-[11px] uppercase tracking-widest text-slate-500">{label}</p>
      <ul className="mt-1 space-y-1">
        {items.map((x) => (
          <li key={x} className="overflow-x-auto rounded border border-edge bg-ink-950 px-2.5 py-1 font-mono text-xs whitespace-pre text-slate-300">
            {x}
          </li>
        ))}
      </ul>
    </div>
  );
}

function exportJson(result: AnalysisResult) {
  const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `shadowbox-${result.file.sha256.slice(0, 12)}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

export function Analysis({ result }: { result: AnalysisResult | null }) {
  if (!result) {
    return (
      <Panel>
        <p className="text-sm text-slate-400">Chưa có kết quả. Hãy quét một file ở màn hình File Scanner hoặc chọn một mục trong History.</p>
      </Panel>
    );
  }
  const f = result.file;
  const script = f.metadata.script as ScriptInfo | undefined;
  const yara = f.metadata.yara as YaraInfo | undefined;
  return (
    <div className="space-y-6">
      <Panel>
        <div className="flex flex-wrap items-center gap-6">
          <ScoreRing score={result.score} level={result.level} />
          <div className="min-w-0 flex-1">
            <p className="break-all text-lg font-semibold text-slate-100">{f.name}</p>
            <div className="mt-2 flex items-center gap-3">
              <LevelBadge level={result.level} label={result.verdict} />
              <span className="text-xs text-slate-500">
                {result.findings.length} phát hiện · rules v{result.rules_version}
              </span>
            </div>
            <p className="mt-3 text-xs leading-relaxed text-slate-500">{result.disclaimer}</p>
          </div>
          <button onClick={() => exportJson(result)} className="rounded-lg border border-edge px-3 py-1.5 text-xs text-slate-300 hover:border-cyan-400/50 hover:text-cyan-300">
            Export JSON
          </button>
        </div>
      </Panel>

      <Panel title="Findings">
        {result.findings.length === 0 ? (
          <p className="text-sm text-slate-400">Không có quy tắc nào khớp. Điều này không bảo đảm file an toàn.</p>
        ) : (
          <div className="space-y-3">
            {result.findings.map((x) => (
              <FindingCard key={x.rule_id} finding={x} />
            ))}
          </div>
        )}
      </Panel>

      {(script || yara) && (
        <Panel title="Script & YARA">
          <div className="space-y-4">
            {script && (
              <>
                <dl className="grid grid-cols-1 gap-4 md:grid-cols-2">
                  <Field label="Ngôn ngữ script" value={script.display_name} />
                  <Field label="Cách nhận diện" value={script.language_source === "extension" ? "Theo đuôi file" : "Suy ra từ nội dung"} />
                </dl>
                <IocList label="URL xuất hiện trong script (chỉ để tham khảo)" items={script.iocs.urls} />
                <IocList label="Địa chỉ IP xuất hiện trong script (chỉ để tham khảo)" items={script.iocs.ips} />
              </>
            )}
            {yara && (
              <div>
                <p className="text-sm text-slate-300">{YARA_TEXT[yara.status]?.(yara) ?? "Không rõ trạng thái YARA."}</p>
                {yara.rule_errors && yara.rule_errors.length > 0 && (
                  <ul className="mt-2 space-y-1">
                    {yara.rule_errors.map((e) => (
                      <li key={e} className="font-mono text-xs text-amber-300">
                        {e}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}
          </div>
        </Panel>
      )}

      <Panel title="File Details">
        <dl className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <Field label="Định dạng thực tế" value={f.detected.label} />
          <Field label="Phần mở rộng" value={f.extension || "(không có)"} />
          <Field label="Dung lượng" value={`${formatSize(f.size)} (${f.size.toLocaleString("vi-VN")} byte)`} />
          <Field label="Loại nội dung" value={f.content_class} />
          <Field label="Sửa đổi lần cuối" value={formatDate(f.modified)} />
          <Field label="Thời điểm tạo" value={formatDate(f.created)} />
          <div className="md:col-span-2">
            <Field label="SHA-256" value={f.sha256} mono />
          </div>
          <div className="md:col-span-2">
            <Field label="MD5" value={f.md5} mono />
          </div>
        </dl>
      </Panel>
    </div>
  );
}
