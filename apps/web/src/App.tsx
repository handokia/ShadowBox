import { useState } from "react";
import { Sidebar } from "./components/ui";
import { Analysis } from "./pages/Analysis";
import { Dashboard } from "./pages/Dashboard";
import { Assistant, History, Scanner, Settings } from "./pages/Others";
import { analyzeFile, loadHistory, saveHistory } from "./services/api";
import type { AnalysisResult, HistoryEntry, PageId } from "./types";

const TITLES: Record<PageId, string> = {
  dashboard: "Dashboard",
  scanner: "File Scanner",
  analysis: "Analysis",
  assistant: "AI Assistant",
  history: "History",
  settings: "Settings",
};

export default function App() {
  const [page, setPage] = useState<PageId>("dashboard");
  const [history, setHistory] = useState<HistoryEntry[]>(loadHistory);
  const [current, setCurrent] = useState<AnalysisResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleFile = async (file: File) => {
    setBusy(true);
    setError(null);
    try {
      const result = await analyzeFile(file);
      const entry: HistoryEntry = { id: crypto.randomUUID(), analyzedAt: new Date().toISOString(), result };
      setHistory((prev) => {
        const next = [entry, ...prev];
        saveHistory(next);
        return next;
      });
      setCurrent(result);
      setPage("analysis");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Lỗi không xác định");
    } finally {
      setBusy(false);
    }
  };

  const open = (e: HistoryEntry) => {
    setCurrent(e.result);
    setPage("analysis");
  };

  const clear = () => {
    setHistory([]);
    saveHistory([]);
  };

  return (
    <div className="flex h-full">
      <Sidebar page={page} onNavigate={setPage} />
      <main className="flex-1 overflow-y-auto">
        <div className="mx-auto max-w-5xl px-8 py-8">
          <h1 className="mb-6 text-xl font-semibold text-slate-100">{TITLES[page]}</h1>
          {page === "dashboard" && <Dashboard history={history} busy={busy} error={error} onFile={handleFile} onOpen={open} />}
          {page === "scanner" && <Scanner busy={busy} error={error} onFile={handleFile} />}
          {page === "analysis" && <Analysis result={current} />}
          {page === "assistant" && <Assistant />}
          {page === "history" && <History history={history} onOpen={open} onClear={clear} />}
          {page === "settings" && <Settings />}
        </div>
      </main>
    </div>
  );
}
