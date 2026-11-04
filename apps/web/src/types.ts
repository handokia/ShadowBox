export type Level = "none" | "low" | "medium" | "high" | "critical";

export interface Finding {
  rule_id: string;
  title: string;
  severity: string;
  points: number;
  description: string;
  evidence: string[];
}

export interface FileInfo {
  name: string;
  extension: string;
  size: number;
  md5: string;
  sha256: string;
  modified: string | null;
  created: string | null;
  detected: { id: string; label: string; category: string };
  content_class: string;
  metadata: Record<string, unknown>;
  signals: Record<string, string[]>;
}

export interface AnalysisResult {
  file: FileInfo;
  score: number;
  level: Level;
  verdict: string;
  findings: Finding[];
  disclaimer: string;
  rules_version: number;
}

export interface HistoryEntry {
  id: string;
  analyzedAt: string;
  result: AnalysisResult;
}

export type PageId = "dashboard" | "scanner" | "analysis" | "assistant" | "history" | "settings";
