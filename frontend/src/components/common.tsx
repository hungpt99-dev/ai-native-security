import { ChevronLeft, ChevronRight, Inbox, AlertTriangle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { FindingStatus, ScanStatus, Severity } from "@/lib/types";

const severityTone: Record<Severity, "critical" | "high" | "medium" | "low" | "info" | "neutral"> = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  INFO: "info",
  UNKNOWN: "neutral",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <Badge tone={severityTone[severity] ?? "neutral"}>{severity}</Badge>;
}

const findingStatusTone: Record<FindingStatus, "danger" | "running" | "neutral" | "success" | "medium"> = {
  OPEN: "danger",
  CONFIRMED: "medium",
  FALSE_POSITIVE: "neutral",
  ACCEPTED_RISK: "running",
  RESOLVED: "success",
};

export function FindingStatusBadge({ status }: { status: FindingStatus }) {
  return <Badge tone={findingStatusTone[status] ?? "neutral"}>{status.replace("_", " ")}</Badge>;
}

const scanStatusTone: Record<ScanStatus, "success" | "running" | "danger" | "neutral" | "medium"> = {
  COMPLETED: "success",
  RUNNING: "running",
  PENDING: "medium",
  FAILED: "danger",
  CANCELED: "neutral",
};

export function ScanStatusBadge({ status }: { status: ScanStatus }) {
  return <Badge tone={scanStatusTone[status] ?? "neutral"}>{status}</Badge>;
}

export function PageHeader({
  title,
  subtitle,
  actions,
}: {
  title: string;
  subtitle?: string;
  actions?: React.ReactNode;
}) {
  return (
    <div className="mb-6 flex flex-wrap items-start justify-between gap-3">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-white">{title}</h1>
        {subtitle ? <p className="mt-1 text-sm text-slate-400">{subtitle}</p> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}

export function EmptyState({
  title,
  description,
  action,
}: {
  title: string;
  description?: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 px-6 py-16 text-center">
      <div className="rounded-full border border-slate-700 bg-slate-800/60 p-3">
        <Inbox className="h-5 w-5 text-slate-400" />
      </div>
      <div>
        <p className="font-medium text-slate-200">{title}</p>
        {description ? <p className="mt-1 text-sm text-slate-400">{description}</p> : null}
      </div>
      {action}
    </div>
  );
}

export function ErrorState({ error }: { error: unknown }) {
  const message = error instanceof Error ? error.message : "Unexpected error";
  return (
    <div className="m-4 flex items-start gap-3 rounded-lg border border-rose-500/30 bg-rose-500/10 p-4 text-sm text-rose-200">
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
      <div>
        <p className="font-medium">Could not load data</p>
        <p className="text-rose-300/80">{message}</p>
      </div>
    </div>
  );
}

export function Pagination({
  page,
  pages,
  total,
  pageSize,
  onPageChange,
}: {
  page: number;
  pages: number;
  total: number;
  pageSize: number;
  onPageChange: (page: number) => void;
}) {
  if (total === 0) return null;
  const start = (page - 1) * pageSize + 1;
  const end = Math.min(page * pageSize, total);
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-800 px-4 py-3 text-sm text-slate-400">
      <span>
        Showing {start}–{end} of {total}
      </span>
      <div className="flex items-center gap-2">
        <Button
          variant="outline"
          size="sm"
          onClick={() => onPageChange(page - 1)}
          disabled={page <= 1}
        >
          <ChevronLeft className="h-4 w-4" /> Prev
        </Button>
        <span className="tabular-nums">
          {page} / {Math.max(pages, 1)}
        </span>
        <Button
          variant="outline"
          size="sm"
          onClick={() => onPageChange(page + 1)}
          disabled={page >= pages}
        >
          Next <ChevronRight className="h-4 w-4" />
        </Button>
      </div>
    </div>
  );
}

export function KeyValue({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <dt className="label">{label}</dt>
      <dd className="mt-1 text-sm text-slate-200">{children}</dd>
    </div>
  );
}

export function Mono({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <span className={cn("font-mono text-xs text-slate-300", className)}>{children}</span>
  );
}
