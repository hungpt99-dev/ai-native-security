import { Link, useParams } from "react-router-dom";
import { ArrowLeft, Ban, SquareTerminal } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ErrorState, KeyValue, Mono, PageHeader, ScanStatusBadge, SeverityBadge } from "@/components/common";
import { TableSkeleton } from "@/components/ui/skeleton";
import { useCancelScan, useScan } from "@/hooks/queries";
import { formatDate, formatDuration, shortSha } from "@/lib/utils";

const executionTone: Record<string, "success" | "danger" | "neutral" | "running" | "medium"> = {
  SUCCESS: "success",
  FAILED: "danger",
  TIMED_OUT: "danger",
  SKIPPED: "neutral",
  RUNNING: "running",
  PENDING: "medium",
};

export function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { data: scan, isLoading, error } = useScan(id);
  const cancelScan = useCancelScan();

  if (error) return <ErrorState error={error} />;
  if (isLoading || !scan) return <TableSkeleton rows={5} columns={4} />;

  const active = scan.status === "PENDING" || scan.status === "RUNNING";

  return (
    <div>
      <Link to="/scans" className="mb-4 inline-flex items-center gap-1 text-xs text-slate-400 hover:text-cyan-300">
        <ArrowLeft className="h-3.5 w-3.5" /> Back to scans
      </Link>
      <PageHeader
        title={`Scan ${shortSha(scan.id)}`}
        subtitle={scan.asset_name ? `${scan.asset_name} · ${scan.asset_repo_url}` : scan.asset_id}
        actions={
          <>
            <ScanStatusBadge status={scan.status} />
            {active ? (
              <Button variant="danger" onClick={() => void cancelScan.mutateAsync(scan.id)} disabled={cancelScan.isPending}>
                <Ban className="h-4 w-4" /> Cancel
              </Button>
            ) : null}
            <Link
              to={`/findings?scan_id=${scan.id}`}
              className="inline-flex h-9 items-center rounded-lg border border-slate-700 px-3 text-sm text-slate-200 hover:bg-slate-800/70"
            >
              View findings ({scan.total_findings})
            </Link>
          </>
        }
      />

      {scan.error_message ? (
        <div className="mb-4 rounded-lg border border-rose-500/30 bg-rose-500/10 p-4 text-sm text-rose-200">
          <p className="font-medium">Scan error</p>
          <p className="mt-1 whitespace-pre-wrap break-words font-mono text-xs text-rose-200/80">
            {scan.error_message}
          </p>
        </div>
      ) : null}

      <div className="grid gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle>Summary</CardTitle>
          </CardHeader>
          <CardContent>
            <dl className="grid grid-cols-2 gap-4">
              <KeyValue label="Started">{formatDate(scan.started_at)}</KeyValue>
              <KeyValue label="Finished">{formatDate(scan.finished_at)}</KeyValue>
              <KeyValue label="Duration">{formatDuration(scan.duration_seconds)}</KeyValue>
              <KeyValue label="Trigger">{scan.trigger}</KeyValue>
              <KeyValue label="Branch">
                <Mono>{scan.branch ?? "—"}</Mono>
              </KeyValue>
              <KeyValue label="Commit">
                <Mono>{shortSha(scan.commit_sha)}</Mono>
              </KeyValue>
              <KeyValue label="New findings">{scan.new_findings}</KeyValue>
              <KeyValue label="Resolved">{scan.resolved_findings}</KeyValue>
            </dl>
          </CardContent>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Findings by severity</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
              {(
                [
                  ["CRITICAL", scan.critical_count],
                  ["HIGH", scan.high_count],
                  ["MEDIUM", scan.medium_count],
                  ["LOW", scan.low_count],
                  ["INFO", scan.info_count],
                  ["UNKNOWN", scan.unknown_count],
                ] as const
              ).map(([severity, count]) => (
                <div key={severity} className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
                  <SeverityBadge severity={severity} />
                  <p className="mt-2 text-2xl font-semibold tabular-nums text-white">{count}</p>
                </div>
              ))}
            </div>
            <p className="mt-4 text-xs text-slate-500">
              Totals count findings detected by this scan; deduplication keeps one record per finding across scans.
            </p>
          </CardContent>
        </Card>
      </div>

      <Card className="mt-4">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <SquareTerminal className="h-4 w-4" /> Scanner executions
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {!scan.executions || scan.executions.length === 0 ? (
            <p className="text-sm text-slate-500">No scanner executions recorded yet.</p>
          ) : (
            scan.executions.map((execution) => (
              <div key={execution.id} className="rounded-lg border border-slate-800 bg-slate-900/40 p-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm text-slate-200">{execution.scanner}</span>
                    <Badge tone={executionTone[execution.status] ?? "neutral"}>{execution.status}</Badge>
                    {execution.version ? (
                      <span className="text-xs text-slate-500">{execution.version}</span>
                    ) : null}
                  </div>
                  <div className="flex gap-4 text-xs text-slate-500">
                    <span>{execution.result_count} findings</span>
                    <span>{formatDuration(execution.duration_seconds)}</span>
                    <span>exit {execution.exit_code ?? "—"}</span>
                  </div>
                </div>
                {execution.error_message ? (
                  <p className="mt-2 whitespace-pre-wrap break-words rounded bg-rose-500/10 p-2 font-mono text-xs text-rose-200">
                    {execution.error_message}
                  </p>
                ) : null}
                {execution.stderr_excerpt ? (
                  <details className="mt-2">
                    <summary className="cursor-pointer text-xs text-slate-400">stderr</summary>
                    <pre className="mt-1 max-h-48 overflow-auto whitespace-pre-wrap break-words rounded bg-slate-950/80 p-2 font-mono text-[11px] text-slate-400">
                      {execution.stderr_excerpt}
                    </pre>
                  </details>
                ) : null}
                {execution.command?.argv ? (
                  <details className="mt-2">
                    <summary className="cursor-pointer text-xs text-slate-400">command</summary>
                    <pre className="mt-1 overflow-auto whitespace-pre-wrap break-words rounded bg-slate-950/80 p-2 font-mono text-[11px] text-slate-500">
                      {execution.command.argv.join(" ")}
                    </pre>
                  </details>
                ) : null}
              </div>
            ))
          )}
        </CardContent>
      </Card>
    </div>
  );
}
