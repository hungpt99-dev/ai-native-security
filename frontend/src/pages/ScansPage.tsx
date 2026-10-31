import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Card } from "@/components/ui/card";
import { Input, Label } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { EmptyState, ErrorState, PageHeader, Pagination, ScanStatusBadge, SeverityBadge } from "@/components/common";
import { TableSkeleton } from "@/components/ui/skeleton";
import { useScans } from "@/hooks/queries";
import { formatDuration, formatRelative, shortSha } from "@/lib/utils";

export function ScansPage() {
  const [page, setPage] = useState(1);
  const [status, setStatus] = useState("all");
  const [trigger, setTrigger] = useState("all");

  const params = useMemo(
    () => ({
      page,
      page_size: 20,
      status: status === "all" ? undefined : status,
      trigger: trigger === "all" ? undefined : trigger,
    }),
    [page, status, trigger],
  );

  const { data, isLoading, error } = useScans(params);

  return (
    <div>
      <PageHeader title="Scans" subtitle="Every scan run across all monitored repositories" />

      <div className="mb-4 flex flex-wrap gap-2">
        <div className="w-44">
          <Label>Status</Label>
          <Select value={status} onValueChange={(value) => { setPage(1); setStatus(value); }}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All statuses</SelectItem>
              <SelectItem value="PENDING">Pending</SelectItem>
              <SelectItem value="RUNNING">Running</SelectItem>
              <SelectItem value="COMPLETED">Completed</SelectItem>
              <SelectItem value="FAILED">Failed</SelectItem>
              <SelectItem value="CANCELED">Canceled</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="w-44">
          <Label>Trigger</Label>
          <Select value={trigger} onValueChange={(value) => { setPage(1); setTrigger(value); }}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All triggers</SelectItem>
              <SelectItem value="MANUAL">Manual</SelectItem>
              <SelectItem value="SCHEDULED">Scheduled</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      <Card>
        {error ? (
          <ErrorState error={error} />
        ) : isLoading ? (
          <TableSkeleton columns={7} />
        ) : !data || data.items.length === 0 ? (
          <EmptyState title="No scans match these filters" description="Trigger a scan from a repository page." />
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="table-base">
                <thead>
                  <tr>
                    <th>Scan</th>
                    <th>Status</th>
                    <th>Trigger</th>
                    <th>Started</th>
                    <th>Duration</th>
                    <th>Findings</th>
                    <th>Severity mix</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((scan) => (
                    <tr key={scan.id}>
                      <td>
                        <Link to={`/scans/${scan.id}`} className="font-mono text-xs text-cyan-300 hover:underline">
                          {shortSha(scan.id)}
                        </Link>
                      </td>
                      <td>
                        <ScanStatusBadge status={scan.status} />
                      </td>
                      <td className="text-xs uppercase tracking-wide text-slate-400">{scan.trigger}</td>
                      <td className="text-xs text-slate-400">{formatRelative(scan.created_at)}</td>
                      <td className="text-xs text-slate-400">{formatDuration(scan.duration_seconds)}</td>
                      <td className="tabular-nums">{scan.total_findings}</td>
                      <td>
                        <div className="flex flex-wrap items-center gap-1">
                          {scan.critical_count > 0 ? <SeverityBadge severity="CRITICAL" /> : null}
                          {scan.high_count > 0 ? <SeverityBadge severity="HIGH" /> : null}
                          {scan.medium_count > 0 ? <SeverityBadge severity="MEDIUM" /> : null}
                          {scan.critical_count + scan.high_count + scan.medium_count === 0 ? (
                            <span className="text-xs text-slate-500">—</span>
                          ) : null}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination
              page={data.page}
              pages={data.pages}
              total={data.total}
              pageSize={data.page_size}
              onPageChange={setPage}
            />
          </>
        )}
      </Card>
      <div className="mt-4 max-w-sm">
        <Label>Quick link</Label>
        <Input placeholder="Search findings instead →" readOnly onClick={() => window.location.assign("/findings")} />
      </div>
    </div>
  );
}
