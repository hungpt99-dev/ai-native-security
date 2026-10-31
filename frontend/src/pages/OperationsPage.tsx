import { useMemo, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { EmptyState, ErrorState, PageHeader, Pagination } from "@/components/common";
import { TableSkeleton } from "@/components/ui/skeleton";
import { useJobs, useScannerStatus, useSchedules, useUpdateSchedule } from "@/hooks/queries";
import { formatDate, formatDuration, formatRelative } from "@/lib/utils";

const jobTone: Record<string, "success" | "danger" | "running" | "medium" | "neutral"> = {
  SUCCEEDED: "success",
  FAILED: "danger",
  RUNNING: "running",
  QUEUED: "medium",
  CANCELED: "neutral",
};

export function OperationsPage() {
  const [page, setPage] = useState(1);
  const [status, setStatus] = useState("all");
  const { data: scanners, isLoading: scannersLoading, error: scannersError } = useScannerStatus();
  const { data: schedules } = useSchedules();
  const params = useMemo(
    () => ({ page, page_size: 20, status: status === "all" ? undefined : status }),
    [page, status],
  );
  const { data: jobs, isLoading: jobsLoading, error: jobsError } = useJobs(params);
  const updateSchedule = useUpdateSchedule();

  return (
    <div>
      <PageHeader
        title="Operations"
        subtitle="Scanner availability, scheduled tasks and the job queue"
      />

      <Card>
        <CardHeader>
          <CardTitle>Scanner availability</CardTitle>
        </CardHeader>
        {scannersError ? (
          <ErrorState error={scannersError} />
        ) : scannersLoading ? (
          <TableSkeleton columns={4} rows={4} />
        ) : (
          <CardContent className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            {(scanners ?? []).map((scanner) => (
              <div key={scanner.scanner} className="rounded-lg border border-slate-800 bg-slate-900/50 p-4">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-sm text-slate-200">{scanner.scanner}</span>
                  <Badge tone={scanner.available ? "success" : "danger"}>
                    {scanner.available ? "ready" : "missing"}
                  </Badge>
                </div>
                <p className="mt-2 truncate text-xs text-slate-500">{scanner.version ?? scanner.error ?? "—"}</p>
                <p className="mt-1 text-[11px] text-slate-600">{scanner.enabled ? "enabled" : "disabled"}</p>
              </div>
            ))}
          </CardContent>
        )}
      </Card>

      <Card className="mt-4">
        <CardHeader>
          <CardTitle>Scheduled tasks</CardTitle>
        </CardHeader>
        {!schedules || schedules.length === 0 ? (
          <EmptyState
            title="No schedules"
            description="The scheduler process creates scan and intelligence sync schedules automatically."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="table-base">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Kind</th>
                  <th>Interval</th>
                  <th>Last run</th>
                  <th>Next run</th>
                  <th>Last status</th>
                  <th className="text-right">Enabled</th>
                </tr>
              </thead>
              <tbody>
                {schedules.map((schedule) => (
                  <tr key={schedule.id}>
                    <td className="max-w-xs truncate font-mono text-xs text-slate-300">{schedule.name}</td>
                    <td className="text-xs text-slate-400">{schedule.kind}</td>
                    <td className="text-xs text-slate-400">{Math.round(schedule.interval_seconds / 60)} min</td>
                    <td className="text-xs text-slate-400">{formatRelative(schedule.last_run_at)}</td>
                    <td className="text-xs text-slate-400">{formatDate(schedule.next_run_at)}</td>
                    <td className="text-xs">
                      {schedule.last_status ? (
                        <Badge tone={jobTone[schedule.last_status] ?? "neutral"}>{schedule.last_status}</Badge>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td className="text-right">
                      <Button
                        size="sm"
                        variant={schedule.enabled ? "secondary" : "outline"}
                        disabled={updateSchedule.isPending}
                        onClick={() =>
                          void updateSchedule.mutateAsync({ id: schedule.id, enabled: !schedule.enabled })
                        }
                      >
                        {schedule.enabled ? "Disable" : "Enable"}
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card className="mt-4">
        <CardHeader>
          <CardTitle>Job queue</CardTitle>
          <div className="w-40">
            <Label>Status</Label>
            <Select value={status} onValueChange={(value) => { setPage(1); setStatus(value); }}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All</SelectItem>
                <SelectItem value="QUEUED">Queued</SelectItem>
                <SelectItem value="RUNNING">Running</SelectItem>
                <SelectItem value="SUCCEEDED">Succeeded</SelectItem>
                <SelectItem value="FAILED">Failed</SelectItem>
                <SelectItem value="CANCELED">Canceled</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardHeader>
        {jobsError ? (
          <ErrorState error={jobsError} />
        ) : jobsLoading ? (
          <TableSkeleton columns={5} />
        ) : !jobs || jobs.items.length === 0 ? (
          <EmptyState title="No jobs" description="Jobs appear here when scans or syncs are queued." />
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="table-base">
                <thead>
                  <tr>
                    <th>Job</th>
                    <th>Kind</th>
                    <th>Status</th>
                    <th>Attempts</th>
                    <th>Created</th>
                    <th>Finished</th>
                  </tr>
                </thead>
                <tbody>
                  {jobs.items.map((job) => (
                    <tr key={job.id}>
                      <td className="font-mono text-xs text-slate-300">{job.id.slice(0, 8)}</td>
                      <td className="text-xs text-slate-400">{job.kind}</td>
                      <td>
                        <Badge tone={jobTone[job.status] ?? "neutral"}>{job.status}</Badge>
                        {job.last_error ? (
                          <p className="mt-1 max-w-xs truncate text-[11px] text-rose-300">{job.last_error}</p>
                        ) : null}
                      </td>
                      <td className="text-xs text-slate-400">
                        {job.attempts}/{job.max_attempts}
                      </td>
                      <td className="text-xs text-slate-400">{formatRelative(job.created_at)}</td>
                      <td className="text-xs text-slate-400">
                        {job.finished_at ? formatDuration(Math.max(0, (new Date(job.finished_at).getTime() - new Date(job.created_at).getTime()) / 1000)) : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination
              page={jobs.page}
              pages={jobs.pages}
              total={jobs.total}
              pageSize={jobs.page_size}
              onPageChange={setPage}
            />
          </>
        )}
      </Card>
    </div>
  );
}
