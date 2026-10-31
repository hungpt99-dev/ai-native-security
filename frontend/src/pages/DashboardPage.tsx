import { Link } from "react-router-dom";
import { Activity, AlertOctagon, Bug, CheckCircle2, Radar, Server } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { buttonVariants } from "@/components/ui/button";
import { TableSkeleton } from "@/components/ui/skeleton";
import { EmptyState, ErrorState, PageHeader, ScanStatusBadge, SeverityBadge } from "@/components/common";
import { useDashboard } from "@/hooks/queries";
import { formatRelative } from "@/lib/utils";

function StatCard({
  label,
  value,
  hint,
  icon: Icon,
  tone = "text-cyan-400",
  to,
}: {
  label: string;
  value: number | string;
  hint?: string;
  icon: React.ComponentType<{ className?: string }>;
  tone?: string;
  to?: string;
}) {
  const content = (
    <Card className="h-full transition-colors hover:border-slate-700">
      <CardContent className="flex items-start justify-between">
        <div>
          <p className="label">{label}</p>
          <p className="stat-value mt-2">{value}</p>
          {hint ? <p className="mt-1 text-xs text-slate-500">{hint}</p> : null}
        </div>
        <div className={`rounded-lg bg-slate-800/70 p-2 ${tone}`}>
          <Icon className="h-5 w-5" />
        </div>
      </CardContent>
    </Card>
  );
  return to ? <Link to={to}>{content}</Link> : content;
}

export function DashboardPage() {
  const { data, isLoading, error } = useDashboard();

  if (error) return <ErrorState error={error} />;

  const severities = data?.findings.by_severity ?? [];
  const maxSeverity = Math.max(1, ...severities.map((entry) => entry.total));
  const scanners = data?.findings.by_scanner ?? [];
  const maxScanner = Math.max(1, ...scanners.map((entry) => entry.total));

  return (
    <div>
      <PageHeader
        title="Security overview"
        subtitle="Live posture across monitored repositories"
        actions={
          <Link
            to="/assets"
            className={buttonVariants({ variant: "outline" }) + " flex items-center gap-2"}
          >
            <Server className="h-4 w-4" /> Manage repositories
          </Link>
        }
      />

      {isLoading || !data ? (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          {Array.from({ length: 4 }).map((_, index) => (
            <Card key={index}>
              <CardContent>
                <TableSkeleton rows={2} columns={1} />
              </CardContent>
            </Card>
          ))}
        </div>
      ) : (
        <>
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            <StatCard
              label="Monitored repositories"
              value={data.assets.monitored}
              hint={`${data.assets.total} registered`}
              icon={Server}
              to="/assets"
            />
            <StatCard
              label="Critical / High open"
              value={`${data.findings.critical_open} / ${data.findings.high_open}`}
              hint={`${data.findings.active} active findings`}
              icon={AlertOctagon}
              tone="text-rose-400"
              to="/findings?severity=CRITICAL&severity=HIGH&status=OPEN"
            />
            <StatCard
              label="Known exploited (KEV)"
              value={data.findings.kev}
              hint={`${data.intelligence.kev} KEV records in intel`}
              icon={Radar}
              tone="text-amber-400"
              to="/findings?search=KEV"
            />
            <StatCard
              label="Resolved findings"
              value={data.findings.resolved}
              hint={`${data.scans.last_24h} scans in last 24h`}
              icon={CheckCircle2}
              tone="text-emerald-400"
              to="/findings?status=RESOLVED"
            />
          </div>

          <div className="mt-6 grid gap-4 lg:grid-cols-3">
            <Card className="lg:col-span-2">
              <CardHeader>
                <CardTitle>Recent scan activity</CardTitle>
                <Link to="/scans" className="text-xs text-cyan-400 hover:underline">
                  View all
                </Link>
              </CardHeader>
              {data.scans.recent.length === 0 ? (
                <EmptyState
                  title="No scans yet"
                  description="Register a repository and trigger a scan to populate the dashboard."
                  action={
                    <Link to="/assets" className={buttonVariants({ size: "sm" })}>
                      Add repository
                    </Link>
                  }
                />
              ) : (
                <table className="table-base">
                  <thead>
                    <tr>
                      <th>Repository</th>
                      <th>Status</th>
                      <th>Trigger</th>
                      <th>Findings</th>
                      <th>Started</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.scans.recent.map((scan) => (
                      <tr key={scan.id}>
                        <td>
                          <Link to={`/scans/${scan.id}`} className="text-slate-100 hover:text-cyan-300">
                            {scan.asset_name ?? "Unknown repository"}
                          </Link>
                        </td>
                        <td>
                          <ScanStatusBadge status={scan.status} />
                        </td>
                        <td className="text-xs uppercase tracking-wide text-slate-400">{scan.trigger}</td>
                        <td className="tabular-nums">{scan.total_findings}</td>
                        <td className="text-xs text-slate-400">{formatRelative(scan.created_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </Card>

            <div className="space-y-4">
              <Card>
                <CardHeader>
                  <CardTitle>Severity distribution</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  {severities.map((entry) => (
                    <div key={entry.severity} className="flex items-center gap-3">
                      <div className="w-20">
                        <SeverityBadge severity={entry.severity} />
                      </div>
                      <div className="h-2 flex-1 overflow-hidden rounded-full bg-slate-800">
                        <div
                          className="h-full rounded-full bg-cyan-500/80"
                          style={{ width: `${(entry.total / maxSeverity) * 100}%` }}
                        />
                      </div>
                      <span className="w-8 text-right text-xs tabular-nums text-slate-400">
                        {entry.total}
                      </span>
                    </div>
                  ))}
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Findings by scanner</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  {scanners.length === 0 ? (
                    <p className="text-sm text-slate-500">No findings recorded yet.</p>
                  ) : (
                    scanners.map((entry) => (
                      <div key={entry.scanner} className="flex items-center gap-3">
                        <span className="w-20 truncate font-mono text-xs text-slate-300">{entry.scanner}</span>
                        <div className="h-2 flex-1 overflow-hidden rounded-full bg-slate-800">
                          <div
                            className="h-full rounded-full bg-indigo-400/80"
                            style={{ width: `${(entry.total / maxScanner) * 100}%` }}
                          />
                        </div>
                        <span className="w-8 text-right text-xs tabular-nums text-slate-400">
                          {entry.total}
                        </span>
                      </div>
                    ))
                  )}
                </CardContent>
              </Card>
            </div>
          </div>

          {data.failing_assets.length > 0 ? (
            <Card className="mt-6 border-rose-500/30">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-rose-200">
                  <Bug className="h-4 w-4" /> Repositories with recent scan failures
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {data.failing_assets.map((asset) => (
                  <div key={asset.id} className="flex flex-wrap items-center justify-between gap-2 text-sm">
                    <Link to={`/assets/${asset.id}`} className="text-slate-200 hover:text-cyan-300">
                      {asset.name}
                    </Link>
                    <div className="flex items-center gap-3">
                      <Badge tone="danger">FAILED</Badge>
                      <span className="text-xs text-slate-500">{formatRelative(asset.last_scan_at)}</span>
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>
          ) : null}

          <p className="mt-6 flex items-center gap-2 text-xs text-slate-500">
            <Activity className="h-3.5 w-3.5" />
            {data.scans.active} scan(s) in progress · {data.scans.failed_last_24h} failed in the last 24h ·{" "}
            {data.intelligence.vulnerabilities} vulnerability records
          </p>
        </>
      )}
    </div>
  );
}
