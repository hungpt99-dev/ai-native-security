import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, Play } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { EmptyState, ErrorState, KeyValue, Mono, PageHeader, Pagination, ScanStatusBadge, SeverityBadge } from "@/components/common";
import { TableSkeleton } from "@/components/ui/skeleton";
import { useAsset, useAssetScans, useAssetSboms, useTriggerScan } from "@/hooks/queries";
import { formatDate, formatDuration, formatRelative, shortSha } from "@/lib/utils";

export function AssetDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [page, setPage] = useState(1);
  const { data: asset, isLoading, error } = useAsset(id);
  const { data: scans } = useAssetScans(id, { page, page_size: 10 });
  const { data: sboms } = useAssetSboms(id, { page: 1, page_size: 5 });
  const triggerScan = useTriggerScan();
  const [actionError, setActionError] = useState<string | null>(null);

  if (error) return <ErrorState error={error} />;
  if (isLoading || !asset) return <TableSkeleton rows={4} columns={3} />;

  return (
    <div>
      <Link to="/assets" className="mb-4 inline-flex items-center gap-1 text-xs text-slate-400 hover:text-cyan-300">
        <ArrowLeft className="h-3.5 w-3.5" /> Back to repositories
      </Link>
      <PageHeader
        title={asset.name}
        subtitle={asset.repo_url}
        actions={
          <>
            <Badge tone={asset.monitoring_enabled ? "success" : "neutral"}>
              {asset.monitoring_enabled ? "monitoring" : "paused"}
            </Badge>
            <Button
              onClick={async () => {
                setActionError(null);
                try {
                  await triggerScan.mutateAsync(asset.id);
                } catch (err) {
                  setActionError(err instanceof Error ? err.message : "Failed to trigger scan");
                }
              }}
              disabled={triggerScan.isPending}
            >
              <Play className="h-4 w-4" /> {triggerScan.isPending ? "Starting…" : "Scan now"}
            </Button>
          </>
        }
      />

      {actionError ? (
        <div className="mb-4 rounded-lg border border-rose-500/30 bg-rose-500/10 px-4 py-2 text-sm text-rose-200">
          {actionError}
        </div>
      ) : null}

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Repository metadata</CardTitle>
          </CardHeader>
          <CardContent>
            <dl className="grid grid-cols-2 gap-4 md:grid-cols-3">
              <KeyValue label="Provider">{asset.provider}</KeyValue>
              <KeyValue label="Default branch">
                <Mono>{asset.default_branch}</Mono>
              </KeyValue>
              <KeyValue label="Scan interval">
                {asset.scan_interval_minutes ? `${asset.scan_interval_minutes} min` : "—"}
              </KeyValue>
              <KeyValue label="Credential">
                {asset.has_credential ? <Mono>{asset.credential_hint}</Mono> : "none"}
              </KeyValue>
              <KeyValue label="Last scan">{formatRelative(asset.last_scan_at)}</KeyValue>
              <KeyValue label="Last status">
                {asset.last_scan_status ? <ScanStatusBadge status={asset.last_scan_status} /> : "never"}
              </KeyValue>
              <KeyValue label="Created">{formatDate(asset.created_at)}</KeyValue>
              <KeyValue label="Updated">{formatDate(asset.updated_at)}</KeyValue>
              <KeyValue label="Description">{asset.description || "—"}</KeyValue>
            </dl>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Latest SBOMs</CardTitle>
            <Link to={`/sboms?asset=${asset.id}`} className="text-xs text-cyan-400 hover:underline">
              All SBOMs
            </Link>
          </CardHeader>
          <CardContent className="space-y-3">
            {!sboms || sboms.items.length === 0 ? (
              <p className="text-sm text-slate-500">No SBOM generated yet.</p>
            ) : (
              sboms.items.map((sbom) => (
                <div key={sbom.id} className="flex items-center justify-between gap-2 text-sm">
                  <Link to={`/sboms/${sbom.id}`} className="text-slate-200 hover:text-cyan-300">
                    {sbom.format.replace("_", " ")} · {sbom.package_count} pkgs
                  </Link>
                  <span className="text-xs text-slate-500">{formatRelative(sbom.created_at)}</span>
                </div>
              ))
            )}
          </CardContent>
        </Card>
      </div>

      <Card className="mt-4">
        <CardHeader>
          <CardTitle>Scan history</CardTitle>
        </CardHeader>
        {!scans || scans.items.length === 0 ? (
          <EmptyState title="No scans yet" description="Trigger a scan to collect findings, SBOMs and scanner output." />
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="table-base">
                <thead>
                  <tr>
                    <th>Scan</th>
                    <th>Status</th>
                    <th>Started</th>
                    <th>Duration</th>
                    <th>Total</th>
                    <th>Critical</th>
                    <th>High</th>
                    <th>New / Resolved</th>
                  </tr>
                </thead>
                <tbody>
                  {scans.items.map((scan) => (
                    <tr key={scan.id}>
                      <td>
                        <Link to={`/scans/${scan.id}`} className="font-mono text-xs text-cyan-300 hover:underline">
                          {shortSha(scan.id)}
                        </Link>
                        <p className="text-[11px] uppercase tracking-wide text-slate-500">{scan.trigger}</p>
                      </td>
                      <td>
                        <ScanStatusBadge status={scan.status} />
                      </td>
                      <td className="text-xs text-slate-400">{formatRelative(scan.created_at)}</td>
                      <td className="text-xs text-slate-400">{formatDuration(scan.duration_seconds)}</td>
                      <td className="tabular-nums">{scan.total_findings}</td>
                      <td>
                        {scan.critical_count > 0 ? <SeverityBadge severity="CRITICAL" /> : "0"}
                        <span className="ml-1 tabular-nums text-xs text-slate-400">{scan.critical_count}</span>
                      </td>
                      <td>
                        {scan.high_count > 0 ? <SeverityBadge severity="HIGH" /> : "0"}
                        <span className="ml-1 tabular-nums text-xs text-slate-400">{scan.high_count}</span>
                      </td>
                      <td className="text-xs text-slate-400">
                        +{scan.new_findings} / -{scan.resolved_findings}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination
              page={scans.page}
              pages={scans.pages}
              total={scans.total}
              pageSize={scans.page_size}
              onPageChange={setPage}
            />
          </>
        )}
      </Card>
    </div>
  );
}
