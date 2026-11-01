import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, Play, RefreshCw, ShieldCheck, PackagePlus } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  EmptyState,
  ErrorState,
  FreshnessBadge,
  KeyValue,
  Mono,
  MonitoringStatusBadge,
  PageHeader,
  Pagination,
  RunStatusBadge,
  ScanStatusBadge,
  SeverityBadge,
} from "@/components/common";
import { TableSkeleton } from "@/components/ui/skeleton";
import {
  useAsset,
  useAssetMonitoringRuns,
  useAssetScans,
  useAssetSboms,
  useCheckDependencies,
  useGenerateSbom,
  useReassessVulnerabilities,
  useSbomStatus,
  useTriggerScan,
} from "@/hooks/queries";
import { formatDate, formatDuration, formatRelative, shortSha } from "@/lib/utils";

function durationMs(value: number | null | undefined): string {
  if (value === null || value === undefined) return "—";
  if (value < 1000) return `${value} ms`;
  return `${(value / 1000).toFixed(1)} s`;
}

export function AssetDetailPage() {
  const { id } = useParams<{ id: string }>();
  const assetId = id ?? "";
  const [page, setPage] = useState(1);
  const [confirmGenerate, setConfirmGenerate] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  const { data: asset, isLoading, error } = useAsset(id);
  const { data: scans } = useAssetScans(id, { page, page_size: 10 });
  const { data: sboms } = useAssetSboms(id, { page: 1, page_size: 5 });
  const { data: status } = useSbomStatus(id);
  const { data: runs } = useAssetMonitoringRuns(id, { page: 1, page_size: 6 });
  const triggerScan = useTriggerScan();
  const checkDependencies = useCheckDependencies(assetId);
  const generateSbom = useGenerateSbom(assetId);
  const reassess = useReassessVulnerabilities(assetId);

  const runAction = async (label: string, action: () => Promise<{ deduplicated: boolean }>) => {
    setActionError(null);
    setActionNotice(null);
    try {
      const result = await action();
      setActionNotice(
        result.deduplicated ? `${label}: already queued` : `${label}: job queued`,
      );
    } catch (err) {
      setActionError(err instanceof Error ? err.message : `${label} failed`);
    }
  };

  if (error) return <ErrorState error={error} />;
  if (isLoading || !asset) return <TableSkeleton rows={4} columns={3} />;

  const snapshot = status?.latest_snapshot ?? null;
  const pending = status?.pending;

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
              onClick={() =>
                runAction("Scan", async () => {
                  await triggerScan.mutateAsync(asset.id);
                  return { deduplicated: false };
                })
              }
              disabled={triggerScan.isPending}
            >
              <Play className="h-4 w-4" /> {triggerScan.isPending ? "Starting…" : "Full scan"}
            </Button>
          </>
        }
      />

      {actionError ? (
        <div className="mb-4 rounded-lg border border-rose-500/30 bg-rose-500/10 px-4 py-2 text-sm text-rose-200">
          {actionError}
        </div>
      ) : null}
      {actionNotice ? (
        <div className="mb-4 rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-4 py-2 text-sm text-cyan-200">
          {actionNotice}
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
                    {shortSha(sbom.id)} · {sbom.package_count} pkgs
                    <span className="ml-1 text-[11px] text-slate-500">
                      {sbom.creation_reason?.toLowerCase().replace("_", " ")}
                    </span>
                  </Link>
                  <span className="text-xs text-slate-500">
                    {formatRelative(sbom.generated_at ?? sbom.created_at)}
                  </span>
                </div>
              ))
            )}
          </CardContent>
        </Card>
      </div>

      {/* ------------------------------------------------ SBOM monitoring */}
      <Card className="mt-4">
        <CardHeader>
          <div>
            <CardTitle>SBOM &amp; continuous monitoring</CardTitle>
            <p className="mt-1 text-xs text-slate-500">
              Composition is tracked from stored snapshots; vulnerabilities are re-evaluated
              against new intelligence without cloning the repository.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {status ? <FreshnessBadge freshness={status.freshness} /> : null}
            {status ? <MonitoringStatusBadge status={status.monitoring_status} /> : null}
          </div>
        </CardHeader>
        <CardContent>
          {!status ? (
            <p className="text-sm text-slate-500">Loading monitoring state…</p>
          ) : (
            <>
              <p className="mb-4 text-sm text-slate-400">{status.freshness_detail}</p>

              {pending?.dependency_change_pending ? (
                <div className="mb-4 rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-2 text-sm text-amber-200">
                  A dependency change was detected and is waiting to be turned into a new
                  snapshot.
                </div>
              ) : null}
              {pending?.sbom_generation ? (
                <div className="mb-4 rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-4 py-2 text-sm text-cyan-200">
                  SBOM generation is running.
                </div>
              ) : null}
              {status.last_reassessment?.status === "FAILED" ? (
                <div className="mb-4 rounded-lg border border-rose-500/30 bg-rose-500/10 px-4 py-2 text-sm text-rose-200">
                  The last vulnerability evaluation failed
                  {status.last_reassessment.error_message
                    ? `: ${status.last_reassessment.error_message}`
                    : "."}{" "}
                  Findings were not resolved.
                </div>
              ) : null}
              {status.failed_evaluations_7d > 0 ? (
                <p className="mb-4 text-xs text-amber-300">
                  {status.failed_evaluations_7d} incomplete or failed evaluation(s) in the last 7
                  days.
                </p>
              ) : null}

              <dl className="grid grid-cols-2 gap-4 md:grid-cols-4">
                <KeyValue label="Latest snapshot">
                  {snapshot ? (
                    <Link to={`/sboms/${snapshot.id}`} className="text-cyan-400 hover:underline">
                      {shortSha(snapshot.id)}
                    </Link>
                  ) : (
                    "none"
                  )}
                </KeyValue>
                <KeyValue label="Commit">
                  <Mono>{snapshot?.commit_sha ? shortSha(snapshot.commit_sha) : "—"}</Mono>
                </KeyValue>
                <KeyValue label="Generated">
                  {snapshot ? formatRelative(snapshot.generated_at ?? snapshot.created_at) : "—"}
                </KeyValue>
                <KeyValue label="Origin">{snapshot?.creation_reason ?? "—"}</KeyValue>
                <KeyValue label="Components">
                  {snapshot?.package_count ?? 0}
                  {snapshot?.direct_package_count !== null &&
                  snapshot?.direct_package_count !== undefined
                    ? ` · ${snapshot.direct_package_count} direct · ${snapshot.transitive_package_count ?? 0} transitive`
                    : ""}
                </KeyValue>
                <KeyValue label="Vulnerable components">
                  <span className={status.vulnerable_components > 0 ? "text-rose-300" : ""}>
                    {status.vulnerable_components}
                  </span>
                </KeyValue>
                <KeyValue label="Last dependency check">
                  {status.last_dependency_check
                    ? `${status.last_dependency_check.outcome ?? status.last_dependency_check.status} · ${formatRelative(
                        status.last_dependency_check.finished_at ??
                          status.last_dependency_check.started_at,
                      )}`
                    : "never"}
                </KeyValue>
                <KeyValue label="Last evaluation">
                  {status.last_reassessment
                    ? `${status.last_reassessment.status} · ${formatRelative(
                        status.last_reassessment.finished_at ??
                          status.last_reassessment.started_at,
                      )}`
                    : "never"}
                </KeyValue>
                <KeyValue label="New findings (last evaluation)">
                  {status.new_findings_since_last_evaluation}
                </KeyValue>
                <KeyValue label="Newly KEV-listed">
                  <span className={status.new_kev_since_last_evaluation > 0 ? "text-rose-300" : ""}>
                    {status.new_kev_since_last_evaluation}
                  </span>
                </KeyValue>
                <KeyValue label="Next dependency check">
                  {formatRelative(status.next_dependency_check)}
                </KeyValue>
                <KeyValue label="Next evaluation">{formatRelative(status.next_reassessment)}</KeyValue>
              </dl>

              {snapshot?.dependency_fingerprint ? (
                <p className="mt-4 text-[11px] text-slate-500">
                  dependency fingerprint{" "}
                  <span className="font-mono">{snapshot.dependency_fingerprint.slice(0, 16)}…</span>
                </p>
              ) : null}

              <div className="mt-5 flex flex-wrap gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={checkDependencies.isPending}
                  onClick={() =>
                    runAction("Refresh dependency status", () => checkDependencies.mutateAsync(undefined))
                  }
                >
                  <RefreshCw className="h-4 w-4" /> Refresh dependency status
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={reassess.isPending}
                  onClick={() =>
                    runAction("Reassess vulnerabilities", () => reassess.mutateAsync(undefined))
                  }
                >
                  <ShieldCheck className="h-4 w-4" /> Reassess vulnerabilities
                </Button>
                <Button size="sm" onClick={() => setConfirmGenerate(true)}>
                  <PackagePlus className="h-4 w-4" /> Generate SBOM
                </Button>
              </div>
            </>
          )}
        </CardContent>
      </Card>

      <Dialog open={confirmGenerate} onOpenChange={setConfirmGenerate}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Generate a new SBOM snapshot?</DialogTitle>
            <DialogDescription>
              The worker checks out {asset.name} and runs Syft. No Trivy, Semgrep or Gitleaks
              execution is triggered — this is a composition refresh, not a security scan.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmGenerate(false)}>
              Cancel
            </Button>
            <Button
              onClick={async () => {
                setConfirmGenerate(false);
                await runAction("Generate SBOM", () => generateSbom.mutateAsync(undefined));
              }}
            >
              Generate SBOM
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Card className="mt-4">
        <CardHeader>
          <CardTitle>Monitoring history</CardTitle>
          <p className="text-xs text-slate-500">
            Dependency checks, snapshot generations and vulnerability evaluations, newest first.
          </p>
        </CardHeader>
        {!runs || runs.items.length === 0 ? (
          <EmptyState
            title="No monitoring runs yet"
            description="Dependency checks run on their own schedule; evaluations re-read stored inventory."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="table-base">
              <thead>
                <tr>
                  <th>Operation</th>
                  <th>Status</th>
                  <th>Outcome</th>
                  <th>Components</th>
                  <th>Findings +/−</th>
                  <th>Duration</th>
                  <th>When</th>
                </tr>
              </thead>
              <tbody>
                {runs.items.map((run) => (
                  <tr key={run.id}>
                    <td className="text-xs text-slate-300">
                      {run.kind.replace(/_/g, " ").toLowerCase()}
                      <p className="text-[11px] text-slate-500">
                        {run.trigger.toLowerCase()}
                        {run.skipped_reason ? ` · ${run.skipped_reason}` : ""}
                      </p>
                    </td>
                    <td>
                      <RunStatusBadge status={run.status} />
                    </td>
                    <td className="text-xs text-slate-400">{run.outcome ?? "—"}</td>
                    <td className="tabular-nums text-xs text-slate-300">
                      {run.components_evaluated}
                    </td>
                    <td className="text-xs text-slate-300">
                      +{run.findings_created} / ~{run.findings_updated} / −{run.findings_resolved}
                      {run.new_kev_findings > 0 ? (
                        <span className="ml-1">
                          <SeverityBadge severity="HIGH" /> KEV {run.new_kev_findings}
                        </span>
                      ) : null}
                    </td>
                    <td className="text-xs text-slate-400">{durationMs(run.duration_ms)}</td>
                    <td className="text-xs text-slate-400">
                      {formatRelative(run.finished_at ?? run.started_at)}
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
