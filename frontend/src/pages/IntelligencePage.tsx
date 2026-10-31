import { useMemo, useState } from "react";
import { RefreshCw, Radar } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input, Label } from "@/components/ui/input";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { EmptyState, ErrorState, PageHeader, Pagination, SeverityBadge } from "@/components/common";
import { TableSkeleton } from "@/components/ui/skeleton";
import {
  useIntelligenceStats,
  useSyncHistory,
  useTriggerSync,
  useVulnerabilities,
  useVulnerability,
} from "@/hooks/queries";
import { formatDate, formatRelative } from "@/lib/utils";

export function IntelligencePage() {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [kevOnly, setKevOnly] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const [syncError, setSyncError] = useState<string | null>(null);

  const { data: stats } = useIntelligenceStats();
  const { data: history } = useSyncHistory({ page: 1, page_size: 10 });
  const triggerSync = useTriggerSync();

  const params = useMemo(
    () => ({ page, page_size: 25, search: search || undefined, kev_only: kevOnly || undefined }),
    [page, search, kevOnly],
  );
  const { data, isLoading, error } = useVulnerabilities(params);

  const startSync = async (source: string) => {
    setSyncError(null);
    try {
      await triggerSync.mutateAsync(source);
    } catch (err) {
      setSyncError(err instanceof Error ? err.message : "Failed to trigger sync");
    }
  };

  return (
    <div>
      <PageHeader
        title="Vulnerability intelligence"
        subtitle="Normalized OSV, NVD and CISA KEV data used to enrich findings"
        actions={
          <>
            <Button variant="outline" onClick={() => void startSync("CISA_KEV")} disabled={triggerSync.isPending}>
              <RefreshCw className="h-4 w-4" /> Sync KEV
            </Button>
            <Button variant="outline" onClick={() => void startSync("OSV")} disabled={triggerSync.isPending}>
              <RefreshCw className="h-4 w-4" /> Sync OSV
            </Button>
            <Button variant="outline" onClick={() => void startSync("NVD")} disabled={triggerSync.isPending}>
              <RefreshCw className="h-4 w-4" /> Sync NVD
            </Button>
          </>
        }
      />

      {syncError ? (
        <div className="mb-4 rounded-lg border border-rose-500/30 bg-rose-500/10 px-4 py-2 text-sm text-rose-200">
          {syncError}
        </div>
      ) : null}

      <div className="grid gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle>Coverage</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <div className="flex items-center justify-between">
              <span className="text-slate-400">Total records</span>
              <span className="tabular-nums text-slate-100">{stats?.total ?? 0}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-400">Known exploited</span>
              <span className="tabular-nums text-amber-300">{stats?.kev ?? 0}</span>
            </div>
            {Object.entries(stats?.by_source ?? {}).map(([source, count]) => (
              <div key={source} className="flex items-center justify-between">
                <span className="text-slate-400">{source}</span>
                <span className="tabular-nums text-slate-100">{count}</span>
              </div>
            ))}
            <div className="border-t border-slate-800 pt-3">
              {Object.entries(stats?.last_sync ?? {}).map(([source, timestamp]) => (
                <div key={source} className="flex items-center justify-between">
                  <span className="text-slate-400">Last {source} sync</span>
                  <span className="text-xs text-slate-500">{formatRelative(timestamp)}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Sync history</CardTitle>
          </CardHeader>
          {!history || history.items.length === 0 ? (
            <EmptyState title="No syncs recorded" description="Trigger a sync to populate vulnerability intelligence." />
          ) : (
            <div className="overflow-x-auto">
              <table className="table-base">
                <thead>
                  <tr>
                    <th>Source</th>
                    <th>Status</th>
                    <th>Started</th>
                    <th>Processed</th>
                    <th>Created</th>
                    <th>Updated</th>
                  </tr>
                </thead>
                <tbody>
                  {history.items.map((entry) => (
                    <tr key={entry.id}>
                      <td className="text-xs text-slate-200">{entry.source}</td>
                      <td>
                        <Badge
                          tone={
                            entry.status === "SUCCESS"
                              ? "success"
                              : entry.status === "RUNNING"
                                ? "running"
                                : "danger"
                          }
                        >
                          {entry.status}
                        </Badge>
                      </td>
                      <td className="text-xs text-slate-400">{formatDate(entry.started_at)}</td>
                      <td className="tabular-nums text-xs">{entry.records_processed}</td>
                      <td className="tabular-nums text-xs text-emerald-300">{entry.records_created}</td>
                      <td className="tabular-nums text-xs text-cyan-300">{entry.records_updated}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>

      <Card className="mt-4">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Radar className="h-4 w-4" /> Vulnerability records
          </CardTitle>
          <div className="flex items-end gap-2">
            <div className="w-56">
              <Label>Search</Label>
              <Input
                placeholder="CVE, OSV id or summary"
                value={search}
                onChange={(event) => {
                  setPage(1);
                  setSearch(event.target.value);
                }}
              />
            </div>
            <Button
              variant={kevOnly ? "default" : "outline"}
              size="sm"
              onClick={() => {
                setPage(1);
                setKevOnly(!kevOnly);
              }}
            >
              KEV only
            </Button>
          </div>
        </CardHeader>
        {error ? (
          <ErrorState error={error} />
        ) : isLoading ? (
          <TableSkeleton columns={5} />
        ) : !data || data.items.length === 0 ? (
          <EmptyState
            title="No vulnerability records"
            description="Run a sync to pull OSV, NVD and KEV data into the platform."
          />
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="table-base">
                <thead>
                  <tr>
                    <th>Identifier</th>
                    <th>Severity</th>
                    <th>CVSS</th>
                    <th>Summary</th>
                    <th>Modified</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((vuln) => (
                    <tr key={vuln.id} className="cursor-pointer" onClick={() => setSelected(vuln.id)}>
                      <td>
                        <span className="font-mono text-xs text-cyan-300">{vuln.cve_id ?? vuln.source_id}</span>
                        <p className="text-[11px] text-slate-500">
                          {vuln.source}
                          {vuln.is_kev ? " · KEV" : ""}
                        </p>
                      </td>
                      <td>
                        <SeverityBadge severity={vuln.severity} />
                      </td>
                      <td className="tabular-nums text-xs">{vuln.cvss_score ?? "—"}</td>
                      <td className="max-w-lg truncate text-xs text-slate-300">{vuln.summary ?? "—"}</td>
                      <td className="text-xs text-slate-500">{formatRelative(vuln.modified_at)}</td>
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

      <VulnerabilityDialog id={selected} onClose={() => setSelected(null)} />
    </div>
  );
}

function VulnerabilityDialog({ id, onClose }: { id: string | null; onClose: () => void }) {
  const { data } = useVulnerability(id);
  return (
    <Dialog open={Boolean(id)} onOpenChange={(open) => (!open ? onClose() : undefined)}>
      <DialogContent className="max-w-3xl">
        <DialogHeader>
          <DialogTitle>{data?.cve_id ?? data?.source_id ?? "Vulnerability"}</DialogTitle>
        </DialogHeader>
        {data ? (
          <div className="space-y-4 text-sm">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={data.severity} />
              <Badge tone="neutral">{data.source}</Badge>
              {data.is_kev ? <Badge tone="medium">Known exploited</Badge> : null}
              {data.cvss_score !== null ? <span className="text-xs text-slate-400">CVSS {data.cvss_score}</span> : null}
            </div>
            <p className="text-slate-300">{data.summary ?? "No summary provided"}</p>
            {data.description ? (
              <p className="max-h-52 overflow-auto whitespace-pre-wrap text-xs text-slate-400">{data.description}</p>
            ) : null}
            {data.kev_required_action ? (
              <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-200">
                <p className="font-semibold">Required action</p>
                <p className="mt-1">{data.kev_required_action}</p>
                {data.kev_due_date ? <p className="mt-1 text-amber-300/80">Due {data.kev_due_date}</p> : null}
              </div>
            ) : null}
            {data.affected_packages && data.affected_packages.length > 0 ? (
              <div>
                <p className="label">Affected packages</p>
                <ul className="mt-1 max-h-40 space-y-1 overflow-auto text-xs text-slate-400">
                  {data.affected_packages.map((pkg) => (
                    <li key={pkg.id} className="font-mono">
                      {pkg.ecosystem ? `${pkg.ecosystem}/` : ""}
                      {pkg.package_name}
                      {pkg.fixed_versions.length > 0 ? ` → fixed in ${pkg.fixed_versions.join(", ")}` : ""}
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}
            {data.references && data.references.length > 0 ? (
              <div>
                <p className="label">References</p>
                <ul className="mt-1 space-y-1 text-xs">
                  {data.references.slice(0, 10).map((ref) => (
                    <li key={ref.id}>
                      <a href={ref.url} target="_blank" rel="noreferrer" className="break-all text-cyan-400 hover:underline">
                        {ref.url}
                      </a>
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}
          </div>
        ) : (
          <TableSkeleton rows={3} columns={2} />
        )}
      </DialogContent>
    </Dialog>
  );
}
