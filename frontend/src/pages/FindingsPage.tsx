import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Filter, ShieldAlert } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input, Label } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import {
  EmptyState,
  ErrorState,
  FindingStatusBadge,
  PageHeader,
  Pagination,
  SeverityBadge,
} from "@/components/common";
import { TableSkeleton } from "@/components/ui/skeleton";
import { useAssets, useFinding, useFindings, useUpdateFindingStatus } from "@/hooks/queries";
import type { Finding, FindingStatus } from "@/lib/types";
import { formatDate, formatRelative } from "@/lib/utils";

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"] as const;
const SCANNERS = ["trivy", "semgrep", "gitleaks", "osv"] as const;
const STATUSES: FindingStatus[] = ["OPEN", "CONFIRMED", "FALSE_POSITIVE", "ACCEPTED_RISK", "RESOLVED"];

export function FindingsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState<string>(searchParams.get("severity") ?? "all");
  const [scanner, setScanner] = useState<string>(searchParams.get("scanner") ?? "all");
  const [status, setStatus] = useState<string>(searchParams.get("status") ?? "all");
  const [assetId, setAssetId] = useState<string>(searchParams.get("asset_id") ?? "all");
  const [sort, setSort] = useState("severity:asc");
  const [selected, setSelected] = useState<string | null>(null);

  const { data: assets } = useAssets({ page: 1, page_size: 100 });
  const scanId = searchParams.get("scan_id") ?? undefined;

  const params = useMemo(() => {
    const [sortBy, sortOrder] = sort.split(":");
    return {
      page,
      page_size: 25,
      search: search || undefined,
      severity: severity === "all" ? undefined : severity,
      scanner: scanner === "all" ? undefined : scanner,
      status: status === "all" ? undefined : status,
      asset_id: assetId === "all" ? undefined : assetId,
      scan_id: scanId,
      sort_by: sortBy,
      sort_order: sortOrder,
    };
  }, [page, search, severity, scanner, status, assetId, sort, scanId]);

  const { data, isLoading, error } = useFindings(params);

  useEffect(() => {
    const next = new URLSearchParams(searchParams);
    if (severity === "all") next.delete("severity");
    else next.set("severity", severity);
    if (scanner === "all") next.delete("scanner");
    else next.set("scanner", scanner);
    if (status === "all") next.delete("status");
    else next.set("status", status);
    if (assetId === "all") next.delete("asset_id");
    else next.set("asset_id", assetId);
    setSearchParams(next, { replace: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [severity, scanner, status, assetId]);

  const reset = () => {
    setPage(1);
    setSearch("");
    setSeverity("all");
    setScanner("all");
    setStatus("all");
    setAssetId("all");
  };

  return (
    <div>
      <PageHeader
        title="Findings"
        subtitle="Normalized, deduplicated findings from every scanner and vulnerability feed"
        actions={
          <Button variant="outline" onClick={reset}>
            <Filter className="h-4 w-4" /> Reset filters
          </Button>
        }
      />

      <div className="mb-4 grid gap-2 md:grid-cols-2 xl:grid-cols-6">
        <div className="xl:col-span-2">
          <Label>Search</Label>
          <Input
            placeholder="Title, rule, CVE, package, file…"
            value={search}
            onChange={(event) => {
              setPage(1);
              setSearch(event.target.value);
            }}
          />
        </div>
        <div>
          <Label>Severity</Label>
          <Select value={severity} onValueChange={(value) => { setPage(1); setSeverity(value); }}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All</SelectItem>
              {SEVERITIES.map((entry) => (
                <SelectItem key={entry} value={entry}>
                  {entry}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div>
          <Label>Scanner</Label>
          <Select value={scanner} onValueChange={(value) => { setPage(1); setScanner(value); }}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All</SelectItem>
              {SCANNERS.map((entry) => (
                <SelectItem key={entry} value={entry}>
                  {entry}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div>
          <Label>Status</Label>
          <Select value={status} onValueChange={(value) => { setPage(1); setStatus(value); }}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All</SelectItem>
              {STATUSES.map((entry) => (
                <SelectItem key={entry} value={entry}>
                  {entry.replace("_", " ")}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div>
          <Label>Repository</Label>
          <Select value={assetId} onValueChange={(value) => { setPage(1); setAssetId(value); }}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All repositories</SelectItem>
              {(assets?.items ?? []).map((asset) => (
                <SelectItem key={asset.id} value={asset.id}>
                  {asset.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      <div className="mb-3 flex items-center justify-between">
        <p className="text-xs text-slate-500">
          {data ? `${data.total} findings` : "Loading…"} {scanId ? `· filtered to scan ${scanId.slice(0, 8)}` : ""}
        </p>
        <div className="w-56">
          <Select value={sort} onValueChange={setSort}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="severity:asc">Severity (highest first)</SelectItem>
              <SelectItem value="last_detected_at:desc">Last detected (newest)</SelectItem>
              <SelectItem value="first_detected_at:desc">First detected (newest)</SelectItem>
              <SelectItem value="cvss_score:desc">CVSS score</SelectItem>
              <SelectItem value="title:asc">Title (A–Z)</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      <Card>
        {error ? (
          <ErrorState error={error} />
        ) : isLoading ? (
          <TableSkeleton columns={6} />
        ) : !data || data.items.length === 0 ? (
          <EmptyState
            title="No findings"
            description="Either no scan has run yet, or the current filters exclude everything."
            action={<Button variant="outline" onClick={reset}>Clear filters</Button>}
          />
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="table-base">
                <thead>
                  <tr>
                    <th>Finding</th>
                    <th>Severity</th>
                    <th>Scanner</th>
                    <th>Location / package</th>
                    <th>Status</th>
                    <th>Last detected</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((finding: Finding) => (
                    <tr key={finding.id} className="cursor-pointer" onClick={() => setSelected(finding.id)}>
                      <td className="max-w-md">
                        <p className="truncate font-medium text-slate-100">{finding.title}</p>
                        <p className="mt-0.5 flex items-center gap-2 truncate font-mono text-[11px] text-slate-500">
                          {finding.cve_id ? <span className="text-amber-300">{finding.cve_id}</span> : null}
                          <span className="truncate">{finding.rule_id}</span>
                          {finding.cvss_score !== null ? <span>CVSS {finding.cvss_score}</span> : null}
                        </p>
                      </td>
                      <td>
                        <SeverityBadge severity={finding.severity} />
                      </td>
                      <td className="font-mono text-xs text-slate-300">{finding.scanner}</td>
                      <td className="max-w-xs text-xs text-slate-400">
                        {finding.package_name ? (
                          <span className="font-mono">
                            {finding.package_name}@{finding.package_version}
                          </span>
                        ) : finding.file_path ? (
                          <span className="font-mono">
                            {finding.file_path}
                            {finding.line_number ? `:${finding.line_number}` : ""}
                          </span>
                        ) : (
                          "—"
                        )}
                      </td>
                      <td>
                        <FindingStatusBadge status={finding.status} />
                      </td>
                      <td className="text-xs text-slate-400">{formatRelative(finding.last_detected_at)}</td>
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

      <FindingDialog id={selected} onClose={() => setSelected(null)} />
    </div>
  );
}

function FindingDialog({ id, onClose }: { id: string | null; onClose: () => void }) {
  const { data: finding, isLoading } = useFinding(id);
  const updateStatus = useUpdateFindingStatus();
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);

  const applyStatus = async (status: string) => {
    if (!finding) return;
    setError(null);
    try {
      await updateStatus.mutateAsync({ id: finding.id, status, note: note || undefined });
      setNote("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update status");
    }
  };

  return (
    <Dialog open={Boolean(id)} onOpenChange={(open) => (!open ? onClose() : undefined)}>
      <DialogContent className="max-w-3xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 pr-6">
            <ShieldAlert className="h-4 w-4 text-cyan-400" />
            {isLoading || !finding ? "Loading finding…" : finding.title}
          </DialogTitle>
        </DialogHeader>
        {finding ? (
          <div className="space-y-5">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={finding.severity} />
              <FindingStatusBadge status={finding.status} />
              <span className="font-mono text-xs text-slate-400">{finding.scanner}</span>
              {finding.cve_id ? <span className="font-mono text-xs text-amber-300">{finding.cve_id}</span> : null}
              {finding.cvss_score !== null ? (
                <span className="text-xs text-slate-400">CVSS {finding.cvss_score}</span>
              ) : null}
              {(finding.metadata?.intel as { is_kev?: boolean } | undefined)?.is_kev ? (
                <span className="rounded-full border border-amber-500/40 bg-amber-500/15 px-2 py-0.5 text-[11px] font-semibold uppercase text-amber-300">
                  Known exploited
                </span>
              ) : null}
            </div>

            <dl className="grid grid-cols-2 gap-4 text-sm md:grid-cols-3">
              <div>
                <dt className="label">Rule</dt>
                <dd className="mt-1 break-all font-mono text-xs text-slate-300">{finding.rule_id}</dd>
              </div>
              <div>
                <dt className="label">Location</dt>
                <dd className="mt-1 break-all font-mono text-xs text-slate-300">
                  {finding.file_path ? `${finding.file_path}${finding.line_number ? `:${finding.line_number}` : ""}` : "—"}
                </dd>
              </div>
              <div>
                <dt className="label">Package</dt>
                <dd className="mt-1 break-all font-mono text-xs text-slate-300">
                  {finding.package_name ? `${finding.package_name}@${finding.package_version}` : "—"}
                </dd>
              </div>
              <div>
                <dt className="label">First detected</dt>
                <dd className="mt-1 text-xs text-slate-300">{formatDate(finding.first_detected_at)}</dd>
              </div>
              <div>
                <dt className="label">Last detected</dt>
                <dd className="mt-1 text-xs text-slate-300">{formatDate(finding.last_detected_at)}</dd>
              </div>
              <div>
                <dt className="label">Resolved</dt>
                <dd className="mt-1 text-xs text-slate-300">{formatDate(finding.resolved_at)}</dd>
              </div>
            </dl>

            {finding.description ? (
              <div>
                <p className="label">Description</p>
                <p className="mt-1 max-h-48 overflow-auto whitespace-pre-wrap text-sm text-slate-300">
                  {finding.description}
                </p>
              </div>
            ) : null}

            <div>
              <p className="label">Metadata</p>
              <pre className="mt-1 max-h-56 overflow-auto rounded-lg bg-slate-950/80 p-3 font-mono text-[11px] text-slate-400">
                {JSON.stringify(finding.metadata, null, 2)}
              </pre>
            </div>

            <div>
              <p className="label">History</p>
              <div className="mt-2 space-y-1.5">
                {(finding.history ?? []).map((entry) => (
                  <div key={entry.id} className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
                    <span className="font-mono text-slate-300">{entry.event}</span>
                    {entry.from_status ? <span>→ {entry.from_status}</span> : null}
                    <span className="text-slate-500">{entry.actor}</span>
                    <span className="text-slate-600">{formatDate(entry.created_at)}</span>
                    {entry.note ? <span className="text-slate-500">· {entry.note}</span> : null}
                  </div>
                ))}
              </div>
            </div>

            <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
              <p className="label">Update status</p>
              <div className="mt-2 flex flex-wrap gap-2">
                {STATUSES.filter((entry) => entry !== finding.status).map((entry) => (
                  <Button
                    key={entry}
                    size="sm"
                    variant="outline"
                    onClick={() => void applyStatus(entry)}
                    disabled={updateStatus.isPending}
                  >
                    {entry.replace("_", " ")}
                  </Button>
                ))}
              </div>
              <Input
                className="mt-3"
                placeholder="Optional note for the audit trail"
                value={note}
                onChange={(event) => setNote(event.target.value)}
              />
              {error ? <p className="mt-2 text-xs text-rose-300">{error}</p> : null}
            </div>
          </div>
        ) : (
          <TableSkeleton rows={4} columns={2} />
        )}
      </DialogContent>
    </Dialog>
  );
}
