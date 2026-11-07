import { useMemo, useState } from "react";
import { Boxes, Play, Plus, ServerCog } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input, Label } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { TableSkeleton } from "@/components/ui/skeleton";
import { EmptyState, ErrorState, PageHeader, Pagination } from "@/components/common";
import {
  useAssets,
  useCreateInfraAsset,
  useCreateInfraScan,
  useInfraAssets,
  useInfrastructureScans,
  useInfrastructureSummary,
} from "@/hooks/queries";
import { formatDate, formatRelative } from "@/lib/utils";

const TARGET_KINDS = ["IAC_REPOSITORY", "CONTAINER_IMAGE"] as const;
const ASSET_KINDS = ["CONTAINER_IMAGE", "HOST", "CLOUD_RESOURCE", "KUBERNETES_WORKLOAD", "API_SERVICE"];

const statusTone: Record<string, "success" | "running" | "danger" | "medium" | "neutral"> = {
  COMPLETED: "success",
  RUNNING: "running",
  PENDING: "medium",
  FAILED: "danger",
  SKIPPED: "neutral",
};

function CreateScanDialog({ onClose }: { onClose: () => void }) {
  const [targetKind, setTargetKind] = useState<string>("CONTAINER_IMAGE");
  const [scanner, setScanner] = useState<string>("trivy-image");
  const [assetId, setAssetId] = useState<string>("");
  const [targetRef, setTargetRef] = useState("");
  const { data: assets } = useAssets({ page: 1, page_size: 100 });
  const create = useCreateInfraScan();

  const changeTarget = (value: string) => {
    setTargetKind(value);
    setScanner(value === "CONTAINER_IMAGE" ? "trivy-image" : "trivy-config");
  };

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogHeader><DialogTitle>New infrastructure assessment</DialogTitle></DialogHeader>
        <div className="space-y-3">
          <div>
            <Label>Target kind</Label>
            <Select value={targetKind} onValueChange={changeTarget}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                {TARGET_KINDS.map((kind) => <SelectItem key={kind} value={kind}>{kind}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>
          <div>
            <Label>Scanner</Label>
            <Select value={scanner} onValueChange={setScanner}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                {targetKind === "CONTAINER_IMAGE" ? (
                  <SelectItem value="trivy-image">trivy-image</SelectItem>
                ) : (
                  <>
                    <SelectItem value="trivy-config">trivy-config</SelectItem>
                    <SelectItem value="checkov">checkov</SelectItem>
                  </>
                )}
              </SelectContent>
            </Select>
          </div>
          {targetKind === "CONTAINER_IMAGE" ? (
            <div>
              <Label>Image reference</Label>
              <Input value={targetRef} onChange={(event) => setTargetRef(event.target.value)} placeholder="ghcr.io/acme/api:1.2.3" />
              <p className="mt-1 text-[11px] text-slate-500">Only allowlisted registries are accepted (ANS_ALLOWED_IMAGE_REGISTRIES).</p>
            </div>
          ) : (
            <div>
              <Label>IaC repository</Label>
              <Select value={assetId} onValueChange={setAssetId}>
                <SelectTrigger><SelectValue placeholder="Select a repository" /></SelectTrigger>
                <SelectContent>
                  {(assets?.items ?? []).map((asset) => (
                    <SelectItem key={asset.id} value={asset.id}>{asset.name}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="mt-1 text-[11px] text-slate-500">The worker clones the repository, runs the scanner, then deletes the workspace.</p>
            </div>
          )}
          {create.error && <p className="text-xs text-rose-300">{(create.error as Error).message}</p>}
          <Button
            className="w-full"
            disabled={create.isPending || (targetKind === "CONTAINER_IMAGE" ? !targetRef : !assetId)}
            onClick={() =>
              create
                .mutateAsync(
                  targetKind === "CONTAINER_IMAGE"
                    ? { target_kind: targetKind, scanner, target_ref: targetRef }
                    : { target_kind: targetKind, scanner, asset_id: assetId },
                )
                .then(onClose)
            }
          >
            <Play className="h-4 w-4" /> Queue assessment
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

function RegisterAssetDialog({ onClose }: { onClose: () => void }) {
  const [name, setName] = useState("");
  const [kind, setKind] = useState("HOST");
  const [externalRef, setExternalRef] = useState("");
  const create = useCreateInfraAsset();
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogHeader><DialogTitle>Register infrastructure asset</DialogTitle></DialogHeader>
        <div className="space-y-3">
          <div>
            <Label>Name</Label>
            <Input value={name} onChange={(event) => setName(event.target.value)} placeholder="api-prod-01" />
          </div>
          <div>
            <Label>Kind</Label>
            <Select value={kind} onValueChange={setKind}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                {ASSET_KINDS.map((entry) => <SelectItem key={entry} value={entry}>{entry}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>
          <div>
            <Label>External reference</Label>
            <Input value={externalRef} onChange={(event) => setExternalRef(event.target.value)} placeholder="host://api-prod-01" />
          </div>
          {create.error && <p className="text-xs text-rose-300">{(create.error as Error).message}</p>}
          <Button
            className="w-full"
            disabled={create.isPending || !name || !externalRef}
            onClick={() => create.mutateAsync({ name, kind, external_ref: externalRef }).then(onClose)}
          >
            <Plus className="h-4 w-4" /> Register
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

export function InfrastructurePage() {
  const [page, setPage] = useState(1);
  const [showScan, setShowScan] = useState(false);
  const [showAsset, setShowAsset] = useState(false);
  const [status, setStatus] = useState("all");

  const params = useMemo(
    () => ({ page, page_size: 25, status: status === "all" ? undefined : status }),
    [page, status],
  );
  const { data, isLoading, error } = useInfrastructureScans(params);
  const { data: summary } = useInfrastructureSummary();
  const { data: assets } = useInfraAssets({ page: 1, page_size: 50 });

  return (
    <div>
      <PageHeader
        title="Infrastructure security"
        subtitle="IaC, container image and configuration assessment feeding the same finding pipeline"
        actions={
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => setShowAsset(true)}><Plus className="h-4 w-4" /> Register asset</Button>
            <Button onClick={() => setShowScan(true)}><Play className="h-4 w-4" /> New assessment</Button>
          </div>
        }
      />

      <div className="mb-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <div className="panel p-4">
          <p className="text-xs text-slate-500">Active assessments</p>
          <p className="text-2xl font-semibold text-white">{summary?.active ?? "—"}</p>
        </div>
        <div className="panel p-4">
          <p className="text-xs text-slate-500">Critical open findings</p>
          <p className="text-2xl font-semibold text-rose-300">{summary?.open_findings_by_severity?.CRITICAL ?? 0}</p>
        </div>
        <div className="panel p-4">
          <p className="text-xs text-slate-500">High open findings</p>
          <p className="text-2xl font-semibold text-orange-300">{summary?.open_findings_by_severity?.HIGH ?? 0}</p>
        </div>
        <div className="panel p-4">
          <p className="text-xs text-slate-500">Last assessment</p>
          <p className="text-sm text-slate-200">{formatRelative(summary?.last_scan_at)}</p>
        </div>
      </div>

      <Card className="mb-6">
        <CardHeader><CardTitle className="flex items-center gap-2"><ServerCog className="h-4 w-4 text-cyan-400" /> Scanner availability</CardTitle></CardHeader>
        <CardContent className="grid gap-3 pt-0 sm:grid-cols-3">
          {(summary?.scanners ?? []).map((scanner) => (
            <div key={scanner.scanner} className="rounded-lg border border-slate-800 bg-slate-900/40 p-3">
              <div className="flex items-center justify-between">
                <p className="text-sm text-slate-200">{scanner.scanner}</p>
                <Badge tone={scanner.available ? "success" : "danger"}>{scanner.available ? "available" : "missing"}</Badge>
              </div>
              <p className="text-[11px] text-slate-500">{scanner.target_kind}</p>
              {scanner.error && <p className="mt-1 text-[11px] text-amber-300">{scanner.error}</p>}
            </div>
          ))}
          {!summary && <p className="text-sm text-slate-500">Loading scanner status…</p>}
        </CardContent>
      </Card>

      <div className="mb-4 flex items-end gap-3">
        <div className="w-48">
          <Label>Status</Label>
          <Select value={status} onValueChange={(value) => { setPage(1); setStatus(value); }}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All</SelectItem>
              <SelectItem value="PENDING">PENDING</SelectItem>
              <SelectItem value="RUNNING">RUNNING</SelectItem>
              <SelectItem value="COMPLETED">COMPLETED</SelectItem>
              <SelectItem value="FAILED">FAILED</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      <Card className="mb-6 overflow-hidden">
        {error ? (
          <ErrorState error={error} />
        ) : isLoading ? (
          <TableSkeleton rows={5} />
        ) : !data || data.items.length === 0 ? (
          <EmptyState title="No infrastructure assessments" description="Queue a Trivy config, Checkov or container image assessment." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="border-b border-slate-800 text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th className="px-4 py-3">Created</th>
                  <th className="px-4 py-3">Target</th>
                  <th className="px-4 py-3">Scanner</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Findings</th>
                  <th className="px-4 py-3">Duration</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((scan) => (
                  <tr key={scan.id} className="border-b border-slate-800/60">
                    <td className="px-4 py-3 text-slate-400">{formatRelative(scan.created_at)}</td>
                    <td className="px-4 py-3">
                      <p className="text-slate-200">{scan.target_ref}</p>
                      <p className="text-xs text-slate-500">{scan.target_kind}{scan.commit_sha ? ` · ${scan.commit_sha.slice(0, 8)}` : ""}</p>
                      {scan.error_message && <p className="text-xs text-rose-300">{scan.error_message}</p>}
                    </td>
                    <td className="px-4 py-3 text-slate-300">{scan.scanner}</td>
                    <td className="px-4 py-3"><Badge tone={statusTone[scan.status] ?? "neutral"}>{scan.status}</Badge></td>
                    <td className="px-4 py-3 text-xs text-slate-300">
                      {scan.total_findings} total · {scan.critical_count} critical · {scan.high_count} high
                    </td>
                    <td className="px-4 py-3 text-slate-400">{scan.duration_seconds ? `${scan.duration_seconds}s` : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {data && data.total > 0 && (
          <Pagination page={data.page} pages={data.pages} total={data.total} pageSize={data.page_size} onPageChange={setPage} />
        )}
      </Card>

      <Card>
        <CardHeader className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2"><Boxes className="h-4 w-4 text-cyan-400" /> Infrastructure assets</CardTitle>
          <span className="text-xs text-slate-500">{assets?.total ?? 0} assets</span>
        </CardHeader>
        {!assets || assets.items.length === 0 ? (
          <CardContent className="text-sm text-slate-500">No infrastructure assets registered yet.</CardContent>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="border-b border-slate-800 text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th className="px-4 py-3">Name</th>
                  <th className="px-4 py-3">Kind</th>
                  <th className="px-4 py-3">Reference</th>
                  <th className="px-4 py-3">Last assessment</th>
                  <th className="px-4 py-3">Monitoring</th>
                </tr>
              </thead>
              <tbody>
                {assets.items.map((asset) => (
                  <tr key={asset.id} className="border-b border-slate-800/60">
                    <td className="px-4 py-3 text-slate-200">{asset.name}</td>
                    <td className="px-4 py-3"><Badge tone="info">{asset.kind}</Badge></td>
                    <td className="px-4 py-3 text-xs text-slate-400">{asset.external_ref ?? asset.repo_url ?? "—"}</td>
                    <td className="px-4 py-3 text-xs text-slate-400">
                      {formatRelative(asset.last_infra_scan_at)} {asset.last_infra_scan_status ? `· ${asset.last_infra_scan_status}` : ""}
                    </td>
                    <td className="px-4 py-3">
                      <Badge tone={asset.monitoring_enabled ? "success" : "neutral"}>{asset.monitoring_enabled ? "on" : "off"}</Badge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {showScan && <CreateScanDialog onClose={() => setShowScan(false)} />}
      {showAsset && <RegisterAssetDialog onClose={() => setShowAsset(false)} />}
      <p className="mt-4 text-[11px] text-slate-500">Last checked {formatDate(summary?.last_scan_at)}</p>
    </div>
  );
}
