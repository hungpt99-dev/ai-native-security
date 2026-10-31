import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Plus, Play, RefreshCw, Trash2 } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input, Label } from "@/components/ui/input";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { SelectContent, SelectItem, Select, SelectTrigger, SelectValue } from "@/components/ui/select";
import { EmptyState, ErrorState, PageHeader, Pagination, ScanStatusBadge } from "@/components/common";
import { TableSkeleton } from "@/components/ui/skeleton";
import {
  useAssets,
  useCreateAsset,
  useDeleteAsset,
  useTriggerScan,
  useUpdateAsset,
  type AssetPayload,
} from "@/hooks/queries";
import type { Asset } from "@/lib/types";
import { formatRelative } from "@/lib/utils";

export function AssetsPage() {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [provider, setProvider] = useState("all");
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editing, setEditing] = useState<Asset | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const params = useMemo(
    () => ({
      page,
      page_size: 20,
      search: search || undefined,
      provider: provider === "all" ? undefined : provider,
    }),
    [page, search, provider],
  );

  const { data, isLoading, error } = useAssets(params);
  const triggerScan = useTriggerScan();
  const deleteAsset = useDeleteAsset();

  const handleScan = async (asset: Asset) => {
    setActionError(null);
    try {
      await triggerScan.mutateAsync(asset.id);
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "Failed to trigger scan");
    }
  };

  const handleDelete = async (asset: Asset) => {
    if (!window.confirm(`Delete ${asset.name} and all of its findings?`)) return;
    setActionError(null);
    try {
      await deleteAsset.mutateAsync(asset.id);
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "Failed to delete repository");
    }
  };

  return (
    <div>
      <PageHeader
        title="Repositories"
        subtitle="Registered source repositories and their monitoring state"
        actions={
          <Button
            onClick={() => {
              setEditing(null);
              setDialogOpen(true);
            }}
          >
            <Plus className="h-4 w-4" /> Add repository
          </Button>
        }
      />

      <div className="mb-4 flex flex-wrap items-end gap-2">
        <div className="w-full max-w-xs">
          <Label>Search</Label>
          <Input
            placeholder="Name or URL"
            value={search}
            onChange={(event) => {
              setPage(1);
              setSearch(event.target.value);
            }}
          />
        </div>
        <div className="w-40">
          <Label>Provider</Label>
          <Select
            value={provider}
            onValueChange={(value) => {
              setPage(1);
              setProvider(value);
            }}
          >
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All providers</SelectItem>
              <SelectItem value="github">GitHub</SelectItem>
              <SelectItem value="gitlab">GitLab</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      {actionError ? (
        <div className="mb-4 rounded-lg border border-rose-500/30 bg-rose-500/10 px-4 py-2 text-sm text-rose-200">
          {actionError}
        </div>
      ) : null}

      <Card>
        {error ? (
          <ErrorState error={error} />
        ) : isLoading ? (
          <TableSkeleton columns={6} />
        ) : !data || data.items.length === 0 ? (
          <EmptyState
            title="No repositories registered"
            description="Add a GitHub or GitLab repository to start scanning it for vulnerabilities, secrets and risky code patterns."
            action={<Button onClick={() => setDialogOpen(true)}>Add your first repository</Button>}
          />
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="table-base">
                <thead>
                  <tr>
                    <th>Repository</th>
                    <th>Provider</th>
                    <th>Monitoring</th>
                    <th>Last scan</th>
                    <th>Status</th>
                    <th className="text-right">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((asset) => (
                    <tr key={asset.id}>
                      <td>
                        <Link to={`/assets/${asset.id}`} className="font-medium text-slate-100 hover:text-cyan-300">
                          {asset.name}
                        </Link>
                        <p className="mt-0.5 max-w-md truncate font-mono text-xs text-slate-500">
                          {asset.repo_url}
                        </p>
                      </td>
                      <td>
                        <Badge tone="neutral">{asset.provider}</Badge>
                      </td>
                      <td>
                        <Badge tone={asset.monitoring_enabled ? "success" : "neutral"}>
                          {asset.monitoring_enabled ? "enabled" : "disabled"}
                        </Badge>
                      </td>
                      <td className="text-xs text-slate-400">{formatRelative(asset.last_scan_at)}</td>
                      <td>
                        {asset.last_scan_status ? (
                          <ScanStatusBadge status={asset.last_scan_status} />
                        ) : (
                          <span className="text-xs text-slate-500">never scanned</span>
                        )}
                      </td>
                      <td>
                        <div className="flex justify-end gap-1">
                          <Button
                            size="sm"
                            variant="secondary"
                            onClick={() => void handleScan(asset)}
                            disabled={triggerScan.isPending}
                            title="Trigger scan"
                          >
                            <Play className="h-3.5 w-3.5" />
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => {
                              setEditing(asset);
                              setDialogOpen(true);
                            }}
                            title="Edit"
                          >
                            <RefreshCw className="h-3.5 w-3.5" />
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => void handleDelete(asset)}
                            title="Delete"
                          >
                            <Trash2 className="h-3.5 w-3.5 text-rose-400" />
                          </Button>
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

      <AssetDialog
        open={dialogOpen}
        asset={editing}
        onClose={() => {
          setDialogOpen(false);
          setEditing(null);
        }}
      />
    </div>
  );
}

function AssetDialog({
  open,
  asset,
  onClose,
}: {
  open: boolean;
  asset: Asset | null;
  onClose: () => void;
}) {
  const createAsset = useCreateAsset();
  const updateAsset = useUpdateAsset(asset?.id ?? "");
  const [form, setForm] = useState<AssetPayload>({
    name: "",
    repo_url: "",
    default_branch: "main",
    description: "",
    access_token: "",
    monitoring_enabled: true,
    scan_interval_minutes: 240,
  });
  const [error, setError] = useState<string | null>(null);

  const isEdit = Boolean(asset);
  const key = asset?.id ?? "new";

  // Reset form when the dialog target changes.
  useMemo(() => {
    if (!open) return;
    setError(null);
    setForm({
      name: asset?.name ?? "",
      repo_url: asset?.repo_url ?? "",
      default_branch: asset?.default_branch ?? "main",
      description: asset?.description ?? "",
      access_token: "",
      monitoring_enabled: asset?.monitoring_enabled ?? true,
      scan_interval_minutes: asset?.scan_interval_minutes ?? 240,
    });
  }, [open, asset, key]);

  const submit = async () => {
    setError(null);
    try {
      if (isEdit && asset) {
        await updateAsset.mutateAsync({
          name: form.name,
          default_branch: form.default_branch,
          description: form.description,
          monitoring_enabled: form.monitoring_enabled,
          scan_interval_minutes: form.scan_interval_minutes,
          ...(form.access_token ? { access_token: form.access_token } : {}),
        });
      } else {
        await createAsset.mutateAsync({
          ...form,
          access_token: form.access_token || undefined,
          description: form.description || null,
        });
      }
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Request failed");
    }
  };

  return (
    <Dialog open={open} onOpenChange={(next) => (!next ? onClose() : undefined)}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{isEdit ? "Edit repository" : "Register repository"}</DialogTitle>
        </DialogHeader>
        <div className="grid gap-4">
          <div>
            <Label>Name</Label>
            <Input
              value={form.name}
              onChange={(event) => setForm({ ...form, name: event.target.value })}
              placeholder="payments-api"
            />
          </div>
          {!isEdit ? (
            <div>
              <Label>Repository URL (https, GitHub or GitLab)</Label>
              <Input
                value={form.repo_url}
                onChange={(event) => setForm({ ...form, repo_url: event.target.value })}
                placeholder="https://github.com/org/repo"
              />
            </div>
          ) : (
            <div>
              <Label>Repository URL</Label>
              <Input value={form.repo_url} disabled readOnly />
            </div>
          )}
          <div className="grid gap-4 sm:grid-cols-2">
            <div>
              <Label>Default branch</Label>
              <Input
                value={form.default_branch ?? "main"}
                onChange={(event) => setForm({ ...form, default_branch: event.target.value })}
              />
            </div>
            <div>
              <Label>Scan interval (minutes)</Label>
              <Input
                type="number"
                min={5}
                value={form.scan_interval_minutes ?? 240}
                onChange={(event) =>
                  setForm({ ...form, scan_interval_minutes: Number(event.target.value) })
                }
              />
            </div>
          </div>
          <div>
            <Label>Description</Label>
            <Input
              value={form.description ?? ""}
              onChange={(event) => setForm({ ...form, description: event.target.value })}
              placeholder="What does this repository own?"
            />
          </div>
          <div>
            <Label>Access token (private repositories — encrypted at rest)</Label>
            <Input
              type="password"
              value={form.access_token ?? ""}
              onChange={(event) => setForm({ ...form, access_token: event.target.value })}
              placeholder={asset?.has_credential ? `Stored: ${asset.credential_hint}` : "ghp_… (optional)"}
              autoComplete="off"
            />
          </div>
          <label className="flex items-center gap-2 text-sm text-slate-300">
            <input
              type="checkbox"
              checked={form.monitoring_enabled ?? true}
              onChange={(event) => setForm({ ...form, monitoring_enabled: event.target.checked })}
              className="h-4 w-4 rounded border-slate-600 bg-slate-800"
            />
            Monitor this repository on a schedule
          </label>
          {error ? <p className="text-sm text-rose-300">{error}</p> : null}
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button
            onClick={() => void submit()}
            disabled={createAsset.isPending || updateAsset.isPending || !form.name || (!isEdit && !form.repo_url)}
          >
            {createAsset.isPending || updateAsset.isPending ? "Saving…" : "Save"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
