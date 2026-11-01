import { useMemo, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { ArrowLeft } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Label } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { EmptyState, ErrorState, PageHeader, Pagination } from "@/components/common";
import { TableSkeleton } from "@/components/ui/skeleton";
import { useAssetSboms, useSbom, useSbomDiff } from "@/hooks/queries";
import type { SbomChangeType } from "@/lib/types";
import { formatDate, shortSha } from "@/lib/utils";

const changeTone: Record<SbomChangeType, "success" | "danger" | "medium" | "neutral"> = {
  ADDED: "danger",
  REMOVED: "success",
  VERSION_CHANGED: "medium",
  UNCHANGED: "neutral",
};

function dependencyRole(before: boolean | null, after: boolean | null): string {
  const value = after ?? before;
  if (value === true) return "direct";
  if (value === false) return "transitive";
  return "unknown";
}

const changeLabel: Record<SbomChangeType, string> = {
  ADDED: "added",
  REMOVED: "removed",
  VERSION_CHANGED: "changed",
  UNCHANGED: "unchanged",
};

export function SbomComparePage() {
  const { id } = useParams<{ id: string }>();
  const [searchParams, setSearchParams] = useSearchParams();
  const [page, setPage] = useState(1);
  const [filter, setFilter] = useState<string>("");
  const against = searchParams.get("against") ?? undefined;

  const { data: sbom, isLoading: sbomLoading, error: sbomError } = useSbom(id);
  const { data: snapshots } = useAssetSboms(sbom?.asset_id, { page: 1, page_size: 100 });
  const params = useMemo(
    () => ({ against, change: filter || undefined, page, page_size: 50 }),
    [against, filter, page],
  );
  const { data: diff, isLoading, error } = useSbomDiff(id, params);

  if (sbomError) return <ErrorState error={sbomError} />;
  if (error) return <ErrorState error={error} />;
  if (sbomLoading || !sbom) return <TableSkeleton rows={5} columns={3} />;

  const previousId = against ?? sbom.previous_snapshot_id ?? undefined;
  const candidates = (snapshots?.items ?? []).filter((entry) => entry.id !== sbom.id);

  return (
    <div>
      <Link
        to={`/sboms/${sbom.id}`}
        className="mb-4 inline-flex items-center gap-1 text-xs text-slate-400 hover:text-cyan-300"
      >
        <ArrowLeft className="h-3.5 w-3.5" /> Back to snapshot
      </Link>
      <PageHeader
        title="SBOM comparison"
        subtitle={`${shortSha(sbom.id)} generated ${formatDate(sbom.generated_at ?? sbom.created_at)} · identity is the PURL without its version`}
      />

      <div className="mb-4 flex flex-wrap items-end gap-4">
        <div className="w-80">
          <Label>Compare against</Label>
          <Select
            value={previousId ?? ""}
            onValueChange={(value) => {
              setPage(1);
              const next = new URLSearchParams(searchParams);
              next.set("against", value);
              setSearchParams(next, { replace: true });
            }}
          >
            <SelectTrigger>
              <SelectValue placeholder="Select a snapshot" />
            </SelectTrigger>
            <SelectContent>
              {candidates.map((entry) => (
                <SelectItem key={entry.id} value={entry.id}>
                  {shortSha(entry.id)} · {entry.creation_reason ?? "snapshot"} ·{" "}
                  {formatDate(entry.generated_at ?? entry.created_at)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="w-56">
          <Label>Show</Label>
          <Select
            value={filter || "changes"}
            onValueChange={(value) => {
              setPage(1);
              setFilter(value === "changes" ? "" : value);
            }}
          >
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="changes">Changes only</SelectItem>
              <SelectItem value="ADDED">Added</SelectItem>
              <SelectItem value="REMOVED">Removed</SelectItem>
              <SelectItem value="VERSION_CHANGED">Version changed</SelectItem>
              <SelectItem value="UNCHANGED">Unchanged</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      {diff ? (
        <div className="mb-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
          {(
            [
              ["Added", diff.added, "text-rose-300"],
              ["Removed", diff.removed, "text-emerald-300"],
              ["Version changed", diff.version_changed, "text-amber-300"],
              ["Unchanged", diff.unchanged, "text-slate-300"],
              ["Total components", diff.total_current, "text-cyan-300"],
            ] as const
          ).map(([label, value, tone]) => (
            <Card key={label}>
              <CardContent className="pt-4">
                <p className="label">{label}</p>
                <p className={`mt-1 text-2xl font-semibold tabular-nums ${tone}`}>{value}</p>
              </CardContent>
            </Card>
          ))}
        </div>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle>Component differences</CardTitle>
          <p className="text-xs text-slate-500">
            {diff?.previous_sbom_id
              ? `Comparing against ${shortSha(diff.previous_sbom_id)}`
              : "No previous snapshot is recorded for this one; every component is shown as added."}
          </p>
        </CardHeader>
        {isLoading ? (
          <TableSkeleton columns={5} />
        ) : !diff || diff.items.length === 0 ? (
          <EmptyState
            title="No differences"
            description="The two snapshots describe the same component inventory."
          />
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="table-base">
                <thead>
                  <tr>
                    <th>Change</th>
                    <th>Component</th>
                    <th>Ecosystem</th>
                    <th>Before</th>
                    <th>After</th>
                    <th>Dependency</th>
                  </tr>
                </thead>
                <tbody>
                  {diff.items.map((item) => (
                    <tr key={`${item.change}-${item.identity}`}>
                      <td>
                        <Badge tone={changeTone[item.change]}>{changeLabel[item.change]}</Badge>
                      </td>
                      <td className="font-medium text-slate-100">
                        {item.name}
                        <p className="font-mono text-[11px] text-slate-500">{item.identity}</p>
                      </td>
                      <td className="text-xs text-slate-400">{item.ecosystem ?? "—"}</td>
                      <td className="font-mono text-xs text-slate-400">{item.version_before ?? "—"}</td>
                      <td className="font-mono text-xs text-slate-200">{item.version_after ?? "—"}</td>
                      <td className="text-xs text-slate-400">
                        {dependencyRole(item.is_direct_before, item.is_direct_after)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination
              page={diff.page}
              pages={diff.pages}
              total={diff.total}
              pageSize={diff.page_size}
              onPageChange={setPage}
            />
          </>
        )}
      </Card>
    </div>
  );
}
