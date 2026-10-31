import { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, Download } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Label } from "@/components/ui/input";
import { KeyValue, ErrorState, Mono, PageHeader, Pagination } from "@/components/common";
import { EmptyState } from "@/components/common";
import { TableSkeleton } from "@/components/ui/skeleton";
import { useSbom, useSbomPackages } from "@/hooks/queries";
import { downloadUrl } from "@/lib/api";
import { formatBytes, formatDate } from "@/lib/utils";

export function SbomDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [ecosystem, setEcosystem] = useState("");

  const { data: sbom, isLoading, error } = useSbom(id);
  const params = useMemo(
    () => ({
      page,
      page_size: 50,
      search: search || undefined,
      ecosystem: ecosystem || undefined,
    }),
    [page, search, ecosystem],
  );
  const { data: packages, isLoading: packagesLoading } = useSbomPackages(id, params);

  if (error) return <ErrorState error={error} />;
  if (isLoading || !sbom) return <TableSkeleton rows={5} columns={3} />;

  return (
    <div>
      <Link to="/sboms" className="mb-4 inline-flex items-center gap-1 text-xs text-slate-400 hover:text-cyan-300">
        <ArrowLeft className="h-3.5 w-3.5" /> Back to SBOMs
      </Link>
      <PageHeader
        title={`SBOM ${sbom.id.slice(0, 8)}`}
        subtitle={`${sbom.format.replace("_", " ")} · ${sbom.package_count} packages`}
        actions={
          <a
            href={downloadUrl(`/sboms/${sbom.id}/download`)}
            className="inline-flex h-9 items-center gap-2 rounded-lg bg-cyan-500 px-4 text-sm font-medium text-slate-950 hover:bg-cyan-400"
          >
            <Download className="h-4 w-4" /> Download
          </a>
        }
      />

      <Card>
        <CardHeader>
          <CardTitle>Document metadata</CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <KeyValue label="Format">
              <Mono>{sbom.format}</Mono>
            </KeyValue>
            <KeyValue label="Spec version">{sbom.spec_version ?? "—"}</KeyValue>
            <KeyValue label="Tool">
              {sbom.tool_name} {sbom.tool_version ?? ""}
            </KeyValue>
            <KeyValue label="Packages">{sbom.package_count}</KeyValue>
            <KeyValue label="Size">{formatBytes(sbom.size_bytes)}</KeyValue>
            <KeyValue label="SHA-256">
              <Mono className="break-all">{sbom.sha256.slice(0, 24)}…</Mono>
            </KeyValue>
            <KeyValue label="Asset">
              <Link to={`/assets/${sbom.asset_id}`} className="text-cyan-400 hover:underline">
                view repository
              </Link>
            </KeyValue>
            <KeyValue label="Scan">
              {sbom.scan_id ? (
                <Link to={`/scans/${sbom.scan_id}`} className="text-cyan-400 hover:underline">
                  {sbom.scan_id.slice(0, 8)}
                </Link>
              ) : (
                "—"
              )}
            </KeyValue>
            <KeyValue label="Created">{formatDate(sbom.created_at)}</KeyValue>
          </dl>
        </CardContent>
      </Card>

      <Card className="mt-4">
        <CardHeader>
          <CardTitle>Packages</CardTitle>
          <div className="flex gap-2">
            <div className="w-56">
              <Label>Search</Label>
              <Input
                placeholder="Package name"
                value={search}
                onChange={(event) => {
                  setPage(1);
                  setSearch(event.target.value);
                }}
              />
            </div>
            <div className="w-40">
              <Label>Ecosystem</Label>
              <Input
                placeholder="e.g. PyPI"
                value={ecosystem}
                onChange={(event) => {
                  setPage(1);
                  setEcosystem(event.target.value);
                }}
              />
            </div>
          </div>
        </CardHeader>
        {packagesLoading ? (
          <TableSkeleton columns={5} />
        ) : !packages || packages.items.length === 0 ? (
          <EmptyState title="No packages" description="This SBOM has no packages matching the filters." />
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="table-base">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Version</th>
                    <th>Ecosystem</th>
                    <th>License</th>
                    <th>PURL</th>
                  </tr>
                </thead>
                <tbody>
                  {packages.items.map((pkg) => (
                    <tr key={pkg.id}>
                      <td className="font-medium text-slate-100">{pkg.name}</td>
                      <td className="font-mono text-xs text-slate-300">{pkg.version || "—"}</td>
                      <td className="text-xs text-slate-400">{pkg.ecosystem ?? "—"}</td>
                      <td className="max-w-xs truncate text-xs text-slate-400">{pkg.license ?? "—"}</td>
                      <td className="max-w-xs truncate font-mono text-[11px] text-slate-500">{pkg.purl ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination
              page={packages.page}
              pages={packages.pages}
              total={packages.total}
              pageSize={packages.page_size}
              onPageChange={setPage}
            />
          </>
        )}
      </Card>
    </div>
  );
}
