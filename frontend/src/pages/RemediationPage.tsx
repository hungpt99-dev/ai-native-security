import { useMemo, useState } from "react";
import { GitPullRequest, ShieldCheck } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { EmptyState, ErrorState, PageHeader, Pagination } from "@/components/common";
import { TableSkeleton } from "@/components/ui/skeleton";
import {
  useApproveRemediation,
  useRejectRemediation,
  useRemediationQueue,
  useStartVerification,
  useVerifications,
} from "@/hooks/queries";
import { formatRelative } from "@/lib/utils";
import type { RemediationRecommendation } from "@/lib/types";

const STATUSES = [
  "ALL",
  "AWAITING_APPROVAL",
  "APPROVED",
  "VALIDATING",
  "VERIFIED",
  "FAILED",
  "REJECTED",
  "REOPENED",
  "CLOSED",
] as const;

function statusTone(status: string) {
  switch (status) {
    case "VERIFIED":
    case "CLOSED":
      return "success" as const;
    case "FAILED":
    case "REJECTED":
      return "danger" as const;
    case "AWAITING_APPROVAL":
    case "APPROVED":
    case "VALIDATING":
      return "medium" as const;
    case "REOPENED":
      return "high" as const;
    default:
      return "neutral" as const;
  }
}

export function RemediationPage() {
  const [status, setStatus] = useState<string>("ALL");
  const [page, setPage] = useState(1);
  const [expanded, setExpanded] = useState<string | null>(null);

  const params = useMemo(
    () => ({ page, page_size: 25, status: status === "ALL" ? undefined : status }),
    [page, status],
  );
  const { data, isLoading, error } = useRemediationQueue(params);

  return (
    <div>
      <PageHeader
        title="Remediation centre"
        subtitle="AI proposals, human decisions and deterministic verification"
      />

      <div className="mb-3 flex flex-wrap items-end justify-between gap-3">
        <div className="w-56">
          <label className="label" htmlFor="status">
            Lifecycle status
          </label>
          <Select
            value={status}
            onValueChange={(value) => {
              setPage(1);
              setStatus(value);
            }}
          >
            <SelectTrigger id="status">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {STATUSES.map((entry) => (
                <SelectItem key={entry} value={entry}>
                  {entry === "ALL" ? "All proposals" : entry.replaceAll("_", " ")}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <p className="text-xs text-slate-500">
          Proposals are never applied automatically. Verification status comes only from scanner evidence.
        </p>
      </div>

      <Card>
        {error ? (
          <ErrorState error={error} />
        ) : isLoading ? (
          <TableSkeleton columns={5} />
        ) : !data || data.items.length === 0 ? (
          <EmptyState
            title="No remediation proposals"
            description="Propose remediation from a finding's AI panel; proposals appear here for approval."
          />
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="table-base">
                <thead>
                  <tr>
                    <th>Proposal</th>
                    <th>Strategy</th>
                    <th>Version</th>
                    <th>Status</th>
                    <th>Created</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((row: RemediationRecommendation) => (
                    <tr key={row.id} className="cursor-pointer" onClick={() => setExpanded(expanded === row.id ? null : row.id)}>
                      <td className="max-w-md">
                        <p className="truncate text-slate-100">{row.summary ?? row.target_package ?? row.id.slice(0, 8)}</p>
                        <p className="mt-0.5 font-mono text-[11px] text-slate-500">
                          {row.target_package ?? "—"} · finding {row.finding_id.slice(0, 8)}
                        </p>
                      </td>
                      <td className="text-xs text-slate-300">{row.strategy.replaceAll("_", " ")}</td>
                      <td className="font-mono text-xs text-slate-400">
                        {row.current_version ?? "—"} → {row.recommended_version ?? "—"}
                        {row.version_verified ? <span className="ml-1 text-emerald-300">✓</span> : null}
                      </td>
                      <td>
                        <Badge tone={statusTone(row.status)}>{row.status.replaceAll("_", " ")}</Badge>
                      </td>
                      <td className="text-xs text-slate-400">{formatRelative(row.created_at)}</td>
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

      {expanded ? <RecommendationDetail id={expanded} onClose={() => setExpanded(null)} /> : null}
    </div>
  );
}

function RecommendationDetail({ id, onClose }: { id: string; onClose: () => void }) {
  const { data } = useRemediationQueue({ page: 1, page_size: 200 });
  const recommendation = data?.items.find((entry) => entry.id === id);
  const verifications = useVerifications(recommendation?.finding_id);
  const approve = useApproveRemediation();
  const reject = useRejectRemediation();
  const verify = useStartVerification();
  const [note, setNote] = useState("");

  if (!recommendation) return null;
  const canDecide = ["AWAITING_APPROVAL", "REMEDIATION_PROPOSED"].includes(recommendation.status);
  const canVerify = ["APPROVED", "VALIDATING", "VERIFIED"].includes(recommendation.status);

  return (
    <Card className="mt-4 border-slate-700">
      <div className="space-y-3 p-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="flex items-center gap-2 text-sm font-medium text-slate-100">
            <GitPullRequest className="h-4 w-4 text-cyan-400" /> {recommendation.target_package ?? "Proposal"}
          </p>
          <Button size="sm" variant="outline" onClick={onClose}>
            Close
          </Button>
        </div>
        <p className="text-sm text-slate-200">{recommendation.summary}</p>
        {recommendation.reasoning ? <p className="text-xs text-slate-400">{recommendation.reasoning}</p> : null}

        {recommendation.breaking_change_risks?.length ? (
          <div>
            <p className="label">Breaking-change risks</p>
            <ul className="mt-1 space-y-0.5 text-xs text-amber-200">
              {recommendation.breaking_change_risks.map((risk) => (
                <li key={risk}>· {risk}</li>
              ))}
            </ul>
          </div>
        ) : null}

        {recommendation.patch ? (
          <details>
            <summary className="cursor-pointer text-xs text-slate-400">
              Proposed patch (unverified, proposal only)
            </summary>
            <pre className="mt-1 max-h-60 overflow-auto rounded-lg bg-slate-950/80 p-3 font-mono text-[11px] text-slate-400">
              {recommendation.patch}
            </pre>
          </details>
        ) : null}

        {recommendation.missing_information?.length ? (
          <div>
            <p className="label">Missing information</p>
            <ul className="mt-1 space-y-0.5 text-xs text-slate-400">
              {recommendation.missing_information.map((item) => (
                <li key={item.code}>· {item.message}</li>
              ))}
            </ul>
          </div>
        ) : null}

        <div className="flex flex-wrap items-center gap-2">
          <Input
            className="max-w-sm"
            placeholder="Decision note (required to reject)"
            value={note}
            onChange={(event) => setNote(event.target.value)}
          />
          <Button
            size="sm"
            disabled={!canDecide || approve.isPending}
            onClick={() => approve.mutate({ id: recommendation.id, note: note || undefined })}
          >
            Approve
          </Button>
          <Button
            size="sm"
            variant="outline"
            disabled={!canDecide || reject.isPending}
            onClick={() => reject.mutate({ id: recommendation.id, note: note || "rejected" })}
          >
            Reject
          </Button>
          <Button
            size="sm"
            variant="outline"
            disabled={!canVerify || verify.isPending}
            onClick={() => verify.mutate(recommendation.id)}
          >
            <ShieldCheck className="h-3.5 w-3.5" /> Verify with a new scan
          </Button>
        </div>
        {reject.error ? <p className="text-xs text-rose-300">{String(reject.error.message)}</p> : null}
        {verify.data ? (
          <p className="text-xs text-cyan-300">
            Scan {verify.data.scan.id.slice(0, 8)} queued for verification.
          </p>
        ) : null}

        <div>
          <p className="label">Verification history</p>
          {(verifications.data ?? []).length === 0 ? (
            <p className="mt-1 text-xs text-slate-500">No verification run yet.</p>
          ) : (
            <div className="mt-1 space-y-1">
              {(verifications.data ?? []).map((verification) => (
                <div key={verification.id} className="rounded-md border border-slate-800 bg-slate-950/50 p-2 text-xs">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge tone={statusTone(verification.status === "VERIFIED_FIXED" ? "VERIFIED" : verification.status)}>
                      {verification.status.replaceAll("_", " ")}
                    </Badge>
                    <span className="font-mono text-slate-400">
                      {verification.before_version ?? "—"} → {verification.after_version ?? "—"}
                    </span>
                    <span className="text-slate-500">
                      {formatRelative(verification.verified_at ?? verification.created_at)}
                    </span>
                  </div>
                  {verification.notes ? <p className="mt-1 text-slate-400">{verification.notes}</p> : null}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </Card>
  );
}
