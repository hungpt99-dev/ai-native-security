import { useState } from "react";
import { Bot, GitPullRequest, ShieldCheck, Sparkles } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  useApproveRemediation,
  useAssessRisk,
  useBuildSecurityContext,
  useFindingRemediations,
  useInvestigations,
  useInvestigate,
  useProposeRemediation,
  useRejectRemediation,
  useRiskAssessments,
  useSecurityContext,
  useStartVerification,
  useVerifications,
} from "@/hooks/queries";
import { cn, formatRelative } from "@/lib/utils";
import type { EvidenceItem, InvestigationReport, RemediationRecommendation, RiskAssessment } from "@/lib/types";

const TABS = ["Context", "Risk", "Investigation", "Remediation", "Verification"] as const;
type Tab = (typeof TABS)[number];

function riskTone(level: string | null | undefined) {
  switch ((level ?? "").toUpperCase()) {
    case "CRITICAL":
      return "critical" as const;
    case "HIGH":
      return "high" as const;
    case "MEDIUM":
      return "medium" as const;
    case "LOW":
      return "low" as const;
    default:
      return "neutral" as const;
  }
}

function statusTone(status: string | null | undefined) {
  switch ((status ?? "").toUpperCase()) {
    case "VERIFIED_FIXED":
    case "VERIFIED":
    case "CONFIRMED_IMPACT":
      return "success" as const;
    case "NEW_RISK_INTRODUCED":
    case "STILL_VULNERABLE":
    case "FAILED":
      return "danger" as const;
    case "PARTIALLY_FIXED":
    case "POTENTIAL_IMPACT":
    case "AWAITING_APPROVAL":
    case "VALIDATING":
      return "medium" as const;
    case "NO_EVIDENCE_FOUND":
    case "INCONCLUSIVE":
    case "NEEDS_MANUAL_REVIEW":
      return "info" as const;
    default:
      return "neutral" as const;
  }
}

/**
 * AI analysis panel for a single finding.
 *
 * Every AI block is labelled with the model, prompt version and confidence, and
 * the deterministic numbers are shown next to the AI judgement rather than merged
 * into it.
 */
export function FindingAiPanel({ findingId }: { findingId: string }) {
  const [tab, setTab] = useState<Tab>("Context");

  return (
    <div className="rounded-lg border border-cyan-500/20 bg-cyan-500/[0.03] p-4">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <p className="flex items-center gap-2 text-sm font-medium text-cyan-200">
          <Sparkles className="h-4 w-4" /> AI analysis
        </p>
        <div className="flex flex-wrap gap-1">
          {TABS.map((entry) => (
            <button
              key={entry}
              type="button"
              onClick={() => setTab(entry)}
              className={cn(
                "rounded-md px-2 py-1 text-xs text-slate-400 transition-colors hover:text-slate-100",
                tab === entry && "bg-slate-800 text-white",
              )}
            >
              {entry}
            </button>
          ))}
        </div>
      </div>
      <p className="mb-3 text-[11px] text-slate-500">
        AI-generated. Deterministic scanner evidence and policy remain authoritative.
      </p>
      {tab === "Context" ? <ContextTab findingId={findingId} /> : null}
      {tab === "Risk" ? <RiskTab findingId={findingId} /> : null}
      {tab === "Investigation" ? <InvestigationTab findingId={findingId} /> : null}
      {tab === "Remediation" ? <RemediationTab findingId={findingId} /> : null}
      {tab === "Verification" ? <VerificationTab findingId={findingId} /> : null}
    </div>
  );
}

function ContextTab({ findingId }: { findingId: string }) {
  const { data, error } = useSecurityContext(findingId);
  const build = useBuildSecurityContext();
  const payload = (data?.payload ?? {}) as { evidence?: EvidenceItem[]; evidence_count?: number };
  const evidence = payload.evidence ?? [];

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-2">
        <Button size="sm" variant="outline" onClick={() => build.mutate(findingId)} disabled={build.isPending}>
          {build.isPending ? "Building…" : "Build / refresh context"}
        </Button>
      </div>
      {build.error ? <p className="text-xs text-rose-300">{String(build.error.message)}</p> : null}
      {error ? (
        <p className="text-xs text-slate-500">No context snapshot yet. Build one to see what the model receives.</p>
      ) : null}
      {data ? (
        <>
          <div className="grid grid-cols-2 gap-3 text-xs text-slate-400 md:grid-cols-4">
            <div>
              <p className="label">Evidence items</p>
              <p className="mt-1 text-slate-200">{payload.evidence_count ?? evidence.length ?? "—"}</p>
            </div>
            <div>
              <p className="label">Version</p>
              <p className="mt-1 text-slate-200">v{data.context_version}</p>
            </div>
            <div className="col-span-2">
              <p className="label">Evidence hash</p>
              <p className="mt-1 truncate font-mono text-[11px] text-slate-300">{data.evidence_hash}</p>
            </div>
          </div>
          <div>
            <p className="label">Missing information</p>
            <div className="mt-1 flex flex-wrap gap-1">
              {(data.missing_information ?? []).length === 0 ? (
                <span className="text-xs text-emerald-300">None reported</span>
              ) : (
                data.missing_information.map((item) => (
                  <Badge key={item.code} tone="info" title={item.message}>
                    {item.code}
                  </Badge>
                ))
              )}
            </div>
          </div>
          <div>
            <p className="label">Evidence</p>
            <div className="mt-1 space-y-1">
              {evidence.map((item) => (
                <div key={item.key} className="text-xs text-slate-400">
                  <span className="font-mono text-slate-300">{item.key}</span>{" "}
                  <span className="text-slate-500">{item.kind}</span>{" "}
                  {item.locator ? <span className="font-mono text-slate-500">{item.locator}</span> : null}
                </div>
              ))}
            </div>
          </div>
        </>
      ) : null}
    </div>
  );
}

function RiskTab({ findingId }: { findingId: string }) {
  const { data } = useRiskAssessments(findingId);
  const assess = useAssessRisk();
  const latest: RiskAssessment | undefined = data?.[0];

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-2">
        <Button size="sm" onClick={() => assess.mutate({ findingId, useAi: true })} disabled={assess.isPending}>
          {assess.isPending ? "Assessing…" : "Assess risk (AI)"}
        </Button>
        <Button
          size="sm"
          variant="outline"
          onClick={() => assess.mutate({ findingId, useAi: false })}
          disabled={assess.isPending}
        >
          Deterministic only
        </Button>
      </div>
      {assess.error ? <p className="text-xs text-rose-300">{String(assess.error.message)}</p> : null}
      {!latest ? (
        <p className="text-xs text-slate-500">No assessment yet.</p>
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone={riskTone(latest.risk_level)}>{latest.risk_level}</Badge>
            {latest.deterministic_only ? <Badge tone="info">deterministic only</Badge> : null}
            {latest.requires_human_review ? <Badge tone="medium">needs review</Badge> : null}
            <span className="text-xs text-slate-500">
              {latest.model ?? "no model"} · prompt v{latest.prompt_version ?? "—"} ·{" "}
              {formatRelative(latest.created_at)}
            </span>
          </div>
          <div className="grid grid-cols-2 gap-3 text-xs md:grid-cols-5">
            <Metric label="CVSS" value={latest.cvss_score ?? "—"} hint="vendor score" />
            <Metric label="Deterministic" value={latest.deterministic_score} hint="platform signals" />
            <Metric label="AI score" value={latest.ai_risk_score ?? "—"} hint="model judgement" />
            <Metric label="Final" value={latest.final_score} hint="policy blend" />
            <Metric
              label="Confidence"
              value={latest.confidence !== null ? latest.confidence.toFixed(2) : "—"}
              hint="evidence coverage"
            />
          </div>
          {latest.summary ? <p className="text-sm text-slate-200">{latest.summary}</p> : null}
          {latest.impact_analysis ? (
            <p className="text-xs text-slate-400">
              <span className="text-slate-500">Impact: </span>
              {latest.impact_analysis}
            </p>
          ) : null}
          <div className="overflow-x-auto">
            <table className="table-base text-xs">
              <thead>
                <tr>
                  <th>Signal</th>
                  <th>Value</th>
                  <th>Weight</th>
                  <th>Known</th>
                </tr>
              </thead>
              <tbody>
                {latest.signals.map((signal) => (
                  <tr key={signal.key}>
                    <td className="text-slate-300">{signal.label}</td>
                    <td className="font-mono text-slate-400">{String(signal.value ?? "—")}</td>
                    <td className="text-slate-500">{signal.weight}</td>
                    <td>
                      {signal.known ? (
                        <span className="text-emerald-300">yes</span>
                      ) : (
                        <span className="text-amber-300">missing</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {(latest.missing_information ?? []).length ? (
            <div>
              <p className="label">Missing information</p>
              <ul className="mt-1 space-y-0.5 text-xs text-slate-400">
                {latest.missing_information.map((item) => (
                  <li key={item.code}>· {item.message}</li>
                ))}
              </ul>
            </div>
          ) : null}
          {(latest.recommended_actions ?? []).length ? (
            <div>
              <p className="label">Recommended actions</p>
              <ul className="mt-1 space-y-0.5 text-xs text-slate-300">
                {latest.recommended_actions.map((action) => (
                  <li key={action}>→ {action}</li>
                ))}
              </ul>
            </div>
          ) : null}
        </>
      )}
    </div>
  );
}

function Metric({ label, value, hint }: { label: string; value: string | number; hint: string }) {
  return (
    <div className="rounded-md border border-slate-800 bg-slate-950/60 p-2">
      <p className="text-[10px] uppercase tracking-wide text-slate-500">{label}</p>
      <p className="mt-0.5 text-sm font-semibold text-slate-100">{value}</p>
      <p className="text-[10px] text-slate-600">{hint}</p>
    </div>
  );
}

function InvestigationTab({ findingId }: { findingId: string }) {
  const { data } = useInvestigations(findingId);
  const investigate = useInvestigate();
  const latest: InvestigationReport | undefined = data?.[0];

  return (
    <div className="space-y-3">
      <Button size="sm" onClick={() => investigate.mutate(findingId)} disabled={investigate.isPending}>
        {investigate.isPending ? "Investigating…" : "Run investigation"}
      </Button>
      {investigate.error ? <p className="text-xs text-rose-300">{String(investigate.error.message)}</p> : null}
      {!latest ? (
        <p className="text-xs text-slate-500">No investigation yet.</p>
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone={statusTone(latest.status)}>{latest.status.replaceAll("_", " ")}</Badge>
            <span className="text-xs text-slate-500">
              confidence {latest.confidence?.toFixed(2) ?? "—"} · {latest.model || "no model"} ·{" "}
              {latest.workflow.name} v{latest.workflow.version}
            </span>
          </div>
          {latest.status === "NO_EVIDENCE_FOUND" ? (
            <p className="rounded-md border border-amber-500/30 bg-amber-500/10 p-2 text-xs text-amber-200">
              No evidence was found either way. This is not a statement that the application is safe.
            </p>
          ) : null}
          {latest.summary ? <p className="text-sm text-slate-200">{latest.summary}</p> : null}
          <dl className="space-y-1 text-xs">
            {Object.entries(latest.answers ?? {}).map(([key, value]) => (
              <div key={key}>
                <dt className="text-slate-500">{key.replaceAll("_", " ")}</dt>
                <dd className="text-slate-300">{String(value)}</dd>
              </div>
            ))}
          </dl>
          {latest.next_steps?.length ? (
            <div>
              <p className="label">Next steps</p>
              <ul className="mt-1 space-y-0.5 text-xs text-slate-300">
                {latest.next_steps.map((step) => (
                  <li key={step}>→ {step}</li>
                ))}
              </ul>
            </div>
          ) : null}
          {latest.evidence?.length ? (
            <div>
              <p className="label">Cited evidence</p>
              <ul className="mt-1 space-y-0.5 text-xs text-slate-400">
                {latest.evidence.map((item) => (
                  <li key={item.key}>
                    <span className="font-mono text-slate-300">{item.key}</span> {item.kind}
                    {item.cited ? <span className="ml-1 text-emerald-300">cited</span> : null}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </>
      )}
    </div>
  );
}

function RemediationTab({ findingId }: { findingId: string }) {
  const { data } = useFindingRemediations(findingId);
  const propose = useProposeRemediation();
  const approve = useApproveRemediation();
  const reject = useRejectRemediation();
  const verify = useStartVerification();
  const [note, setNote] = useState("");
  const latest: RemediationRecommendation | undefined = data?.[0];

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-2">
        <Button size="sm" onClick={() => propose.mutate(findingId)} disabled={propose.isPending}>
          <GitPullRequest className="h-3.5 w-3.5" />
          {propose.isPending ? "Proposing…" : "Propose remediation"}
        </Button>
      </div>
      {propose.error ? <p className="text-xs text-rose-300">{String(propose.error.message)}</p> : null}
      {!latest ? (
        <p className="text-xs text-slate-500">No remediation proposal yet.</p>
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone={statusTone(latest.status)}>{latest.status.replaceAll("_", " ")}</Badge>
            <Badge tone="neutral">{latest.strategy.replaceAll("_", " ")}</Badge>
            {latest.version_verified ? (
              <Badge tone="success">version verified</Badge>
            ) : (
              <Badge tone="info">version unverified</Badge>
            )}
          </div>
          <p className="text-sm text-slate-200">{latest.summary}</p>
          <div className="grid grid-cols-2 gap-3 text-xs md:grid-cols-4">
            <Metric label="Package" value={latest.target_package ?? "—"} hint="target" />
            <Metric label="Current" value={latest.current_version ?? "—"} hint="installed" />
            <Metric label="Recommended" value={latest.recommended_version ?? "—"} hint="authoritative" />
            <Metric label="Proposal" value={latest.model ?? "no model"} hint={formatRelative(latest.created_at)} />
          </div>
          {latest.reasoning ? <p className="text-xs text-slate-400">{latest.reasoning}</p> : null}
          {latest.breaking_change_risks?.length ? (
            <div>
              <p className="label">Breaking-change risks</p>
              <ul className="mt-1 space-y-0.5 text-xs text-amber-200">
                {latest.breaking_change_risks.map((risk) => (
                  <li key={risk}>· {risk}</li>
                ))}
              </ul>
            </div>
          ) : null}
          {latest.recommended_tests?.length ? (
            <div>
              <p className="label">Recommended tests</p>
              <ul className="mt-1 space-y-0.5 text-xs text-slate-300">
                {latest.recommended_tests.map((test) => (
                  <li key={test}>→ {test}</li>
                ))}
              </ul>
            </div>
          ) : null}
          {latest.patch ? (
            <details>
              <summary className="cursor-pointer text-xs text-slate-400">
                Proposed patch (unverified, never applied automatically)
              </summary>
              <pre className="mt-1 max-h-56 overflow-auto rounded-lg bg-slate-950/80 p-3 font-mono text-[11px] text-slate-400">
                {latest.patch}
              </pre>
            </details>
          ) : null}
          <Input
            placeholder="Decision note (required to reject)"
            value={note}
            onChange={(event) => setNote(event.target.value)}
          />
          <div className="flex flex-wrap gap-2">
            <Button
              size="sm"
              onClick={() => approve.mutate({ id: latest.id, note: note || undefined })}
              disabled={approve.isPending || !["AWAITING_APPROVAL", "REMEDIATION_PROPOSED"].includes(latest.status)}
            >
              Approve
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => reject.mutate({ id: latest.id, note: note || "rejected" })}
              disabled={reject.isPending || !["AWAITING_APPROVAL", "REMEDIATION_PROPOSED"].includes(latest.status)}
            >
              Reject
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => verify.mutate(latest.id)}
              disabled={verify.isPending || !["APPROVED", "VALIDATING", "VERIFIED"].includes(latest.status)}
            >
              <ShieldCheck className="h-3.5 w-3.5" /> Verify with a new scan
            </Button>
          </div>
          {approve.error ? <p className="text-xs text-rose-300">{String(approve.error.message)}</p> : null}
          {reject.error ? <p className="text-xs text-rose-300">{String(reject.error.message)}</p> : null}
          {verify.data ? (
            <p className="text-xs text-cyan-300">
              Verification scan {verify.data.scan.id.slice(0, 8)} queued. The result is derived from scanner
              evidence only.
            </p>
          ) : null}
        </>
      )}
    </div>
  );
}

function VerificationTab({ findingId }: { findingId: string }) {
  const { data } = useVerifications(findingId);
  if (!data || data.length === 0) {
    return <p className="text-xs text-slate-500">No verification run yet.</p>;
  }
  return (
    <div className="space-y-2">
      {data.map((verification) => (
        <div key={verification.id} className="rounded-md border border-slate-800 bg-slate-950/50 p-2 text-xs">
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone={statusTone(verification.status)}>{verification.status.replaceAll("_", " ")}</Badge>
            <span className="font-mono text-slate-400">
              {verification.before_version ?? "—"} → {verification.after_version ?? "—"}
            </span>
            <span className="text-slate-500">{formatRelative(verification.verified_at ?? verification.created_at)}</span>
          </div>
          {verification.notes ? <p className="mt-1 text-slate-400">{verification.notes}</p> : null}
          {verification.ai_explanation ? (
            <p className="mt-1 text-slate-500">
              <Bot className="mr-1 inline h-3 w-3" />
              {verification.ai_explanation}
            </p>
          ) : null}
        </div>
      ))}
    </div>
  );
}
