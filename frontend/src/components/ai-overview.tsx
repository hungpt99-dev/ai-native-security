import { Link } from "react-router-dom";
import { AlertTriangle, Bot, BrainCircuit, GitPullRequest } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useAiOverview } from "@/hooks/queries";
import { formatRelative } from "@/lib/utils";

function tone(level: string) {
  switch (level.toUpperCase()) {
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

export function AiOverviewSection() {
  const { data, error } = useAiOverview();
  if (error || !data) return null;

  const provider = data.provider;
  const inactive = !provider.enabled || !provider.configured;

  return (
    <Card className="mb-4 border-cyan-500/20 bg-cyan-500/[0.03]">
      <CardHeader className="flex flex-row items-center justify-between gap-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <BrainCircuit className="h-4 w-4 text-cyan-400" /> AI risk overview
        </CardTitle>
        <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500">
          <Badge tone={inactive ? "info" : "success"}>
            {inactive ? "AI inactive" : `${provider.provider}/${provider.model}`}
          </Badge>
          <span>${data.budget.cost_usd_today.toFixed(4)} today</span>
          <span>· {data.budget.executions_today} calls</span>
          <Link to="/assistant" className="flex items-center gap-1 text-cyan-300 hover:text-cyan-200">
            <Bot className="h-3.5 w-3.5" /> Ask the assistant
          </Link>
        </div>
      </CardHeader>
      <CardContent className="grid gap-4 md:grid-cols-3">
        <div>
          <p className="label">Highest-risk repositories</p>
          <div className="mt-2 space-y-1.5">
            {data.top_risk_assets.length === 0 ? (
              <p className="text-xs text-slate-500">No assessments yet.</p>
            ) : (
              data.top_risk_assets.map((asset) => (
                <div key={asset.asset_id} className="flex items-center justify-between gap-2 text-sm">
                  <Link to={`/assets/${asset.asset_id}`} className="truncate text-slate-200 hover:text-cyan-300">
                    {asset.name}
                  </Link>
                  <span className="font-mono text-xs text-slate-400">{asset.highest_final_score}</span>
                </div>
              ))
            )}
          </div>
        </div>
        <div>
          <p className="label">Highest assessed findings</p>
          <div className="mt-2 space-y-1.5">
            {data.critical_findings.length === 0 ? (
              <p className="text-xs text-slate-500">No critical or high assessments.</p>
            ) : (
              data.critical_findings.slice(0, 5).map((finding) => (
                <div key={finding.assessment_id} className="flex items-start justify-between gap-2 text-xs">
                  <div className="min-w-0">
                    <Link
                      to={`/findings?severity=${finding.severity}`}
                      className="block truncate text-slate-200 hover:text-cyan-300"
                      title={finding.title}
                    >
                      {finding.title}
                    </Link>
                    <span className="text-slate-500">
                      {finding.asset_name} · {formatRelative(finding.created_at)}
                    </span>
                  </div>
                  <div className="flex shrink-0 flex-col items-end gap-1">
                    <Badge tone={tone(finding.risk_level)}>{finding.risk_level}</Badge>
                    {finding.deterministic_only ? <span className="text-[10px] text-slate-500">det. only</span> : null}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
        <div className="space-y-2 text-xs">
          <div className="flex items-center justify-between rounded-md border border-slate-800 bg-slate-950/50 p-2">
            <span className="flex items-center gap-1.5 text-slate-400">
              <AlertTriangle className="h-3.5 w-3.5 text-amber-400" /> Needs human review
            </span>
            <span className="font-mono text-slate-200">{data.needs_review}</span>
          </div>
          <div className="flex items-center justify-between rounded-md border border-slate-800 bg-slate-950/50 p-2">
            <span className="flex items-center gap-1.5 text-slate-400">
              <GitPullRequest className="h-3.5 w-3.5 text-cyan-400" /> Remediation pending
            </span>
            <span className="font-mono text-slate-200">{data.remediation_pending}</span>
          </div>
          <div className="flex items-center justify-between rounded-md border border-slate-800 bg-slate-950/50 p-2">
            <span className="text-slate-400">Unverified proposals</span>
            <span className="font-mono text-slate-200">{data.unverified_proposals}</span>
          </div>
          <Link to="/remediation" className="block text-cyan-300 hover:text-cyan-200">
            Open remediation centre →
          </Link>
        </div>
      </CardContent>
    </Card>
  );
}
