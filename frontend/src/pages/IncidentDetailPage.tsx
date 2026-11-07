import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, Bot, GitMerge, Link2, MessageSquare } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Label, Textarea } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { SeverityBadge, ErrorState, PageHeader } from "@/components/common";
import { IncidentStatusBadge } from "@/pages/IncidentsPage";
import {
  useAddIncidentNote,
  useAssignIncident,
  useCorrelateIncident,
  useIncident,
  useIncidentInvestigations,
  useInvestigateIncident,
  useUpdateIncident,
} from "@/hooks/queries";
import { formatDate, formatRelative } from "@/lib/utils";

const NEXT_STATUS: Record<string, string[]> = {
  OPEN: ["TRIAGING", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"],
  TRIAGING: ["INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"],
  INVESTIGATING: ["CONTAINED", "RESOLVED", "CLOSED", "TRIAGING"],
  CONTAINED: ["RESOLVED", "INVESTIGATING", "CLOSED"],
  RESOLVED: ["CLOSED", "OPEN"],
  CLOSED: ["OPEN"],
};

export function IncidentDetailPage() {
  const { id } = useParams();
  const { data, isLoading, error } = useIncident(id);
  const { data: investigations } = useIncidentInvestigations(id);
  const updateStatus = useUpdateIncident(id ?? "");
  const assign = useAssignIncident(id ?? "");
  const addNote = useAddIncidentNote(id ?? "");
  const correlate = useCorrelateIncident(id ?? "");
  const investigate = useInvestigateIncident(id ?? "");

  const [nextStatus, setNextStatus] = useState<string>("");
  const [note, setNote] = useState("");
  const [assignee, setAssignee] = useState("");
  const [statusNote, setStatusNote] = useState("");
  const [correlationResult, setCorrelationResult] = useState<string | null>(null);

  if (error) return <ErrorState error={error} />;
  if (isLoading || !data) {
    return <div className="panel h-64 animate-pulse" />;
  }

  const { incident, asset, events, findings, timeline } = data;
  const options = NEXT_STATUS[incident.status] ?? [];
  const latest = investigations?.[0];

  return (
    <div>
      <Link to="/incidents" className="mb-3 inline-flex items-center gap-1 text-xs text-slate-400 hover:text-slate-200">
        <ArrowLeft className="h-3 w-3" /> All incidents
      </Link>
      <PageHeader
        title={incident.title}
        subtitle={asset ? `${asset.kind} · ${asset.name}` : "Unattributed incident"}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={incident.severity} />
            <Badge tone="critical">{incident.priority}</Badge>
            <IncidentStatusBadge status={incident.status} />
            <Badge tone="neutral">risk {incident.risk_score}</Badge>
          </div>
        }
      />

      {incident.summary && <p className="mb-4 max-w-4xl text-sm text-slate-300">{incident.summary}</p>}

      <div className="mb-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <div className="panel p-4">
          <p className="text-xs text-slate-500">Opened</p>
          <p className="text-sm text-slate-200">{formatDate(incident.opened_at)}</p>
        </div>
        <div className="panel p-4">
          <p className="text-xs text-slate-500">Evidence</p>
          <p className="text-sm text-slate-200">{incident.event_count} events · {incident.finding_count} findings</p>
        </div>
        <div className="panel p-4">
          <p className="text-xs text-slate-500">Assigned to</p>
          <p className="text-sm text-slate-200">{incident.assigned_to ?? "unassigned"}</p>
        </div>
        <div className="panel p-4">
          <p className="text-xs text-slate-500">Detection rule</p>
          <p className="text-sm text-slate-200">{incident.detection_rule_slug ?? "correlation"}</p>
        </div>
      </div>

      <div className="mb-6 grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader><CardTitle>Lifecycle</CardTitle></CardHeader>
          <CardContent className="space-y-3 pt-0">
            <div className="flex flex-wrap items-end gap-2">
              <div className="min-w-40 flex-1">
                <Label>Move to status</Label>
                <Select value={nextStatus} onValueChange={setNextStatus}>
                  <SelectTrigger><SelectValue placeholder="Select transition" /></SelectTrigger>
                  <SelectContent>
                    {options.map((status) => (
                      <SelectItem key={status} value={status}>{status}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <Button
                disabled={!nextStatus || updateStatus.isPending}
                onClick={() =>
                  updateStatus
                    .mutateAsync({ status: nextStatus, note: statusNote || undefined })
                    .then(() => {
                      setNextStatus("");
                      setStatusNote("");
                    })
                }
              >
                Apply
              </Button>
            </div>
            <div>
              <Label>Transition note (optional)</Label>
              <Input value={statusNote} onChange={(event) => setStatusNote(event.target.value)} placeholder="Why is the status changing?" />
            </div>
            <div className="flex flex-wrap items-end gap-2">
              <div className="min-w-40 flex-1">
                <Label>Assign</Label>
                <Input value={assignee} onChange={(event) => setAssignee(event.target.value)} placeholder="analyst or team" />
              </div>
              <Button variant="outline" disabled={assign.isPending} onClick={() => assign.mutate(assignee || null)}>
                Assign
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle>Investigation</CardTitle></CardHeader>
          <CardContent className="space-y-3 pt-0">
            <div className="flex flex-wrap gap-2">
              <Button
                variant="outline"
                disabled={correlate.isPending}
                onClick={() =>
                  correlate.mutateAsync().then((result) =>
                    setCorrelationResult(`${result.events} event(s) and ${result.findings} finding(s) attached`),
                  )
                }
              >
                <GitMerge className="h-4 w-4" /> Correlate evidence
              </Button>
              <Button disabled={investigate.isPending} onClick={() => investigate.mutate()}>
                <Bot className="h-4 w-4" /> {investigate.isPending ? "Investigating…" : "AI investigation"}
              </Button>
            </div>
            {correlationResult && <p className="text-xs text-emerald-300">{correlationResult}</p>}
            {investigate.error && <p className="text-xs text-rose-300">{(investigate.error as Error).message}</p>}
            <div>
              <Label>Add note</Label>
              <Textarea
                rows={3}
                value={note}
                onChange={(event) => setNote(event.target.value)}
                placeholder="Evidence, decision or handover note"
              />
              <Button
                className="mt-2"
                variant="outline"
                disabled={!note.trim() || addNote.isPending}
                onClick={() => addNote.mutateAsync(note).then(() => setNote(""))}
              >
                <MessageSquare className="h-4 w-4" /> Add to timeline
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>

      {latest && (
        <Card className="mb-6">
          <CardHeader className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2"><Bot className="h-4 w-4 text-cyan-400" /> AI investigation</CardTitle>
            <div className="flex items-center gap-2">
              <Badge tone={latest.status === "CONFIRMED_IMPACT" ? "high" : latest.status === "NO_EVIDENCE_FOUND" ? "medium" : "neutral"}>
                {latest.status}
              </Badge>
              {latest.confidence !== null && <Badge tone="info">confidence {Math.round(latest.confidence * 100)}%</Badge>}
            </div>
          </CardHeader>
          <CardContent className="space-y-3 pt-0 text-sm">
            <p className="text-slate-200">{latest.summary}</p>
            {latest.error_code && (
              <p className="text-xs text-amber-300">Recorded as {latest.error_code}: no conclusion was drawn.</p>
            )}
            {latest.attack_steps.length > 0 && (
              <div>
                <p className="mb-1 text-xs font-semibold text-slate-400">Attack steps</p>
                <ol className="list-decimal space-y-1 pl-5 text-xs text-slate-300">
                  {latest.attack_steps.map((step) => (
                    <li key={`${step.order}-${step.description}`}>
                      {step.description} <span className="text-slate-500">[{step.evidence.join(", ")}]</span>
                    </li>
                  ))}
                </ol>
              </div>
            )}
            {latest.evidence.length > 0 && (
              <p className="text-xs text-slate-500">
                Cited evidence: {latest.evidence.map((item) => `${item.key}${item.note ? ` (${item.note})` : ""}`).join(", ")}
              </p>
            )}
            {latest.next_actions.length > 0 && (
              <div>
                <p className="mb-1 text-xs font-semibold text-slate-400">Recommended containment</p>
                <ul className="list-disc space-y-1 pl-5 text-xs text-slate-300">
                  {latest.next_actions.map((action) => <li key={action}>{action}</li>)}
                </ul>
              </div>
            )}
            <p className="text-[11px] text-slate-500">
              {latest.model || "no model"} · {latest.prompt_id}@{latest.prompt_version} · {formatRelative(latest.created_at)}.
              An AI report never changes the incident status, severity or priority.
            </p>
          </CardContent>
        </Card>
      )}

      <Card className="mb-6">
        <CardHeader className="flex items-center justify-between">
          <CardTitle>Timeline</CardTitle>
          <span className="text-xs text-slate-500">{timeline.length} entries</span>
        </CardHeader>
        <CardContent className="space-y-3 pt-0">
          {timeline.map((entry) => (
            <div key={entry.id} className="flex gap-3 border-l border-slate-800 pl-3">
              <div className="min-w-32 text-[11px] text-slate-500">
                {formatDate(entry.created_at)}
                <div>{entry.actor}</div>
              </div>
              <div>
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-400">{entry.kind}</p>
                <p className="text-sm text-slate-200">{entry.message}</p>
              </div>
            </div>
          ))}
        </CardContent>
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader><CardTitle>Attached events</CardTitle></CardHeader>
          <CardContent className="space-y-2 pt-0">
            {events.length === 0 ? (
              <p className="text-sm text-slate-500">No events attached.</p>
            ) : (
              events.map((event) => (
                <div key={event.id} className="rounded-lg border border-slate-800 bg-slate-900/40 p-3">
                  <div className="flex items-center justify-between gap-2">
                    <p className="text-sm text-slate-200">{event.title}</p>
                    <SeverityBadge severity={event.severity} />
                  </div>
                  <p className="text-xs text-slate-500">
                    {event.event_type} · {event.occurrence_count} occurrence(s) · last {formatRelative(event.last_seen_at)}
                  </p>
                </div>
              ))
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle>Linked findings</CardTitle></CardHeader>
          <CardContent className="space-y-2 pt-0">
            {findings.length === 0 ? (
              <p className="text-sm text-slate-500">No findings linked.</p>
            ) : (
              findings.map((finding) => (
                <div key={finding.id} className="rounded-lg border border-slate-800 bg-slate-900/40 p-3">
                  <div className="flex items-center justify-between gap-2">
                    <Link to={`/findings?search=${encodeURIComponent(finding.cve_id ?? finding.title)}`} className="text-sm text-slate-200 hover:text-cyan-300">
                      {finding.title}
                    </Link>
                    <SeverityBadge severity={finding.severity} />
                  </div>
                  <p className="text-xs text-slate-500">
                    <Link2 className="mr-1 inline h-3 w-3" />
                    {finding.cve_id ?? "no CVE"} · {finding.package_name ?? finding.file_path ?? "—"}
                  </p>
                </div>
              ))
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
