import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Filter, ShieldAlert } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input, Label } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { TableSkeleton } from "@/components/ui/skeleton";
import {
  EmptyState,
  ErrorState,
  PageHeader,
  Pagination,
  SeverityBadge,
} from "@/components/common";
import { useIncidentSummary, useIncidents } from "@/hooks/queries";
import { formatRelative } from "@/lib/utils";
import type { Incident, Severity } from "@/lib/types";

const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"];
const STATUSES = ["OPEN", "TRIAGING", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"];
const PRIORITIES = ["P1", "P2", "P3", "P4"];

const priorityTone: Record<string, "critical" | "high" | "medium" | "low"> = {
  P1: "critical",
  P2: "high",
  P3: "medium",
  P4: "low",
};

const statusTone: Record<string, "danger" | "running" | "medium" | "success" | "neutral"> = {
  OPEN: "danger",
  TRIAGING: "medium",
  INVESTIGATING: "running",
  CONTAINED: "medium",
  RESOLVED: "success",
  CLOSED: "neutral",
};

export function IncidentStatusBadge({ status }: { status: string }) {
  return <Badge tone={statusTone[status] ?? "neutral"}>{status}</Badge>;
}

export function IncidentsPage() {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState("active");
  const [severity, setSeverity] = useState("all");
  const [priority, setPriority] = useState("all");

  const params = useMemo(
    () => ({
      page,
      page_size: 25,
      search: search || undefined,
      active_only: status === "active" ? true : undefined,
      status: status === "active" || status === "all" ? undefined : status,
      severity: severity === "all" ? undefined : severity,
      priority: priority === "all" ? undefined : priority,
      sort_by: "opened_at",
      sort_order: "desc",
    }),
    [page, search, status, severity, priority],
  );

  const { data, isLoading, error } = useIncidents(params);
  const { data: summary } = useIncidentSummary();

  return (
    <div>
      <PageHeader
        title="Incident management"
        subtitle="Correlated security incidents with a human-owned lifecycle and investigation timeline"
        actions={
          <Button
            variant="outline"
            onClick={() => {
              setPage(1);
              setSearch("");
              setStatus("active");
              setSeverity("all");
              setPriority("all");
            }}
          >
            <Filter className="h-4 w-4" /> Reset filters
          </Button>
        }
      />

      <div className="mb-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <div className="panel p-4">
          <p className="text-xs text-slate-500">Active incidents</p>
          <p className="text-2xl font-semibold text-white">{summary?.active ?? "—"}</p>
        </div>
        {(["P1", "P2", "P3"] as const).map((band) => (
          <div key={band} className="panel p-4">
            <p className="text-xs text-slate-500">{band} open</p>
            <p className="text-2xl font-semibold text-slate-200">
              {summary?.top_open?.filter((incident) => incident.priority === band).length ?? 0}
            </p>
          </div>
        ))}
      </div>

      <div className="mb-4 grid gap-2 md:grid-cols-2 xl:grid-cols-4">
        <div>
          <Label>Search</Label>
          <Input
            placeholder="Title or summary…"
            value={search}
            onChange={(event) => {
              setPage(1);
              setSearch(event.target.value);
            }}
          />
        </div>
        <div>
          <Label>Status</Label>
          <Select value={status} onValueChange={(value) => { setPage(1); setStatus(value); }}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="active">Active only</SelectItem>
              <SelectItem value="all">All</SelectItem>
              {STATUSES.map((entry) => (
                <SelectItem key={entry} value={entry}>{entry}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div>
          <Label>Severity</Label>
          <Select value={severity} onValueChange={(value) => { setPage(1); setSeverity(value); }}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All</SelectItem>
              {SEVERITIES.map((entry) => (
                <SelectItem key={entry} value={entry}>{entry}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div>
          <Label>Priority</Label>
          <Select value={priority} onValueChange={(value) => { setPage(1); setPriority(value); }}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All</SelectItem>
              {PRIORITIES.map((entry) => (
                <SelectItem key={entry} value={entry}>{entry}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      <Card className="overflow-hidden">
        {error ? (
          <ErrorState error={error} />
        ) : isLoading ? (
          <TableSkeleton rows={6} />
        ) : !data || data.items.length === 0 ? (
          <EmptyState
            title="No incidents"
            description="Incidents are opened by detection rules that require one, and by correlation of related evidence."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="border-b border-slate-800 text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th className="px-4 py-3">Opened</th>
                  <th className="px-4 py-3">Priority</th>
                  <th className="px-4 py-3">Incident</th>
                  <th className="px-4 py-3">Severity</th>
                  <th className="px-4 py-3">Evidence</th>
                  <th className="px-4 py-3">Status</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((incident: Incident) => (
                  <tr key={incident.id} className="border-b border-slate-800/60 hover:bg-slate-800/30">
                    <td className="px-4 py-3 text-slate-400">{formatRelative(incident.opened_at)}</td>
                    <td className="px-4 py-3">
                      <Badge tone={priorityTone[incident.priority] ?? "neutral"}>{incident.priority}</Badge>
                    </td>
                    <td className="px-4 py-3">
                      <Link to={`/incidents/${incident.id}`} className="font-medium text-slate-100 hover:text-cyan-300">
                        {incident.title}
                      </Link>
                      <p className="text-xs text-slate-500">
                        {incident.detection_rule_slug ?? incident.correlation_key} · risk {incident.risk_score}
                      </p>
                    </td>
                    <td className="px-4 py-3"><SeverityBadge severity={incident.severity} /></td>
                    <td className="px-4 py-3 text-xs text-slate-400">
                      {incident.event_count} event(s) · {incident.finding_count} finding(s)
                    </td>
                    <td className="px-4 py-3"><IncidentStatusBadge status={incident.status} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {data && data.total > 0 && (
          <Pagination
            page={data.page}
            pages={data.pages}
            total={data.total}
            pageSize={data.page_size}
            onPageChange={setPage}
          />
        )}
      </Card>

      {data && data.items.length === 0 && (
        <p className="mt-4 flex items-center gap-2 text-xs text-slate-500">
          <ShieldAlert className="h-3 w-3" /> Incident creation is deterministic: detection rules and
          correlation open incidents, AI never does.
        </p>
      )}
    </div>
  );
}
