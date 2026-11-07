import { useMemo, useState } from "react";
import { Activity, Filter, ShieldCheck } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
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
import {
  useAcknowledgeEvent,
  useDetectionRules,
  useEvents,
  useEventSummary,
  useMonitoringHealth,
  useUpdateRule,
} from "@/hooks/queries";
import { formatDate, formatRelative } from "@/lib/utils";
import type { EventCategory, SecurityEvent, Severity } from "@/lib/types";

const CATEGORIES: EventCategory[] = [
  "RUNTIME",
  "NETWORK",
  "IDENTITY",
  "INFRASTRUCTURE",
  "APPLICATION",
  "DATA",
];
const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"];

const healthTone: Record<string, "success" | "danger" | "medium" | "neutral"> = {
  HEALTHY: "success",
  DEGRADED: "danger",
  UNKNOWN: "medium",
  DISABLED: "neutral",
};

function HealthStrip() {
  const { data, isLoading } = useMonitoringHealth();
  if (isLoading || !data) {
    return <div className="mb-6 grid gap-3 md:grid-cols-4">{[0, 1, 2, 3].map((i) => (
      <div key={i} className="panel h-20 animate-pulse" />
    ))}</div>;
  }
  const components = Object.entries(data.components);
  return (
    <Card className="mb-6">
      <CardHeader className="flex items-center justify-between">
        <CardTitle className="flex items-center gap-2">
          <ShieldCheck className="h-4 w-4 text-cyan-400" /> Monitoring health
        </CardTitle>
        <Badge tone={healthTone[data.status] ?? "neutral"}>{data.status}</Badge>
      </CardHeader>
      <CardContent className="grid gap-3 pt-0 sm:grid-cols-2 lg:grid-cols-4">
        {components.map(([name, component]) => (
          <div key={name} className="rounded-lg border border-slate-800 bg-slate-900/40 p-3">
            <div className="flex items-center justify-between gap-2">
              <p className="text-xs font-medium text-slate-200">{name.replaceAll("_", " ")}</p>
              <Badge tone={healthTone[component.status] ?? "neutral"}>{component.status}</Badge>
            </div>
            <p className="mt-1 line-clamp-2 text-[11px] text-slate-500">
              {typeof component.detail.reason === "string"
                ? component.detail.reason
                : typeof component.detail.last_event_at === "string"
                  ? `last event ${formatRelative(component.detail.last_event_at)}`
                  : typeof component.detail.last_scan_at === "string"
                    ? `last scan ${formatRelative(component.detail.last_scan_at)}`
                    : "evidence recorded"}
            </p>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

function EventDialog({ event, onClose }: { event: SecurityEvent; onClose: () => void }) {
  const acknowledge = useAcknowledgeEvent();
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{event.title}</DialogTitle>
        </DialogHeader>
        <div className="space-y-4 text-sm">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={event.severity} />
            <Badge tone="neutral">{event.category}</Badge>
            <Badge tone="info">{event.source}</Badge>
            <Badge tone={event.status === "OPEN" ? "danger" : "success"}>{event.status}</Badge>
            <span className="text-xs text-slate-500">
              {event.occurrence_count} occurrence(s) · first {formatDate(event.first_seen_at)} · last{" "}
              {formatDate(event.last_seen_at)}
            </span>
          </div>

          {event.description && <p className="text-slate-300">{event.description}</p>}

          <div>
            <p className="mb-1 text-xs font-semibold text-slate-400">Normalized fields</p>
            <pre className="max-h-48 overflow-auto rounded-lg border border-slate-800 bg-slate-950 p-3 text-[11px] text-slate-300">
              {JSON.stringify(event.normalized, null, 2)}
            </pre>
          </div>

          {event.enrichment.threat_matches && event.enrichment.threat_matches.length > 0 && (
            <div>
              <p className="mb-1 text-xs font-semibold text-rose-300">Threat intelligence matches</p>
              <ul className="space-y-1 text-xs text-slate-300">
                {event.enrichment.threat_matches.map((match) => (
                  <li key={`${match.type}-${match.value}`}>
                    {match.type} {match.value} · {match.source} · confidence {match.confidence}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {event.rule_slug && (
            <p className="text-xs text-slate-500">
              Detection rule: <span className="text-slate-300">{event.rule_slug}</span>
              {event.rule_version ? ` v${event.rule_version}` : ""}
            </p>
          )}

          {event.indicators.length > 0 && (
            <p className="text-xs text-slate-500">
              Indicators: {event.indicators.map((i) => `${i.type}:${i.value}`).join(", ")}
            </p>
          )}

          {event.incident_id && (
            <p className="text-xs text-slate-500">
              Incident: <span className="text-cyan-300">{event.incident_id}</span>
            </p>
          )}

          {event.status === "OPEN" && (
            <Button
              onClick={() => acknowledge.mutateAsync(event.id).then(onClose)}
              disabled={acknowledge.isPending}
            >
              Acknowledge event
            </Button>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}

export function MonitoringPage() {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [category, setCategory] = useState("all");
  const [severity, setSeverity] = useState("all");
  const [status, setStatus] = useState("all");
  const [selected, setSelected] = useState<SecurityEvent | null>(null);

  const params = useMemo(
    () => ({
      page,
      page_size: 25,
      search: search || undefined,
      category: category === "all" ? undefined : category,
      severity: severity === "all" ? undefined : severity,
      status: status === "all" ? undefined : status,
    }),
    [page, search, category, severity, status],
  );

  const { data, isLoading, error } = useEvents(params);
  const { data: summary } = useEventSummary(24);
  const { data: rules } = useDetectionRules();
  const updateRule = useUpdateRule();

  return (
    <div>
      <PageHeader
        title="Security monitoring"
        subtitle="Runtime, network, identity and infrastructure telemetry with deterministic detections"
        actions={
          <Button
            variant="outline"
            onClick={() => {
              setPage(1);
              setSearch("");
              setCategory("all");
              setSeverity("all");
              setStatus("all");
            }}
          >
            <Filter className="h-4 w-4" /> Reset filters
          </Button>
        }
      />

      <HealthStrip />

      <div className="mb-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
        <div className="panel p-4">
          <p className="text-xs text-slate-500">Events (24h)</p>
          <p className="text-2xl font-semibold text-white">{summary?.total ?? "—"}</p>
        </div>
        <div className="panel p-4">
          <p className="text-xs text-slate-500">Still open</p>
          <p className="text-2xl font-semibold text-amber-300">{summary?.open ?? "—"}</p>
        </div>
        {(["RUNTIME", "NETWORK", "IDENTITY"] as EventCategory[]).map((entry) => (
          <div key={entry} className="panel p-4">
            <p className="text-xs text-slate-500">{entry}</p>
            <p className="text-2xl font-semibold text-slate-200">
              {summary?.by_category?.[entry] ?? 0}
            </p>
          </div>
        ))}
      </div>

      <div className="mb-4 grid gap-2 md:grid-cols-2 xl:grid-cols-4">
        <div>
          <Label>Search</Label>
          <Input
            placeholder="Rule, command line, path, source IP…"
            value={search}
            onChange={(event) => {
              setPage(1);
              setSearch(event.target.value);
            }}
          />
        </div>
        <div>
          <Label>Category</Label>
          <Select value={category} onValueChange={(value) => { setPage(1); setCategory(value); }}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All</SelectItem>
              {CATEGORIES.map((entry) => (
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
          <Label>Status</Label>
          <Select value={status} onValueChange={(value) => { setPage(1); setStatus(value); }}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All</SelectItem>
              <SelectItem value="OPEN">OPEN</SelectItem>
              <SelectItem value="ACKNOWLEDGED">ACKNOWLEDGED</SelectItem>
              <SelectItem value="CLOSED">CLOSED</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      <Card className="mb-8 overflow-hidden">
        {error ? (
          <ErrorState error={error} />
        ) : isLoading ? (
          <TableSkeleton rows={6} />
        ) : !data || data.items.length === 0 ? (
          <EmptyState
            title="No security events"
            description="Events appear once a sensor posts to /api/v1/ingest (Falco or the generic schema)."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="border-b border-slate-800 text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th className="px-4 py-3">Last seen</th>
                  <th className="px-4 py-3">Severity</th>
                  <th className="px-4 py-3">Event</th>
                  <th className="px-4 py-3">Category</th>
                  <th className="px-4 py-3">Count</th>
                  <th className="px-4 py-3">Status</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((event) => (
                  <tr
                    key={event.id}
                    className="cursor-pointer border-b border-slate-800/60 hover:bg-slate-800/30"
                    onClick={() => setSelected(event)}
                  >
                    <td className="px-4 py-3 text-slate-400">{formatRelative(event.last_seen_at)}</td>
                    <td className="px-4 py-3"><SeverityBadge severity={event.severity} /></td>
                    <td className="px-4 py-3">
                      <p className="font-medium text-slate-100">{event.title}</p>
                      <p className="text-xs text-slate-500">
                        {event.rule_slug ?? event.event_type}
                        {event.enrichment.threat_matches?.length ? " · threat intel match" : ""}
                      </p>
                    </td>
                    <td className="px-4 py-3 text-slate-400">{event.category}</td>
                    <td className="px-4 py-3 text-slate-300">{event.occurrence_count}</td>
                    <td className="px-4 py-3">
                      <Badge tone={event.status === "OPEN" ? "danger" : event.status === "CLOSED" ? "neutral" : "running"}>
                        {event.status}
                      </Badge>
                    </td>
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

      <Card>
        <CardHeader className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2">
            <Activity className="h-4 w-4 text-cyan-400" /> Detection rules
          </CardTitle>
          <span className="text-xs text-slate-500">{rules?.length ?? 0} rules</span>
        </CardHeader>
        {!rules || rules.length === 0 ? (
          <CardContent className="text-sm text-slate-400">No rules loaded.</CardContent>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="border-b border-slate-800 text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th className="px-4 py-3">Rule</th>
                  <th className="px-4 py-3">Type</th>
                  <th className="px-4 py-3">Severity</th>
                  <th className="px-4 py-3">Matches</th>
                  <th className="px-4 py-3">Enabled</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((rule) => (
                  <tr key={rule.id} className="border-b border-slate-800/60">
                    <td className="px-4 py-3">
                      <p className="font-medium text-slate-100">{rule.name}</p>
                      <p className="text-xs text-slate-500">{rule.slug} · v{rule.version} · {rule.source}</p>
                    </td>
                    <td className="px-4 py-3 text-slate-400">{rule.rule_type}</td>
                    <td className="px-4 py-3"><SeverityBadge severity={rule.severity} /></td>
                    <td className="px-4 py-3 text-slate-300">{rule.match_count}</td>
                    <td className="px-4 py-3">
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={updateRule.isPending}
                        onClick={() => updateRule.mutate({ id: rule.id, payload: { enabled: !rule.enabled } })}
                      >
                        {rule.enabled ? "Disable" : "Enable"}
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {selected && <EventDialog event={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
