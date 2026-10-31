import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type QueryParams } from "@/lib/api";
import type {
  AiExecution,
  AiHealth,
  AiOverview,
  Asset,
  DashboardSummary,
  Finding,
  IntelligenceStats,
  Job,
  InvestigationReport,
  Page,
  RemediationRecommendation,
  RemediationVerification,
  RiskAssessment,
  Sbom,
  SecurityContextPayload,
  AssistantReply,
  SbomPackage,
  Scan,
  ScannerStatus,
  Schedule,
  SystemInfo,
  Vulnerability,
} from "@/lib/types";

const refetchFast = { refetchInterval: 5000 } as const;

export function useDashboard() {
  return useQuery({
    queryKey: ["dashboard"],
    queryFn: () => api.get<DashboardSummary>("/dashboard/summary"),
    refetchInterval: 15000,
  });
}

export function useAssets(params: QueryParams) {
  return useQuery({
    queryKey: ["assets", params],
    queryFn: () => api.get<Page<Asset>>("/assets", params),
  });
}

export function useAsset(id: string | undefined) {
  return useQuery({
    queryKey: ["asset", id],
    queryFn: () => api.get<Asset>(`/assets/${id}`),
    enabled: Boolean(id),
  });
}

export function useAssetScans(id: string | undefined, params: QueryParams) {
  return useQuery({
    queryKey: ["asset-scans", id, params],
    queryFn: () => api.get<Page<Scan>>(`/assets/${id}/scans`, params),
    enabled: Boolean(id),
    refetchInterval: 8000,
  });
}

export interface AssetPayload {
  name: string;
  repo_url: string;
  default_branch?: string;
  description?: string | null;
  access_token?: string | null;
  monitoring_enabled?: boolean;
  scan_interval_minutes?: number | null;
}

export function useCreateAsset() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: AssetPayload) => api.post<Asset>("/assets", payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["assets"] });
      void queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    },
  });
}

export function useUpdateAsset(id: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: Partial<AssetPayload> & { clear_credential?: boolean }) =>
      api.put<Asset>(`/assets/${id}`, payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["assets"] });
      void queryClient.invalidateQueries({ queryKey: ["asset", id] });
    },
  });
}

export function useDeleteAsset() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.delete<void>(`/assets/${id}`),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["assets"] });
      void queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    },
  });
}

export function useTriggerScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (assetId: string) =>
      api.post<{ scan_id: string; status: string }>(`/assets/${assetId}/scan`),
    onSuccess: (_data, assetId) => {
      void queryClient.invalidateQueries({ queryKey: ["asset-scans", assetId] });
      void queryClient.invalidateQueries({ queryKey: ["scans"] });
      void queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    },
  });
}

export function useScans(params: QueryParams) {
  return useQuery({
    queryKey: ["scans", params],
    queryFn: () => api.get<Page<Scan>>("/scans", params),
    refetchInterval: 8000,
  });
}

export function useScan(id: string | undefined) {
  return useQuery({
    queryKey: ["scan", id],
    queryFn: () => api.get<Scan>(`/scans/${id}`),
    enabled: Boolean(id),
    ...refetchFast,
  });
}

export function useCancelScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (scanId: string) => api.post<Scan>(`/scans/${scanId}/cancel`),
    onSuccess: (scan) => {
      void queryClient.invalidateQueries({ queryKey: ["scan", scan.id] });
      void queryClient.invalidateQueries({ queryKey: ["scans"] });
    },
  });
}

export function useFindings(params: QueryParams) {
  return useQuery({
    queryKey: ["findings", params],
    queryFn: () => api.get<Page<Finding>>("/findings", params),
    placeholderData: (previous) => previous,
  });
}

export function useFinding(id: string | null) {
  return useQuery({
    queryKey: ["finding", id],
    queryFn: () => api.get<Finding>(`/findings/${id}`),
    enabled: Boolean(id),
  });
}

export function useUpdateFindingStatus() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, status, note }: { id: string; status: string; note?: string }) =>
      api.patch<Finding>(`/findings/${id}/status`, { status, note }),
    onSuccess: (finding) => {
      void queryClient.invalidateQueries({ queryKey: ["findings"] });
      void queryClient.invalidateQueries({ queryKey: ["finding", finding.id] });
      void queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    },
  });
}

export function useSboms(params: QueryParams) {
  return useQuery({
    queryKey: ["sboms", params],
    queryFn: () => api.get<Page<Sbom>>("/sboms", params),
  });
}

export function useAssetSboms(assetId: string | undefined, params: QueryParams) {
  return useQuery({
    queryKey: ["asset-sboms", assetId, params],
    queryFn: () => api.get<Page<Sbom>>(`/assets/${assetId}/sboms`, params),
    enabled: Boolean(assetId),
  });
}

export function useSbom(id: string | undefined) {
  return useQuery({
    queryKey: ["sbom", id],
    queryFn: () => api.get<Sbom>(`/sboms/${id}`),
    enabled: Boolean(id),
  });
}

export function useSbomPackages(id: string | undefined, params: QueryParams) {
  return useQuery({
    queryKey: ["sbom-packages", id, params],
    queryFn: () => api.get<Page<SbomPackage>>(`/sboms/${id}/packages`, params),
    enabled: Boolean(id),
    placeholderData: (previous) => previous,
  });
}

export function useVulnerabilities(params: QueryParams) {
  return useQuery({
    queryKey: ["vulnerabilities", params],
    queryFn: () => api.get<Page<Vulnerability>>("/vulnerabilities", params),
  });
}

export function useVulnerability(id: string | null) {
  return useQuery({
    queryKey: ["vulnerability", id],
    queryFn: () => api.get<Vulnerability>(`/vulnerabilities/${id}`),
    enabled: Boolean(id),
  });
}

export function useIntelligenceStats() {
  return useQuery({
    queryKey: ["intelligence-stats"],
    queryFn: () => api.get<IntelligenceStats>("/vulnerabilities/stats"),
  });
}

export function useSyncHistory(params: QueryParams) {
  return useQuery({
    queryKey: ["sync-history", params],
    queryFn: () =>
      api.get<Page<{ id: string; source: string; status: string; started_at: string; finished_at: string | null; records_processed: number; records_created: number; records_updated: number; error_message: string | null; duration_seconds: number | null }>>(
        "/vulnerabilities/sync/history",
        params,
      ),
  });
}

export function useTriggerSync() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (source: string) => api.post<{ job_id: string; source: string }>(`/vulnerabilities/sync/${source}`),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["sync-history"] });
      void queryClient.invalidateQueries({ queryKey: ["jobs"] });
    },
  });
}

export function useSystemInfo() {
  return useQuery({
    queryKey: ["system-info"],
    queryFn: () => api.get<SystemInfo>("/system/info"),
    staleTime: 60000,
  });
}

export function useScannerStatus() {
  return useQuery({
    queryKey: ["scanner-status"],
    queryFn: () => api.get<ScannerStatus[]>("/system/scanners"),
    refetchInterval: 60000,
  });
}

export function useJobs(params: QueryParams) {
  return useQuery({
    queryKey: ["jobs", params],
    queryFn: () => api.get<Page<Job>>("/jobs", params),
    refetchInterval: 10000,
  });
}

export function useSchedules() {
  return useQuery({
    queryKey: ["schedules"],
    queryFn: () => api.get<Schedule[]>("/schedules"),
    refetchInterval: 15000,
  });
}

export function useUpdateSchedule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      api.patch<Schedule>(`/schedules/${id}`, { enabled }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["schedules"] }),
  });
}

// -------------------------------------------------------------------- AI layer
export function useAiHealth() {
  return useQuery({
    queryKey: ["ai-health"],
    queryFn: () => api.get<AiHealth>("/ai/health"),
    refetchInterval: 30000,
  });
}

export function useAiOverview() {
  return useQuery({
    queryKey: ["ai-overview"],
    queryFn: () => api.get<AiOverview>("/ai/overview"),
    refetchInterval: 20000,
  });
}

export function useSecurityContext(findingId: string | undefined) {
  return useQuery({
    queryKey: ["ai-context", findingId],
    queryFn: () => api.get<SecurityContextPayload>(`/findings/${findingId}/security-context`),
    enabled: Boolean(findingId),
    retry: false,
  });
}

export function useBuildSecurityContext() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (findingId: string) => api.post<SecurityContextPayload>(`/findings/${findingId}/security-context`),
    onSuccess: (_data, findingId) => {
      void queryClient.invalidateQueries({ queryKey: ["ai-context", findingId] });
    },
  });
}

export function useRiskAssessments(findingId: string | undefined) {
  return useQuery({
    queryKey: ["ai-risk", findingId],
    queryFn: () => api.get<RiskAssessment[]>(`/findings/${findingId}/risk-assessments`),
    enabled: Boolean(findingId),
  });
}

export function useAssessRisk() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ findingId, useAi }: { findingId: string; useAi: boolean }) =>
      api.post<RiskAssessment>(`/findings/${findingId}/risk-assessment?use_ai=${useAi}`),
    onSuccess: (_data, variables) => {
      void queryClient.invalidateQueries({ queryKey: ["ai-risk", variables.findingId] });
      void queryClient.invalidateQueries({ queryKey: ["ai-overview"] });
      void queryClient.invalidateQueries({ queryKey: ["ai-executions"] });
    },
  });
}

export function useInvestigations(findingId: string | undefined) {
  return useQuery({
    queryKey: ["ai-investigations", findingId],
    queryFn: () => api.get<InvestigationReport[]>(`/findings/${findingId}/investigations`),
    enabled: Boolean(findingId),
  });
}

export function useInvestigate() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (findingId: string) => api.post<InvestigationReport>(`/findings/${findingId}/investigation`),
    onSuccess: (_data, findingId) => {
      void queryClient.invalidateQueries({ queryKey: ["ai-investigations", findingId] });
      void queryClient.invalidateQueries({ queryKey: ["ai-executions"] });
    },
  });
}

export function useFindingRemediations(findingId: string | undefined) {
  return useQuery({
    queryKey: ["ai-remediations", findingId],
    queryFn: () => api.get<RemediationRecommendation[]>(`/findings/${findingId}/remediations`),
    enabled: Boolean(findingId),
  });
}

export function useProposeRemediation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (findingId: string) => api.post<RemediationRecommendation>(`/findings/${findingId}/remediation`),
    onSuccess: (_data, findingId) => {
      void queryClient.invalidateQueries({ queryKey: ["ai-remediations", findingId] });
      void queryClient.invalidateQueries({ queryKey: ["remediation-queue"] });
    },
  });
}

export function useRemediationQueue(params: QueryParams) {
  return useQuery({
    queryKey: ["remediation-queue", params],
    queryFn: () => api.get<Page<RemediationRecommendation>>("/remediations", params),
  });
}

export function useApproveRemediation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, note }: { id: string; note?: string }) =>
      api.post<RemediationRecommendation>(`/remediations/${id}/approve`, { note }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["remediation-queue"] });
      void queryClient.invalidateQueries({ queryKey: ["ai-overview"] });
    },
  });
}

export function useRejectRemediation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, note }: { id: string; note: string }) =>
      api.post<RemediationRecommendation>(`/remediations/${id}/reject`, { note }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["remediation-queue"] });
    },
  });
}

export function useStartVerification() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      api.post<{ recommendation: RemediationRecommendation; scan: { id: string; status: string } }>(
        `/remediations/${id}/verify`,
      ),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["remediation-queue"] });
    },
  });
}

export function useVerifications(findingId: string | undefined) {
  return useQuery({
    queryKey: ["ai-verifications", findingId],
    queryFn: () => api.get<RemediationVerification[]>(`/findings/${findingId}/verifications`),
    enabled: Boolean(findingId),
  });
}

export function useAskAssistant() {
  return useMutation({
    mutationFn: (payload: { question: string; conversation_id?: string }) =>
      api.post<AssistantReply>("/ai/assistant/ask", payload),
  });
}

export function useAiExecutions(params: QueryParams) {
  return useQuery({
    queryKey: ["ai-executions", params],
    queryFn: () => api.get<Page<AiExecution>>("/ai/executions", params),
  });
}
