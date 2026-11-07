import { Navigate, Route, Routes } from "react-router-dom";
import { AppShell } from "@/components/layout";
import { DashboardPage } from "@/pages/DashboardPage";
import { AssetsPage } from "@/pages/AssetsPage";
import { AssetDetailPage } from "@/pages/AssetDetailPage";
import { ScansPage } from "@/pages/ScansPage";
import { ScanDetailPage } from "@/pages/ScanDetailPage";
import { FindingsPage } from "@/pages/FindingsPage";
import { SbomsPage } from "@/pages/SbomsPage";
import { SbomDetailPage } from "@/pages/SbomDetailPage";
import { SbomComparePage } from "@/pages/SbomComparePage";
import { IntelligencePage } from "@/pages/IntelligencePage";
import { OperationsPage } from "@/pages/OperationsPage";
import { RemediationPage } from "@/pages/RemediationPage";
import { AssistantPage } from "@/pages/AssistantPage";
import { MonitoringPage } from "@/pages/MonitoringPage";
import { IncidentsPage } from "@/pages/IncidentsPage";
import { IncidentDetailPage } from "@/pages/IncidentDetailPage";
import { InfrastructurePage } from "@/pages/InfrastructurePage";

export function App() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<DashboardPage />} />
        <Route path="assets" element={<AssetsPage />} />
        <Route path="assets/:id" element={<AssetDetailPage />} />
        <Route path="scans" element={<ScansPage />} />
        <Route path="scans/:id" element={<ScanDetailPage />} />
        <Route path="findings" element={<FindingsPage />} />
        <Route path="monitoring" element={<MonitoringPage />} />
        <Route path="incidents" element={<IncidentsPage />} />
        <Route path="incidents/:id" element={<IncidentDetailPage />} />
        <Route path="infrastructure" element={<InfrastructurePage />} />
        <Route path="sboms" element={<SbomsPage />} />
        <Route path="sboms/:id" element={<SbomDetailPage />} />
        <Route path="sboms/:id/compare" element={<SbomComparePage />} />
        <Route path="intelligence" element={<IntelligencePage />} />
        <Route path="remediation" element={<RemediationPage />} />
        <Route path="assistant" element={<AssistantPage />} />
        <Route path="operations" element={<OperationsPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
