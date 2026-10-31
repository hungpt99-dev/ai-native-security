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
import { IntelligencePage } from "@/pages/IntelligencePage";
import { OperationsPage } from "@/pages/OperationsPage";

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
        <Route path="sboms" element={<SbomsPage />} />
        <Route path="sboms/:id" element={<SbomDetailPage />} />
        <Route path="intelligence" element={<IntelligencePage />} />
        <Route path="operations" element={<OperationsPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
