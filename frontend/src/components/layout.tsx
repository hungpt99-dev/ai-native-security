import { NavLink, Outlet } from "react-router-dom";
import {
  Activity,
  Bot,
  Boxes,
  GitPullRequest,
  LayoutDashboard,
  Package,
  Radar,
  Server,
  ShieldAlert,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useSystemInfo } from "@/hooks/queries";

const navigation = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/assets", label: "Repositories", icon: Server },
  { to: "/scans", label: "Scans", icon: Activity },
  { to: "/findings", label: "Findings", icon: ShieldAlert },
  { to: "/remediation", label: "Remediation", icon: GitPullRequest },
  { to: "/assistant", label: "Assistant", icon: Bot },
  { to: "/sboms", label: "SBOMs", icon: Package },
  { to: "/intelligence", label: "Intelligence", icon: Radar },
  { to: "/operations", label: "Operations", icon: Boxes },
];

export function AppShell() {
  const { data: info } = useSystemInfo();

  return (
    <div className="flex min-h-screen">
      <aside className="hidden w-60 shrink-0 flex-col border-r border-slate-800/80 bg-slate-950/70 px-3 py-5 lg:flex">
        <div className="mb-8 flex items-center gap-2 px-2">
          <div className="rounded-lg bg-cyan-500/15 p-2 text-cyan-400">
            <ShieldAlert className="h-5 w-5" />
          </div>
          <div>
            <p className="text-sm font-semibold leading-tight text-white">AI-Native</p>
            <p className="text-xs text-slate-500">Security Platform</p>
          </div>
        </div>
        <nav className="flex-1 space-y-1">
          {navigation.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm text-slate-400 transition-colors hover:bg-slate-800/60 hover:text-slate-100",
                  isActive && "bg-slate-800/80 text-white",
                )
              }
            >
              <item.icon className="h-4 w-4" />
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="mt-4 space-y-1 rounded-lg border border-slate-800 bg-slate-900/50 p-3 text-xs text-slate-500">
          <p className="font-medium text-slate-300">{info?.name ?? "Phase 1"}</p>
          <p>v{info?.version ?? "0.1.0"} · {info?.environment ?? "development"}</p>
          <p>Auth {info?.auth_enabled ? "enabled" : "disabled"}</p>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex items-center justify-between gap-3 border-b border-slate-800/80 bg-slate-950/80 px-4 py-3 backdrop-blur lg:px-8">
          <div className="flex items-center gap-2 lg:hidden">
            <ShieldAlert className="h-5 w-5 text-cyan-400" />
            <span className="text-sm font-semibold text-white">AI-Native Security</span>
          </div>
          <div className="hidden text-xs text-slate-500 lg:block">
            Continuous repository scanning · SBOM · vulnerability intelligence
          </div>
          <div className="flex items-center gap-2 text-xs text-slate-400">
            <span className="inline-flex h-2 w-2 rounded-full bg-emerald-400" />
            API connected
          </div>
        </header>

        <nav className="flex gap-1 overflow-x-auto border-b border-slate-800/80 px-2 py-2 lg:hidden">
          {navigation.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                cn(
                  "whitespace-nowrap rounded-md px-2.5 py-1.5 text-xs text-slate-400",
                  isActive && "bg-slate-800 text-white",
                )
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>

        <main className="flex-1 px-4 py-6 lg:px-8">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
