import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide",
  {
    variants: {
      tone: {
        neutral: "border-slate-700 bg-slate-800/60 text-slate-300",
        critical: "border-rose-500/40 bg-rose-500/15 text-rose-300",
        high: "border-orange-500/40 bg-orange-500/15 text-orange-300",
        medium: "border-amber-500/40 bg-amber-500/15 text-amber-300",
        low: "border-sky-500/40 bg-sky-500/15 text-sky-300",
        info: "border-slate-500/40 bg-slate-500/15 text-slate-300",
        success: "border-emerald-500/40 bg-emerald-500/15 text-emerald-300",
        running: "border-cyan-500/40 bg-cyan-500/15 text-cyan-300",
        danger: "border-rose-500/40 bg-rose-500/15 text-rose-300",
      },
    },
    defaultVariants: { tone: "neutral" },
  },
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {}

export function Badge({ className, tone, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ tone }), className)} {...props} />;
}
