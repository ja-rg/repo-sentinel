import type React from "react";


export function SectionTitle({
  title, subtitle, action,
}: {
  title: string;
  subtitle: string;
  action?: string;
}) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-zinc-800 p-4">
      <div>
        <h2 className="text-sm font-semibold uppercase tracking-[0.18em] text-zinc-300">
          {title}
        </h2>
        <p className="mt-1 text-sm text-zinc-500">{subtitle}</p>
      </div>
      {action && <div className="shrink-0 text-xs text-zinc-500">{action}</div>}
    </div>
  );
}
export function Subsection({
  title, children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="border-b border-zinc-800 last:border-b-0">
      <div className="border-b border-zinc-800 px-4 py-3 text-xs uppercase tracking-[0.18em] text-zinc-500">
        {title}
      </div>
      <div className="p-4">{children}</div>
    </section>
  );
}
export function Field({
  label, children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <label className="block">
      <div className="mb-2 text-xs uppercase tracking-[0.18em] text-zinc-500">
        {label}
      </div>
      {children}
    </label>
  );
}
