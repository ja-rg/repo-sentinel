import { flattenTrivy } from "../tools/trivy";
import type { FindingsSection } from "../types";
import { JsonBlock } from "../utilities/json";

export function FindingsSectionView({ section }: { section: FindingsSection }) {
  if (section.kind === "semgrep") {
    return (
      <SemgrepFindings
        title={section.title}
        items={section.items}
        raw={section.raw}
      />
    );
  }

  if (section.kind === "trivy") {
    return (
      <TrivyFindings
        title={section.title}
        items={section.items}
        raw={section.raw}
      />
    );
  }

  if (section.kind === "syft") {
    return <SyftSbomFindings title={section.title} raw={section.raw} />;
  }

  return (
    <GenericFindings
      title={section.title}
      raw={section.raw}
      count={section.items.length}
    />
  );
}
function SyftSbomFindings({ title, raw }: { title: string; raw: unknown }) {
  const data = (raw && typeof raw === "object" ? raw : {}) as Record<
    string,
    unknown
  >;

  const bomFormat = data.bomFormat ?? "unknown";
  const specVersion = data.specVersion ?? "unknown";
  const serialNumber = data.serialNumber ?? "unknown";
  const version = data.version ?? "unknown";

  const metadata =
    data.metadata && typeof data.metadata === "object"
      ? (data.metadata as Record<string, unknown>)
      : {};
  const timestamp =
    (metadata as Record<string, unknown>).timestamp ?? "unknown";

  const components = (metadata as Record<string, unknown>).components;
  const tools = Array.isArray(components) ? components : [];

  const subject = (metadata as Record<string, unknown>).component ?? null;

  return (
    <div>
      <div className="mb-2 flex items-center justify-between gap-3">
        <h3 className="text-sm font-medium text-white">{title}</h3>
        <span className="text-xs text-zinc-500">Syft SBOM</span>
      </div>

      <div className="space-y-3">
        <div className="border border-zinc-800 p-3">
          <div className="grid gap-x-4 gap-y-2 sm:grid-cols-2">
            <div>
              <div className="text-[11px] uppercase tracking-wide text-zinc-500">
                format
              </div>
              <div className="mt-1 text-sm text-white">{String(bomFormat)}</div>
            </div>
            <div>
              <div className="text-[11px] uppercase tracking-wide text-zinc-500">
                spec version
              </div>
              <div className="mt-1 text-sm text-white">
                {String(specVersion)}
              </div>
            </div>
            <div>
              <div className="text-[11px] uppercase tracking-wide text-zinc-500">
                document version
              </div>
              <div className="mt-1 text-sm text-white">{String(version)}</div>
            </div>
            <div>
              <div className="text-[11px] uppercase tracking-wide text-zinc-500">
                timestamp
              </div>
              <div className="mt-1 text-sm text-white">{String(timestamp)}</div>
            </div>
          </div>

          <div className="mt-3">
            <div className="text-[11px] uppercase tracking-wide text-zinc-500">
              serial number
            </div>
            <div className="mt-1 break-all text-sm text-zinc-300">
              {String(serialNumber)}
            </div>
          </div>
        </div>

        {subject && (
          <div className="border border-zinc-800 p-3">
            <div className="mb-2 text-[11px] uppercase tracking-wide text-zinc-500">
              subject
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <span className="border border-zinc-700 px-2 py-1 text-[11px] uppercase tracking-wide text-zinc-300">
                {String((subject as Record<string, unknown>).type ?? "unknown")}
              </span>
              <span className="text-sm text-white">
                {String((subject as Record<string, unknown>).name ?? "unknown")}
              </span>
            </div>
            {(subject as Record<string, unknown>)["bom-ref"] ? (
              <div className="mt-2 break-all text-xs text-zinc-500">
                {String((subject as Record<string, unknown>)["bom-ref"])}
              </div>
            ) : null}
          </div>
        )}

        <div className="border border-zinc-800 p-3">
          <div className="mb-2 flex items-center justify-between gap-3">
            <div className="text-[11px] uppercase tracking-wide text-zinc-500">
              tools
            </div>
            <span className="text-xs text-zinc-500">
              {tools.length} entries
            </span>
          </div>

          {tools.length === 0 ? (
            <div className="text-sm text-zinc-500">No tool metadata.</div>
          ) : (
            <div className="space-y-2">
              {tools.map((tool: Record<string, unknown>, index: number) => (
                <div
                  key={`${tool?.name ?? "tool"}-${index}`}
                  className="border border-zinc-800 p-3"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="border border-zinc-700 px-2 py-1 text-[11px] uppercase tracking-wide text-zinc-300">
                      {String(tool?.type ?? "tool")}
                    </span>
                    <span className="text-sm text-white">
                      {String(tool?.name ?? "unknown")}
                    </span>
                    {String(tool?.version) && (
                      <span className="text-xs text-zinc-500">
                        {String(tool.version)}
                      </span>
                    )}
                  </div>
                  <div className="mt-2 text-xs text-zinc-500">
                    {String(tool?.author ?? "unknown author")}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <details className="border border-zinc-800">
          <summary className="cursor-pointer px-3 py-2 text-sm text-zinc-300">
            Raw SBOM
          </summary>
          <div className="border-t border-zinc-800">
            <JsonBlock value={raw} />
          </div>
        </details>
      </div>
    </div>
  );
}
function SemgrepFindings({
  title,
  items,
  raw,
}: {
  title: string;
  items: unknown[];
  raw: unknown;
}) {
  const rows = Array.isArray(items) ? items : [];

  return (
    <div>
      <div className="mb-2 flex items-center justify-between gap-3">
        <h3 className="text-sm font-medium text-white">{title}</h3>
        <span className="text-xs text-zinc-500">{rows.length} results</span>
      </div>

      {rows.length === 0 ? (
        <JsonBlock value={raw} />
      ) : (
        <div className="space-y-2">
          {rows.map((entry, index) => {
            const item = (entry ?? {}) as Record<string, unknown>;
            const severity = String(
              (item.extra as Record<string, unknown>)?.severity ??
                (item.severity as string) ??
                "unknown",
            );
            const message =
              (item.extra as Record<string, unknown>)?.message ??
              item.message ??
              item.check_id ??
              "Semgrep finding";
            const path =
              item.path ??
              (item.location as Record<string, unknown>)?.path ??
              "unknown";
            const line =
              (item.start as Record<string, unknown>)?.line ?? item.line ?? "?";

            return (
              <div
                key={`${item.check_id || "semgrep"}-${index}`}
                className="border border-zinc-800 p-3"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="border border-zinc-700 px-2 py-1 text-[11px] uppercase tracking-wide text-zinc-300">
                    {severity}
                  </span>
                  <span className="text-xs text-zinc-500">
                    {String(item.check_id || "rule")}
                  </span>
                </div>
                <p className="mt-2 text-sm text-white">{String(message)}</p>
                <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-zinc-500">
                  <span>{String(path)}</span>
                  <span>line {String(line)}</span>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
function TrivyFindings({
  title,
  items,
  raw,
}: {
  title: string;
  items: unknown[];
  raw: unknown;
}) {
  const rows = flattenTrivy(items);

  const counts = rows.reduce(
    (acc, row) => {
      const category = String(
        (row as Record<string, unknown>).category ?? "other",
      );
      acc[category] = ((acc[category] as number) ?? 0) + 1;
      return acc;
    },
    {} as Record<string, number>,
  );

  const summary = counts.secret
    ? `${rows.length} findings · ${counts.secret} secrets`
    : counts.vulnerability
      ? `${rows.length} findings · ${counts.vulnerability} vulnerabilities`
      : counts.misconfiguration
        ? `${rows.length} findings · ${counts.misconfiguration} misconfigurations`
        : `${rows.length} findings`;

  return (
    <div>
      <div className="mb-2 flex items-center justify-between gap-3">
        <h3 className="text-sm font-medium text-white">{title}</h3>
        <span className="text-xs text-zinc-500">{summary}</span>
      </div>

      {rows.length === 0 ? (
        <JsonBlock value={raw} />
      ) : (
        <div className="space-y-2">
          {rows.map((entry, index) => {
            const item = entry as Record<string, unknown>;
            const category = item.category ?? "finding";
            const severity = item.Severity ?? item.severity ?? "unknown";

            if (category === "secret") {
              const id = item.RuleID ?? item.ruleId ?? "secret-rule";
              const titleText =
                item.Title ??
                item.title ??
                item.Category ??
                item.category ??
                "Trivy secret";
              const target = item.target ?? "unknown";
              const startLine = item.StartLine ?? item.startLine;
              const endLine = item.EndLine ?? item.endLine;
              const match = item.Match ?? item.match;

              return (
                <div
                  key={`${id}-${index}`}
                  className="border border-zinc-800 p-3"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="border border-zinc-700 px-2 py-1 text-[11px] uppercase tracking-wide text-zinc-300">
                      {String(severity)}
                    </span>
                    <span className="border border-zinc-700 px-2 py-1 text-[11px] uppercase tracking-wide text-zinc-300">
                      secret
                    </span>
                    <span className="text-xs text-zinc-500">{String(id)}</span>
                  </div>

                  <p className="mt-2 text-sm text-white">{String(titleText)}</p>

                  <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-zinc-500">
                    <span>{String(target)}</span>
                    {String(item.Category) && (
                      <span>{String(item.Category)}</span>
                    )}
                    {String(startLine) && (
                      <span>
                        line {String(startLine)}
                        {String(endLine) && endLine !== startLine
                          ? `-${String(endLine)}`
                          : ""}
                      </span>
                    )}
                  </div>

                  {String(match) && (
                    <pre className="mt-3 overflow-auto border border-zinc-800 bg-black p-3 text-xs leading-6 text-emerald-200">
                      <code>{String(match)}</code>
                    </pre>
                  )}
                </div>
              );
            }

            if (category === "misconfiguration") {
              const id = item.ID ?? item.AVDID ?? item.id ?? "rule";
              const titleText =
                item.Title ?? item.title ?? item.Message ?? item.message ?? id;
              const target = item.target ?? item.Target ?? "unknown";

              return (
                <div
                  key={`${id}-${index}`}
                  className="border border-zinc-800 p-3"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="border border-zinc-700 px-2 py-1 text-[11px] uppercase tracking-wide text-zinc-300">
                      {String(severity)}
                    </span>
                    <span className="border border-zinc-700 px-2 py-1 text-[11px] uppercase tracking-wide text-zinc-300">
                      misconfiguration
                    </span>
                    <span className="text-xs text-zinc-500">{String(id)}</span>
                  </div>

                  <p className="mt-2 text-sm text-white">{String(titleText)}</p>

                  <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-zinc-500">
                    <span>{String(target)}</span>
                    {String(item.Resolution) && (
                      <span>{String(item.Resolution)}</span>
                    )}
                  </div>
                </div>
              );
            }

            const id =
              item.VulnerabilityID ??
              item.ID ??
              item.AVDID ??
              item.id ??
              "vuln";

            const titleText =
              item.Title ??
              item.title ??
              item.Description ??
              item.description ??
              item.Message ??
              item.message ??
              id;

            const target =
              item.PkgName ?? item.Target ?? item.target ?? "unknown";

            const installedVersion =
              item.InstalledVersion ?? item.installedVersion;

            const fixedVersion = item.FixedVersion ?? item.fixedVersion;

            return (
              <div
                key={`${id}-${index}`}
                className="border border-zinc-800 p-3"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="border border-zinc-700 px-2 py-1 text-[11px] uppercase tracking-wide text-zinc-300">
                    {String(severity)}
                  </span>
                  <span className="border border-zinc-700 px-2 py-1 text-[11px] uppercase tracking-wide text-zinc-300">
                    vulnerability
                  </span>
                  <span className="text-xs text-zinc-500">{String(id)}</span>
                </div>

                <p className="mt-2 text-sm text-white">{String(titleText)}</p>

                <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-zinc-500">
                  <span>{String(target)}</span>
                  {String(installedVersion) && (
                    <span>installed: {String(installedVersion)}</span>
                  )}
                  {String(fixedVersion) && (
                    <span>fixed: {String(fixedVersion)}</span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
function GenericFindings({
  title,
  raw,
  count,
}: {
  title: string;
  raw: unknown;
  count: number;
}) {
  return (
    <div>
      <div className="mb-2 flex items-center justify-between gap-3">
        <h3 className="text-sm font-medium text-white">{title}</h3>
        <span className="text-xs text-zinc-500">{count} items</span>
      </div>
      <JsonBlock value={raw} />
    </div>
  );
}
