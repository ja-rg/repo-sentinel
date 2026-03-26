import { flattenTrivy } from "../tools/trivy";
import type { FindingsSection } from "../types";
import { JsonBlock } from "../utilities/json-block";

function summarizeCodeText(value: unknown, maxLength = 20) {
  const text = String(value ?? "")
    .replace(/\s+/g, " ")
    .trim();

  if (!text) return "Empty";
  if (text.length <= maxLength) return text;

  return `${text.slice(0, maxLength)}…`;
}

function CodeTextBlock({
  value,
  label = "Matched content",
}: {
  value: unknown;
  label?: string;
}) {
  if (value == null) return null;

  const text = String(value);
  const summary = summarizeCodeText(text);

  return (
    <details className="mt-3 border border-zinc-800 bg-black">
      <summary className="cursor-pointer px-3 py-2 text-xs text-zinc-400">
        <span className="font-medium text-zinc-300">{label}:</span>{" "}
        <span className="break-all">{summary}</span>
      </summary>

      <div className="border-t border-zinc-800 p-3">
        <code className="block whitespace-pre-wrap break-all overflow-hidden text-xs leading-6 text-emerald-200">
          {text}
        </code>
      </div>
    </details>
  );
}

function ScannerSection({
  title,
  summary,
  children,
  defaultOpen = false,
}: {
  title: string;
  summary: string;
  children: React.ReactNode;
  defaultOpen?: boolean;
}) {
  return (
    <details open={defaultOpen} className="border border-zinc-800 bg-zinc-950">
      <summary className="flex cursor-pointer flex-wrap items-center justify-between gap-3 px-3 py-2">
        <span className="text-sm font-medium text-white">{title}</span>
        <span className="text-xs text-zinc-500">{summary}</span>
      </summary>

      <div className="border-t border-zinc-800 p-3">{children}</div>
    </details>
  );
}

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

  if (section.kind === "gitleaks") {
    return (
      <GitleaksFindings
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

  const timestamp = metadata.timestamp ?? "unknown";

  const toolsObject =
    metadata.tools && typeof metadata.tools === "object"
      ? (metadata.tools as Record<string, unknown>)
      : {};

  const toolComponents = toolsObject.components;
  const tools = Array.isArray(toolComponents) ? toolComponents : [];

  const subject =
    metadata.component && typeof metadata.component === "object"
      ? (metadata.component as Record<string, unknown>)
      : null;

  const components = Array.isArray(data.components) ? data.components : [];

  return (
    <ScannerSection
      title={title}
      summary={`SBOM · ${String(bomFormat)} ${String(specVersion)} · ${components.length} components`}
      defaultOpen
    >
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
                {String(subject.type ?? "unknown")}
              </span>
              <span className="text-sm text-white">
                {String(subject.name ?? "unknown")}
              </span>
            </div>
            {subject["bom-ref"] ? (
              <div className="mt-2 break-all text-xs text-zinc-500">
                {String(subject["bom-ref"])}
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
                  key={`${String(tool.name ?? "tool")}-${index}`}
                  className="border border-zinc-800 p-3"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="border border-zinc-700 px-2 py-1 text-[11px] uppercase tracking-wide text-zinc-300">
                      {String(tool.type ?? "tool")}
                    </span>
                    <span className="text-sm text-white">
                      {String(tool.name ?? "unknown")}
                    </span>
                    {tool.version ? (
                      <span className="text-xs text-zinc-500">
                        {String(tool.version)}
                      </span>
                    ) : null}
                  </div>
                  <div className="mt-2 text-xs text-zinc-500">
                    {String(tool.author ?? "unknown author")}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="border border-zinc-800 p-3">
          <div className="mb-2 flex items-center justify-between gap-3">
            <div className="text-[11px] uppercase tracking-wide text-zinc-500">
              components
            </div>
            <span className="text-xs text-zinc-500">
              {components.length} entries
            </span>
          </div>

          {components.length === 0 ? (
            <div className="text-sm text-zinc-500">No components.</div>
          ) : (
            <div className="space-y-2">
              {components.slice(0, 25).map((component, index) => {
                const item = component as Record<string, unknown>;
                return (
                  <div
                    key={`${String(item["bom-ref"] ?? item.name ?? "component")}-${index}`}
                    className="border border-zinc-800 p-3"
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="border border-zinc-700 px-2 py-1 text-[11px] uppercase tracking-wide text-zinc-300">
                        {String(item.type ?? "component")}
                      </span>
                      <span className="text-sm text-white break-all">
                        {String(item.name ?? "unknown")}
                      </span>
                      {item.version ? (
                        <span className="text-xs text-zinc-500">
                          {String(item.version)}
                        </span>
                      ) : null}
                    </div>

                    <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-zinc-500">
                      {item.purl ? (
                        <span className="break-all">{String(item.purl)}</span>
                      ) : null}
                      {item["bom-ref"] ? (
                        <span className="break-all">
                          {String(item["bom-ref"])}
                        </span>
                      ) : null}
                    </div>
                  </div>
                );
              })}

              {components.length > 25 ? (
                <div className="text-xs text-zinc-500">
                  Showing first 25 of {components.length} components
                </div>
              ) : null}
            </div>
          )}
        </div>

        <CodeTextBlock
          value={JSON.stringify(data, null, 2)}
          label="Raw SBOM JSON"
        />
      </div>
    </ScannerSection>
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
  const summary = `${rows.length} results`;

  return (
    <ScannerSection title={title} summary={summary}>
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
                  <span className="text-xs text-zinc-500 break-all">
                    {String(item.check_id || "rule")}
                  </span>
                </div>
                <p className="mt-2 text-sm text-white">{String(message)}</p>
                <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-zinc-500">
                  <span className="break-all">{String(path)}</span>
                  <span>line {String(line)}</span>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </ScannerSection>
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

  const summary = [
    `${rows.length} findings`,
    counts.secret ? `${counts.secret} secrets` : null,
    counts.vulnerability ? `${counts.vulnerability} vulnerabilities` : null,
    counts.misconfiguration
      ? `${counts.misconfiguration} misconfigurations`
      : null,
  ]
    .filter(Boolean)
    .join(" · ");

  return (
    <ScannerSection title={title} summary={summary}>
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
                    <span className="text-xs text-zinc-500 break-all">
                      {String(id)}
                    </span>
                  </div>

                  <p className="mt-2 text-sm text-white">{String(titleText)}</p>

                  <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-zinc-500">
                    <span className="break-all">{String(target)}</span>
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

                  {match ? <CodeTextBlock value={match} /> : null}
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
                    <span className="text-xs text-zinc-500 break-all">
                      {String(id)}
                    </span>
                  </div>

                  <p className="mt-2 text-sm text-white">{String(titleText)}</p>

                  <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-zinc-500">
                    <span className="break-all">{String(target)}</span>
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
                  <span className="text-xs text-zinc-500 break-all">
                    {String(id)}
                  </span>
                </div>

                <p className="mt-2 text-sm text-white">{String(titleText)}</p>

                <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-zinc-500">
                  <span className="break-all">{String(target)}</span>
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
    </ScannerSection>
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
function GitleaksFindings({
  title,
  items,
  raw,
}: {
  title: string;
  items: unknown[];
  raw: unknown;
}) {
  const rows = Array.isArray(items) ? items : [];
  const summary = `${rows.length} leaks`;

  return (
    <ScannerSection title={title} summary={summary}>
      {rows.length === 0 ? (
        <JsonBlock value={raw} />
      ) : (
        <div className="space-y-2">
          {rows.map((entry, index) => {
            const item = (entry ?? {}) as Record<string, unknown>;
            const id = item.RuleID ?? "gitleaks-rule";
            const description =
              item.Description ?? item.RuleID ?? "Gitleaks finding";
            const file = item.File ?? "unknown";
            const startLine = item.StartLine;
            const endLine = item.EndLine;
            const match = item.Match;
            const fingerprint = item.Fingerprint;
            const tags = Array.isArray(item.Tags) ? item.Tags : [];

            return (
              <div
                key={`${String(fingerprint ?? id)}-${index}`}
                className="border border-zinc-800 p-3"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="border border-zinc-700 px-2 py-1 text-[11px] uppercase tracking-wide text-zinc-300">
                    secret
                  </span>
                  <span className="text-xs text-zinc-500 break-all">
                    {String(id)}
                  </span>
                </div>

                <p className="mt-2 text-sm text-white">{String(description)}</p>

                <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-zinc-500">
                  <span className="break-all">{String(file)}</span>
                  {typeof startLine === "number" && (
                    <span>
                      line {startLine}
                      {typeof endLine === "number" && endLine !== startLine
                        ? `-${endLine}`
                        : ""}
                    </span>
                  )}
                </div>

                {tags.length > 0 ? (
                  <div className="mt-2 flex flex-wrap gap-2">
                    {tags.map((tag, tagIndex) => (
                      <span
                        key={`${String(tag)}-${tagIndex}`}
                        className="border border-zinc-700 px-2 py-1 text-[11px] text-zinc-400"
                      >
                        {String(tag)}
                      </span>
                    ))}
                  </div>
                ) : null}

                {match ? <CodeTextBlock value={match} /> : null}

                {fingerprint ? (
                  <div className="mt-3 break-all text-[11px] text-zinc-600 uppercase tracking-wide">
                    {String(fingerprint)}
                  </div>
                ) : null}
              </div>
            );
          })}
        </div>
      )}
    </ScannerSection>
  );
}
