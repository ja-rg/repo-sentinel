import { useMemo, useState } from "react";
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

function stripAnsi(text: string) {
  return text.replace(/\x1B\[[0-9;]*m/g, "");
}

function severityRank(value: unknown) {
  const severity = String(value ?? "").toLowerCase();
  if (severity === "critical") return 5;
  if (severity === "high") return 4;
  if (severity === "medium") return 3;
  if (severity === "low") return 2;
  if (severity === "info") return 1;
  return 0;
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
  const isJson = text.startsWith("{") || text.startsWith("[");

  const downloadJson = () => {
    const blob = new Blob([text], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${label.toLocaleLowerCase().replace(/\s+/g, "-")}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <details className="mt-3 border border-zinc-800 bg-black">
      <summary className="flex cursor-pointer items-center justify-between gap-2 px-3 py-2 text-xs text-zinc-400 hover:bg-zinc-900">
        <span className="flex-1">
          <span className="font-medium text-zinc-300">{label}:</span>{" "}
          <span className="break-all">{summary}</span>
        </span>
        {isJson && (
          <button
            onClick={(e) => {
              e.stopPropagation();
              downloadJson();
            }}
            className="whitespace-nowrap text-zinc-400 hover:text-zinc-200 transition-colors cursor-pointer text-xs"
            title="Download as JSON"
          >
            ↓ Download
          </button>
        )}
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

const FindingCard = ({ children }: { children: React.ReactNode }) => (
  <div className="border border-zinc-800 bg-zinc-950 p-4">{children}</div>
);

const LabelValue = ({ label, value }: { label: string; value: React.ReactNode }) => (
  <div>
    <div className="text-[11px] uppercase tracking-wide text-zinc-500">{label}</div>
    <div className="mt-1 text-sm text-white break-all">{value}</div>
  </div>
);

const Badge = ({ children }: { children: React.ReactNode }) => (
  <span className="border border-zinc-700 px-2 py-1 text-[11px] uppercase tracking-wide text-zinc-300">
    {children}
  </span>
);

function PaginationControls({
  page,
  totalPages,
  totalItems,
  pageSize,
  onPageChange,
}: {
  page: number;
  totalPages: number;
  totalItems: number;
  pageSize: number;
  onPageChange: (page: number) => void;
}) {
  if (totalPages <= 1) return null;

  const from = (page - 1) * pageSize + 1;
  const to = Math.min(page * pageSize, totalItems);

  return (
    <div className="mt-3 flex flex-wrap items-center justify-between gap-3 border border-zinc-800 bg-black/40 px-3 py-2 text-xs text-zinc-400">
      <span>
        Showing {from}-{to} of {totalItems}
      </span>
      <div className="flex items-center gap-2">
        <button
          type="button"
          onClick={() => onPageChange(page - 1)}
          disabled={page <= 1}
          className="border border-zinc-700 px-2 py-1 text-zinc-300 disabled:cursor-not-allowed disabled:opacity-40"
        >
          Prev
        </button>
        <span>
          Page {page}/{totalPages}
        </span>
        <button
          type="button"
          onClick={() => onPageChange(page + 1)}
          disabled={page >= totalPages}
          className="border border-zinc-700 px-2 py-1 text-zinc-300 disabled:cursor-not-allowed disabled:opacity-40"
        >
          Next
        </button>
      </div>
    </div>
  );
}

function looksLikeDockerInspect(raw: unknown) {
  if (!raw || typeof raw !== "object") return false;
  const data = raw as Record<string, unknown>;
  return (
    typeof data.Id === "string" &&
    typeof data.Os === "string" &&
    typeof data.Architecture === "string" &&
    !!data.Config
  );
}

export function DecisionView({ decision }: { decision: unknown }) {
  if (!decision || typeof decision !== "object") {
    return <JsonBlock value={decision} />;
  }

  const d = decision as Record<string, unknown>;
  const action = String(d.action ?? "unknown");
  const reason = String(d.reason ?? "");
  const stage = String(d.stage ?? "unknown");
  const applied = d.applied === true;
  const exposedUrl = d.exposed_url ? String(d.exposed_url) : null;

  const actionColor =
    action === "allow"
      ? "bg-green-950/30 border-green-700 text-green-200"
      : action === "reject"
        ? "bg-red-950/30 border-red-700 text-red-200"
        : action === "teardown"
          ? "bg-yellow-950/30 border-yellow-700 text-yellow-200"
          : "bg-zinc-900/30 border-zinc-700 text-zinc-200";

  const actionBg =
    action === "allow"
      ? "bg-green-950/40"
      : action === "reject"
        ? "bg-red-950/40"
        : action === "teardown"
          ? "bg-yellow-950/40"
          : "bg-zinc-900/40";

  return (
    <div className={`border-l-4 ${actionColor} border p-4 space-y-3`}>
      <div>
        <div className="text-[11px] uppercase tracking-wide text-zinc-500 mb-1">
          Decision
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <span className={`border ${actionColor} px-3 py-1 text-sm font-semibold uppercase`}>
            {action}
          </span>
          <span className="text-xs text-zinc-400">{stage}</span>
        </div>
      </div>

      {reason && (
        <div className={`${actionBg} px-3 py-2 rounded border border-zinc-700`}>
          <p className="text-sm text-white break-words">{reason}</p>
        </div>
      )}

      {applied && (
        <div className="flex items-center gap-2 text-xs text-green-300">
          <span>✓</span>
          <span>Manifest was applied to cluster</span>
        </div>
      )}

      {!applied && (
        <div className="flex items-center gap-2 text-xs text-red-300">
          <span>✗</span>
          <span>Manifest was not applied</span>
        </div>
      )}

      {exposedUrl && (
        <div>
          <div className="text-[11px] uppercase tracking-wide text-zinc-500 mb-1">
            Service URL
          </div>
          <a
            href={exposedUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="text-blue-400 hover:text-blue-300 underline break-all text-sm"
          >
            {exposedUrl}
          </a>
        </div>
      )}
    </div>
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

  if (section.kind === "grype") {
    return (
      <GrypeFindings
        title={section.title}
        items={section.items}
        raw={section.raw}
      />
    );
  }

  if (section.kind === "syft") {
    return <SyftSbomFindings title={section.title} raw={section.raw} />;
  }

  if (looksLikeDockerInspect(section.raw)) {
    return <DockerImageProfile title={section.title} raw={section.raw} />;
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
  const componentsPageSize = 50;
  const [componentsPage, setComponentsPage] = useState(1);
  const componentsTotalPages = Math.max(
    1,
    Math.ceil(components.length / componentsPageSize),
  );
  const safeComponentsPage = Math.min(componentsPage, componentsTotalPages);
  const pagedComponents = useMemo(() => {
    const start = (safeComponentsPage - 1) * componentsPageSize;
    return components.slice(start, start + componentsPageSize);
  }, [components, safeComponentsPage]);

  return (
    <ScannerSection
      title={title}
      summary={`SBOM · ${String(bomFormat)} ${String(specVersion)} · ${components.length} components`}
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
              {pagedComponents.map((component, index) => {
                const item = component as Record<string, unknown>;
                const absoluteIndex =
                  (safeComponentsPage - 1) * componentsPageSize + index;
                return (
                  <div
                    key={`${String(item["bom-ref"] ?? item.name ?? "component")}-${absoluteIndex}`}
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

              <PaginationControls
                page={safeComponentsPage}
                totalPages={componentsTotalPages}
                totalItems={components.length}
                pageSize={componentsPageSize}
                onPageChange={setComponentsPage}
              />
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
  const pageSize = 50;
  const [page, setPage] = useState(1);
  const totalPages = Math.max(1, Math.ceil(rows.length / pageSize));
  const safePage = Math.min(page, totalPages);
  const pagedRows = useMemo(() => {
    const start = (safePage - 1) * pageSize;
    return rows.slice(start, start + pageSize);
  }, [rows, safePage]);
  const summary = `${rows.length} results`;

  return (
    <ScannerSection title={title} summary={summary}>
      {rows.length === 0 ? (
        <JsonBlock value={raw} />
      ) : (
        <div className="space-y-2">
          {pagedRows.map((entry, index) => {
            const item = (entry ?? {}) as Record<string, unknown>;
            const absoluteIndex = (safePage - 1) * pageSize + index;
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
                key={`${item.check_id || "semgrep"}-${absoluteIndex}`}
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

          <PaginationControls
            page={safePage}
            totalPages={totalPages}
            totalItems={rows.length}
            pageSize={pageSize}
            onPageChange={setPage}
          />
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
  // Check if items are already normalized (manifest findings from backend)
  // vs raw Trivy output that needs flattening
  const isNormalized = items.some(
    (item) =>
      item &&
      typeof item === "object" &&
      ((item as Record<string, unknown>).tool === "trivy" ||
        (item as Record<string, unknown>).category === "manifest")
  );

  const rows = isNormalized ? (items as Record<string, unknown>[]) : flattenTrivy(items);
  const sortedRows = useMemo(() => {
    return [...rows].sort((a, b) => {
      const aSeverity = (a as Record<string, unknown>).severity ?? (a as Record<string, unknown>).Severity;
      const bSeverity = (b as Record<string, unknown>).severity ?? (b as Record<string, unknown>).Severity;
      return severityRank(bSeverity) - severityRank(aSeverity);
    });
  }, [rows]);
  const pageSize = 50;
  const [page, setPage] = useState(1);
  const totalPages = Math.max(1, Math.ceil(sortedRows.length / pageSize));
  const safePage = Math.min(page, totalPages);
  const pagedRows = useMemo(() => {
    const start = (safePage - 1) * pageSize;
    return sortedRows.slice(start, start + pageSize);
  }, [sortedRows, safePage]);

  if (rows.length === 0) {
    const data = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>;
    const metadata =
      data.Metadata && typeof data.Metadata === "object"
        ? (data.Metadata as Record<string, unknown>)
        : {};

    const imageConfig =
      metadata.ImageConfig && typeof metadata.ImageConfig === "object"
        ? (metadata.ImageConfig as Record<string, unknown>)
        : {};

    const config =
      imageConfig.config && typeof imageConfig.config === "object"
        ? (imageConfig.config as Record<string, unknown>)
      : {};

    const repoTags = Array.isArray(metadata.RepoTags) ? metadata.RepoTags : [];
    const repoDigests = Array.isArray(metadata.RepoDigests) ? metadata.RepoDigests : [];
    const layers = Array.isArray(metadata.Layers) ? metadata.Layers : [];
    const env = Array.isArray(config.Env) ? config.Env : [];
    const cmd = Array.isArray(config.Cmd) ? config.Cmd : [];

    return (
      <ScannerSection
        title={title}
        summary={`✓ Clean · ${repoTags.length} tags · ${layers.length} layers`}
        defaultOpen
      >
        <div className="space-y-3">
          <FindingCard>
            <div className="grid gap-x-4 gap-y-3 sm:grid-cols-2">
              <LabelValue 
                label="Image ID" 
                value={String(metadata.ImageID ?? "unknown")} 
              />
              <LabelValue 
                label="Size" 
                value={`${Number(metadata.Size ?? 0).toLocaleString()} bytes`} 
              />
              <LabelValue 
                label="Architecture" 
                value={String(imageConfig.architecture ?? "unknown")} 
              />
              <LabelValue 
                label="OS" 
                value={String(imageConfig.os ?? "unknown")} 
              />
            </div>
          </FindingCard>

          {repoTags.length > 0 && (
            <FindingCard>
              <div className="mb-3 text-[11px] uppercase tracking-wide text-zinc-500">
                Tags
              </div>
              <div className="space-y-2">
                {repoTags.map((tag) => (
                  <div key={String(tag)} className="break-all text-sm text-white">
                    {String(tag)}
                  </div>
                ))}
              </div>
            </FindingCard>
          )}

          {repoDigests.length > 0 && (
            <FindingCard>
              <div className="mb-3 text-[11px] uppercase tracking-wide text-zinc-500">
                Digests
              </div>
              <div className="space-y-2">
                {repoDigests.map((digest) => (
                  <div key={String(digest)} className="break-all text-xs text-zinc-400">
                    {String(digest)}
                  </div>
                ))}
              </div>
            </FindingCard>
          )}

          {cmd.length > 0 && (
            <FindingCard>
              <div className="mb-3 text-[11px] uppercase tracking-wide text-zinc-500">
                Command
              </div>
              <div className="text-sm text-white break-all">
                {cmd.join(" ")}
              </div>
            </FindingCard>
          )}

          {env.length > 0 && (
            <FindingCard>
              <div className="mb-3 flex items-center justify-between gap-3">
                <div className="text-[11px] uppercase tracking-wide text-zinc-500">
                  Environment
                </div>
                <span className="text-xs text-zinc-500">{env.length} vars</span>
              </div>
              <div className="space-y-2">
                {env.slice(0, 10).map((entry, index) => {
                  const text = String(entry);
                  const [key, ...rest] = text.split("=");
                  return (
                    <div
                      key={`${key}-${index}`}
                      className="grid gap-2 border border-zinc-800 p-2 text-xs sm:grid-cols-[140px_1fr]"
                    >
                      <div className="font-medium text-zinc-400">{key}</div>
                      <div className="break-all text-zinc-300">
                        {rest.join("=") || "—"}
                      </div>
                    </div>
                  );
                })}
                {env.length > 10 && (
                  <div className="text-xs text-zinc-500">
                    +{env.length - 10} more variables
                  </div>
                )}
              </div>
            </FindingCard>
          )}

          {layers.length > 0 && (
            <FindingCard>
              <div className="mb-3 flex items-center justify-between gap-3">
                <div className="text-[11px] uppercase tracking-wide text-zinc-500">
                  Layers
                </div>
                <span className="text-xs text-zinc-500">{layers.length} layers</span>
              </div>
              <div className="space-y-2">
                {layers.slice(0, 10).map((layer: unknown, index: number) => {
                  const layerObj = layer as Record<string, unknown>;
                  return (
                    <div
                      key={`${String(layerObj.Digest ?? "layer")}-${index}`}
                      className="border border-zinc-800 p-2 text-xs"
                    >
                      {typeof layerObj.Size !== "undefined" && (
                        <div className="text-zinc-400">
                          {Number(layerObj.Size).toLocaleString()} bytes
                        </div>
                      )}
                      <div className="mt-1 break-all text-zinc-500 text-[10px]">
                        {String(layerObj.Digest ?? "unknown")}
                      </div>
                    </div>
                  );
                })}
                {layers.length > 10 && (
                  <div className="text-xs text-zinc-500">
                    +{layers.length - 10} more layers
                  </div>
                )}
              </div>
            </FindingCard>
          )}

          <CodeTextBlock
            value={JSON.stringify(data, null, 2)}
            label="Raw Trivy scan"
          />
        </div>
      </ScannerSection>
    );
  }

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
      <div className="space-y-2">
        {pagedRows.map((entry, index) => {
          const item = entry as Record<string, unknown>;
          const absoluteIndex = (safePage - 1) * pageSize + index;
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
                key={`${id}-${absoluteIndex}`}
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

          if (category === "misconfiguration" || category === "manifest") {
            const rawData = (item.raw && typeof item.raw === "object" 
              ? item.raw as Record<string, unknown>
              : {}) as Record<string, unknown>;

            const id = item.ID ?? rawData.ID ?? item.id ?? rawData.id ?? "rule";
            const titleText =
              item.title ?? item.Title ?? 
              rawData.Title ?? rawData.title ?? 
              item.Message ?? rawData.Message ?? 
              id;
            const target = item.resource ?? item.target ?? item.Target ?? "unknown";
            const description = item.description ?? rawData.Description ?? item.Description ?? "";
            const resolution = rawData.Resolution ?? item.Resolution ?? item.resolution ?? "";
            const primaryUrl = rawData.PrimaryURL ?? item.PrimaryURL ?? "";
            const references = Array.isArray(rawData.References) ? rawData.References : [];
            const causeMetadata = rawData.CauseMetadata ?? item.CauseMetadata;
            const codeLines = causeMetadata && typeof causeMetadata === "object" 
              ? (causeMetadata as Record<string, unknown>).Code 
              : null;
            const code = codeLines && typeof codeLines === "object"
              ? (codeLines as Record<string, unknown>).Lines
              : null;

            return (
              <div
                key={`${id}-${absoluteIndex}`}
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

                {description && (
                  <p className="mt-2 text-xs text-zinc-300">
                    {String(description)}
                  </p>
                )}

                <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-zinc-500">
                  <span className="break-all">{String(target)}</span>
                </div>

                {(resolution || (Array.isArray(code) && code.length > 0)) && (
                  <details className="mt-3 border border-zinc-800 bg-black/40">
                    <summary className="cursor-pointer px-3 py-2 text-xs uppercase tracking-wide text-zinc-400 hover:bg-zinc-900">
                      Remediation and Problem Location
                    </summary>

                    <div className="space-y-3 border-t border-zinc-800 p-3">
                      {resolution && (
                        <div className="border-l-2 border-yellow-700 bg-yellow-950/30 px-3 py-2 text-xs text-yellow-200">
                          <div className="mb-1 text-[11px] font-medium uppercase tracking-wide text-yellow-300">
                            Resolution
                          </div>
                          <div>{String(resolution)}</div>
                        </div>
                      )}

                      {Array.isArray(code) && code.length > 0 && (
                        <div className="border border-zinc-800 bg-black p-3">
                          <div className="mb-2 text-[11px] uppercase tracking-wide text-zinc-500">
                            Problem Location
                          </div>
                          <div className="space-y-1 font-mono text-xs leading-5">
                            {code.map((line: unknown, codeIndex: number) => {
                              const lineObj = line as Record<string, unknown>;
                              const lineNum = String(lineObj.Number ?? codeIndex + 1);
                              const content = stripAnsi(String(lineObj.Content ?? ""));
                              const highlighted = stripAnsi(String(lineObj.Highlighted ?? content));
                              const renderLine = highlighted || content;
                              const isCause = lineObj.IsCause ?? false;

                              return (
                                <div
                                  key={`line-${lineNum}`}
                                  className={`whitespace-pre-wrap break-words ${isCause ? "bg-red-950/40 text-red-200" : "text-zinc-400"}`}
                                >
                                  <span className="mr-2 inline-block min-w-[40px] text-right text-zinc-600">
                                    {lineNum}
                                  </span>
                                  {renderLine}
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      )}
                    </div>
                  </details>
                )}

                {(primaryUrl || (Array.isArray(references) && references.length > 0)) && (
                  <div className="mt-3 space-y-2">
                    {primaryUrl && (
                      <div className="text-xs">
                        <a
                          href={String(primaryUrl)}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-400 hover:text-blue-300 underline break-all"
                        >
                          {String(primaryUrl)}
                        </a>
                      </div>
                    )}
                    {Array.isArray(references) && references.length > 0 && (
                      <div>
                        <div className="text-[11px] uppercase tracking-wide text-zinc-500 mb-1">
                          References
                        </div>
                        <div className="space-y-1">
                          {references.map((ref: unknown, refIndex: number) => (
                            <div key={`ref-${refIndex}`} className="text-xs">
                              <a
                                href={String(ref)}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-blue-400 hover:text-blue-300 underline break-all"
                              >
                                {String(ref)}
                              </a>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
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
              key={`${id}-${absoluteIndex}`}
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

        <PaginationControls
          page={safePage}
          totalPages={totalPages}
          totalItems={rows.length}
          pageSize={pageSize}
          onPageChange={setPage}
        />
      </div>
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
  const entries =
    raw && typeof raw === "object" && !Array.isArray(raw)
      ? Object.entries(raw as Record<string, unknown>)
      : [];

  return (
    <ScannerSection title={title} summary={`${count} items`}>
      <div className="space-y-3">
        {entries.length > 0 ? (
          <div className="border border-zinc-800 p-3">
            <div className="grid gap-x-4 gap-y-3 sm:grid-cols-2">
              {entries.slice(0, 12).map(([key, value]) => (
                <LabelValue
                  key={key}
                  label={key}
                  value={
                    typeof value === "object"
                      ? Array.isArray(value)
                        ? `${value.length} entries`
                        : "object"
                      : String(value)
                  }
                />
              ))}
            </div>
          </div>
        ) : null}

        <CodeTextBlock value={JSON.stringify(raw, null, 2)} label="Raw JSON" />
      </div>
    </ScannerSection>
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
  const pageSize = 50;
  const [page, setPage] = useState(1);
  const totalPages = Math.max(1, Math.ceil(rows.length / pageSize));
  const safePage = Math.min(page, totalPages);
  const pagedRows = useMemo(() => {
    const start = (safePage - 1) * pageSize;
    return rows.slice(start, start + pageSize);
  }, [rows, safePage]);
  const summary = `${rows.length} leaks`;

  return (
    <ScannerSection title={title} summary={summary}>
      {rows.length === 0 ? (
        <JsonBlock value={raw} />
      ) : (
        <div className="space-y-2">
          {pagedRows.map((entry, index) => {
            const item = (entry ?? {}) as Record<string, unknown>;
            const absoluteIndex = (safePage - 1) * pageSize + index;
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
                key={`${String(fingerprint ?? id)}-${absoluteIndex}`}
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

          <PaginationControls
            page={safePage}
            totalPages={totalPages}
            totalItems={rows.length}
            pageSize={pageSize}
            onPageChange={setPage}
          />
        </div>
      )}
    </ScannerSection>
  );
}

function GrypeFindings({
  title,
  items,
  raw,
}: {
  title: string;
  items: unknown[];
  raw: unknown;
}) {
  const rows = Array.isArray(items) ? items : [];
  const pageSize = 50;
  const [page, setPage] = useState(1);
  const totalPages = Math.max(1, Math.ceil(rows.length / pageSize));
  const safePage = Math.min(page, totalPages);
  const pagedRows = useMemo(() => {
    const start = (safePage - 1) * pageSize;
    return rows.slice(start, start + pageSize);
  }, [rows, safePage]);

  const severityCounts = rows.reduce<Record<string, number>>(
    (acc, entry) => {
      const item = (entry ?? {}) as Record<string, unknown>;
      const vuln =
        item.vulnerability && typeof item.vulnerability === "object"
          ? (item.vulnerability as Record<string, unknown>)
          : {};
      const severity = String(vuln.severity ?? "unknown").toLowerCase();
      acc[severity] = (acc[severity] ?? 0) + 1;
      return acc;
    },
    {},
  );

  const summary = [
    `${rows.length} findings`,
    severityCounts.critical ? `${severityCounts.critical} critical` : null,
    severityCounts.high ? `${severityCounts.high} high` : null,
    severityCounts.medium ? `${severityCounts.medium} medium` : null,
  ]
    .filter(Boolean)
    .join(" · ");

  return (
    <ScannerSection title={title} summary={summary || "No findings"}>
      {rows.length === 0 ? (
        <JsonBlock value={raw} />
      ) : (
        <div className="space-y-2">
          {pagedRows.map((entry, index) => {
            const item = (entry ?? {}) as Record<string, unknown>;
            const absoluteIndex = (safePage - 1) * pageSize + index;
            const vuln =
              item.vulnerability && typeof item.vulnerability === "object"
                ? (item.vulnerability as Record<string, unknown>)
                : {};
            const artifact =
              item.artifact && typeof item.artifact === "object"
                ? (item.artifact as Record<string, unknown>)
                : {};

            const id = vuln.id ?? item.id ?? "grype-vuln";
            const severity = String(vuln.severity ?? "unknown");
            const description =
              vuln.description ?? vuln.id ?? item.matchDetails ?? "Grype finding";
            const packageName = artifact.name ?? item.package ?? "unknown";
            const packageType = artifact.type ?? item.type ?? "package";
            const installedVersion = artifact.version ?? item.version;
            const fix =
              item.fix && typeof item.fix === "object"
                ? (item.fix as Record<string, unknown>)
                : {};
            const fixedVersion = fix.versions
              ? Array.isArray(fix.versions)
                ? (fix.versions as unknown[]).map(String).slice(0, 3).join(", ")
                : String(fix.versions)
              : "";

            return (
              <div
                key={`${String(id)}-${absoluteIndex}`}
                className="border border-zinc-800 p-3"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="border border-zinc-700 px-2 py-1 text-[11px] uppercase tracking-wide text-zinc-300">
                    {severity}
                  </span>
                  <span className="border border-zinc-700 px-2 py-1 text-[11px] uppercase tracking-wide text-zinc-300">
                    {String(packageType)}
                  </span>
                  <span className="text-xs text-zinc-500 break-all">{String(id)}</span>
                </div>

                <p className="mt-2 text-sm text-white">{String(description)}</p>

                <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-zinc-500">
                  <span className="break-all">{String(packageName)}</span>
                  {installedVersion ? (
                    <span>installed: {String(installedVersion)}</span>
                  ) : null}
                  {fixedVersion ? <span>fixed: {fixedVersion}</span> : null}
                </div>
              </div>
            );
          })}

          <PaginationControls
            page={safePage}
            totalPages={totalPages}
            totalItems={rows.length}
            pageSize={pageSize}
            onPageChange={setPage}
          />

          <CodeTextBlock
            value={JSON.stringify(raw, null, 2)}
            label="Raw Grype JSON"
          />
        </div>
      )}
    </ScannerSection>
  );
}

function DockerImageProfile({
  title,
  raw,
}: {
  title: string;
  raw: unknown;
}) {
  const data = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>;

  const config =
    data.Config && typeof data.Config === "object"
      ? (data.Config as Record<string, unknown>)
      : {};

  const exposedPorts =
    config.ExposedPorts && typeof config.ExposedPorts === "object"
      ? Object.keys(config.ExposedPorts as Record<string, unknown>)
      : [];

  const env = Array.isArray(config.Env) ? config.Env : [];
  const entrypoint = Array.isArray(config.Entrypoint) ? config.Entrypoint : [];
  const cmd = Array.isArray(config.Cmd) ? config.Cmd : [];
  const repoTags = Array.isArray(data.RepoTags) ? data.RepoTags : [];
  const repoDigests = Array.isArray(data.RepoDigests) ? data.RepoDigests : [];
  const layers =
    data.RootFS && typeof data.RootFS === "object" &&
      Array.isArray((data.RootFS as Record<string, unknown>).Layers)
      ? ((data.RootFS as Record<string, unknown>).Layers as unknown[])
      : [];

  return (
    <ScannerSection
      title={title}
      summary={`${repoTags.length} tags · ${layers.length} layers · ${String(data.Os ?? "unknown")}/${String(data.Architecture ?? "unknown")}`}
      defaultOpen
    >
      <div className="space-y-3">
        <FindingCard>
          <div className="grid gap-x-4 gap-y-3 sm:grid-cols-2">
            <LabelValue label="Image ID" value={String(data.Id ?? "unknown")} />
            <LabelValue label="Created" value={String(data.Created ?? "unknown")} />
            <LabelValue label="OS" value={String(data.Os ?? "unknown")} />
            <LabelValue label="Architecture" value={String(data.Architecture ?? "unknown")} />
            <LabelValue label="Size" value={`${Number(data.Size ?? 0).toLocaleString()} bytes`} />
            <LabelValue
              label="Working dir"
              value={String(config.WorkingDir ?? "not set")}
            />
          </div>
        </FindingCard>

        <FindingCard>
          <div className="mb-3 text-[11px] uppercase tracking-wide text-zinc-500">
            Runtime
          </div>
          <div className="grid gap-x-4 gap-y-3 sm:grid-cols-2">
            <LabelValue
              label="Entrypoint"
              value={entrypoint.length ? entrypoint.join(" ") : "not set"}
            />
            <LabelValue
              label="Command"
              value={cmd.length ? cmd.join(" ") : "not set"}
            />
            <LabelValue
              label="Stop signal"
              value={String(config.StopSignal ?? "default")}
            />
            <LabelValue
              label="Exposed ports"
              value={
                exposedPorts.length ? (
                  <div className="flex flex-wrap gap-2">
                    {exposedPorts.map((port) => (
                      <Badge key={port}>{port}</Badge>
                    ))}
                  </div>
                ) : (
                  "none"
                )
              }
            />
          </div>
        </FindingCard>

        <FindingCard>
          <div className="mb-3 flex items-center justify-between gap-3">
            <div className="text-[11px] uppercase tracking-wide text-zinc-500">
              Tags and digests
            </div>
          </div>

          <div className="space-y-2">
            {repoTags.map((tag) => (
              <div key={String(tag)} className="break-all text-sm text-white">
                {String(tag)}
              </div>
            ))}
            {repoDigests.map((digest) => (
              <div key={String(digest)} className="break-all text-xs text-zinc-500">
                {String(digest)}
              </div>
            ))}
          </div>
        </FindingCard>

        <FindingCard>
          <div className="mb-3 flex items-center justify-between gap-3">
            <div className="text-[11px] uppercase tracking-wide text-zinc-500">
              Environment variables
            </div>
            <span className="text-xs text-zinc-500">{env.length} entries</span>
          </div>

          {env.length === 0 ? (
            <div className="text-sm text-zinc-500">No environment variables.</div>
          ) : (
            <div className="space-y-2">
              {env.map((entry, index) => {
                const text = String(entry);
                const [key, ...rest] = text.split("=");
                return (
                  <div
                    key={`${key}-${index}`}
                    className="grid gap-2 border border-zinc-800 p-3 sm:grid-cols-[220px_1fr]"
                  >
                    <div className="text-xs font-medium uppercase tracking-wide text-zinc-400">
                      {key}
                    </div>
                    <div className="break-all text-sm text-white">
                      {rest.join("=") || "—"}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </FindingCard>

        <FindingCard>
          <div className="mb-3 flex items-center justify-between gap-3">
            <div className="text-[11px] uppercase tracking-wide text-zinc-500">
              Layers
            </div>
            <span className="text-xs text-zinc-500">{layers.length} layers</span>
          </div>

          <div className="space-y-2">
            {layers.slice(0, 20).map((layer, index) => (
              <div
                key={`${String(layer)}-${index}`}
                className="break-all border border-zinc-800 p-3 text-xs text-zinc-300"
              >
                {String(layer)}
              </div>
            ))}
            {layers.length > 20 ? (
              <div className="text-xs text-zinc-500">
                Showing first 20 of {layers.length} layers
              </div>
            ) : null}
          </div>
        </FindingCard>

        <CodeTextBlock
          value={JSON.stringify(data, null, 2)}
          label="Raw image metadata JSON"
        />
      </div>
    </ScannerSection>
  );
}