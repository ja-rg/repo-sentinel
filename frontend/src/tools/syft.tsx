
export function isSyftSbom(value: unknown) {
  if (!value || typeof value !== "object") return false;

  const data = value as Record<string, unknown>;
  const bomFormat = data.bomFormat;
  const toolComponents = ((data.metadata as Record<string, unknown>)?.tools as Record<string, unknown>)?.components;

  const hasSyftTool = Array.isArray(toolComponents) &&
    toolComponents.some((tool: Record<string, unknown>) => {
      const name = String(tool?.name ?? "").toLowerCase();
      return name === "syft";
    });

  return bomFormat === "CycloneDX" || hasSyftTool;
}
