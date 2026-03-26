
export function flattenTrivy(results: unknown[]) {
  const items: Array<Record<string, unknown>> = [];

  for (const result of results) {
    if (!result || typeof result !== "object") continue;

    const source = result as Record<string, unknown>;
    const target = source.Target ?? source.target;
    const base = {
      target,
      type: source.Type ?? source.type,
      class: source.Class ?? source.class,
    };

    const vulnerabilities = Array.isArray(source.Vulnerabilities)
      ? source.Vulnerabilities
      : Array.isArray(source.vulnerabilities)
        ? source.vulnerabilities
        : [];

    const misconfigurations = Array.isArray(source.Misconfigurations)
      ? source.Misconfigurations
      : Array.isArray(source.misconfigurations)
        ? source.misconfigurations
        : [];

    for (const vulnerability of vulnerabilities) {
      items.push({
        category: "vulnerability",
        ...base,
        ...vulnerability,
      });
    }

    for (const misconfiguration of misconfigurations) {
      items.push({
        category: "misconfiguration",
        ...base,
        ...misconfiguration,
      });
    }
  }

  return items;
}
