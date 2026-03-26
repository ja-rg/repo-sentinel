
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

    const secrets = Array.isArray(source.Secrets)
      ? source.Secrets
      : Array.isArray(source.secrets)
        ? source.secrets
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

    for (const secret of secrets) {
      items.push({
        category: "secret",
        ...base,
        ...secret,
      });
    }
  }

  return items;
}