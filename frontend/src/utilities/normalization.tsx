import { isSyftSbom } from "../tools/syft";
import type { HealthReport, FindingsSection, HealthCheck } from "../types";
import { parseJson } from "./json";

function isGitleaksFinding(value: unknown) {
  if (!value || typeof value !== "object") return false;

  const item = value as Record<string, unknown>;

  return (
    typeof item.RuleID === "string" &&
    typeof item.Description === "string" &&
    typeof item.File === "string" &&
    ("StartLine" in item || "EndLine" in item || "Secret" in item)
  );
}

function isGitleaksReport(value: unknown) {
  return Array.isArray(value) && value.some(isGitleaksFinding);
}

export function normalizeHealth(raw: unknown): HealthReport | null {
  if (!raw || typeof raw !== "object") return null;
  const data = raw as Record<string, unknown>;

  if (Array.isArray(data.checks)) {
    return data as unknown as HealthReport;
  }

  const legacyChecks = data.checks;
  if (!legacyChecks || typeof legacyChecks !== "object") {
    return data as HealthReport;
  }

  const normalizedChecks = Object.entries(
    legacyChecks as Record<string, unknown>,
  ).map(([key, value]) => ({
    key,
    label: key.replace(/_/g, " "),
    status:
      (value as Record<string, unknown>)?.status === "ok"
        ? "pass"
        : (value as Record<string, unknown>)?.status === "fail"
          ? "fail"
          : "unknown",
    summary:
      (value as Record<string, unknown>)?.error ||
      (value as Record<string, unknown>)?.details ||
      key,
    error: (value as Record<string, unknown>)?.error,
    details: (value as Record<string, unknown>)?.details,
    missing: Array.isArray((value as Record<string, unknown>)?.details)
      ? (
          (value as Record<string, unknown>)?.details as Record<
            string,
            unknown
          >[]
        )
          .filter(
            (item: Record<string, unknown>) => item && item.found === false,
          )
          .map((item: Record<string, unknown>) => item.image)
      : undefined,
  })) as HealthCheck[];

  return {
    ok: Boolean(data.ok),
    service: typeof data.service === "string" ? data.service : undefined,
    database: data.database,
    checks: normalizedChecks,
  };
}

export function normalizeFindings(raw: unknown): FindingsSection[] {
  const parsed = parseJson(raw);

  if (isGitleaksReport(parsed)) {
    return [
      {
        key: "gitleaks",
        title: "gitleaks",
        kind: "gitleaks",
        items: parsed as unknown[],
        raw: parsed,
      },
    ];
  }

  if (isSyftSbom(parsed)) {
    return [
      {
        key: "syft",
        title: "syft",
        kind: "syft",
        items: [],
        raw: parsed,
      },
    ];
  }

  if (Array.isArray(parsed)) {
    return [
      {
        key: "findings",
        title: "Findings",
        kind: "generic",
        items: parsed,
        raw: parsed,
      },
    ];
  }

  if (!parsed || typeof parsed !== "object") {
    return [];
  }

  return Object.entries(parsed as Record<string, unknown>).map(
    ([key, value]) => {
      const kind =
        key === "semgrep"
          ? "semgrep"
          : key === "trivy"
            ? "trivy"
            : key === "grype"
              ? "grype"
            : key === "gitleaks" || isGitleaksReport(value)
              ? "gitleaks"
              : isSyftSbom(value)
                ? "syft"
                : "generic";

      return {
        key,
        title: key,
        kind,
        items: Array.isArray(value) ? value : value == null ? [] : [value],
        raw: value,
      };
    },
  );
}
