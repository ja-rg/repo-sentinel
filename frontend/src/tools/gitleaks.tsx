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

export function isGitleaksReport(value: unknown) {
  return Array.isArray(value) && value.some(isGitleaksFinding);
}
