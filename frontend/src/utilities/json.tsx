import type React from "react";

export function cn(...values: Array<string | undefined | false | null>) {
  return values.filter(Boolean).join(" ");
}
export function parseJson<T = unknown>(value: unknown): T | unknown {
  if (typeof value !== "string") return value;
  try {
    return JSON.parse(value) as T;
  } catch {
    return value;
  }
}
export function prettyJson(value: unknown) {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}export function JsonBlock({ value }: { value: unknown; }) {
  return (
    <pre className="overflow-auto border border-zinc-800 bg-black p-3 text-xs leading-6 text-emerald-200">
      <code>{prettyJson(value)}</code>
    </pre>
  );
}

