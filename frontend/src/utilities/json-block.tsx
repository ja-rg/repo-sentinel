import { prettyJson } from "./json";

export function JsonBlock({ value }: { value: unknown }) {
  return (
    <pre className="overflow-auto border border-zinc-800 bg-black p-3 text-xs leading-6 text-emerald-200">
      <code>{prettyJson(value)}</code>
    </pre>
  );
}
