import type { RunKind } from "./db-actions";

export const TOOL_NAMES = ["semgrep", "trivy", "gitleaks", "syft", "grype", "nuclei"] as const;
export type ToolName = typeof TOOL_NAMES[number];

type ToolOverride = {
  image?: string;
  extra_args?: string[];
  command?: string[];
};

export type ToolOptions = {
  enabled_tools?: ToolName[];
  overrides?: Partial<Record<ToolName, ToolOverride>>;
  verbose_commands?: boolean;
};

type FlagSpec = {
  takesValue?: boolean;
};

const TOOLS_BY_KIND: Record<RunKind, ToolName[]> = {
  repo: ["semgrep", "trivy", "gitleaks", "syft"],
  archive: ["semgrep", "trivy", "gitleaks", "syft"],
  dockerfile: ["semgrep", "trivy"],
  image: ["trivy", "syft", "grype"],
  k8s_manifest: ["semgrep", "trivy", "nuclei"],
  k8s_service: ["nuclei"],
};

const FLAG_ALLOWLIST: Record<ToolName, Record<string, FlagSpec>> = {
  semgrep: {
    "--config": { takesValue: true },
    "--severity": { takesValue: true },
    "--exclude": { takesValue: true },
    "--include": { takesValue: true },
    "--max-target-bytes": { takesValue: true },
    "--json": {},
    "--no-git-ignore": {},
    "--error": {},
  },
  trivy: {
    "--severity": { takesValue: true },
    "--ignore-unfixed": {},
    "--timeout": { takesValue: true },
    "--scanners": { takesValue: true },
    "--skip-dirs": { takesValue: true },
    "--skip-files": { takesValue: true },
    "--skip-db-update": {},
    "--vuln-type": { takesValue: true },
    "--exit-code": { takesValue: true },
    "--quiet": {},
    "--format": { takesValue: true },
    "--file-patterns": { takesValue: true },
  },
  gitleaks: {
    "--redact": {},
    "--no-banner": {},
    "--no-git": {},
    "--config": { takesValue: true },
    "--source": { takesValue: true },
    "--report-format": { takesValue: true },
    "--report-path": { takesValue: true },
    "--exit-code": { takesValue: true },
  },
  syft: {
    "-o": { takesValue: true },
    "--scope": { takesValue: true },
    "--exclude": { takesValue: true },
    "--select-catalogers": { takesValue: true },
  },
  grype: {
    "-o": { takesValue: true },
    "--fail-on": { takesValue: true },
    "--add-cpes-if-none": {},
    "--scope": { takesValue: true },
    "--only-fixed": {},
  },
  nuclei: {
    "-u": { takesValue: true },
    "-severity": { takesValue: true },
    "-tags": { takesValue: true },
    "-t": { takesValue: true },
    "-jsonl": {},
    "-silent": {},
    "-rl": { takesValue: true },
    "-c": { takesValue: true },
    "-timeout": { takesValue: true },
    "-retries": { takesValue: true },
  },
};

const SAFE_TOKEN = /^[A-Za-z0-9_./:=,@%+\-*]+$/;

function isToolName(value: unknown): value is ToolName {
  return typeof value === "string" && (TOOL_NAMES as readonly string[]).includes(value);
}

function toToolList(value: unknown): ToolName[] | undefined {
  if (value == null) return undefined;
  if (!Array.isArray(value)) {
    throw new Error("tool_options.enabled_tools must be an array of tool names");
  }

  const out: ToolName[] = [];
  for (const item of value) {
    if (!isToolName(item)) {
      throw new Error(`Unsupported tool in enabled_tools: ${String(item)}`);
    }
    out.push(item);
  }
  return out;
}

function toTokenArray(value: unknown, fieldName: string): string[] | undefined {
  if (value == null) return undefined;
  if (!Array.isArray(value) || value.some((x) => typeof x !== "string")) {
    throw new Error(`${fieldName} must be an array of strings`);
  }

  const tokens = value.map((x) => x.trim()).filter(Boolean);
  for (const token of tokens) {
    if (!SAFE_TOKEN.test(token)) {
      throw new Error(`${fieldName} contains unsupported token: ${token}`);
    }
  }
  return tokens;
}

function validateFlagSequence(tool: ToolName, tokens: string[], fieldName: string) {
  const allowlist = FLAG_ALLOWLIST[tool];

  for (let i = 0; i < tokens.length; i += 1) {
    const token = tokens[i];
    if (!token) continue;

    if (!token.startsWith("-")) {
      continue;
    }

    const spec = allowlist[token];
    if (!spec) {
      throw new Error(`${fieldName} uses a non-allowed flag for ${tool}: ${token}`);
    }

    if (spec.takesValue) {
      const nextToken = tokens[i + 1];
      if (!nextToken) {
        throw new Error(`${fieldName} flag ${token} requires a value`);
      }
      i += 1;
    }
  }
}

function parseOverrides(value: unknown): ToolOptions["overrides"] {
  if (value == null) return undefined;
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("tool_options.overrides must be an object");
  }

  const overrides: Partial<Record<ToolName, ToolOverride>> = {};

  for (const [rawTool, rawConfig] of Object.entries(value as Record<string, unknown>)) {
    if (!isToolName(rawTool)) {
      throw new Error(`Unsupported tool in overrides: ${rawTool}`);
    }
    if (!rawConfig || typeof rawConfig !== "object" || Array.isArray(rawConfig)) {
      throw new Error(`override for ${rawTool} must be an object`);
    }

    const config = rawConfig as Record<string, unknown>;
    const image = typeof config.image === "string" ? config.image.trim() : undefined;
    const extraArgs = toTokenArray(config.extra_args, `tool_options.overrides.${rawTool}.extra_args`);
    const command = toTokenArray(config.command, `tool_options.overrides.${rawTool}.command`);

    if (image && !SAFE_TOKEN.test(image)) {
      throw new Error(`tool_options.overrides.${rawTool}.image contains unsupported characters`);
    }

    if (extraArgs) {
      validateFlagSequence(rawTool, extraArgs, `tool_options.overrides.${rawTool}.extra_args`);
    }

    if (command) {
      validateFlagSequence(rawTool, command, `tool_options.overrides.${rawTool}.command`);
    }

    overrides[rawTool] = {
      image,
      extra_args: extraArgs,
      command,
    };
  }

  return overrides;
}

export function parseToolOptions(raw: unknown): ToolOptions | undefined {
  if (raw == null) return undefined;
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("tool_options must be an object");
  }

  const value = raw as Record<string, unknown>;

  const options: ToolOptions = {
    enabled_tools: toToolList(value.enabled_tools),
    overrides: parseOverrides(value.overrides),
    verbose_commands: typeof value.verbose_commands === "boolean"
      ? value.verbose_commands
      : undefined,
  };

  return options;
}

export function validateToolOptionsForKind(kind: RunKind, options?: ToolOptions) {
  if (!options) return;

  const allowedTools = new Set(TOOLS_BY_KIND[kind]);

  for (const tool of options.enabled_tools ?? []) {
    if (!allowedTools.has(tool)) {
      throw new Error(`Tool ${tool} is not supported for kind ${kind}`);
    }
  }

  for (const tool of Object.keys(options.overrides ?? {}) as ToolName[]) {
    if (!allowedTools.has(tool)) {
      throw new Error(`Override for ${tool} is not supported for kind ${kind}`);
    }
  }
}

export function isToolEnabled(options: ToolOptions | undefined, tool: ToolName, enabledByDefault = true): boolean {
  const selected = options?.enabled_tools;
  if (!selected) return enabledByDefault;
  return selected.includes(tool);
}

export function resolveToolCommand(
  options: ToolOptions | undefined,
  tool: ToolName,
  defaults: { image: string; command: string[] },
): { image: string; command: string[] } {
  const override = options?.overrides?.[tool];

  const image = override?.image || defaults.image;
  const command = override?.command?.length
    ? [...override.command]
    : [...defaults.command, ...(override?.extra_args ?? [])];

  return { image, command };
}

export function parseRunToolOptions(value: unknown): ToolOptions | undefined {
  if (!value || typeof value !== "object") return undefined;
  return value as ToolOptions;
}
