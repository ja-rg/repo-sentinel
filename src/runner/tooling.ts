import {
  isToolEnabled,
  parseRunToolOptions,
  resolveToolCommand,
  type ToolName,
  type ToolOptions,
} from "../api/tool-options";
import type { Run } from "./update-runs";

export function getRunToolOptions(run: Run): ToolOptions | undefined {
  return parseRunToolOptions(run.tool_options_json);
}

export function resolveRunToolInvocation(
  run: Run,
  tool: ToolName,
  defaults: { image: string; command: string[] },
): { image: string; command: string[] } | null {
  const options = getRunToolOptions(run);
  if (!isToolEnabled(options, tool, true)) {
    return null;
  }

  return resolveToolCommand(options, tool, defaults);
}

export function shouldLogVerboseCommands(run: Run): boolean {
  const options = getRunToolOptions(run);
  return options?.verbose_commands === true;
}
