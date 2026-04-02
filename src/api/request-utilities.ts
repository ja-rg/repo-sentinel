import { type RunKind, RUN_KINDS } from "./db-actions"
import {
    parseToolOptions,
    validateToolOptionsForKind,
} from "./tool-options";


export function isValidKind(value: unknown): value is RunKind {
    return typeof value === "string" && RUN_KINDS.includes(value as RunKind);
}
export function rowToApi(row: any) {
    return {
        ...row,
        tool_options_json: row?.tool_options_json ? JSON.parse(row.tool_options_json) : null,
        findings_json: row?.findings_json ? JSON.parse(row.findings_json) : null,
        decision_json: row?.decision_json ? JSON.parse(row.decision_json) : null,
        details_json: row?.details_json ? JSON.parse(row.details_json) : null,
        command_json: row?.command_json ? JSON.parse(row.command_json) : null,
    };
}

type CreateRunInput = {
    kind: unknown;
    input_ref?: unknown;
    file?: File | null;
    tool_options?: unknown;
};

export async function parseCreateRunRequest(c: any): Promise<CreateRunInput | Response> {
    const contentType = (c.req.header("content-type") ?? "").toLowerCase();

    if (contentType.includes("application/json")) {
        const body = await c.req.json();

        if (!body || typeof body !== "object") {
            return c.json({ error: "Invalid JSON body" }, 400);
        }

        return body as CreateRunInput;
    }

    if (contentType.includes("multipart/form-data")) {
        const form = await c.req.formData();

        return {
            kind: form.get("kind"),
            input_ref: form.get("input_ref"),
            file: form.get("file") as File | null,
            tool_options: (() => {
                const raw = form.get("tool_options");
                if (typeof raw !== "string" || !raw.trim()) return undefined;
                try {
                    return JSON.parse(raw);
                } catch {
                    return raw;
                }
            })(),
        };
    }

    return c.json(
        { error: "Unsupported Content-Type. Use application/json or multipart/form-data" },
        415
    );
}

export function validateCreateRunInput(parsed: CreateRunInput): { toolOptionsJson: string | null } {
    const options = parseToolOptions(parsed.tool_options);

    if (isValidKind(parsed.kind)) {
        validateToolOptionsForKind(parsed.kind, options);
    }

    return {
        toolOptionsJson: options ? JSON.stringify(options) : null,
    };
}