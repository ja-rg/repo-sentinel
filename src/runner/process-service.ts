import { spawn } from "bun";
import { logRun } from "../api/worker-manager";
import { dockerRun } from "./docker";
import { type Run, setRunStage } from "./update-runs";

type FindingSeverity = "info" | "low" | "medium" | "high" | "critical";

type Finding = {
	tool: string;
	category: "runtime" | "deployment";
	severity: FindingSeverity;
	title: string;
	description: string;
	resource?: string;
	raw?: unknown;
};

type Decision = {
	action: "allow" | "teardown" | "failed";
	reason: string;
	stage: string;
	applied: boolean;
	exposed_url?: string | null;
};

type MatchedService = {
	namespace: string;
	name: string;
	selector: Record<string, string>;
};

type ServiceRecord = {
	metadata?: {
		namespace?: string;
		name?: string;
	};
	spec?: {
		type?: string;
		clusterIP?: string;
		externalIPs?: string[];
		ports?: Array<{ port?: number; nodePort?: number }>;
		selector?: Record<string, string>;
	};
	status?: {
		loadBalancer?: {
			ingress?: Array<{ ip?: string; hostname?: string }>;
		};
	};
};

export async function processService(run: Run): Promise<[Finding[], Decision]> {
	const findings: Finding[] = [];
	let targetUrl: string;

	try {
		setRunStage(run.id, "validating-service-url", "Validating service URL");
		targetUrl = validateServiceUrl(run.input_ref);

		setRunStage(run.id, "runtime-scan", "Running Nuclei runtime scan");
		logRun(run.id, "info", "Nuclei service scan started", {
			stage: "runtime-scan",
			details: { target: targetUrl },
		});

		const nucleiFindings = await runNucleiScan(targetUrl, run.id);
		findings.push(...nucleiFindings);

		const blocking = hasBlockingRuntimeFindings(nucleiFindings);
		logRun(run.id, "info", "Nuclei service scan finished", {
			stage: "runtime-scan",
			details: { target: targetUrl, resultCount: nucleiFindings.length, blocking },
		});

		if (!blocking) {
			setRunStage(run.id, "completed", "Service scan completed without blocking findings");
			return [
				findings,
				{
					action: "allow",
					reason: "No critical/high runtime findings were reported by Nuclei.",
					stage: "completed",
					applied: false,
					exposed_url: targetUrl,
				},
			];
		}

		setRunStage(run.id, "teardown", "Blocking findings found, attempting service teardown");
		const teardown = await teardownServiceByUrl(targetUrl, run.id);

		if (!teardown.matchedService) {
			findings.push({
				tool: "deployment",
				category: "deployment",
				severity: "high",
				title: "Teardown target not resolved",
				description:
					"Critical/High findings were detected, but the URL could not be matched to a Kubernetes service for automatic teardown.",
				resource: targetUrl,
				raw: { target: targetUrl },
			});

			return [
				findings,
				{
					action: "teardown",
					reason:
						"Critical/High findings were detected, but teardown could not be applied automatically because the service could not be identified from the URL.",
					stage: "teardown",
					applied: false,
					exposed_url: targetUrl,
				},
			];
		}

		if (teardown.errors.length > 0) {
			findings.push({
				tool: "deployment",
				category: "deployment",
				severity: "high",
				title: "Automatic teardown failed",
				description: teardown.errors.join("; "),
				resource: `${teardown.matchedService.namespace}/${teardown.matchedService.name}`,
				raw: teardown,
			});

			return [
				findings,
				{
					action: "teardown",
					reason:
						"Critical/High findings were detected, but one or more kubectl delete operations failed.",
					stage: "teardown",
					applied: false,
					exposed_url: targetUrl,
				},
			];
		}

		findings.push({
			tool: "deployment",
			category: "deployment",
			severity: "high",
			title: "Automatic teardown applied",
			description:
				"Critical/High findings were detected and the matched Kubernetes service/workloads were deleted.",
			resource: `${teardown.matchedService.namespace}/${teardown.matchedService.name}`,
			raw: teardown,
		});

		setRunStage(run.id, "completed", "Service scan completed with automatic teardown");
		return [
			findings,
			{
				action: "teardown",
				reason:
					"Critical/High findings were detected and teardown was applied automatically.",
				stage: "completed",
				applied: true,
				exposed_url: targetUrl,
			},
		];
	} catch (error) {
		const message = String(error);
		setRunStage(run.id, "error", "Service processing failed");
		logRun(run.id, "error", "Service processing failed", {
			stage: "error",
			details: { error: message },
		});

		findings.push({
			tool: "pipeline",
			category: "deployment",
			severity: "high",
			title: "Service processing failed",
			description: message,
			resource: run.input_ref,
			raw: { error: message },
		});

		return [
			findings,
			{
				action: "failed",
				reason: message,
				stage: "error",
				applied: false,
				exposed_url: null,
			},
		];
	}
}

function validateServiceUrl(input: string): string {
	const value = String(input ?? "").trim();
	if (!value) {
		throw new Error("k8s_service requires a non-empty URL in input_ref.");
	}

	let parsed: URL;
	try {
		parsed = new URL(value);
	} catch {
		throw new Error("k8s_service input_ref must be a valid URL.");
	}

	if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
		throw new Error("k8s_service URL must use http or https.");
	}

	return parsed.toString();
}

async function runNucleiScan(targetUrl: string, runId: number): Promise<Finding[]> {
	const findings: Finding[] = [];

	const proc = dockerRun(
		["-u", targetUrl, "-jsonl", "-silent"],
		"projectdiscovery/nuclei:latest",
		[],
		"minikube"
	);

	const output = await proc.stdout.text();
	const errText = await proc.stderr.text();
	const exitCode = await proc.exited;

	if (exitCode !== 0 && !output.trim()) {
		throw new Error(
			`Nuclei failed for run ${runId} with exit code ${exitCode}${errText.trim() ? `: ${errText.trim()}` : ""}`,
		);
	}

	const lines = output
		.split(/\r?\n/)
		.map((line) => line.trim())
		.filter(Boolean);

	for (const line of lines) {
		try {
			const item = JSON.parse(line) as Record<string, unknown>;
			const info = (item.info && typeof item.info === "object")
				? (item.info as Record<string, unknown>)
				: {};

			findings.push({
				tool: "nuclei",
				category: "runtime",
				severity: normalizeSeverity(info.severity),
				title: String(info.name ?? item.templateID ?? "Runtime finding"),
				description:
					String(info.description ?? "Nuclei detected a runtime issue."),
				resource: String(item.matchedAt ?? targetUrl),
				raw: item,
			});
		} catch {
			// ignore malformed jsonl lines
		}
	}

	return findings;
}

function hasBlockingRuntimeFindings(findings: Finding[]): boolean {
	return findings.some((finding) => {
		return finding.severity === "critical" || finding.severity === "high";
	});
}

function normalizeSeverity(input: unknown): FindingSeverity {
	const value = String(input ?? "").toLowerCase();

	if (value === "critical") return "critical";
	if (value === "high") return "high";
	if (value === "medium") return "medium";
	if (value === "low") return "low";
	return "info";
}

async function teardownServiceByUrl(
	targetUrl: string,
	runId: number,
): Promise<{ matchedService: MatchedService | null; deleted: string[]; errors: string[] }> {
	const matchedService = await resolveServiceFromUrl(targetUrl, runId);
	if (!matchedService) {
		return { matchedService: null, deleted: [], errors: [] };
	}

	const deleted: string[] = [];
	const errors: string[] = [];

	const deleteService = await runCommand(
		"kubectl",
		[
			"delete",
			"service",
			matchedService.name,
			"-n",
			matchedService.namespace,
			"--ignore-not-found",
		],
		20_000,
	);

	if (deleteService.exitCode === 0) {
		deleted.push(`service/${matchedService.namespace}/${matchedService.name}`);
	} else {
		errors.push(deleteService.stderr || deleteService.stdout || "service delete failed");
	}

	const selector = formatSelector(matchedService.selector);
	if (!selector) {
		return { matchedService, deleted, errors };
	}

	const workloadKinds = ["deployment", "statefulset", "daemonset"];
	for (const kind of workloadKinds) {
		const result = await runCommand(
			"kubectl",
			[
				"delete",
				kind,
				"-n",
				matchedService.namespace,
				"-l",
				selector,
				"--ignore-not-found",
			],
			30_000,
		);

		if (result.exitCode === 0) {
			deleted.push(`${kind}/${matchedService.namespace}/${selector}`);
		} else {
			errors.push(result.stderr || result.stdout || `${kind} delete failed`);
		}
	}

	logRun(runId, "warn", "Automatic teardown attempted", {
		stage: "teardown",
		details: {
			target: targetUrl,
			matched_service: matchedService,
			deleted,
			errors,
		},
	});

	return { matchedService, deleted, errors };
}

function formatSelector(selector: Record<string, string>): string | null {
	const pairs = Object.entries(selector)
		.filter(([key, value]) => key.trim() && String(value).trim())
		.map(([key, value]) => `${key}=${value}`);

	if (pairs.length === 0) return null;
	return pairs.join(",");
}

async function resolveServiceFromUrl(targetUrl: string, runId: number): Promise<MatchedService | null> {
	const parsed = new URL(targetUrl);
	const host = parsed.hostname.toLowerCase();
	const port = parsed.port ? Number(parsed.port) : parsed.protocol === "https:" ? 443 : 80;

	const dnsPattern = /^([a-z0-9-]+)\.([a-z0-9-]+)\.svc(?:\.cluster\.local)?$/;
	const dnsMatch = host.match(dnsPattern);
	if (dnsMatch) {
		const serviceName = dnsMatch[1];
		const namespace = dnsMatch[2];

		if (serviceName && namespace) {
			const byName = await getServiceByName(namespace, serviceName);
			if (byName) {
				return byName;
			}
		}
	}

	const services = await getAllServices(runId);
	if (services.length === 0) return null;

	const matches = services.filter((service) => serviceMatchesUrl(service, host, port));
	if (matches.length === 0) return null;

	return matches[0] ?? null;
}

async function getServiceByName(namespace: string, serviceName: string): Promise<MatchedService | null> {
	const result = await runCommand(
		"kubectl",
		["get", "service", serviceName, "-n", namespace, "-o", "json"],
		20_000,
	);

	if (result.exitCode !== 0) return null;

	let parsed: ServiceRecord;
	try {
		parsed = JSON.parse(result.stdout) as ServiceRecord;
	} catch {
		return null;
	}

	const name = parsed.metadata?.name;
	const ns = parsed.metadata?.namespace;

	if (!name || !ns) return null;

	return {
		namespace: ns,
		name,
		selector: parsed.spec?.selector ?? {},
	};
}

async function getAllServices(runId: number): Promise<Array<MatchedService & { raw: ServiceRecord }>> {
	const result = await runCommand(
		"kubectl",
		["get", "service", "-A", "-o", "json"],
		30_000,
	);

	if (result.exitCode !== 0) {
		logRun(runId, "warn", "Could not enumerate services for URL resolution", {
			stage: "teardown",
			details: { stderr: result.stderr, stdout: result.stdout },
		});
		return [];
	}

	try {
		const parsed = JSON.parse(result.stdout) as { items?: ServiceRecord[] };
		const items = Array.isArray(parsed.items) ? parsed.items : [];

		return items
			.map((item) => {
				const name = item.metadata?.name;
				const namespace = item.metadata?.namespace;

				if (!name || !namespace) return null;

				return {
					name,
					namespace,
					selector: item.spec?.selector ?? {},
					raw: item,
				};
			})
			.filter((item): item is MatchedService & { raw: ServiceRecord } => Boolean(item));
	} catch {
		return [];
	}
}

function serviceMatchesUrl(
	service: MatchedService & { raw: ServiceRecord },
	host: string,
	port: number,
): boolean {
	const dnsHosts = [
		`${service.name}.${service.namespace}.svc`,
		`${service.name}.${service.namespace}.svc.cluster.local`,
	].map((value) => value.toLowerCase());

	if (dnsHosts.includes(host)) {
		return portMatchesServicePorts(service.raw, port, true);
	}

	const spec = service.raw.spec ?? {};
	const clusterIP = String(spec.clusterIP ?? "").toLowerCase();
	if (clusterIP && clusterIP !== "none" && clusterIP === host) {
		return portMatchesServicePorts(service.raw, port, true);
	}

	const externalIPs = Array.isArray(spec.externalIPs) ? spec.externalIPs : [];
	if (externalIPs.map((value) => String(value).toLowerCase()).includes(host)) {
		return portMatchesServicePorts(service.raw, port, true);
	}

	const ingress = service.raw.status?.loadBalancer?.ingress ?? [];
	const ingressHosts = ingress
		.flatMap((item) => [item.ip, item.hostname])
		.filter(Boolean)
		.map((value) => String(value).toLowerCase());

	if (ingressHosts.includes(host)) {
		return portMatchesServicePorts(service.raw, port, true);
	}

	return portMatchesServicePorts(service.raw, port, false);
}

function portMatchesServicePorts(
	service: ServiceRecord,
	port: number,
	strictPortMatch: boolean,
): boolean {
	const ports = Array.isArray(service.spec?.ports) ? service.spec?.ports : [];
	if (ports.length === 0) {
		return !strictPortMatch;
	}

	return ports.some((item) => {
		const servicePort = Number(item.port ?? 0);
		const nodePort = Number(item.nodePort ?? 0);

		if (servicePort > 0 && servicePort === port) return true;
		if (nodePort > 0 && nodePort === port) return true;
		return false;
	});
}

async function runCommand(
	command: string,
	args: string[],
	timeoutMs: number,
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
	const proc = spawn({
		cmd: [command, ...args],
		stdout: "pipe",
		stderr: "pipe",
	});

	const stdoutPromise = new Response(proc.stdout).text();
	const stderrPromise = new Response(proc.stderr).text();

	let timedOut = false;
	const timeoutPromise = Bun.sleep(timeoutMs).then(() => {
		timedOut = true;
		try {
			proc.kill();
		} catch {
			// best effort
		}
	});

	await Promise.race([proc.exited, timeoutPromise]);
	const [stdout, stderr] = await Promise.all([stdoutPromise, stderrPromise]);
	const exitCode = await proc.exited;

	if (timedOut) {
		return {
			stdout,
			stderr: `Command timed out after ${timeoutMs}ms. ${stderr}`.trim(),
			exitCode: exitCode ?? 1,
		};
	}

	return {
		stdout,
		stderr,
		exitCode,
	};
}
