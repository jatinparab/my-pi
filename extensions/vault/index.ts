import type { ExtensionAPI, ExtensionContext, Theme } from "@earendil-works/pi-coding-agent";
import { Container, Input, Key, matchesKey, Text, truncateToWidth, wrapTextWithAnsi } from "@earendil-works/pi-tui";
import { StringEnum } from "@earendil-works/pi-ai";
import { Type } from "typebox";
import { VaultBrokerClient, BrokerRequestError, type SetupInput, type VaultRunInput, type VaultStatus } from "./client.ts";
import type { VaultItemsInput, VaultItemsResult, VaultSshRunInput } from "./items-types.ts";
import { validateItemsInput, VaultContentError } from "./metadata.mjs";
import { EU_SERVER, US_SERVER, normalizeEmail, normalizeServer, validateMasterPassword } from "./security.mjs";
import { validateVaultRunInput, VaultRunError } from "./run.mjs";
import { validateVaultSshInput, SshError } from "./ssh.mjs";
import { bitwardenGuardReason } from "./guard.mjs";

const VaultRunParameters = Type.Object({
	executable: Type.String({ minLength: 1, maxLength: 1_024, description: "Executable path or name; invoked directly without a shell" }),
	argv: Type.Array(Type.String({ maxLength: 4_096 }), { maxItems: 128, description: "Arguments excluding the executable" }),
	cwd: Type.Optional(Type.String({ minLength: 1, maxLength: 4_096, description: "Absolute working directory" })),
	env: Type.Optional(Type.Record(Type.String({ minLength: 1, maxLength: 256 }), Type.String({ maxLength: 65_536 }), { description: "Explicit non-secret environment overrides" })),
	materialEnv: Type.Optional(Type.Record(Type.String({ minLength: 1, maxLength: 256 }), Type.String({ minLength: 1, maxLength: 256 }), { description: "Environment name to opaque material handle" })),
	stdin: Type.Optional(Type.String({ minLength: 1, maxLength: 256, description: "At most one opaque material handle for stdin" })),
	timeoutMs: Type.Optional(Type.Integer({ minimum: 1, maximum: 900_000, description: "Bounded timeout; defaults to 120 seconds" })),
}, { additionalProperties: false });

const VaultItemsParameters = Type.Object({
	action: StringEnum(["status", "list", "search", "inspect"] as const, { description: "Safe Metadata operation" }),
	query: Type.Optional(Type.String({ minLength: 1, maxLength: 256, description: "Native Bitwarden search text; never echoed in results" })),
	cursor: Type.Optional(Type.String({ minLength: 1, maxLength: 256, description: "Opaque continuation cursor from a prior list/search result" })),
	itemHandle: Type.Optional(Type.String({ minLength: 1, maxLength: 256, description: "Opaque item handle from a prior list/search result" })),
	limit: Type.Optional(Type.Integer({ minimum: 1, maximum: 100, description: "Page size, at most 100" })),
}, { additionalProperties: false });

const VaultSshRunParameters = Type.Object({
	host: Type.Optional(Type.String({ minLength: 1, maxLength: 512, description: "Explicit non-secret remote SSH host" })),
	hostHandle: Type.Optional(Type.String({ minLength: 1, maxLength: 256, description: "Opaque material handle for host" })),
	username: Type.Optional(Type.String({ minLength: 1, maxLength: 128, description: "Remote username; defaults to root" })),
	port: Type.Optional(Type.Integer({ minimum: 1, maximum: 65535, description: "SSH port; defaults to 22" })),
	privateKeyHandle: Type.String({ minLength: 1, maxLength: 256, description: "Opaque handle for SSH private key" }),
	passphraseHandle: Type.Optional(Type.String({ minLength: 1, maxLength: 256, description: "Opaque handle for private key passphrase" })),
	command: Type.String({ minLength: 1, maxLength: 4_096, description: "Remote command to execute" }),
	stdinHandle: Type.Optional(Type.String({ minLength: 1, maxLength: 256, description: "Opaque material handle for optional remote stdin" })),
	timeoutMs: Type.Optional(Type.Integer({ minimum: 1, maximum: 900_000, description: "Bounded timeout; defaults to 120 seconds" })),
}, { additionalProperties: false });

const labelFor = (state: VaultStatus) => `Vault: ${state}`;
const safeErrors = new Set(["invalid_server", "invalid_email", "invalid_password", "invalid_credentials", "network_error", "keychain_unavailable", "cli_unavailable", "cli_error", "cli_state", "invalid_cli_json", "config_recovery", "output_overflow", "invalid_input", "invalid_action", "invalid_cursor", "invalid_handle", "vault_not_unlocked", "invalid_item_data", "over_limit", "duplicate_handle", "wrong_item", "material_incompatible", "material_unavailable", "run_failed", "cleanup_partial", "cancelled", "ui_unavailable", "internal_error", "host_key_changed", "auth_failed", "timed_out", "host_key_unavailable"]);

type VaultDetails = {
	action: VaultItemsInput["action"] | "run" | "sshRun";
	state?: VaultStatus; serverHost?: string; error?: string; cancelled?: boolean;
	items?: unknown[]; nextCursor?: string; materials?: unknown[]; attachments?: unknown[]; itemHandle?: string; type?: string;
	count?: number;
	mode?: string; exitCode?: number | null; signal?: string | null; durationMs?: number;
	timedOut?: boolean; stdoutBytes?: number; stderrBytes?: number; stdout?: string; stderr?: string;
	// SSH-specific display fields (non-secret)
	host?: string; username?: string; port?: number; command?: string;
};
type WizardResult = SetupInput | null;

type CommandContext = Pick<ExtensionContext, "mode" | "hasUI" | "ui">;

function lifecycleRequiresTui(ctx: CommandContext): boolean {
	if (ctx.mode === "tui" && ctx.hasUI) return true;
	ctx.ui.notify("This Vault lifecycle action requires the Pi TUI.", "error");
	return false;
}

function safeError(error: unknown): string {
	const code = error instanceof BrokerRequestError ? error.code : (error && typeof (error as { code?: unknown }).code === "string" ? (error as { code: string }).code : "internal_error");
	return safeErrors.has(code) ? code : "internal_error";
}

function resultFor(details: VaultDetails, text: string, modelValue?: unknown) {
	return { content: [{ type: "text" as const, text: modelValue === undefined ? text : JSON.stringify(modelValue) }], details };
}

function wizard(ctx: ExtensionContext, signal?: AbortSignal): Promise<WizardResult> {
	let removeAbort = () => {};
	const pending = ctx.ui.custom<WizardResult>((tui, theme, _keybindings, done) => {
		let step: "region" | "server" | "email" | "password" = "region";
		let region = 0;
		let serverValue = "";
		let emailValue = "";
		let finished = false;
		let error = "";
		const serverInput = new Input();
		const emailInput = new Input();
		const passwordInput = new Input();
		const regions = [
			{ label: "US cloud", value: US_SERVER },
			{ label: "EU cloud", value: EU_SERVER },
			{ label: "Custom HTTPS server", value: "custom" },
		];
		const close = (value: WizardResult) => { if (!finished) { finished = true; passwordInput.setValue(""); serverInput.setValue(""); emailInput.setValue(""); done(value); } };
		const refresh = () => tui.requestRender();
		const currentInput = () => step === "server" ? serverInput : step === "email" ? emailInput : passwordInput;
		const next = () => { error = ""; if (step === "region") { if (regions[region]?.value === "custom") step = "server"; else { serverValue = regions[region]!.value; step = "email"; } } else if (step === "server") { try { serverValue = normalizeServer(serverInput.getValue()).url; step = "email"; } catch { error = "invalid_server"; } } else if (step === "email") { try { emailValue = normalizeEmail(emailInput.getValue()); step = "password"; } catch { error = "invalid_email"; } } else { try { validateMasterPassword(passwordInput.getValue()); close({ server: serverValue, email: emailValue, masterPassword: passwordInput.getValue() }); return; } catch { error = "invalid_password"; } } refresh(); };
		serverInput.onSubmit = next;
		emailInput.onSubmit = next;
		passwordInput.onSubmit = next;
		const onAbort = () => close(null);
		signal?.addEventListener("abort", onAbort, { once: true });
		removeAbort = () => signal?.removeEventListener("abort", onAbort);
		const component = {
			render(width: number): string[] {
				const lines: string[] = [];
				const w = Math.max(1, width);
				const add = (text: string) => lines.push(...wrapTextWithAnsi(text, w));
				lines.push(theme.fg("accent", "─".repeat(w)), theme.fg("accent", theme.bold("Bitwarden setup")), "");
				if (step === "region") {
					add("Choose the Bitwarden server:");
					regions.forEach((item, index) => lines.push(theme.fg(index === region ? "accent" : "text", `${index === region ? ">" : " "} ${item.label}`)));
				} else if (step === "server") {
					add("Enter a custom HTTPS server URL (no path, query, or credentials):");
					lines.push(`> ${truncateToWidth(serverInput.render(Math.max(1, w - 2))[0] ?? "", Math.max(1, w - 2), "")}`);
				} else if (step === "email") {
					add("Enter your Bitwarden email address:");
					lines.push(`> ${truncateToWidth(emailInput.render(Math.max(1, w - 2))[0] ?? "", Math.max(1, w - 2), "")}`);
				} else {
					add("Enter your Bitwarden master password:");
					// Never call passwordInput.render(): it would place the raw value in a renderer.
					lines.push(`> ${"•".repeat(Math.min(passwordInput.getValue().length, Math.max(0, w - 2)))}`);
				}
				if (error) lines.push("", theme.fg("error", error === "invalid_server" ? "Invalid HTTPS server." : error === "invalid_email" ? "Invalid email address." : "Invalid master password."));
				lines.push("", theme.fg("dim", "Enter to continue • Esc to cancel"), theme.fg("accent", "─".repeat(w)));
				return lines;
			},
			invalidate() {},
			handleInput(data: string) {
				if (matchesKey(data, Key.escape)) { close(null); return; }
				if (step === "region") {
					if (matchesKey(data, Key.up)) region = Math.max(0, region - 1);
					else if (matchesKey(data, Key.down)) region = Math.min(regions.length - 1, region + 1);
					else if (matchesKey(data, Key.enter)) next();
				} else currentInput().handleInput(data);
				refresh();
			},
		};
		return component;
	});
	return pending.finally(removeAbort);
}

async function performVaultRequest(client: VaultBrokerClient, ctx: ExtensionContext, signal?: AbortSignal): Promise<ReturnType<typeof resultFor>> {
	let state: VaultStatus | undefined;
	try { state = await client.status(signal); }
	catch (error) {
		if (error instanceof DOMException && error.name === "AbortError") return resultFor({ action: "status", error: "cancelled" }, "Vault request cancelled.");
		if (safeError(error) !== "invalid_credentials") return resultFor({ action: "status", error: safeError(error) }, "Vault Broker request failed.");
	}
	if (state === "unlocked") return resultFor({ action: "status", state }, `Vault Broker status: ${state}`);
	// Real Pi always supplies mode. The compatibility branch keeps the T1 unit
	// harness's status-only fake UI from accidentally trying to open a wizard.
	if (ctx.mode !== "tui" && !(ctx.mode === undefined && typeof ctx.ui.custom !== "function")) return resultFor({ action: "status", state, error: "ui_unavailable" }, "Vault setup requires TUI mode.");
	if (ctx.mode === undefined && typeof ctx.ui.custom !== "function") return resultFor({ action: "status", state }, `Vault Broker status: ${state ?? "unconfigured"}`);
	const input = await wizard(ctx, signal);
	if (!input) return resultFor({ action: "status", state, error: "cancelled", cancelled: true }, "Vault setup cancelled.");
	try {
		const setup = await client.setup(input, signal);
		input.masterPassword = "";
		return resultFor({ action: "status", state: setup.state, serverHost: setup.serverHost }, `Vault setup complete for ${setup.serverHost}.`);
	} catch (error) {
		input.masterPassword = "";
		return resultFor({ action: "status", state, error: safeError(error) }, "Vault setup failed.");
	}
}

function itemErrorAction(value: unknown): VaultItemsInput["action"] {
	return value === "list" || value === "search" || value === "inspect" || value === "status" ? value : "status";
}

async function performItemsRequest(client: VaultBrokerClient, params: unknown, signal?: AbortSignal): Promise<ReturnType<typeof resultFor>> {
	let input: VaultItemsInput;
	try { input = validateItemsInput(params) as VaultItemsInput; }
	catch (error) {
		const code = error instanceof VaultContentError ? error.code : "invalid_input";
		return resultFor({ action: itemErrorAction((params as { action?: unknown })?.action), error: safeErrors.has(code) ? code : "invalid_input" }, "Vault request failed.");
	}
	try {
		const result = await client.items(input, signal) as VaultItemsResult;
		if (result.state !== "unlocked") return resultFor({ action: result.action, state: result.state }, `Vault Broker status: ${result.state}`);
		if (result.action === "list" || result.action === "search") {
			const modelValue = { action: result.action, items: result.items, ...(result.nextCursor === undefined ? {} : { nextCursor: result.nextCursor }) };
			return resultFor({ action: result.action, state: result.state, items: result.items, nextCursor: result.nextCursor, count: result.items.length }, `${result.action === "search" ? "Search" : "List"} returned ${result.items.length} Safe Metadata summaries.`, modelValue);
		}
		if (result.action === "inspect") {
			const modelValue = { action: result.action, itemHandle: result.itemHandle, type: result.type, materials: result.materials, attachments: result.attachments };
			return resultFor({ action: result.action, state: result.state, itemHandle: result.itemHandle, type: result.type, materials: result.materials, attachments: result.attachments, count: result.materials.length + result.attachments.length }, `Inspection returned ${result.materials.length} material descriptors and ${result.attachments.length} attachment descriptors.`, modelValue);
		}
		return resultFor({ action: "status", state: result.state }, `Vault Broker status: ${result.state}`);
	} catch (error) {
		if (error instanceof DOMException && error.name === "AbortError") return resultFor({ action: input.action, error: "cancelled", cancelled: true }, "Vault request cancelled.");
		return resultFor({ action: input.action, error: safeError(error) }, "Vault request failed.");
	}
}

async function performVaultRunRequest(client: VaultBrokerClient, params: unknown, signal?: AbortSignal): Promise<ReturnType<typeof resultFor>> {
	let input: VaultRunInput;
	try { input = validateVaultRunInput(params) as VaultRunInput; }
	catch (error) {
		const code = error instanceof VaultRunError ? error.code : "invalid_input";
		return resultFor({ action: "run", error: safeErrors.has(code) ? code : "invalid_input" }, "Vault run rejected before execution.");
	}
	try {
		const result = await client.run(input, signal);
		return resultFor({ action: "run", ...result }, "Vault run complete.", { action: "run", ...result });
	} catch (error) {
		if (error instanceof DOMException && error.name === "AbortError") return resultFor({ action: "run", error: "cancelled", cancelled: true }, "Vault run cancelled.");
		return resultFor({ action: "run", error: safeError(error) }, "Vault run failed.");
	}
}

async function performVaultSshRunRequest(client: VaultBrokerClient, params: unknown, signal?: AbortSignal): Promise<ReturnType<typeof resultFor>> {
	let input: VaultSshRunInput;
	try { input = validateVaultSshInput(params) as VaultSshRunInput; }
	catch (error) {
		const code = error instanceof SshError ? error.code : "invalid_input";
		return resultFor({ action: "sshRun", error: safeErrors.has(code) ? code : "invalid_input" }, "SSH run rejected before execution.");
	}
	try {
		const result = await client.sshRun(input, signal);
		return resultFor({
			action: "sshRun", host: input.host, username: input.username, port: input.port, command: input.command, ...result,
		}, "SSH run complete.", { action: "sshRun", ...result });
	} catch (error) {
		if (error instanceof DOMException && error.name === "AbortError") return resultFor({ action: "sshRun", error: "cancelled", cancelled: true }, "SSH run cancelled.");
		return resultFor({ action: "sshRun", error: safeError(error) }, "SSH run failed.");
	}
}

function displayValue(value: unknown): string {
	const encoded = JSON.stringify(value);
	return encoded === undefined ? String(value) : encoded;
}

function detailLine(theme: Theme, label: string, value: unknown): string {
	return theme.fg("muted", `  ${label}: ${displayValue(value)}`);
}

function compactHint(theme: Theme): string { return theme.fg("dim", "  Ctrl+O to expand"); }

function quotedLabel(value: unknown): string {
	return JSON.stringify(typeof value === "string" ? value : String(value ?? ""));
}

function vaultItemsInvocation(args: Partial<VaultItemsInput> | undefined): string {
	switch (args?.action) {
		case "search": return `vault_search: ${quotedLabel(args.query)}`;
		case "inspect": return `vault_inspect: ${quotedLabel(args.itemHandle)}`;
		case "list": return "vault_list";
		case "status": return "vault_status";
		default: return "vault_items";
	}
}

function shellDisplayWord(value: unknown): string {
	const text = String(value ?? "");
	if (/^[A-Za-z0-9_@%+=:,./-]+$/u.test(text)) return text;
	return `'${text.replaceAll("'", `'"'"'`)}'`;
}

function vaultRunCommand(args: Partial<VaultRunInput>): string {
	const words: string[] = [];
	for (const [name, value] of Object.entries(args.env ?? {})) words.push(`${name}=${shellDisplayWord(value)}`);
	for (const name of Object.keys(args.materialEnv ?? {})) words.push(`${name}=\${${name}}`);
	words.push(shellDisplayWord(args.executable));
	for (const arg of args.argv ?? []) words.push(shellDisplayWord(arg));
	let command = words.join(" ");
	if (args.cwd !== undefined) command = `cd ${shellDisplayWord(args.cwd)} && ${command}`;
	if (args.stdin !== undefined) command += " < ${VAULT_STDIN}";
	return command;
}

function runOutput(details: VaultDetails, theme: Theme): string {
	if (details.mode === "bulk") return theme.fg("muted", "(protected output withheld)");
	const sections: string[] = [];
	if (details.stdout) sections.push(details.stdout.split("\n").map((line) => theme.fg("toolOutput", line)).join("\n"));
	if (details.stderr) sections.push(details.stderr.split("\n").map((line) => theme.fg("warning", line)).join("\n"));
	return sections.join("\n");
}

function runFooter(details: VaultDetails, theme: Theme): string {
	const parts: string[] = [];
	if (details.timedOut) parts.push("timed out");
	else if (details.cancelled) parts.push("cancelled");
	else if (details.signal) parts.push(`signal ${details.signal}`);
	else if (details.exitCode !== 0 && details.exitCode != null) parts.push(`exit ${details.exitCode}`);
	if (details.durationMs !== undefined) parts.push(`Took ${(details.durationMs / 1_000).toFixed(1)}s`);
	return parts.length === 0 ? "" : theme.fg(parts[0]?.startsWith("Took") ? "muted" : "warning", parts.join(" · "));
}

function collapsedRunResult(details: VaultDetails, theme: Theme) {
	let cachedWidth: number | undefined;
	let cachedLines: string[] | undefined;
	return {
		render(width: number): string[] {
			const safeWidth = Math.max(1, width);
			if (cachedLines !== undefined && cachedWidth === safeWidth) return cachedLines;
			const output = runOutput(details, theme);
			const allOutputLines = output ? wrapTextWithAnsi(output, safeWidth) : [];
			const shown = allOutputLines.slice(-5);
			const hidden = allOutputLines.length - shown.length;
			const lines: string[] = [];
			if (output) {
				lines.push("");
				if (hidden > 0) lines.push(truncateToWidth(theme.fg("muted", `... (${hidden} earlier lines, Ctrl+O to expand)`), safeWidth));
				lines.push(...shown);
			} else if (details.mode !== "bulk") {
				lines.push("", theme.fg("muted", "(no output)"));
			}
			const footer = runFooter(details, theme);
			if (footer) lines.push("", truncateToWidth(footer, safeWidth));
			cachedWidth = safeWidth;
			cachedLines = lines;
			return lines;
		},
		invalidate() { cachedWidth = undefined; cachedLines = undefined; },
	};
}

function expandedRunResult(details: VaultDetails, theme: Theme): Text {
	const lines: string[] = [];
	const output = runOutput(details, theme);
	if (output) lines.push("", output);
	else if (details.mode !== "bulk") lines.push("", theme.fg("muted", "(no output)"));
	const footer = runFooter(details, theme);
	if (footer) lines.push("", footer);
	return new Text(lines.join("\n"), 0, 0);
}

function completeRunResult(details: VaultDetails, theme: Theme, title: string): Text {
	const lines = [theme.fg("success", title)];
	for (const key of ["mode", "exitCode", "signal", "durationMs", "timedOut", "cancelled", "stdoutBytes", "stderrBytes"] as const) lines.push(detailLine(theme, key, details[key]));
	if (details.mode !== "bulk") {
		lines.push(theme.fg("toolTitle", "  Sanitized stdout:"), theme.fg("toolOutput", details.stdout ?? ""));
		lines.push(theme.fg("toolTitle", "  Sanitized stderr:"), theme.fg("warning", details.stderr ?? ""));
	}
	return new Text(lines.join("\n"), 0, 0);
}

export type VaultExtensionDependencies = { client?: VaultBrokerClient };

export function registerVaultExtension(pi: ExtensionAPI, dependencies: VaultExtensionDependencies = {}): void {
	const client = dependencies.client ?? new VaultBrokerClient();
	const setVisibleStatus = (ctx: { ui: { setStatus(key: string, value: string | undefined): void } }, state: VaultStatus) => ctx.ui.setStatus("vault_items", labelFor(state));
	pi.registerTool({
		name: "vault_items",
		label: "Vault Items",
		description: "Use one strictly validated surface to read Safe Metadata: status, 100-item list pages, native Bitwarden search, or inspect descriptors. Results contain only opaque lease-scoped handles, type, favorite, title, folder name, normalized web origins, labels/types, attachment filename/MIME/size, delivery support, and counts—never Vault Material, durable Bitwarden UUIDs, full URI paths/queries/fragments, usernames, values, notes, TOTP data, keys, or attachment bytes. Native search delegates to `bw list items --search`; Bitwarden may match hidden values, so search is an accepted membership oracle under the cooperative-agent model. Cursors and handles expire with the Vault Session and are invalid after lock, logout, profile replacement, or lease expiry. Bitwarden's non-paginated list response is captured in a finite 8 MiB private buffer; larger or incomplete output fails closed with output_overflow rather than using partial JSON.",
		promptSnippet: "Discover Bitwarden Safe Metadata or inspect non-secret material descriptors",
		promptGuidelines: ["Use vault_items with action status, list, search, or inspect; use only opaque handles and cursors returned by vault_items.", "vault_items never returns master passwords, Vault Sessions, or Vault Material; native search may disclose hidden-value membership as documented."],
		parameters: VaultItemsParameters,
		async execute(_toolCallId, params, signal, _onUpdate, ctx) {
			const result = params.action === "status" ? await performVaultRequest(client, ctx, signal) : await performItemsRequest(client, params, signal);
			if (result.details.state) setVisibleStatus(ctx, result.details.state);
			return result;
		},
		renderCall(args, theme, context) {
			// Once a result exists, renderResult owns the complete one-line preview so
			// the operation reads like a native tool instead of two stacked labels.
			if (context.isPartial === false) return new Container();
			const title = theme.fg("toolTitle", theme.bold(vaultItemsInvocation(args)));
			if (!context.expanded) return new Text(title, 0, 0);
			const lines = [title];
			for (const key of ["cursor", "limit"] as const) if (args[key] !== undefined) lines.push(detailLine(theme, key, args[key]));
			return new Text(lines.join("\n"), 0, 0);
		},
		renderResult(result, options, theme, context) {
			const details = result.details as VaultDetails | undefined;
			if (!details) return new Text("", 0, 0);
			const args = context?.args as Partial<VaultItemsInput> | undefined;
			const invocation = vaultItemsInvocation(args ?? { action: details.action as VaultItemsInput["action"], itemHandle: details.itemHandle });
			if (details.error) return new Text(theme.fg(details.error === "cancelled" ? "warning" : "error", `${invocation} - ${details.cancelled ? "cancelled" : `failed (${details.error})`}`), 0, 0);
			if (details.action === "list" || details.action === "search") {
				const count = details.count ?? 0;
				const title = theme.fg("toolTitle", `${invocation} - ${count} ${count === 1 ? "result" : "results"}`);
				if (!options.expanded) return new Text(title + compactHint(theme), 0, 0);
				const lines = [title];
				if (args?.cursor !== undefined) lines.push(detailLine(theme, "cursor", args.cursor));
				if (args?.limit !== undefined) lines.push(detailLine(theme, "limit", args.limit));
				if (details.nextCursor !== undefined) lines.push(detailLine(theme, "next cursor", details.nextCursor));
				for (const [index, item] of ((details.items ?? []) as Array<Record<string, unknown>>).entries()) {
					lines.push(theme.fg("toolTitle", `  ${index + 1}. ${String(item.title ?? "Untitled")}`));
					for (const key of ["handle", "type", "favorite", "folderName", "normalizedOrigins", "materialCount", "attachmentCount"]) {
						lines.push(detailLine(theme, key, item[key]));
					}
				}
				return new Text(lines.join("\n"), 0, 0);
			}
			if (details.action === "inspect") {
				const count = details.count ?? 0;
				const title = theme.fg("toolTitle", `${invocation} - ${count} ${count === 1 ? "descriptor" : "descriptors"}`);
				if (!options.expanded) return new Text(title + compactHint(theme), 0, 0);
				const lines = [title, detailLine(theme, "item handle", details.itemHandle), detailLine(theme, "type", details.type)];
				for (const [group, descriptors] of [["materials", details.materials ?? []], ["attachments", details.attachments ?? []]] as const) {
					lines.push(theme.fg("toolTitle", `  ${group}`));
					for (const [index, descriptor] of (descriptors as Array<Record<string, unknown>>).entries()) {
						lines.push(theme.fg("muted", `    ${index + 1}.`));
						for (const [key, value] of Object.entries(descriptor)) lines.push(detailLine(theme, key, value));
					}
				}
				return new Text(lines.join("\n"), 0, 0);
			}
			const title = theme.fg("toolTitle", `${invocation} - ${details.state ?? "unknown"}`);
			if (!options.expanded) return new Text(title, 0, 0);
			const lines = [title];
			for (const key of ["state", "serverHost", "cancelled"] as const) if (details[key] !== undefined) lines.push(detailLine(theme, key, details[key]));
			return new Text(lines.join("\n"), 0, 0);
		},
	});
	pi.registerTool({
		name: "vault_run",
		label: "Vault Run",
		description: "Run one executable directly with selected Vault Material delivered only through validated environment mappings or at most one stdin handle. Accepts no material values, uses a minimal environment, requires no confirmation, withholds text output until completion and redacts selected material encodings; attachment, bulk, and binary stdin return execution metadata only.",
		promptSnippet: "Run a local executable with opaque Vault Material handles",
		promptGuidelines: ["Use only executable, argv, optional cwd, explicit non-secret env overrides, materialEnv mappings to opaque handles from vault_items, one optional stdin handle, and a bounded timeout.", "vault_run never returns Vault Material; do not put material values in any argument or environment override."],
		parameters: VaultRunParameters,
		async execute(_toolCallId, params, signal) { return performVaultRunRequest(client, params, signal); },
		renderCall(args, theme, _context) {
			const command = vaultRunCommand(args);
			const timeout = args.timeoutMs === undefined ? "" : theme.fg("muted", ` (timeout ${args.timeoutMs}ms)`);
			return new Text(theme.fg("toolTitle", theme.bold(`vault_run - ${command}`)) + timeout, 0, 0);
		},
		renderResult(result, options, theme, _context) {
			const details = result.details as VaultDetails | undefined;
			if (!details) return new Text("", 0, 0);
			if (details.error) return new Text(theme.fg(details.error === "cancelled" ? "warning" : "error", details.cancelled ? "Command cancelled" : `Command failed (${details.error})`), 0, 0);
			return options.expanded ? expandedRunResult(details, theme) : collapsedRunResult(details, theme);
		},
	});
	pi.registerTool({
		name: "vault_ssh_run",
		label: "Vault SSH Run",
		description: "Run one remote command via native SSH using Bitwarden-held SSH key material. Accepts exactly one explicit non-secret host or opaque hostHandle, bounded username, optional port, one private-key handle, optional private-key-passphrase handle, one bounded remote command string, optional stdin material handle, and bounded timeout. Fixed SSH roles (host, key, passphrase, stdin) may reference different vault items but must have compatible descriptor types. Private key and passphrase remain memory-only; selected material and common encodings are redacted from output. The in-process ssh2 hostVerifier checks keyed, atomically persisted trust before authentication. Unknown host keys are accepted on first use; changed keys fail closed with an actionable non-secret error.",
		promptSnippet: "Run a remote SSH command using Bitwarden-held credentials with in-process SSH—no system ssh, shell, or agent",
		promptGuidelines: [
			"Use vault_ssh_run with exactly one host (explicit string) or hostHandle (opaque handle), optional username (defaults to root), optional port (defaults to 22), one privateKeyHandle, optional passphraseHandle, one command string, optional stdinHandle, and optional timeoutMs.",
			"Fixed SSH roles may reference different vault items but handles must have compatible descriptor types/delivery; wrong-kind, duplicate, stale, or NUL-bearing host handles fail before connection.",
			"vault_ssh_run performs SSH natively in-process—no system ssh, shell, agent socket, decrypted key/config/known-host temporary file, or implicit interactive prompt.",
			"Private key and passphrase remain memory-only for authentication; optional stdin is streamed to the remote command with backpressure. Unknown host keys are accepted on first use; changed keys fail closed.",
		],
		parameters: VaultSshRunParameters,
		async execute(_toolCallId, params, signal) { return performVaultSshRunRequest(client, params, signal); },
		renderCall(args, theme, context) {
			const title = theme.fg("toolTitle", theme.bold("vault_ssh_run"));
			const compactHost = args.host === undefined ? " hostHandle" : ` ${String(args.host)}`;
			if (!context.expanded) return new Text(title + theme.fg("muted", compactHost) + compactHint(theme), 0, 0);
			const lines = [title];
			for (const key of ["host", "hostHandle", "username", "port", "privateKeyHandle", "passphraseHandle", "command", "stdinHandle", "timeoutMs"] as const) {
				if (args[key] !== undefined) lines.push(detailLine(theme, key, args[key]));
			}
			return new Text(lines.join("\n"), 0, 0);
		},
		renderResult(result, options, theme, _context) {
			const details = result.details as VaultDetails | undefined;
			if (!details) return new Text("", 0, 0);
			if (details.error) {
				const messages: Record<string, string> = {
					host_key_changed: "Host key changed—connection rejected",
					auth_failed: "SSH authentication failed",
					timed_out: "SSH deadline expired",
					cancelled: "Cancelled",
				};
				return new Text(theme.fg(details.error === "cancelled" ? "warning" : "error", messages[details.error] ?? `SSH run failed (${details.error})`), 0, 0);
			}
			if (!options.expanded) return new Text(theme.fg("success", `SSH: ${details.exitCode ?? "signal"}`) + compactHint(theme), 0, 0);
			return completeRunResult(details, theme, "SSH run");
		},
	});
	pi.registerCommand("vault-status", {
		description: "Show the shared Vault Broker status",
		handler: async (_args, ctx) => {
			const result = await performVaultRequest(client, ctx);
			if (result.details.state) setVisibleStatus(ctx, result.details.state);
			ctx.ui.notify(result.details.error ? (result.details.cancelled ? "Vault setup cancelled." : "Vault Broker request failed.") : `Vault Broker: ${result.details.state}`, result.details.error ? "error" : "info");
		},
	});
	pi.registerCommand("vault-lock", {
		description: "Lock the shared Vault Session without deleting the stored credential or profile",
		handler: async (_args, ctx) => {
			if (!lifecycleRequiresTui(ctx)) return;
			try {
				const state = await client.lock(ctx.signal);
				setVisibleStatus(ctx, state);
				ctx.ui.notify("Vault locked; stored credential and profile retained.", "info");
			} catch (error) { ctx.ui.notify(`Vault lock failed (${safeError(error)}).`, "error"); }
		},
	});
	pi.registerCommand("vault-config", {
		description: "Replace the Bitwarden server and account using the local masked wizard",
		handler: async (_args, ctx) => {
			if (!lifecycleRequiresTui(ctx)) return;
			const input = await wizard(ctx, ctx.signal);
			if (!input) { ctx.ui.notify("Vault configuration cancelled.", "info"); return; }
			try {
				const result = await client.config(input, ctx.signal);
				setVisibleStatus(ctx, result.state);
				ctx.ui.notify(`Vault configuration replaced for ${result.serverHost}.`, "info");
			} catch (error) {
				const code = safeError(error);
				ctx.ui.notify(code === "config_recovery"
					? "Vault configuration may have completed; retry /vault-config to confirm."
					: `Vault configuration failed (${code}).`, code === "config_recovery" ? "warning" : "error");
			}
			finally { input.masterPassword = ""; }
		},
	});
	pi.registerCommand("vault-forget", {
		description: "After TUI confirmation, log out and remove the dedicated Vault profile and credential",
		handler: async (_args, ctx) => {
			if (!lifecycleRequiresTui(ctx)) return;
			const confirmed = await ctx.ui.confirm("Forget Bitwarden profile?", "This logs out where possible and deletes the dedicated Keychain credential and CLI profile.");
			if (!confirmed) { ctx.ui.notify("Vault forget cancelled.", "info"); return; }
			try {
				const result = await client.forget(ctx.signal);
				ctx.ui.setStatus("vault_items", "Vault: unconfigured");
				ctx.ui.notify(result.cleanup === "complete" ? "Vault profile and credential forgotten." : "Vault forgotten with partial cleanup; inspect the dedicated fixture/profile if recovery is needed.", result.cleanup === "complete" ? "info" : "warning");
			} catch (error) { ctx.ui.notify(`Vault forget failed (${safeError(error)}).`, "error"); }
		},
	});
	pi.on("tool_call", async (event) => {
		// Only agent-facing shell tools are guarded. Broker-owned bw children are
		// spawned below the extension IPC boundary and never emit this event.
		if (event.toolName !== "bash") return;
		const command = (event.input as { command?: unknown })?.command;
		const reason = bitwardenGuardReason(command);
		if (reason) return { block: true, reason };
	});
	pi.on("session_start", (_event, ctx) => { if (ctx.hasUI) ctx.ui.setStatus("vault_items", "Vault: not checked"); });
	pi.on("session_shutdown", (_event, ctx) => { if (ctx.hasUI) ctx.ui.setStatus("vault_items", undefined); });
}

export default function vaultExtension(pi: ExtensionAPI): void { registerVaultExtension(pi); }
