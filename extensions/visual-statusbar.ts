import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { truncateToWidth, visibleWidth } from "@earendil-works/pi-tui";

type LimitUsage = {
	primary?: number;
	secondary?: number;
};

const RESET = "\x1b[0m";
const color = (hex: string, text: string) => `\x1b[38;2;${hexToRgb(hex)}m${text}${RESET}`;
const hexToRgb = (hex: string) => {
	const value = Number.parseInt(hex.slice(1), 16);
	return `${(value >> 16) & 255};${(value >> 8) & 255};${value & 255}`;
};

// Soft colors stay readable on a dark terminal without turning the footer into a rainbow.
const pastel = {
	muted: "#94a3b8",
	provider: "#c4b5fd",
	model: "#93c5fd",
	thinking: "#f9a8d4",
	context: "#a7f3d0",
	limit: "#fcd34d",
	empty: "#475569",
	text: "#e2e8f0",
};

function providerLabel(provider: string | undefined): string {
	if (!provider) return "No provider";
	if (provider === "openai-codex") return "Codex";
	if (provider.startsWith("llama-cpp")) return "Local";
	if (provider.toLowerCase().startsWith("deepseek")) return "Deepseek";
	return provider.replace(/[-_]/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function modelLabel(modelId: string | undefined): string {
	if (!modelId) return "No model";
	const qwen = modelId.match(/qwen\d+(?:\.\d+)?-\d+b/i)?.[0];
	if (qwen) return qwen.replace(/^q/, "Q");
	return modelId.replace(/^gpt-/i, "").replace(/^deepseek-/i, "").replace(/\.gguf$/i, "");
}

function contextWindowLabel(tokens: number): string {
	if (tokens >= 1_000_000) return `${(tokens / 1_000_000).toFixed(tokens % 1_000_000 ? 1 : 0)}M`;
	if (tokens >= 1_000) return `${Math.round(tokens / 1_000)}k`;
	return `${tokens}`;
}

function percentage(value: number | null | undefined): string {
	return value === null || value === undefined ? "?%" : `${Math.round(Math.max(0, Math.min(100, value)))}%`;
}

/** A compact, thin meter with its label physically centered inside the bar. */
function meter(value: number | null | undefined, width: number, fill: string, suffix = "", label = percentage(value)): string {
	const normalized = value === null || value === undefined ? 0 : Math.max(0, Math.min(100, value));
	const filled = Math.round((normalized / 100) * width);
	const meterLabel = `${label}${suffix}`;
	const chars = Array.from({ length: width }, (_, index) => (index < filled ? "━" : "─"));
	const start = Math.max(0, Math.floor((width - meterLabel.length) / 2));
	for (let index = 0; index < meterLabel.length && start + index < width; index++) chars[start + index] = meterLabel[index]!;

	return chars
		.map((character, index) => {
			if (index >= start && index < start + meterLabel.length) return color(pastel.text, character);
			return color(index < filled ? fill : pastel.empty, character);
		})
		.join("");
}

function fit(line: string, width: number): string {
	return truncateToWidth(line, width, color(pastel.muted, "…"));
}


function accountIdFromAccessToken(token: string): string | undefined {
	try {
		const payload = JSON.parse(Buffer.from(token.split(".")[1]!, "base64url").toString("utf8")) as {
			"https://api.openai.com/auth"?: { chatgpt_account_id?: string };
		};
		return payload["https://api.openai.com/auth"]?.chatgpt_account_id;
	} catch {
		return undefined;
	}
}

export default function (pi: ExtensionAPI) {
	let limits: LimitUsage = {};
	let requestRender: (() => void) | undefined;
	let refreshTimer: ReturnType<typeof setTimeout> | undefined;
	let usagePollAt = 0;
	let usagePollInFlight = false;
	let deepseekBalance: number | undefined;

	const refresh = () => {
		if (refreshTimer) return;
		refreshTimer = setTimeout(() => {
			refreshTimer = undefined;
			requestRender?.();
		}, 80);
	};

	const maybeFetchBalance = async (provider: string, baseUrl: string, apiKey: string, headers?: Record<string, string>) => {
		const h = new Headers(headers);
		h.set("Authorization", `Bearer ${apiKey}`);
		h.set("Accept", "application/json");
		const endpoint = `${baseUrl.replace(/\/+$/, "")}/user/balance`;
		const response = await fetch(endpoint, { headers: h, signal: AbortSignal.timeout(10_000) });
		if (!response.ok) return;
		const payload = (await response.json()) as {
			balance_infos?: Array<{ total_balance?: string }>;
		};
		const raw = payload.balance_infos?.[0]?.total_balance;
		const value = raw != null ? Number.parseFloat(raw) : NaN;
		if (Number.isFinite(value)) {
			if (provider === "deepseek") deepseekBalance = value;
		}
	};

	const refreshCodexUsage = async (ctx: ExtensionContext) => {
		const model = ctx.model;
		const provider = model?.provider;

		// Deepseek: fetch balance on first opportunity and after turns.
		if (provider === "deepseek" && model?.baseUrl && !usagePollInFlight && Date.now() - usagePollAt >= 60_000) {
			usagePollInFlight = true;
			usagePollAt = Date.now();
			try {
				const auth = await ctx.modelRegistry.getApiKeyAndHeaders(model);
				if (auth.ok && auth.apiKey) await maybeFetchBalance("deepseek", model.baseUrl, auth.apiKey, auth.headers);
			} catch { /* offline ok */ }
			finally { usagePollInFlight = false; }
			refresh();
		}

		if (provider !== "openai-codex" || usagePollInFlight || Date.now() - usagePollAt < 60_000) return;
		usagePollInFlight = true;
		usagePollAt = Date.now();
		try {
			const auth = await ctx.modelRegistry.getApiKeyAndHeaders(model);
			if (!auth.ok || !auth.apiKey) return;
			const accountId = accountIdFromAccessToken(auth.apiKey);
			if (!accountId) return;
			const headers = new Headers(auth.headers);
			headers.set("Authorization", `Bearer ${auth.apiKey}`);
			headers.set("ChatGPT-Account-Id", accountId);
			headers.set("Accept", "application/json");
			headers.set("originator", "pi");
			const endpoint = `${model.baseUrl.replace(/\/+$/, "")}/wham/usage`;
			const response = await fetch(endpoint, { headers, signal: AbortSignal.timeout(10_000) });
			if (!response.ok) return;
			const payload = (await response.json()) as {
				rate_limit?: {
					primary_window?: { used_percent?: number };
					secondary_window?: { used_percent?: number };
				};
			};
			const primary = payload.rate_limit?.primary_window?.used_percent;
			const secondary = payload.rate_limit?.secondary_window?.used_percent;
			limits = {
				primary: typeof primary === "number" && Number.isFinite(primary) ? primary : limits.primary,
				secondary: typeof secondary === "number" && Number.isFinite(secondary) ? secondary : limits.secondary,
			};
			refresh();
		} catch {
			// Quietly tolerate offline mode and non-subscription credentials.
		} finally {
			usagePollInFlight = false;
		}
	};

	pi.on("session_start", (_event, ctx) => {
		if (ctx.mode !== "tui") return;

		ctx.ui.setFooter((tui) => {
			requestRender = () => tui.requestRender();

			return {
				invalidate() {},
				dispose() {
					requestRender = undefined;
				},
				render(width: number): string[] {
					const model = ctx.model;
					const provider = model?.provider;
					const isCodex = provider === "openai-codex";
					const usage = ctx.getContextUsage();
					const cwd = ctx.sessionManager.getCwd();
					const contextPercent = usage?.percent;
					const contextWindow = usage?.contextWindow ?? model?.contextWindow ?? 0;

					const home = process.env.HOME;
					const displayCwd = home && (cwd === home || cwd.startsWith(`${home}/`)) ? `~${cwd.slice(home.length)}` : cwd;
					const identity = [
						color(pastel.provider, `● ${providerLabel(provider)}`),
						color(pastel.muted, "·"),
						color(pastel.model, modelLabel(model?.id)),
						color(pastel.muted, "·"),
						color(pastel.thinking, pi.getThinkingLevel()),
					].join(" ");
					const contextSuffix = contextWindow ? ` (${contextWindowLabel(contextWindow)})` : "";
					const context = `${color(pastel.muted, "ctx:")} ${meter(contextPercent, Math.min(22, Math.max(16, width - 42)), pastel.context, contextSuffix)}`;
					const isDeepseek = provider?.toLowerCase().startsWith("deepseek") ?? false;
					const status = isCodex
						? (() => {
							const usage = [
								color(pastel.muted, "5h:"),
								meter(limits.primary, Math.min(12, Math.max(8, width - 54)), pastel.limit),
								color(pastel.muted, "week:"),
								color(pastel.provider, percentage(limits.secondary)),
							].join(" ");
							return `${usage}   ${context}`;
						})()
						: isDeepseek
							? (() => {
								let cost = 0;
								for (const entry of ctx.sessionManager.getEntries()) {
									if (entry.type !== "message" || entry.message.role !== "assistant") continue;
									if (!entry.message.provider.toLowerCase().startsWith("deepseek")) continue;
									cost += entry.message.usage.cost.total;
								}
																const budgetLabel = (deepseekBalance ?? 0) > 0 ? deepseekBalance!.toFixed(2) : "?";
								const usage = `${color(pastel.muted, "$$")} ${color(pastel.model, cost.toFixed(2))} ${color(pastel.muted, "|")} ${color(pastel.model, budgetLabel)}`;
								return `${usage}   ${context}`;
							})()
							: context;

					// Two columns on one line: cwd left; model and live meters grouped on the right.
					const rightColumn = `${identity}   ${status}`;
					const directoryText = truncateToWidth(
						color(pastel.muted, displayCwd),
						Math.max(0, width - visibleWidth(rightColumn) - 2),
						color(pastel.muted, "…"),
					);
					return [
						fit(
							directoryText +
								" ".repeat(Math.max(2, width - visibleWidth(directoryText) - visibleWidth(rightColumn))) +
								rightColumn,
							width,
						),
					];
				},
			};
		});
		void refreshCodexUsage(ctx);
		refresh();
	});

	pi.on("after_provider_response", (event, ctx) => {
		if (ctx.model?.provider !== "openai-codex") return;
		const headers = Object.fromEntries(Object.entries(event.headers).map(([key, value]) => [key.toLowerCase(), value]));
		const parse = (name: string) => {
			const value = Number.parseFloat(headers[name] ?? "");
			return Number.isFinite(value) ? value : undefined;
		};
		// Codex currently uses x-codex-*, but newer model-specific limits add a
		// segment (for example x-codex-<limit>-primary-used-percent). Support both.
		const primaryHeader = Object.keys(headers).find((name) =>
			/^x-codex(?:-[a-z0-9]+)*-primary-used-percent$/.test(name),
		);
		const prefix = primaryHeader?.replace(/-primary-used-percent$/, "");
		limits = {
			primary: (primaryHeader ? parse(primaryHeader) : undefined) ?? limits.primary,
			secondary: (prefix ? parse(`${prefix}-secondary-used-percent`) : undefined) ?? limits.secondary,
		};
		void refreshCodexUsage(ctx);
		refresh();
	});

	pi.on("agent_settled", (_event, ctx) => {
		void refreshCodexUsage(ctx);
		refresh();
	});
	pi.on("message_update", refresh);
	pi.on("message_end", refresh);
	pi.on("model_select", (_event, ctx) => {
		void refreshCodexUsage(ctx);
		refresh();
	});
	pi.on("thinking_level_select", refresh);
	pi.on("session_shutdown", () => {
		if (refreshTimer) clearTimeout(refreshTimer);
		refreshTimer = undefined;
		requestRender = undefined;
	});
}
