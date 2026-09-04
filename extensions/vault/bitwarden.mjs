import { spawn as nodeSpawn } from "node:child_process";

// `bw list items` is not paginated. Capture a deliberately larger, still
// finite response so a small Safe Metadata item is not lost merely because
// another item's Vault Material makes the JSON exceed 256 KiB. A response
// beyond this bound is rejected as output_overflow; partial JSON is never
// parsed, logged, or returned across the broker boundary.
export const MAX_OUTPUT_BYTES = 8 * 1024 * 1024;
export const MAX_CHILD_MS = 30_000;
const STATES = new Set(["unauthenticated", "locked", "unlocked"]);

function childEnv(profilePath, password, session) {
	const env = {};
	for (const key of ["PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"]) {
		if (typeof process.env[key] === "string" && !/[\u0000-\u001f\u007f]/u.test(process.env[key])) env[key] = process.env[key];
	}
	if (env.PATH === undefined) env.PATH = "/usr/bin:/bin";
	if (env.HOME === undefined) env.HOME = process.env.HOME ?? "/tmp";
	env.BITWARDENCLI_APPDATA_DIR = profilePath;
	if (password !== undefined) env.BW_PASSWORD = password;
	if (session !== undefined) env.BW_SESSION = session;
	return env;
}

function collect(stream) {
	return new Promise((resolve) => {
		const chunks = [];
		let length = 0;
		let overflowed = false;
		const finish = () => resolve({ text: Buffer.concat(chunks).toString("utf8"), overflowed, truncated: overflowed });
		stream?.on("data", (chunk) => {
			const value = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
			if (length >= MAX_OUTPUT_BYTES) { overflowed = true; return; }
			const kept = value.subarray(0, MAX_OUTPUT_BYTES - length);
			if (kept.length !== value.length) overflowed = true;
			chunks.push(kept);
			length += kept.length;
		});
		stream?.on("end", finish);
		stream?.on("error", finish);
		if (!stream) finish();
	});
}

async function runChild(executable, args, options) {
	let child;
	try {
		child = nodeSpawn(executable, args, { env: options.env, shell: false, stdio: ["ignore", "pipe", "pipe"] });
	} catch {
		return { code: undefined, stdout: "", stderr: "", timedOut: false };
	}
	const stdoutPromise = collect(child.stdout);
	const stderrPromise = collect(child.stderr);
	let timedOut = false;
	const timer = setTimeout(() => {
		timedOut = true;
		child.kill("SIGKILL");
	}, MAX_CHILD_MS);
	timer.unref?.();
	const code = await new Promise((resolve) => {
		let settled = false;
		const finish = (value) => { if (!settled) { settled = true; resolve(value); } };
		child.once("error", () => finish(undefined));
		child.once("close", (exitCode) => finish(exitCode));
	});
	clearTimeout(timer);
	const [stdout, stderr] = await Promise.all([stdoutPromise, stderrPromise]);
	return {
		code,
		stdout: stdout.text,
		stderr: stderr.text,
		stdoutTruncated: stdout.truncated,
		stderrTruncated: stderr.truncated,
		stdoutOverflowed: stdout.overflowed,
		stderrOverflowed: stderr.overflowed,
		timedOut,
	};
}

function parseJsonOutput(output) {
	try { return JSON.parse(output.trim()); }
	catch { return undefined; }
}

function outputOverflow(result) {
	return Boolean(result?.stdoutOverflowed || result?.stderrOverflowed || result?.stdoutTruncated || result?.stderrTruncated);
}

function reauthenticationRequired(result) {
	const text = `${result?.stdout ?? ""}\n${result?.stderr ?? ""}`.toLowerCase();
	return /invalid[_ -]?grant|not (?:currently )?logged in|session (?:is )?(?:invalid|expired)|token (?:is )?(?:invalid|expired|revoked)/u.test(text);
}

function sessionFromOutput(output) {
	for (const line of output.split(/\r?\n/u)) {
		const match = line.match(/(?:export\s+)?BW_SESSION\s*=\s*["']([^"']+)["']/u) ??
			line.match(/(?:env:)?BW_SESSION\s*[:=]\s*["']?([^\s"']+)["']?/u);
		if (match?.[1] && /^[A-Za-z0-9+/=_-]{16,512}$/u.test(match[1])) return match[1];
	}
	const singleLine = output.trim();
	return /^[A-Za-z0-9+/=_-]{16,512}$/u.test(singleLine) ? singleLine : undefined;
}

export function parseStatusInfo(stdout) {
	try {
		const value = JSON.parse(stdout.trim());
		if (value && typeof value === "object" && STATES.has(value.status)) {
			return {
				state: value.status,
				serverUrl: typeof value.serverUrl === "string" ? value.serverUrl : undefined,
				userEmail: typeof value.userEmail === "string" ? value.userEmail : undefined,
			};
		}
	} catch { /* Never expose or diagnose CLI JSON. */ }
	return undefined;
}

export function parseStatus(stdout) {
	return parseStatusInfo(stdout)?.state;
}

export function classifyCliFailure(result) {
	if (result?.stdoutOverflowed || result?.stderrOverflowed || result?.stdoutTruncated || result?.stderrTruncated) return "output_overflow";
	if (result?.timedOut) return "network_error";
	const text = `${result?.stdout ?? ""}\n${result?.stderr ?? ""}`.toLowerCase();
	if (/invalid|incorrect|wrong|unauthori[sz]ed|authentication failed|master password/u.test(text)) return "invalid_credentials";
	if (/network|connect|timeout|timed out|dns|socket|econn|fetch|server|503|502|504/u.test(text)) return "network_error";
	if (result?.code === undefined) return "cli_unavailable";
	return "cli_error";
}

function boundedExecution(result = {}) {
	const bounded = (value) => {
		const text = typeof value === "string" ? value : "";
		const bytes = Buffer.from(text, "utf8");
		if (bytes.length <= MAX_OUTPUT_BYTES) return { text, overflowed: false };
		return { text: bytes.subarray(0, MAX_OUTPUT_BYTES).toString("utf8"), overflowed: true };
	};
	const stdout = bounded(result.stdout);
	const stderr = bounded(result.stderr);
	return {
		...result,
		stdout: stdout.text,
		stderr: stderr.text,
		stdoutOverflowed: Boolean(result.stdoutOverflowed || result.stdoutTruncated || stdout.overflowed),
		stderrOverflowed: Boolean(result.stderrOverflowed || result.stderrTruncated || stderr.overflowed),
	};
}

export function createBitwardenAdapter({ profilePath, executable = "bw", run, spawn = nodeSpawn } = {}) {
	if (typeof profilePath !== "string" || !profilePath) throw new TypeError("profilePath is required");
	const execute = run ?? ((args, options) => runChild(executable, args, options));
	const call = (args, { password, session } = {}) => Promise.resolve(execute(args, { env: childEnv(profilePath, password, session) })).then(boundedExecution);
	return {
		async status({ session } = {}) {
			const result = await call(["status", "--nointeraction"], { session });
			const info = parseStatusInfo(result.stdout);
			return {
				...result,
				state: info?.state,
				serverUrl: info?.serverUrl,
				userEmail: info?.userEmail,
				failure: result.code === 0 && info ? undefined : classifyCliFailure(result),
			};
		},
		async configure(server) {
			const result = await call(["config", "server", server, "--nointeraction"]);
			return { ...result, failure: result.code === 0 ? undefined : classifyCliFailure(result) };
		},
		async login(email, password) {
			const result = await call(["login", email, "--passwordenv", "BW_PASSWORD", "--nointeraction"], { password });
			return { ...result, session: sessionFromOutput(result.stdout), failure: result.code === 0 ? undefined : classifyCliFailure(result) };
		},
		async unlock(password) {
			// v2026.2.0 can return empty stdout for --raw in a non-TTY child. Parse
			// the normal private response instead, then discard all CLI output.
			const result = await call(["unlock", "--passwordenv", "BW_PASSWORD", "--nointeraction"], { password });
			return { ...result, session: sessionFromOutput(result.stdout), failure: result.code === 0 ? undefined : classifyCliFailure(result) };
		},
		async lock(session) {
			const result = await call(["lock", "--nointeraction"], { session });
			return { ...result, failure: result.code === 0 ? undefined : classifyCliFailure(result) };
		},
		async logout(session) {
			const result = await call(["logout", "--nointeraction"], { session });
			return { ...result, failure: result.code === 0 ? undefined : classifyCliFailure(result) };
		},
		async sync({ session } = {}) {
			const result = await call(["sync", "--nointeraction"], { session });
			return {
				...result,
				failure: result.code === 0 ? undefined : classifyCliFailure(result),
				reauthenticationRequired: result.code !== 0 && reauthenticationRequired(result),
			};
		},
		async listItems({ search, session } = {}) {
			// Bitwarden has no pagination for this command in the supported CLI.
			// A truncated JSON document is never parsed: fail closed and require a
			// later bounded retrieval strategy rather than silently enumerating a
			// partial vault.
			const args = ["list", "items"];
			if (search !== undefined) args.push("--search", search);
			args.push("--nointeraction");
			const result = await call(args, { session });
			const parsed = result.code === 0 && !outputOverflow(result) ? parseJsonOutput(result.stdout) : undefined;
			const failure = result.code !== 0 ? classifyCliFailure(result) : outputOverflow(result) ? "output_overflow" : Array.isArray(parsed) ? undefined : "invalid_cli_json";
			return { ...result, items: Array.isArray(parsed) ? parsed : undefined, failure };
		},
		async listFolders({ session } = {}) {
			const result = await call(["list", "folders", "--nointeraction"], { session });
			const parsed = result.code === 0 && !outputOverflow(result) ? parseJsonOutput(result.stdout) : undefined;
			const failure = result.code !== 0 ? classifyCliFailure(result) : outputOverflow(result) ? "output_overflow" : Array.isArray(parsed) ? undefined : "invalid_cli_json";
			return { ...result, folders: Array.isArray(parsed) ? parsed : undefined, failure };
		},
		streamAttachment({ itemId, attachmentId, session } = {}) {
			if (typeof itemId !== "string" || typeof attachmentId !== "string") throw new Error("attachment unavailable");
			const child = spawn(executable, ["get", "attachment", attachmentId, "--itemid", itemId, "--raw", "--nointeraction"], {
				env: childEnv(profilePath, undefined, session), shell: false, detached: true, stdio: ["ignore", "pipe", "pipe"],
			});
			child.stderr?.resume();
			return { stream: child.stdout, process: child };
		},
	};
}
