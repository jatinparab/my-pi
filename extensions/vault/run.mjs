import { spawn as nodeSpawn } from "node:child_process";
import { once } from "node:events";
import { homedir } from "node:os";
import { isAbsolute } from "node:path";

export const MAX_RUN_TIMEOUT_MS = 15 * 60 * 1_000;
export const DEFAULT_RUN_TIMEOUT_MS = 120 * 1_000;
export const RUN_TRANSPORT_GRACE_MS = 5_000;
export const MAX_RUN_REQUEST_BODY_BYTES = 16 * 1024 - 256;
export const MAX_RUN_OUTPUT_BYTES = 1 * 1024 * 1024;
export const MAX_RUN_ENV_ENTRIES = 64;
export const MAX_RUN_ENV_VALUE_BYTES = 64 * 1024;
export const MAX_RUN_ENV_BYTES = 256 * 1024;
export const MAX_RUN_ARGV = 128;
export const MAX_RUN_ARG_BYTES = 4 * 1024;
export const MAX_RUN_ARGV_BYTES = 64 * 1024;
export const MAX_RUN_CWD_BYTES = 4 * 1024;
export const MAX_TEXT_STDIN_BYTES = 256 * 1024;

const CONTROL = /[\u0000-\u001f\u007f]/u;
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/u;
const PROCESS_CONTROL = new Set([
	"PATH", "HOME", "SHELL", "NODE_OPTIONS", "PYTHONPATH", "BASH_ENV", "ENV", "IFS", "CDPATH",
	"LD_PRELOAD", "LD_LIBRARY_PATH", "RUBYOPT", "RUBYLIB", "PERL5OPT", "PERL5LIB", "GEM_HOME", "GEM_PATH",
	"JAVA_TOOL_OPTIONS", "_", "BW_PASSWORD", "BW_SESSION", "BITWARDENCLI_APPDATA_DIR",
]);

export class VaultRunError extends Error {
	constructor(code) { super(code); this.name = "VaultRunError"; this.code = code; }
}

function reject(code = "invalid_input") { throw new VaultRunError(code); }
function bytes(value) { return Buffer.byteLength(value, "utf8"); }
function safeString(value, max) { return typeof value === "string" && value.length > 0 && bytes(value) <= max && !CONTROL.test(value); }
function plain(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
function safeEnvName(name) { return safeString(name, 256) && ENV_NAME.test(name); }
function safeEnvValue(value, max) { return typeof value === "string" && bytes(value) <= max && !CONTROL.test(value); }

function validateEnv(value, { material = false } = {}) {
	if (value === undefined) return {};
	if (!plain(value)) reject();
	const names = Object.keys(value);
	if (names.length > MAX_RUN_ENV_ENTRIES) reject("over_limit");
	const result = {};
	let total = 0;
	for (const name of names) {
		if (!safeEnvName(name)) reject();
		if (PROCESS_CONTROL.has(name) || name.startsWith("DYLD_") || name.startsWith("LD_")) {
			if (material) reject("material_incompatible");
			reject("invalid_input");
		}
		const valueText = value[name];
		if (!safeEnvValue(valueText, MAX_RUN_ENV_VALUE_BYTES)) reject();
		total += bytes(name) + bytes(valueText) + 2;
		if (total > MAX_RUN_ENV_BYTES) reject("over_limit");
		result[name] = valueText;
	}
	return result;
}

export function validateVaultRunInput(input) {
	if (!plain(input)) reject();
	const allowed = new Set(["executable", "argv", "cwd", "env", "materialEnv", "stdin", "timeoutMs"]);
	if (Object.keys(input).some((key) => !allowed.has(key))) reject();
	if (!safeString(input.executable, 1_024)) reject();
	if (!Array.isArray(input.argv) || input.argv.length > MAX_RUN_ARGV) reject();
	let argvBytes = 0;
	const argv = input.argv.map((arg) => {
		if (typeof arg !== "string" || bytes(arg) > MAX_RUN_ARG_BYTES || CONTROL.test(arg)) reject();
		argvBytes += bytes(arg) + 1;
		if (argvBytes > MAX_RUN_ARGV_BYTES) reject("over_limit");
		return arg;
	});
	if (input.cwd !== undefined && (!safeString(input.cwd, MAX_RUN_CWD_BYTES) || !isAbsolute(input.cwd))) reject();
	const env = validateEnv(input.env);
	const materialEnv = input.materialEnv === undefined ? {} : input.materialEnv;
	if (!plain(materialEnv)) reject();
	const materialNames = Object.keys(materialEnv);
	if (materialNames.length > MAX_RUN_ENV_ENTRIES) reject("over_limit");
	for (const name of materialNames) {
		if (!safeEnvName(name)) reject();
		if (PROCESS_CONTROL.has(name) || name.startsWith("DYLD_") || name.startsWith("LD_")) reject("material_incompatible");
		if (env[name] !== undefined) reject("invalid_input");
		if (!safeString(materialEnv[name], 256)) reject("invalid_handle");
	}
	if (input.stdin !== undefined && !safeString(input.stdin, 256)) reject("invalid_handle");
	if (input.timeoutMs !== undefined && (!Number.isSafeInteger(input.timeoutMs) || input.timeoutMs < 1 || input.timeoutMs > MAX_RUN_TIMEOUT_MS)) reject("over_limit");
	const normalized = {
		executable: input.executable,
		argv,
		...(input.cwd === undefined ? {} : { cwd: input.cwd }),
		env,
		materialEnv: { ...materialEnv },
		...(input.stdin === undefined ? {} : { stdin: input.stdin }),
		timeoutMs: input.timeoutMs ?? DEFAULT_RUN_TIMEOUT_MS,
	};
	const encodedBytes = Buffer.byteLength(JSON.stringify(normalized), "utf8");
	if (encodedBytes > MAX_RUN_REQUEST_BODY_BYTES) reject("over_limit");
	return normalized;
}

function materialBuffer(value) {
	if (Buffer.isBuffer(value)) return Buffer.from(value);
	if (typeof value === "string") return Buffer.from(value, "utf8");
	if (value === undefined) return Buffer.alloc(0);
	if (typeof value === "number" || typeof value === "boolean" || value === null) return Buffer.from(String(value), "utf8");
	try { return Buffer.from(JSON.stringify(value), "utf8"); } catch { throw new VaultRunError("invalid_item_data"); }
}

export function materialEncodingVariants(value) {
	const buffer = materialBuffer(value);
	const raw = buffer.toString("utf8");
	const variants = new Set();
	const add = (text) => { if (typeof text === "string" && text.length > 0) variants.add(text); };
	add(raw);
	try {
		const json = JSON.stringify(raw);
		add(json);
		add(json.slice(1, -1));
		add(JSON.stringify(value));
	} catch { /* raw still has a safe representation */ }
	try {
		const encoded = encodeURIComponent(raw);
		add(encoded); add(encoded.replace(/%20/gu, "+"));
		add(encodeURI(raw));
		add(new URLSearchParams({ value: raw }).toString().slice(6));
	} catch { /* malformed surrogate text is still covered raw */ }
	const base64 = buffer.toString("base64");
	const base64url = buffer.toString("base64url");
	add(base64); add(base64.replace(/=+$/u, ""));
	add(base64url); add(base64url + "=".repeat((4 - (base64url.length % 4)) % 4));
	add(buffer.toString("hex"));
	add(buffer.toString("hex").toUpperCase());
	return [...variants].sort((left, right) => right.length - left.length);
}

function replaceBounded(input, needle, replacement) {
	const first = input.indexOf(needle);
	if (first < 0) return input;
	const pieces = [];
	let position = 0;
	let outputBytes = 0;
	while (position < input.length) {
		const found = input.indexOf(needle, position);
		if (found < 0) {
			const tail = input.slice(position);
			pieces.push(tail);
			outputBytes += bytes(tail);
			if (outputBytes > MAX_RUN_OUTPUT_BYTES) throw new VaultRunError("output_overflow");
			break;
		}
		const prefix = input.slice(position, found);
		pieces.push(prefix, replacement);
		outputBytes += bytes(prefix) + bytes(replacement);
		if (outputBytes > MAX_RUN_OUTPUT_BYTES) throw new VaultRunError("output_overflow");
		position = found + needle.length;
	}
	return pieces.join("");
}

export function redactVaultOutput(output, values) {
	let result = output;
	const variants = new Set();
	for (const value of values) for (const variant of materialEncodingVariants(value)) variants.add(variant);
	for (const variant of [...variants].sort((left, right) => right.length - left.length)) result = replaceBounded(result, variant, "[REDACTED]");
	return result;
}

function minimalEnvironment() {
	const env = {};
	for (const key of ["PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"]) {
		if (typeof process.env[key] === "string" && !CONTROL.test(process.env[key])) env[key] = process.env[key];
	}
	if (env.PATH === undefined) env.PATH = "/usr/bin:/bin";
	if (env.HOME === undefined) env.HOME = homedir();
	return env;
}

function groupExists(pid) {
	if (!pid || process.platform === "win32") return false;
	try { process.kill(-pid, 0); return true; } catch (error) { return error?.code === "EPERM"; }
}

function groupSignal(child, signal) {
	try { if (child?.pid && process.platform !== "win32") process.kill(-child.pid, signal); }
	catch (error) { if (error?.code !== "ESRCH") throw error; }
	try { child?.kill(signal); } catch (error) { if (error?.code !== "ESRCH") throw error; }
}

function abortError() { return new DOMException("The operation was cancelled", "AbortError"); }

function childExited(child) { return child?.exitCode !== null || child?.signalCode !== null; }
function delay(ms) { return new Promise((resolve) => setTimeout(resolve, ms)); }
async function waitForClose(child, ms) {
	if (!child || childExited(child)) return true;
	return await new Promise((resolve) => {
		const timer = setTimeout(() => { cleanup(); resolve(false); }, ms);
		const onClose = () => { cleanup(); resolve(true); };
		const cleanup = () => { clearTimeout(timer); child.removeListener("close", onClose); };
		child.once("close", onClose);
	});
}
async function terminateProcessGroup(child) {
	if (!child || (childExited(child) && !groupExists(child.pid))) return;
	try { groupSignal(child, "SIGTERM"); } catch { /* process may already be gone */ }
	const deadline = Date.now() + 2_000;
	await waitForClose(child, 2_000);
	const groupAlive = () => groupExists(child.pid);
	const directAlive = () => !childExited(child);
	if (!groupAlive() && !directAlive()) return;
	const remaining = deadline - Date.now();
	if (remaining > 0) await delay(remaining);
	if (groupAlive()) {
		try { groupSignal(child, "SIGKILL"); } catch { /* process may already be gone */ }
	} else if (directAlive()) {
		try { child.kill("SIGKILL"); } catch (error) { if (error?.code !== "ESRCH") throw error; }
	}
	await waitForClose(child, 2_000);
	if (groupAlive()) {
		try { groupSignal(child, "SIGKILL"); } catch { /* process may already be gone */ }
	} else if (directAlive()) {
		try { child.kill("SIGKILL"); } catch (error) { if (error?.code !== "ESRCH") throw error; }
	}
}

async function pipeAttachment(sourceResult, destination, signal) {
	const source = sourceResult?.stream ?? sourceResult;
	if (!source || typeof source[Symbol.asyncIterator] !== "function" || (typeof source.destroy !== "function" && !sourceResult?.process)) throw new VaultRunError("material_unavailable");
	const sourceProcess = sourceResult?.process;
	let destinationError;
	let destinationClosed = false;
	const onDestinationError = (error) => { destinationError = error; };
	const onDestinationClose = () => { destinationClosed = true; };
	destination.on("error", onDestinationError);
	destination.on("close", onDestinationClose);
	const drain = () => signal?.aborted ? Promise.reject(abortError()) : new Promise((resolve, reject) => {
		const onDrain = () => { cleanup(); resolve(); };
		const onClose = () => { cleanup(); reject(new VaultRunError("run_failed")); };
		const onAbort = () => { cleanup(); reject(abortError()); };
		const cleanup = () => { destination.removeListener("drain", onDrain); destination.removeListener("close", onClose); signal?.removeEventListener("abort", onAbort); };
		destination.once("drain", onDrain);
		destination.once("close", onClose);
		signal?.addEventListener("abort", onAbort, { once: true });
	});
	try {
		for await (const chunk of source) {
			if (destinationError || destinationClosed) throw new VaultRunError("run_failed");
			if (signal?.aborted) throw abortError();
			if (!destination.write(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk))) await drain();
		}
		if (signal?.aborted) throw abortError();
		destination.end();
		if (sourceProcess) {
			let code = sourceProcess.exitCode;
			if (code === null && sourceProcess.signalCode === null) [code] = await once(sourceProcess, "close");
			if (code !== 0) throw new VaultRunError("cli_error");
		}
	} finally {
		destination.removeListener("error", onDestinationError);
		destination.removeListener("close", onDestinationClose);
	}
}

function childClose(child) {
	if (childExited(child)) return Promise.resolve([child.exitCode, child.signalCode]);
	return once(child, "close");
}

function outputCollector(store = true) {
	const chunks = [];
	let count = 0;
	let overflow = false;
	return {
		add(chunk, combined) {
			const value = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
			count += value.length;
			const remaining = Math.max(0, MAX_RUN_OUTPUT_BYTES - combined());
			if (value.length > remaining) overflow = true;
			if (store && remaining > 0) chunks.push(value.subarray(0, remaining));
		},
		text() { return Buffer.concat(chunks).toString("utf8"); },
		get count() { return count; },
		get overflow() { return overflow; },
	};
}

export async function executeVaultRun(input, {
	resolveMaterial,
	resolveAttachment,
	adapter,
	session,
	signal,
	spawn = nodeSpawn,
	now = Date.now,
} = {}) {
	const run = validateVaultRunInput(input);
	if (signal?.aborted) throw abortError();
	const selected = [];
	const used = new Set();
	let ownerItemHandle;
	const selectOwner = (record) => {
		if (typeof record.ownerItemHandle !== "string") reject("material_unavailable");
		if (ownerItemHandle === undefined) ownerItemHandle = record.ownerItemHandle;
		else if (ownerItemHandle !== record.ownerItemHandle) reject("wrong_item");
	};
	const env = { ...minimalEnvironment(), ...run.env };
	let environmentBytes = Object.entries(env).reduce((total, [name, value]) => total + bytes(name) + bytes(value) + 2, 0);
	let stdinRecord;
	let stdinBuffer;
	let attachment;
	for (const [name, handle] of Object.entries(run.materialEnv)) {
		if (used.has(handle)) reject("duplicate_handle");
		used.add(handle);
		const record = resolveMaterial?.(handle) ?? resolveAttachment?.(handle);
		if (!record) reject("invalid_handle");
		if (!record.descriptor?.delivery?.environment || record.descriptor.category === "attachment") reject("material_incompatible");
		selectOwner(record);
		const value = materialBuffer(record.value);
		if (value.includes(0)) reject("material_incompatible");
		if (value.length > MAX_RUN_ENV_VALUE_BYTES) reject("over_limit");
		env[name] = value.toString("utf8");
		environmentBytes += bytes(name) + bytes(env[name]) + 2;
		if (environmentBytes > MAX_RUN_ENV_BYTES) reject("over_limit");
		selected.push(record.value);
	}
	if (run.stdin !== undefined) {
		if (used.has(run.stdin)) reject("duplicate_handle");
		used.add(run.stdin);
		stdinRecord = resolveMaterial?.(run.stdin) ?? resolveAttachment?.(run.stdin);
		if (!stdinRecord) reject("invalid_handle");
		if (!stdinRecord.descriptor?.delivery?.stdin) reject("material_incompatible");
		selectOwner(stdinRecord);
		if (stdinRecord.descriptor.category === "attachment") {
			attachment = stdinRecord;
			if (typeof attachment.itemId !== "string" || typeof attachment.attachmentId !== "string") reject("material_unavailable");
			if (typeof adapter?.streamAttachment !== "function") reject("cli_unavailable");
			selected.push(stdinRecord.value);
		} else {
			stdinBuffer = materialBuffer(stdinRecord.value);
			selected.push(stdinRecord.value);
		}
	}
	const bulk = Boolean(attachment || stdinBuffer?.length > MAX_TEXT_STDIN_BYTES || stdinRecord?.binary === true);
	const started = now();
	let child;
	let sourceResult;
	let sourceStream;
	let sourceProcess;
	let sourceTermination;
	let terminating;
	let timedOut = false;
	let cancelled = false;
	const inputController = new AbortController();
	const stopSource = () => {
		inputController.abort();
		try { sourceStream?.destroy?.(); } catch { /* source cleanup is best effort */ }
		if (sourceProcess && !sourceTermination) sourceTermination = terminateProcessGroup(sourceProcess);
	};
	const terminate = (reason) => {
		if (reason === "timeout") timedOut = true;
		if (reason === "cancelled") cancelled = true;
		stopSource();
		if (terminating) return terminating;
		terminating = Promise.all([terminateProcessGroup(child), sourceTermination ?? Promise.resolve()]);
		return terminating;
	};
	if (attachment) {
		try { sourceResult = adapter.streamAttachment({ itemId: attachment.itemId, attachmentId: attachment.attachmentId, session, signal: inputController.signal }); }
		catch { throw new VaultRunError("material_unavailable"); }
		if (sourceResult && typeof sourceResult.then === "function") throw new VaultRunError("material_unavailable");
		sourceStream = sourceResult?.stream ?? sourceResult;
		sourceProcess = sourceResult?.process;
		if (!sourceStream || typeof sourceStream[Symbol.asyncIterator] !== "function" || (typeof sourceStream.destroy !== "function" && !sourceProcess)) {
			stopSource();
			if (sourceTermination) await sourceTermination;
			throw new VaultRunError("material_unavailable");
		}
	}
	if (signal?.aborted) {
		stopSource();
		if (sourceTermination) await sourceTermination;
		throw abortError();
	}
	try {
		child = spawn(run.executable, run.argv, { cwd: run.cwd, env, shell: false, detached: process.platform !== "win32", stdio: ["pipe", "pipe", "pipe"] });
	} catch {
		stopSource();
		if (sourceTermination) await sourceTermination;
		throw new VaultRunError("run_failed");
	}
	const stdout = outputCollector(!bulk);
	const stderr = outputCollector(!bulk);
	const onStdinError = () => {};
	child.stdin?.on("error", onStdinError);
	let childError = false;
	child.once("error", () => { childError = true; });
	let combined = 0;
	const collect = (collector, stream) => {
		stream?.on("data", (chunk) => {
			combined += Buffer.isBuffer(chunk) ? chunk.length : Buffer.byteLength(String(chunk));
			collector.add(chunk, () => combined - (Buffer.isBuffer(chunk) ? chunk.length : Buffer.byteLength(String(chunk))));
		});
		stream?.resume();
	};
	collect(stdout, child.stdout);
	collect(stderr, child.stderr);
	const onAbort = () => { inputController.abort(); void terminate("cancelled"); };
	signal?.addEventListener("abort", onAbort, { once: true });
	const timeoutTimer = setTimeout(() => { inputController.abort(); void terminate("timeout"); }, run.timeoutMs);
	timeoutTimer.unref?.();
	try {
		if (attachment) await pipeAttachment(sourceResult, child.stdin, inputController.signal);
		else if (stdinBuffer !== undefined) child.stdin.end(stdinBuffer);
		else child.stdin.end();
	} catch (error) {
		if (!terminating) await terminate(signal?.aborted ? "cancelled" : "internal");
		if (signal?.aborted) {
			if (terminating) await terminating;
			if (sourceTermination) await sourceTermination;
			throw abortError();
		}
		if (!timedOut && !cancelled) {
			if (error instanceof VaultRunError) throw error;
			throw new VaultRunError("run_failed");
		}
	}
	const [exitCode, signalName] = await childClose(child);
	child.stdin?.removeListener("error", onStdinError);
	clearTimeout(timeoutTimer);
	if (childError && !timedOut && !cancelled && exitCode === null && signalName === null) throw new VaultRunError("run_failed");
	signal?.removeEventListener("abort", onAbort);
	if (terminating) await terminating;
	if (sourceTermination) await sourceTermination;
	if (timedOut || cancelled) return {
		mode: bulk ? "bulk" : "text", exitCode: typeof exitCode === "number" ? exitCode : null, signal: signalName ?? null,
		durationMs: Math.max(0, now() - started), timedOut, cancelled, stdoutBytes: stdout.count, stderrBytes: stderr.count,
		...(bulk ? {} : { stdout: "", stderr: "" }),
	};
	if (!bulk && (stdout.overflow || stderr.overflow || combined > MAX_RUN_OUTPUT_BYTES)) throw new VaultRunError("output_overflow");
	const result = {
		mode: bulk ? "bulk" : "text", exitCode: typeof exitCode === "number" ? exitCode : null, signal: signalName ?? null,
		durationMs: Math.max(0, now() - started), timedOut: false, cancelled: false, stdoutBytes: stdout.count, stderrBytes: stderr.count,
	};
	if (!bulk) {
		result.stdout = redactVaultOutput(stdout.text(), selected);
		result.stderr = redactVaultOutput(stderr.text(), selected);
		if (bytes(result.stdout) + bytes(result.stderr) > MAX_RUN_OUTPUT_BYTES) throw new VaultRunError("output_overflow");
	}
	return result;
}

export function minimalVaultEnvironmentForTest() { return minimalEnvironment(); }
export const processControlEnvironmentNames = Object.freeze([...PROCESS_CONTROL]);
