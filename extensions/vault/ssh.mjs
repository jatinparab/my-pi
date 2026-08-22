import ssh2 from "ssh2";
import { createHmac, randomBytes, randomUUID } from "node:crypto";
import { once } from "node:events";
import { chmod, lstat, mkdir, open, readFile, rename, unlink } from "node:fs/promises";
import { dirname, join } from "node:path";
import { TextDecoder } from "node:util";
import { materialEncodingVariants, redactVaultOutput, VaultRunError } from "./run.mjs";

export const MAX_SSH_HOST_BYTES = 512;
export const MAX_SSH_USERNAME_BYTES = 128;
export const MAX_SSH_COMMAND_BYTES = 4 * 1024;
export const MAX_SSH_PORT = 65_535;
export const MAX_SSH_OUTPUT_BYTES = 1024 * 1024;
export const MAX_SSH_TIMEOUT_MS = 15 * 60 * 1_000;
export const DEFAULT_SSH_TIMEOUT_MS = 120 * 1_000;
export const SSH_TRANSPORT_GRACE_MS = 5_000;
export const MAX_KNOWN_HOSTS_ENTRIES = 1024;
export const MAX_KNOWN_HOSTS_BYTES = 256 * 1024;
export const MAX_SSH_PRIVATE_KEY_BYTES = 1024 * 1024;
export const MAX_SSH_PASSPHRASE_BYTES = 64 * 1024;

const CONTROL = /[\u0000-\u001f\u007f]/u;
const WHITESPACE = /\s/u;
const SSH_KEY_PREFIX = /^-{2,}BEGIN\s.*PRIVATE\sKEY/u;
const TRUST_VERSION = 1;
const TRUST_KEY_BYTES = 32;
const TRUST_DIGEST = /^[a-f0-9]{64}$/u;
const TRUST_KEY = /^[A-Za-z0-9_-]{43}$/u;
const DefaultClient = ssh2.Client;

export class SshError extends Error {
	constructor(code) { super(code); this.name = "SshError"; this.code = code; }
}
export class SshHostKeyError extends SshError {
	constructor(code = "host_key_changed") { super(code); this.name = "SshHostKeyError"; }
}

function reject(code = "invalid_input") { throw new SshError(code); }
function bytes(value) { return Buffer.byteLength(value, "utf8"); }
function plain(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
function safeString(value, max) { return typeof value === "string" && value.length > 0 && bytes(value) <= max && !CONTROL.test(value); }
function abortError() { return new DOMException("The operation was cancelled", "AbortError"); }
function isAbort(error) { return error?.name === "AbortError"; }

function normalizeHost(value, incompatible = false) {
	if (!safeString(value, MAX_SSH_HOST_BYTES) || WHITESPACE.test(value) || value !== value.trim()) reject(incompatible ? "material_incompatible" : "invalid_input");
	return value;
}

export function validateVaultSshInput(input) {
	if (!plain(input)) reject();
	const allowed = new Set(["host", "hostHandle", "username", "port", "privateKeyHandle", "passphraseHandle", "command", "stdinHandle", "timeoutMs"]);
	if (Object.keys(input).some((key) => !allowed.has(key))) reject();
	if ((input.host === undefined) === (input.hostHandle === undefined)) reject();
	if (input.host !== undefined) normalizeHost(input.host);
	if (input.hostHandle !== undefined && !safeString(input.hostHandle, 256)) reject("invalid_handle");
	if (input.username !== undefined && (!safeString(input.username, MAX_SSH_USERNAME_BYTES) || WHITESPACE.test(input.username))) reject();
	if (input.port !== undefined && (!Number.isSafeInteger(input.port) || input.port < 1 || input.port > MAX_SSH_PORT)) reject();
	if (!safeString(input.privateKeyHandle, 256)) reject("invalid_handle");
	if (input.passphraseHandle !== undefined && !safeString(input.passphraseHandle, 256)) reject("invalid_handle");
	if (!safeString(input.command, MAX_SSH_COMMAND_BYTES)) reject();
	if (input.stdinHandle !== undefined && !safeString(input.stdinHandle, 256)) reject("invalid_handle");
	if (input.timeoutMs !== undefined && (!Number.isSafeInteger(input.timeoutMs) || input.timeoutMs < 1 || input.timeoutMs > MAX_SSH_TIMEOUT_MS)) reject("over_limit");
	return {
		...(input.host === undefined ? {} : { host: input.host }),
		...(input.hostHandle === undefined ? {} : { hostHandle: input.hostHandle }),
		username: input.username ?? "root",
		port: input.port ?? 22,
		privateKeyHandle: input.privateKeyHandle,
		...(input.passphraseHandle === undefined ? {} : { passphraseHandle: input.passphraseHandle }),
		command: input.command,
		...(input.stdinHandle === undefined ? {} : { stdinHandle: input.stdinHandle }),
		timeoutMs: input.timeoutMs ?? DEFAULT_SSH_TIMEOUT_MS,
	};
}

function materialBuffer(value) {
	if (Buffer.isBuffer(value)) return Buffer.from(value);
	if (typeof value === "string") return Buffer.from(value, "utf8");
	if (value === undefined) return Buffer.alloc(0);
	if (typeof value === "number" || typeof value === "boolean" || value === null) return Buffer.from(String(value), "utf8");
	try { return Buffer.from(JSON.stringify(value), "utf8"); }
	catch { throw new SshError("invalid_item_data"); }
}

function trustError() { return new SshError("host_key_unavailable"); }
function exactKeys(value, expected) {
	const actual = Object.keys(value).sort();
	const sorted = [...expected].sort();
	return actual.length === sorted.length && actual.every((key, index) => key === sorted[index]);
}

async function assertPrivateDirectory(directory) {
	try {
		const info = await lstat(directory);
		if (!info.isDirectory() || info.isSymbolicLink() || (info.mode & 0o777) !== 0o700) throw trustError();
	} catch (error) {
		if (error?.code !== "ENOENT") throw error instanceof SshError ? error : trustError();
		try { await mkdir(directory, { recursive: true, mode: 0o700 }); }
		catch { throw trustError(); }
		const info = await lstat(directory).catch(() => undefined);
		if (!info?.isDirectory() || info.isSymbolicLink() || (info.mode & 0o777) !== 0o700) throw trustError();
	}
}

function parseTrustState(text) {
	let parsed;
	try { parsed = JSON.parse(text); } catch { throw trustError(); }
	if (!plain(parsed) || !exactKeys(parsed, ["version", "key", "entries"]) || parsed.version !== TRUST_VERSION || !TRUST_KEY.test(parsed.key) || !plain(parsed.entries)) throw trustError();
	const pairs = Object.entries(parsed.entries);
	if (pairs.length > MAX_KNOWN_HOSTS_ENTRIES || pairs.some(([id, verifier]) => !TRUST_DIGEST.test(id) || !TRUST_DIGEST.test(verifier))) throw trustError();
	return { version: TRUST_VERSION, key: parsed.key, entries: Object.fromEntries(pairs) };
}

async function readTrustState(storePath) {
	let info;
	try { info = await lstat(storePath); }
	catch (error) { if (error?.code === "ENOENT") return undefined; throw trustError(); }
	if (!info.isFile() || info.isSymbolicLink() || (info.mode & 0o777) !== 0o600 || info.size <= 0 || info.size > MAX_KNOWN_HOSTS_BYTES) throw trustError();
	let text;
	try { text = await readFile(storePath, "utf8"); } catch { throw trustError(); }
	if (Buffer.byteLength(text, "utf8") !== info.size) throw trustError();
	return parseTrustState(text);
}

async function atomicWriteTrustState(storePath, state) {
	const directory = dirname(storePath);
	await assertPrivateDirectory(directory);
	const text = JSON.stringify(state);
	if (Buffer.byteLength(text, "utf8") > MAX_KNOWN_HOSTS_BYTES) throw trustError();
	const temporary = join(directory, `.known-hosts-${randomUUID()}.tmp`);
	let handle;
	try {
		handle = await open(temporary, "wx", 0o600);
		await handle.writeFile(text, "utf8");
		await handle.chmod(0o600);
		await handle.sync();
		await handle.close();
		handle = undefined;
		await rename(temporary, storePath);
		await chmod(storePath, 0o600);
		const info = await lstat(storePath);
		if (!info.isFile() || info.isSymbolicLink() || (info.mode & 0o777) !== 0o600) throw trustError();
		const directoryHandle = await open(directory, "r");
		try { await directoryHandle.sync(); } finally { await directoryHandle.close(); }
	} catch (error) {
		try { await handle?.close(); } catch { /* no material is returned */ }
		try { await unlink(temporary); } catch { /* absent or unwritable */ }
		throw error instanceof SshError ? error : trustError();
	}
}

function keyedDigest(key, domain, value) {
	return createHmac("sha256", key).update(domain).update(value).digest("hex");
}

/**
 * Private trust adapter. Its single verify interface serializes concurrent
 * checks, persists first use before acceptance, and never writes host text,
 * raw host-key bytes, or their ordinary encodings.
 */
export async function createKnownHostsStore({ storePath } = {}) {
	if (!safeString(storePath, 4096)) throw trustError();
	await assertPrivateDirectory(dirname(storePath));
	let state = await readTrustState(storePath);
	if (!state) {
		state = { version: TRUST_VERSION, key: randomBytes(TRUST_KEY_BYTES).toString("base64url"), entries: {} };
		await atomicWriteTrustState(storePath, state);
	}
	let key = Buffer.from(state.key, "base64url");
	if (key.length !== TRUST_KEY_BYTES) throw trustError();
	let closed = false;
	let queue = Promise.resolve();
	const serialized = (operation) => {
		const result = queue.then(operation, operation);
		queue = result.catch(() => {});
		return result;
	};
	return {
		verify(host, port, rawHostKey) {
			return serialized(async () => {
				if (closed || !Buffer.isBuffer(rawHostKey) || rawHostKey.length === 0 || rawHostKey.length > 1024 * 1024) throw trustError();
				normalizeHost(host);
				if (!Number.isSafeInteger(port) || port < 1 || port > MAX_SSH_PORT) throw trustError();
				// Reload before every mutation so external corruption or insecure mode
				// cannot be silently overwritten by a previously valid in-memory copy.
				const current = await readTrustState(storePath);
				if (!current || current.key !== state.key) throw trustError();
				state = current;
				const identifier = keyedDigest(key, "host-id\0", Buffer.from(`${host}\0${port}`, "utf8"));
				const verifier = keyedDigest(key, "host-key\0", rawHostKey);
				const trusted = state.entries[identifier];
				if (trusted !== undefined) {
					if (trusted !== verifier) throw new SshHostKeyError();
					return "trusted";
				}
				if (Object.keys(state.entries).length >= MAX_KNOWN_HOSTS_ENTRIES) throw trustError();
				const updated = { version: TRUST_VERSION, key: state.key, entries: { ...state.entries, [identifier]: verifier } };
				await atomicWriteTrustState(storePath, updated);
				state = updated;
				return "accepted";
			});
		},
		async close() {
			await serialized(async () => {
				if (closed) return;
				closed = true;
				key.fill(0);
				key = Buffer.alloc(0);
				state = { version: TRUST_VERSION, key: "", entries: {} };
			});
		},
		get size() { return Object.keys(state.entries).length; },
	};
}

function classifyClientError(error, verificationError) {
	if (verificationError instanceof SshError) return verificationError;
	if (isAbort(error)) return error;
	const message = `${error?.code ?? ""} ${error?.message ?? ""}`;
	if (/authentication.*fail|auth\s*fail|permission denied|invalid.*key|no auth/i.test(message)) return new SshError("auth_failed");
	if (/timed?\s*out|ETIMEDOUT/i.test(message)) return new SshError("timed_out");
	if (/connect|ECONN|ENOTFOUND|EHOSTUNREACH|resolve|socket/i.test(message)) return new SshError("network_error");
	return new SshError("run_failed");
}

function waitForEmitterClose(emitter, isClosed) {
	if (isClosed()) return Promise.resolve();
	return new Promise((resolve) => emitter.once("close", resolve));
}

function destroyConnection(conn) {
	try { conn.end?.(); } catch { /* destroy below is authoritative */ }
	try { conn.destroy?.(); } catch { /* close event still determines settlement */ }
}

function waitForDrain(stream, signal) {
	if (signal?.aborted) return Promise.reject(abortError());
	return new Promise((resolve, reject) => {
		const cleanup = () => {
			stream.removeListener("drain", onDrain);
			stream.removeListener("close", onClose);
			stream.removeListener("error", onError);
			signal?.removeEventListener("abort", onAbort);
		};
		const onDrain = () => { cleanup(); resolve(); };
		const onClose = () => { cleanup(); reject(new SshError("run_failed")); };
		const onError = () => { cleanup(); reject(new SshError("run_failed")); };
		const onAbort = () => { cleanup(); reject(abortError()); };
		stream.once("drain", onDrain);
		stream.once("close", onClose);
		stream.once("error", onError);
		signal?.addEventListener("abort", onAbort, { once: true });
	});
}

function collectChannelOutput(stream, onOverflow, store = true) {
	const stdout = [];
	const stderr = [];
	let stdoutBytes = 0;
	let stderrBytes = 0;
	let stored = 0;
	let overflow = false;
	const add = (destination, chunk) => {
		const value = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
		if (destination === stdout) stdoutBytes += value.length; else stderrBytes += value.length;
		if (!Number.isSafeInteger(stdoutBytes) || !Number.isSafeInteger(stderrBytes)) {
			overflow = true;
			onOverflow();
			return;
		}
		if (!store) return;
		const remaining = Math.max(0, MAX_SSH_OUTPUT_BYTES - stored);
		if (value.length > remaining) {
			overflow = true;
			onOverflow();
		}
		if (remaining > 0) {
			const kept = value.subarray(0, remaining);
			destination.push(kept);
			stored += kept.length;
		}
	};
	stream.on("data", (chunk) => add(stdout, chunk));
	stream.stderr?.on("data", (chunk) => add(stderr, chunk));
	stream.resume?.();
	stream.stderr?.resume?.();
	return {
		result: () => ({ stdout: Buffer.concat(stdout), stderr: Buffer.concat(stderr), stdoutBytes, stderrBytes, overflow }),
	};
}

/**
 * Production ssh2 adapter. executeVaultSsh is the external seam; this adapter
 * is injected privately by the broker and can be replaced with an in-process
 * ssh2-compatible Client in tests.
 */
export function createSshClient({ Client = DefaultClient } = {}) {
	if (typeof Client !== "function") throw new TypeError("SSH Client constructor is required");
	return async function connectSsh({ host, port, username, privateKey, passphrase, timeoutMs, signal, verifyHostKey }) {
		if (signal?.aborted) throw abortError();
		const conn = new Client();
		let closed = false;
		let ready = false;
		let verificationError;
		conn.once("close", () => { closed = true; });
		const close = async () => {
			if (closed) return;
			const pending = waitForEmitterClose(conn, () => closed);
			destroyConnection(conn);
			await pending;
		};
		await new Promise((resolve, rejectPromise) => {
			let settled = false;
			const cleanup = () => {
				signal?.removeEventListener("abort", onAbort);
				conn.removeListener("ready", onReady);
				conn.removeListener("error", onError);
				conn.removeListener("close", onPrematureClose);
			};
			const settleError = async (error) => {
				if (settled) return;
				settled = true;
				cleanup();
				await close().catch(() => {});
				rejectPromise(classifyClientError(error, verificationError));
			};
			const onAbort = () => { void settleError(abortError()); };
			const onReady = () => {
				if (settled) return;
				settled = true;
				ready = true;
				cleanup();
				resolve();
			};
			const onError = (error) => { void settleError(error); };
			const onPrematureClose = () => { if (!ready) void settleError(new SshError("network_error")); };
			signal?.addEventListener("abort", onAbort, { once: true });
			conn.once("ready", onReady);
			conn.once("error", onError);
			conn.once("close", onPrematureClose);
			try {
				conn.connect({
					host,
					port,
					username,
					privateKey,
					...(passphrase === undefined ? {} : { passphrase: passphrase.toString("utf8") }),
					readyTimeout: Math.max(1, Math.floor(timeoutMs)),
					keepaliveInterval: 0,
					hostVerifier(rawKey, callback) {
						Promise.resolve().then(() => verifyHostKey(Buffer.from(rawKey))).then(
							() => callback(true),
							(error) => { verificationError = error instanceof SshError ? error : new SshError("host_key_unavailable"); callback(false); },
						);
					},
				});
			} catch (error) { void settleError(error); }
		});

		let sessionFailure;
		conn.on("error", (error) => { sessionFailure = classifyClientError(error, verificationError); });
		return {
			hostVerified: true,
			async exec(command, stdinStream, execSignal, { suppressOutput = false } = {}) {
				if (execSignal?.aborted) throw abortError();
				return await new Promise((resolve, rejectPromise) => {
					let callbackCalled = false;
					let finished = false;
					let stream;
					let channelClosed = false;
					let channelFailure;
					let exitCode = null;
					let signalName = null;
					let pumpPromise = Promise.resolve();
					let pumpError;
					let collector;
					const finishAfterClose = async () => {
						if (finished) return;
						finished = true;
						execSignal?.removeEventListener("abort", onAbort);
						try { await pumpPromise; } catch (error) { pumpError = error; }
						if (channelFailure || sessionFailure) return rejectPromise(channelFailure ?? sessionFailure);
						if (pumpError && !isAbort(pumpError)) return rejectPromise(pumpError instanceof SshError ? pumpError : new SshError("run_failed"));
						if (!collector) return rejectPromise(execSignal?.aborted ? abortError() : new SshError("run_failed"));
						resolve({ exitCode, signal: signalName, ...collector.result() });
					};
					const closeChannel = () => {
						try { stdinStream?.destroy?.(); } catch { /* source owner also cleans up */ }
						try { stream?.close?.(); } catch { /* connection destroy is authoritative */ }
						destroyConnection(conn);
					};
					const onAbort = () => closeChannel();
					execSignal?.addEventListener("abort", onAbort, { once: true });
					conn.exec(command, (error, channel) => {
						callbackCalled = true;
						if (error || !channel) {
							execSignal?.removeEventListener("abort", onAbort);
							return rejectPromise(execSignal?.aborted ? abortError() : new SshError("run_failed"));
						}
						stream = channel;
						collector = collectChannelOutput(stream, closeChannel, !suppressOutput);
						stream.once("exit", (code, remoteSignal) => { exitCode = Number.isSafeInteger(code) ? code : null; signalName = typeof remoteSignal === "string" ? remoteSignal : null; });
						stream.once("close", (code, remoteSignal) => {
							channelClosed = true;
							if (Number.isSafeInteger(code)) exitCode = code;
							if (typeof remoteSignal === "string") signalName = remoteSignal;
							void finishAfterClose();
						});
						stream.once("error", () => { channelFailure = new SshError("run_failed"); closeChannel(); });
						pumpPromise = (async () => {
							if (stdinStream) {
								for await (const chunk of stdinStream) {
									if (execSignal?.aborted || channelClosed) throw abortError();
									if (!stream.write(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk))) await waitForDrain(stream, execSignal);
								}
							}
							if (!channelClosed) stream.end();
						})().catch((error) => { pumpError = error; closeChannel(); });
					});
					conn.once("close", () => {
						if (!callbackCalled) {
							finished = true;
							execSignal?.removeEventListener("abort", onAbort);
							rejectPromise(execSignal?.aborted ? abortError() : sessionFailure ?? new SshError("run_failed"));
						} else if (!channelClosed) void finishAfterClose();
					});
				});
			},
			close,
			get closed() { return closed; },
		};
	};
}

export function sshMaterialEncodingVariants(value) { return materialEncodingVariants(value); }
export function redactSshOutput(output, values) {
	try { return redactVaultOutput(output, values); }
	catch (error) { throw error instanceof VaultRunError ? new SshError(error.code) : error; }
}

function groupExists(pid) {
	if (!pid || process.platform === "win32") return false;
	try { process.kill(-pid, 0); return true; } catch (error) { return error?.code === "EPERM"; }
}
function childExited(child) { return child?.exitCode !== null || child?.signalCode !== null; }
async function waitForChildClose(child) {
	if (!child || childExited(child)) return;
	await once(child, "close").catch(() => {});
}
function signalProcessTree(child, signal) {
	try { if (child?.pid && process.platform !== "win32") process.kill(-child.pid, signal); } catch (error) { if (error?.code !== "ESRCH") throw error; }
	try { child?.kill?.(signal); } catch (error) { if (error?.code !== "ESRCH") throw error; }
}
async function terminateSourceProcess(child) {
	if (!child || (childExited(child) && !groupExists(child.pid))) return;
	try { signalProcessTree(child, "SIGTERM"); } catch { /* it may already be gone */ }
	const closed = Promise.race([waitForChildClose(child).then(() => true), new Promise((resolve) => setTimeout(() => resolve(false), 2_000))]);
	await closed;
	if (groupExists(child.pid) || !childExited(child)) {
		try { signalProcessTree(child, "SIGKILL"); } catch { /* it may already be gone */ }
	}
	await waitForChildClose(child);
	if (groupExists(child.pid)) throw new SshError("run_failed");
}

function validateScalarRecord(record) {
	return record && record.descriptor?.category !== "attachment" && (record.descriptor?.delivery?.stdin || record.descriptor?.delivery?.environment);
}
function scalarSource(buffer) {
	return (async function* () { yield buffer; })();
}
function decodeOutput(buffer) { return new TextDecoder("utf-8", { fatal: false }).decode(buffer); }

/**
 * Deep SSH module: validation, fixed-role material selection, trust-on-first-use,
 * one total deadline, streaming, cleanup, output caps, and redaction sit behind
 * this one-shot interface. sshConnect/openAttachment are private adapter seams.
 */
export async function executeVaultSsh(input, {
	resolveMaterial,
	resolveAttachment,
	openAttachment,
	sshConnect,
	knownHosts,
	signal,
	now = Date.now,
} = {}) {
	const params = validateVaultSshInput(input);
	if (signal?.aborted) throw abortError();
	if (typeof sshConnect !== "function" || typeof knownHosts?.verify !== "function") throw new SshError("host_key_unavailable");

	const used = new Set();
	const selected = [];
	const take = (handle) => {
		if (used.has(handle)) reject("duplicate_handle");
		used.add(handle);
		const record = resolveMaterial?.(handle) ?? resolveAttachment?.(handle);
		if (!record) reject("invalid_handle");
		return record;
	};

	let host = params.host;
	if (params.hostHandle !== undefined) {
		const record = take(params.hostHandle);
		if (!validateScalarRecord(record)) reject("material_incompatible");
		const value = materialBuffer(record.value);
		if (value.includes(0)) reject("material_incompatible");
		host = normalizeHost(value.toString("utf8"), true);
		selected.push(record.value);
	}

	const keyRecord = take(params.privateKeyHandle);
	if (keyRecord.descriptor?.category !== "ssh-key" || keyRecord.descriptor?.type !== "private-key" || !keyRecord.descriptor?.delivery?.stdin || !keyRecord.descriptor?.delivery?.environment) reject("material_incompatible");
	const privateKey = materialBuffer(keyRecord.value);
	if (privateKey.length === 0 || privateKey.length > MAX_SSH_PRIVATE_KEY_BYTES || privateKey.includes(0) || !SSH_KEY_PREFIX.test(privateKey.toString("utf8"))) reject(privateKey.length > MAX_SSH_PRIVATE_KEY_BYTES ? "over_limit" : "material_incompatible");
	selected.push(keyRecord.value);

	let passphrase;
	if (params.passphraseHandle !== undefined) {
		const record = take(params.passphraseHandle);
		if (!validateScalarRecord(record)) reject("material_incompatible");
		passphrase = materialBuffer(record.value);
		if (passphrase.includes(0) || passphrase.length > MAX_SSH_PASSPHRASE_BYTES) reject(passphrase.length > MAX_SSH_PASSPHRASE_BYTES ? "over_limit" : "material_incompatible");
		selected.push(record.value);
	}

	let stdinRecord;
	let stdinBuffer;
	let attachment;
	if (params.stdinHandle !== undefined) {
		stdinRecord = take(params.stdinHandle);
		if (!stdinRecord.descriptor?.delivery?.stdin) reject("material_incompatible");
		if (stdinRecord.descriptor.category === "attachment") {
			if (typeof stdinRecord.itemId !== "string" || typeof stdinRecord.attachmentId !== "string" || typeof openAttachment !== "function") reject("material_unavailable");
			attachment = stdinRecord;
		} else {
			stdinBuffer = materialBuffer(stdinRecord.value);
		}
		selected.push(stdinRecord.value);
	}
	// Every role and duplicate is validated before sshConnect can touch a socket.
	const bulk = Boolean(attachment || stdinBuffer?.length > 256 * 1024 || stdinRecord?.binary === true);
	const started = now();
	const deadline = started + params.timeoutMs;
	const controller = new AbortController();
	let timedOut = false;
	let cancelled = false;
	const onAbort = () => { cancelled = true; controller.abort(); };
	signal?.addEventListener("abort", onAbort, { once: true });
	const timer = setTimeout(() => { timedOut = true; controller.abort(); }, params.timeoutMs);
	timer.unref?.();
	let connection;
	let sourceResult;
	let sourceStream;
	let sourceProcess;
	const stopSource = async () => {
		try { sourceStream?.destroy?.(); } catch { /* process cleanup below is authoritative */ }
		await terminateSourceProcess(sourceProcess);
	};
	try {
		connection = await sshConnect({
			host,
			port: params.port,
			username: params.username,
			privateKey,
			passphrase,
			timeoutMs: Math.max(1, deadline - now()),
			signal: controller.signal,
			verifyHostKey: (rawHostKey) => knownHosts.verify(host, params.port, rawHostKey),
		});
		if (controller.signal.aborted) throw abortError();
		if (connection?.hostVerified !== true) throw new SshError("host_key_unavailable");
		if (typeof connection.exec !== "function" || typeof connection.close !== "function") throw new SshError("run_failed");

		let stdinSource;
		if (attachment) {
			try { sourceResult = openAttachment({ itemId: attachment.itemId, attachmentId: attachment.attachmentId, signal: controller.signal }); }
			catch { throw new SshError("material_unavailable"); }
			if (sourceResult && typeof sourceResult.then === "function") throw new SshError("material_unavailable");
			sourceStream = sourceResult?.stream ?? sourceResult;
			sourceProcess = sourceResult?.process;
			if (!sourceStream || typeof sourceStream[Symbol.asyncIterator] !== "function" || (typeof sourceStream.destroy !== "function" && !sourceProcess)) throw new SshError("material_unavailable");
			stdinSource = sourceStream;
		} else if (stdinBuffer !== undefined) stdinSource = scalarSource(stdinBuffer);

		let execResult;
		try { execResult = await connection.exec(params.command, stdinSource, controller.signal, { suppressOutput: bulk }); }
		catch (error) {
			if (timedOut) {
				execResult = { exitCode: null, signal: null, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0), stdoutBytes: 0, stderrBytes: 0, overflow: false };
			} else if (cancelled || isAbort(error)) throw abortError();
			else throw error instanceof SshError ? error : new SshError("run_failed");
		}
		if (cancelled && !timedOut) throw abortError();
		if (!Buffer.isBuffer(execResult.stdout) || !Buffer.isBuffer(execResult.stderr) ||
			!Number.isSafeInteger(execResult.stdoutBytes) || execResult.stdoutBytes < 0 ||
			!Number.isSafeInteger(execResult.stderrBytes) || execResult.stderrBytes < 0 ||
			execResult.stdoutBytes < execResult.stdout.length || execResult.stderrBytes < execResult.stderr.length) throw new SshError("run_failed");
		if (execResult.overflow || (!bulk && execResult.stdout.length + execResult.stderr.length > MAX_SSH_OUTPUT_BYTES)) throw new SshError("output_overflow");
		const result = {
			mode: bulk ? "bulk" : "text",
			exitCode: Number.isSafeInteger(execResult.exitCode) ? execResult.exitCode : null,
			signal: typeof execResult.signal === "string" ? execResult.signal : null,
			durationMs: Math.max(0, now() - started),
			timedOut,
			cancelled,
			stdoutBytes: Number.isSafeInteger(execResult.stdoutBytes) ? execResult.stdoutBytes : 0,
			stderrBytes: Number.isSafeInteger(execResult.stderrBytes) ? execResult.stderrBytes : 0,
		};
		if (!bulk) {
			if (timedOut || cancelled) {
				result.stdout = "";
				result.stderr = "";
			} else {
				result.stdout = redactSshOutput(decodeOutput(execResult.stdout), selected);
				result.stderr = redactSshOutput(decodeOutput(execResult.stderr), selected);
				if (bytes(result.stdout) + bytes(result.stderr) > MAX_SSH_OUTPUT_BYTES) throw new SshError("output_overflow");
			}
		}
		return result;
	} catch (error) {
		if (timedOut && !connection) throw new SshError("timed_out");
		if (cancelled || (isAbort(error) && !timedOut)) throw abortError();
		if (error instanceof SshError) throw error;
		throw new SshError("run_failed");
	} finally {
		clearTimeout(timer);
		signal?.removeEventListener("abort", onAbort);
		controller.abort();
		const cleanup = await Promise.allSettled([
			Promise.resolve().then(() => connection?.close?.()),
			Promise.resolve().then(stopSource),
		]);
		privateKey.fill(0);
		passphrase?.fill(0);
		stdinBuffer?.fill(0);
		if (cleanup.some((entry) => entry.status === "rejected")) throw new SshError("run_failed");
	}
}
