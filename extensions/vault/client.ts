import { chmod, mkdir, open, readFile, stat, unlink } from "node:fs/promises";
import { spawn as nodeSpawn, type ChildProcess } from "node:child_process";
import { randomUUID } from "node:crypto";
import { homedir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import net from "node:net";
import { FrameParser, MAX_CHUNKED_ENCODED_BYTES, MAX_CHUNKED_RESULT_BYTES, ProtocolError, configFrame, itemsFrame, lifecycleFrame, requestFrame, runFrame, setupFrame, sshFrame, validateResponse } from "./protocol.mjs";
import { RUN_TRANSPORT_GRACE_MS, validateVaultRunInput } from "./run.mjs";
import { SSH_TRANSPORT_GRACE_MS, validateVaultSshInput } from "./ssh.mjs";
import type { VaultItemsInput, VaultItemsResult, VaultRunInput, VaultRunResult, VaultSshRunInput, VaultSshRunResult } from "./items-types.ts";

export type VaultStatus = "unconfigured" | "unauthenticated" | "locked" | "unlocked";
export type SetupInput = { server: string; email: string; masterPassword: string };
export type ForgetResult = { action: "forget"; state: "unconfigured"; cleanup: "complete" | "partial" };
export type { VaultItemsInput, VaultItemsResult, VaultRunInput, VaultRunResult, VaultSshRunInput, VaultSshRunResult } from "./items-types.ts";
export const STARTUP_TIMEOUT_MS = 15_000;
export const STARTUP_LOCK_MAX_AGE_MS = 10_000;
export const CONNECT_TIMEOUT_MS = 2_000;
export const REQUEST_TIMEOUT_MS = 35_000;
// A config response can be lost after the broker has replaced its profile.
// Retry the same request ID briefly so the broker can replay its safe ack
// without repeating the destructive replacement.
export const CONFIG_RECOVERY_TIMEOUT_MS = 2_000;

export type BrokerPaths = { directory: string; socketPath: string; lockPath: string; brokerPath: string };
type Spawn = (command: string, args: string[], options: { detached: boolean; stdio: "ignore"; env: NodeJS.ProcessEnv }) => ChildProcess;

export class BrokerRequestError extends Error {
	code: string;
	constructor(code: string) { super(code); this.name = "BrokerRequestError"; this.code = code; }
}

class BrokerTransportError extends Error {
	constructor(message: string) { super(message); this.name = "BrokerTransportError"; }
}

export function brokerPaths(options: { directory?: string; socketPath?: string; lockPath?: string; brokerPath?: string } = {}): BrokerPaths {
	const directory = options.directory ?? process.env.PI_VAULT_BROKER_DIR ?? join(homedir(), ".pi", "vault-broker");
	return {
		directory,
		socketPath: options.socketPath ?? join(directory, "broker.sock"),
		lockPath: options.lockPath ?? join(directory, "startup.lock"),
		brokerPath: options.brokerPath ?? fileURLToPath(new URL("./broker.mjs", import.meta.url)),
	};
}

function abortError(): Error { return new DOMException("The operation was cancelled", "AbortError"); }
function isAbort(error: unknown): boolean { return error instanceof DOMException && error.name === "AbortError"; }
function sleep(ms: number, signal?: AbortSignal): Promise<void> {
	return new Promise((resolve, reject) => {
		if (signal?.aborted) return reject(abortError());
		let timer: ReturnType<typeof setTimeout> | undefined;
		const cleanup = () => { if (timer) clearTimeout(timer); signal?.removeEventListener("abort", abort); };
		const abort = () => { cleanup(); reject(abortError()); };
		timer = setTimeout(() => { cleanup(); resolve(); }, ms);
		signal?.addEventListener("abort", abort, { once: true });
	});
}

async function ensurePrivateDirectory(directory: string): Promise<void> {
	await mkdir(directory, { recursive: true, mode: 0o700 });
	await chmod(directory, 0o700);
	const info = await stat(directory);
	if (!info.isDirectory() || (info.mode & 0o777) !== 0o700) throw new Error("Vault Broker runtime directory is not private");
}
async function removeStaleSocket(socketPath: string): Promise<void> {
	try {
		const info = await stat(socketPath);
		if (!info.isSocket()) throw new Error("Vault Broker endpoint is not a socket");
		await unlink(socketPath);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
	}
}
function socketError(message: string): Error { return new BrokerTransportError(message); }

async function requestResponse<T extends { id: string; ok: boolean; state?: VaultStatus; serverHost?: string; result?: unknown; error?: string }>(
	socketPath: string,
	frame: Buffer,
	id: string,
	signal?: AbortSignal,
	requestTimeoutMs = REQUEST_TIMEOUT_MS,
): Promise<T> {
	if (signal?.aborted) throw abortError();
	return await new Promise<T>((resolve, reject) => {
		const parser = new FrameParser();
		const chunks = new Map<number, string>();
		let chunkCount: number | undefined;
		let encodedLength = 0;
		let settled = false;
		let timer: ReturnType<typeof setTimeout> | undefined;
		const socket = net.createConnection(socketPath);
		const finish = (error?: unknown, value?: T) => {
			if (settled) return;
			settled = true;
			if (timer) clearTimeout(timer);
			signal?.removeEventListener("abort", onAbort);
			socket.destroy();
			if (error) reject(error); else resolve(value!);
		};
		const onAbort = () => finish(abortError());
		signal?.addEventListener("abort", onAbort, { once: true });
		timer = setTimeout(() => finish(socketError("Vault Broker request timed out")), requestTimeoutMs);
		timer.unref?.();
		socket.once("connect", () => {
			try { socket.write(frame); }
			catch { finish(socketError("Vault Broker request could not be framed")); }
		});
		socket.on("data", (chunk) => {
			try {
				for (const raw of parser.push(chunk)) {
					const response = validateResponse(raw) as T & { chunkIndex?: number; chunkCount?: number; data?: string };
					if (response.id !== id) throw new ProtocolError("response id mismatch");
					if (!response.ok) { finish(new BrokerRequestError(response.error ?? "internal_error")); continue; }
					if (response.chunkIndex !== undefined) {
						if (chunkCount === undefined) chunkCount = response.chunkCount;
						if (chunkCount !== response.chunkCount || chunks.has(response.chunkIndex) || response.data === undefined) throw new ProtocolError("invalid response chunks");
						encodedLength += response.data.length;
						if (encodedLength > MAX_CHUNKED_ENCODED_BYTES) throw new ProtocolError("invalid response chunks");
						chunks.set(response.chunkIndex, response.data);
						if (chunks.size !== chunkCount) continue;
						const encoded = Array.from({ length: chunkCount }, (_, index) => chunks.get(index)).join("");
						let result: unknown;
						try {
							const decoded = Buffer.from(encoded, "base64");
							if (decoded.length > MAX_CHUNKED_RESULT_BYTES) throw new Error("decoded response exceeds bound");
							const text = new TextDecoder("utf-8", { fatal: true }).decode(decoded);
							result = JSON.parse(text);
						} catch { throw new ProtocolError("invalid response chunks"); }
						finish(undefined, validateResponse({ id, ok: true, result }) as T);
					} else finish(undefined, response);
				}
			} catch (error) {
				if (error instanceof BrokerRequestError) return;
				finish(socketError("Vault Broker returned an invalid response"));
			}
		});
		socket.once("error", () => finish(socketError("Vault Broker is unavailable")));
		socket.once("close", () => { if (!settled) finish(socketError("Vault Broker disconnected")); });
	});
}

export async function requestStatus(socketPath: string, signal?: AbortSignal): Promise<VaultStatus> {
	const id = randomUUID();
	const response = await requestResponse(socketPath, requestFrame(id), id, signal);
	if (response.state === undefined) throw socketError("Vault Broker returned no state");
	return response.state;
}

export async function requestSetup(socketPath: string, params: SetupInput, signal?: AbortSignal): Promise<{ state: VaultStatus; serverHost: string }> {
	const id = randomUUID();
	const response = await requestResponse(socketPath, setupFrame(id, params), id, signal);
	if (response.state === undefined || typeof response.serverHost !== "string") throw socketError("Vault Broker returned an incomplete setup response");
	return { state: response.state, serverHost: response.serverHost };
}

export async function requestConfig(socketPath: string, params: SetupInput, signal?: AbortSignal): Promise<{ state: VaultStatus; serverHost: string }> {
	const id = randomUUID();
	const frame = configFrame(id, params);
	const readAck = async (timeoutMs = REQUEST_TIMEOUT_MS) => {
		const response = await requestResponse(socketPath, frame, id, signal, timeoutMs);
		if (response.state === undefined || typeof response.serverHost !== "string") throw socketError("Vault Broker returned an incomplete config response");
		return response;
	};
	let response: Awaited<ReturnType<typeof readAck>>;
	try {
		response = await readAck();
	} catch (error) {
		// A transport/parser failure is ambiguous: the broker may have committed
		// before the client lost its response. Replaying the same id is safe and
		// lets the broker return its bounded, non-secret acknowledgement. Never
		// retry cancellation or a broker-declared operation failure.
		if (!(error instanceof BrokerTransportError)) throw error;
		try { response = await readAck(CONFIG_RECOVERY_TIMEOUT_MS); }
		catch (retryError) {
			if (retryError instanceof BrokerRequestError) throw retryError;
			throw new BrokerRequestError("config_recovery");
		}
	}
	return { state: response.state!, serverHost: response.serverHost! };
}

export async function requestLock(socketPath: string, signal?: AbortSignal): Promise<VaultStatus> {
	const id = randomUUID();
	const response = await requestResponse(socketPath, lifecycleFrame(id, "lock"), id, signal);
	if (response.state !== "locked") throw socketError("Vault Broker returned an incomplete lock response");
	return response.state;
}

export async function requestForget(socketPath: string, signal?: AbortSignal): Promise<ForgetResult> {
	const id = randomUUID();
	const response = await requestResponse(socketPath, lifecycleFrame(id, "forget"), id, signal);
	if (!response.result || typeof response.result !== "object") throw socketError("Vault Broker returned an incomplete forget response");
	return response.result as ForgetResult;
}

export async function requestVaultItems(socketPath: string, params: VaultItemsInput, signal?: AbortSignal): Promise<VaultItemsResult> {
	const id = randomUUID();
	const response = await requestResponse(socketPath, itemsFrame(id, params), id, signal);
	if (!response.result || typeof response.result !== "object") throw socketError("Vault Broker returned an incomplete items response");
	return response.result as VaultItemsResult;
}

export function vaultRunRequestTimeoutMs(params: VaultRunInput): number {
	return validateVaultRunInput(params).timeoutMs + RUN_TRANSPORT_GRACE_MS;
}

export async function requestVaultRun(socketPath: string, params: VaultRunInput, signal?: AbortSignal): Promise<VaultRunResult> {
	const id = randomUUID();
	const validated = validateVaultRunInput(params);
	const response = await requestResponse(socketPath, runFrame(id, validated), id, signal, vaultRunRequestTimeoutMs(validated));
	if (!response.result || typeof response.result !== "object") throw socketError("Vault Broker returned an incomplete run response");
	return response.result as VaultRunResult;
}

export function vaultSshRunRequestTimeoutMs(params: VaultSshRunInput): number {
	return validateVaultSshInput(params).timeoutMs + SSH_TRANSPORT_GRACE_MS;
}

export async function requestVaultSshRun(socketPath: string, params: VaultSshRunInput, signal?: AbortSignal): Promise<VaultSshRunResult> {
	const id = randomUUID();
	const validated = validateVaultSshInput(params);
	const response = await requestResponse(socketPath, sshFrame(id, validated), id, signal, vaultSshRunRequestTimeoutMs(validated));
	if (!response.result || typeof response.result !== "object") throw socketError("Vault Broker returned an incomplete ssh run response");
	return response.result as VaultSshRunResult;
}

async function readLock(lockPath: string): Promise<{ pid: number; createdAt: number } | undefined> {
	try {
		const [text, info] = await Promise.all([readFile(lockPath, "utf8"), stat(lockPath)]);
		const value = JSON.parse(text) as { pid?: unknown; createdAt?: unknown };
		const pid = typeof value.pid === "number" && Number.isSafeInteger(value.pid) && value.pid > 0 ? value.pid : 0;
		const createdAt = typeof value.createdAt === "number" && Number.isFinite(value.createdAt) ? value.createdAt : info.mtimeMs;
		return { pid, createdAt };
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
		try { return { pid: 0, createdAt: (await stat(lockPath)).mtimeMs }; }
		catch (statError) {
			if ((statError as NodeJS.ErrnoException).code === "ENOENT") return undefined;
			return { pid: 0, createdAt: Date.now() };
		}
	}
}
function processExists(pid: number): boolean { if (!pid) return false; try { process.kill(pid, 0); return true; } catch { return false; } }
async function recoverStaleLock(lockPath: string, now: number): Promise<void> {
	const lock = await readLock(lockPath);
	if (!lock) return;
	const stale = now - lock.createdAt > STARTUP_LOCK_MAX_AGE_MS && !processExists(lock.pid);
	if (stale || (lock.pid === 0 && now - lock.createdAt > STARTUP_LOCK_MAX_AGE_MS)) await unlink(lockPath).catch((error) => { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; });
}
async function acquireLock(lockPath: string, now: () => number, signal?: AbortSignal): Promise<import("node:fs/promises").FileHandle | undefined> {
	await recoverStaleLock(lockPath, now());
	try {
		const handle = await open(lockPath, "wx", 0o600);
		await handle.writeFile(JSON.stringify({ pid: process.pid, createdAt: now() }), "utf8");
		await handle.chmod(0o600);
		return handle;
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "EEXIST") return undefined;
		if (isAbort(error)) throw error;
		throw error;
	}
}
function spawnBroker(paths: BrokerPaths, spawn: Spawn): ChildProcess {
	const env: NodeJS.ProcessEnv = { PATH: process.env.PATH ?? "/usr/bin:/bin", HOME: process.env.HOME ?? homedir(), TMPDIR: process.env.TMPDIR, VAULT_BROKER_SOCKET: paths.socketPath };
	const child = spawn(process.execPath, [paths.brokerPath, paths.socketPath], { detached: true, stdio: "ignore", env });
	child.unref();
	return child;
}

export type VaultClientOptions = {
	paths?: Partial<BrokerPaths>;
	startupTimeoutMs?: number;
	connect?: (socketPath: string, signal?: AbortSignal) => Promise<VaultStatus>;
	spawn?: Spawn;
	now?: () => number;
	sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
};

export class VaultBrokerClient {
	private readonly options: Required<Pick<VaultClientOptions, "startupTimeoutMs" | "now" | "sleep">> & VaultClientOptions;
	constructor(options: VaultClientOptions = {}) { this.options = { startupTimeoutMs: STARTUP_TIMEOUT_MS, now: Date.now, sleep, ...options }; }

	async status(signal?: AbortSignal): Promise<VaultStatus> {
		const paths = brokerPaths(this.options.paths);
		const connect = this.options.connect ?? requestStatus;
		await ensurePrivateDirectory(paths.directory);
		try { return await connect(paths.socketPath, signal); }
		catch (error) { if (isAbort(error)) throw error; }
		const deadline = this.options.now() + this.options.startupTimeoutMs;
		let lockHandle;
		while (this.options.now() < deadline) {
			if (signal?.aborted) throw abortError();
			lockHandle = await acquireLock(paths.lockPath, this.options.now, signal);
			if (lockHandle) break;
			try { return await connect(paths.socketPath, signal); } catch (error) { if (isAbort(error)) throw error; }
			await recoverStaleLock(paths.lockPath, this.options.now());
			await this.options.sleep(25, signal);
		}
		if (!lockHandle) throw new Error("Vault Broker did not become ready");
		try {
			try { return await connect(paths.socketPath, signal); } catch (error) { if (isAbort(error)) throw error; }
			await removeStaleSocket(paths.socketPath).catch((error) => { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; });
			spawnBroker(paths, this.options.spawn ?? ((command, args, options) => nodeSpawn(command, args, options)));
			while (this.options.now() < deadline) {
				try { return await connect(paths.socketPath, signal); }
				catch (error) { if (isAbort(error)) throw error; await this.options.sleep(25, signal); }
			}
			throw new Error("Vault Broker did not become ready");
		} finally {
			await lockHandle.close().catch(() => {});
			await unlink(paths.lockPath).catch(() => {});
		}
	}

	async setup(params: SetupInput, signal?: AbortSignal): Promise<{ state: VaultStatus; serverHost: string }> {
		try { await this.status(signal); } catch (error) { if (isAbort(error)) throw error; }
		return requestSetup(brokerPaths(this.options.paths).socketPath, params, signal);
	}

	async config(params: SetupInput, signal?: AbortSignal): Promise<{ state: VaultStatus; serverHost: string }> {
		try { await this.status(signal); } catch (error) { if (isAbort(error)) throw error; }
		return requestConfig(brokerPaths(this.options.paths).socketPath, params, signal);
	}

	async lock(signal?: AbortSignal): Promise<VaultStatus> {
		try { await this.status(signal); } catch (error) { if (isAbort(error)) throw error; }
		return requestLock(brokerPaths(this.options.paths).socketPath, signal);
	}

	async forget(signal?: AbortSignal): Promise<ForgetResult> {
		try { await this.status(signal); } catch (error) { if (isAbort(error)) throw error; }
		return requestForget(brokerPaths(this.options.paths).socketPath, signal);
	}

	async items(params: VaultItemsInput, signal?: AbortSignal): Promise<VaultItemsResult> {
		try {
			const state = await this.status(signal);
			if (state !== "unlocked") return { action: params.action, state } as VaultItemsResult;
		} catch (error) { if (isAbort(error)) throw error; }
		return requestVaultItems(brokerPaths(this.options.paths).socketPath, params, signal);
	}

	async run(params: VaultRunInput, signal?: AbortSignal): Promise<VaultRunResult> {
		try { await this.status(signal); }
		catch (error) { if (isAbort(error)) throw error; }
		return requestVaultRun(brokerPaths(this.options.paths).socketPath, params, signal);
	}

	async sshRun(params: VaultSshRunInput, signal?: AbortSignal): Promise<VaultSshRunResult> {
		try { await this.status(signal); }
		catch (error) { if (isAbort(error)) throw error; }
		return requestVaultSshRun(brokerPaths(this.options.paths).socketPath, params, signal);
	}
}

export const defaultVaultBrokerClient = () => new VaultBrokerClient();
