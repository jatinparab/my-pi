import { chmod, lstat, mkdir, rm, stat, unlink } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { createServer } from "node:net";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createBitwardenAdapter } from "./bitwarden.mjs";
import { defaultKeychain, isMissingCredentialError } from "./keychain.mjs";
import { normalizeSetup, errorCode } from "./security.mjs";
import { FrameParser, ProtocolError, responseFrames, validateRequest } from "./protocol.mjs";
import { deriveSafeRecord, publicInspection, validateItemsInput, VaultContentError } from "./metadata.mjs";
import { executeVaultRun } from "./run.mjs";
import { createKnownHostsStore, createSshClient, executeVaultSsh } from "./ssh.mjs";

export const BROKER_IDLE_MS = 30 * 60 * 1_000;
export const VAULT_SESSION_IDLE_MS = 15 * 60 * 1_000;
// This is intentionally larger than the normal compact page target: the
// declared descriptor limits must remain inspectable, while this finite bound
// still keeps one model-visible result and each private snapshot bounded.
export const MAX_MODEL_METADATA_BYTES = 256 * 1024;
export const MAX_ACTIVE_SNAPSHOTS = 4;
export const MAX_ACTIVE_CURSORS = 1024;
export const MAX_SNAPSHOT_BYTES = 8 * 1024 * 1024;
export const MAX_CONFIG_ACKNOWLEDGEMENTS = 64;
export const MAX_IN_FLIGHT_CONFIG_OPERATIONS = 64;

class BrokerError extends Error {
	constructor(code) { super(code); this.name = "BrokerError"; this.code = code; }
}

async function removeSocketIfPresent(socketPath) {
	try {
		const info = await stat(socketPath);
		if (!info.isSocket()) throw new Error("broker endpoint is not a socket");
		await unlink(socketPath);
	} catch (error) {
		if (error?.code !== "ENOENT") throw error;
	}
}

function failureCode(result, operation) {
	if (result?.code === 0 && operation === "status" && !result?.state) return "invalid_cli_json";
	return result?.failure ?? (result?.code === 0 ? "cli_state" : "cli_error");
}

function opaque(prefix) { return `${prefix}_${randomUUID()}`; }

function throwFailure(result, operation) {
	if (result?.code !== 0 || result?.failure || (operation === "status" && !result?.state)) {
		throw new BrokerError(failureCode(result, operation));
	}
}

export function createBrokerServer({
	socketPath,
	profilePath = join(dirname(socketPath ?? ""), "profile"),
	idleMs = BROKER_IDLE_MS,
	sessionIdleMs = VAULT_SESSION_IDLE_MS,
	now = Date.now,
	adapter,
	keychain = defaultKeychain,
	runSpawn,
	sshConnect,
	knownHostsStore,
	writeResponse,
	maxInFlightConfigOperations = MAX_IN_FLIGHT_CONFIG_OPERATIONS,
	onRequest,
} = {}) {
	if (typeof socketPath !== "string" || socketPath.length === 0) throw new TypeError("socketPath is required");
	let server;
	let startPromise;
	let stopPromise;
	let idleTimer;
	let leaseTimer;
	let lastRequestAt = now();
	let session;
	let sessionLastActivity = 0;
	let configuredHost;
	let sessionCleared = false;
	let profileIdentity;
	let promptRequired = false;
	let stopping = false;
	let ownsSocket = false;
	let authChain = Promise.resolve();
	const itemHandles = new Map();
	const materialHandles = new Map();
	const attachmentHandles = new Map();
	const cursors = new Map();
	const snapshots = new Map();
	// A config acknowledgement is deliberately only the request id, state, and
	// normalized host. Keeping this bounded replay record allows a client to
	// recover when the destructive replacement commits before its socket reply
	// is delivered; it never stores wizard input or any Vault Material.
	const configAcknowledgements = new Map();
	const inFlightConfigOperations = new Map();
	const knownHostsPath = join(dirname(socketPath), "known_hosts.json");
	let knownHosts = knownHostsStore;
	const sshAdapter = sshConnect ?? createSshClient();
	const writeFrame = writeResponse ?? ((socket, frame) => socket.write(frame));
	const configCapacity = Number.isSafeInteger(maxInFlightConfigOperations) && maxInFlightConfigOperations > 0
		? maxInFlightConfigOperations : MAX_IN_FLIGHT_CONFIG_OPERATIONS;

	const configRecoveryResponse = (id) => ({ id, ok: false, error: "config_recovery" });
	const invalidateConfigAcknowledgements = () => {
		for (const [id, response] of configAcknowledgements) {
			if (response.ok === true) configAcknowledgements.set(id, configRecoveryResponse(id));
		}
	};

	const rememberConfigAcknowledgement = (id, response) => {
		configAcknowledgements.set(id, response);
		while (configAcknowledgements.size > MAX_CONFIG_ACKNOWLEDGEMENTS) configAcknowledgements.delete(configAcknowledgements.keys().next().value);
	};

	const evictSnapshot = (snapshotId) => {
		const snapshot = snapshots.get(snapshotId);
		if (!snapshot) return;
		for (const [handle, record] of itemHandles) if (record.snapshotId === snapshotId) itemHandles.delete(handle);
		for (const [handle, field] of materialHandles) if (field.snapshotId === snapshotId) materialHandles.delete(handle);
		for (const [handle, attachment] of attachmentHandles) if (attachment.snapshotId === snapshotId) attachmentHandles.delete(handle);
		for (const [cursor, saved] of cursors) if (saved.snapshotId === snapshotId) cursors.delete(cursor);
		snapshots.delete(snapshotId);
	};

	const addSnapshot = (snapshotId, records) => {
		snapshots.set(snapshotId, { records });
		while (snapshots.size > MAX_ACTIVE_SNAPSHOTS) evictSnapshot(snapshots.keys().next().value);
	};

	const addCursor = (cursor, saved) => {
		cursors.set(cursor, saved);
		while (cursors.size > MAX_ACTIVE_CURSORS) cursors.delete(cursors.keys().next().value);
	};
	const connections = new Set();
	const cli = adapter ?? createBitwardenAdapter({ profilePath });

	const serialize = (operation) => {
		const run = authChain.then(operation, operation);
		authChain = run.catch(() => {});
		return run;
	};

	const invalidateLeases = () => {
		itemHandles.clear();
		materialHandles.clear();
		attachmentHandles.clear();
		cursors.clear();
		snapshots.clear();
	};

	const clearSession = () => {
		session = undefined;
		sessionLastActivity = 0;
		invalidateLeases();
	};

	const expireSession = async () => {
		// This runs inside the broker's serialized lifecycle chain. Tombstone
		// config receipts here so an earlier in-flight replacement cannot commit
		// an ack after expiry, logout, profile replacement, or shutdown.
		invalidateConfigAcknowledgements();
		const current = session;
		sessionCleared = true;
		clearSession();
		if (current !== undefined) {
			try { await cli.lock(current); } catch { /* Lock failure cannot retain a secret handle. */ }
		}
	};

	const lockVault = async () => {
		const current = session;
		sessionCleared = true;
		clearSession();
		try {
			if (typeof cli.lock === "function") throwFailure(await cli.lock(current), "lock");
		} catch { /* Memory leases are invalid even when the CLI is unavailable. */ }
		return "locked";
	};

	const checkSessionLease = async () => {
		if (session !== undefined && now() - sessionLastActivity >= sessionIdleMs) await expireSession();
	};

	const scheduleLease = () => {
		if (leaseTimer) clearTimeout(leaseTimer);
		if (session === undefined || stopping) { leaseTimer = undefined; return; }
		const remaining = Math.max(1, sessionIdleMs - (now() - sessionLastActivity));
		leaseTimer = setTimeout(() => {
			leaseTimer = undefined;
			void serialize(async () => {
				await checkSessionLease();
				if (session !== undefined) scheduleLease();
			});
		}, remaining);
		leaseTimer.unref?.();
	};

	const establishSession = (candidate, host) => {
		if (typeof candidate !== "string" || candidate.length < 16 || candidate.length > 512) throw new BrokerError("invalid_cli_json");
		// A new Vault Session gets a fresh handle namespace. No handle or cursor
		// survives lock, logout, replacement, or automatic re-unlock.
		invalidateLeases();
		session = candidate;
		sessionCleared = false;
		sessionLastActivity = now();
		if (host) configuredHost = host;
		scheduleLease();
	};

	const profileExists = async () => {
		try {
			const info = await lstat(profilePath);
			if (!info.isDirectory() || (info.mode & 0o777) !== 0o700) {
				if (session !== undefined) await expireSession();
				throw new BrokerError("internal_error");
			}
			const identity = `${info.dev}:${info.ino}`;
			if (session !== undefined && profileIdentity !== undefined && identity !== profileIdentity) await expireSession();
			profileIdentity = identity;
			return true;
		} catch (error) {
			if (error instanceof BrokerError) throw error;
			if (error?.code === "ENOENT") return false;
			throw new BrokerError("internal_error");
		}
	};

	const ensureProfile = async () => {
		await mkdir(profilePath, { recursive: true, mode: 0o700 });
		await chmod(profilePath, 0o700);
		const info = await lstat(profilePath);
		if (!info.isDirectory() || (info.mode & 0o777) !== 0o700) throw new BrokerError("internal_error");
		profileIdentity = `${info.dev}:${info.ino}`;
	};

	const deleteInvalidStoredCredential = async () => {
		try { await keychain.delete(); }
		catch (error) { if (!isMissingCredentialError(error)) throw new BrokerError("keychain_unavailable"); }
		promptRequired = true;
	};

	const useStoredCredential = async (stateResult) => {
		let password;
		try { password = await keychain.get(); }
		catch { throw new BrokerError("keychain_unavailable"); }
		if (typeof password !== "string" || password.length === 0) return false;
		let result;
		try {
			if (stateResult.state === "unauthenticated") {
				if (!stateResult.userEmail) throw new BrokerError("cli_state");
				result = await cli.login(stateResult.userEmail, password);
			} else {
				result = await cli.unlock(password);
			}
		} finally {
			password = undefined;
		}
		if (result?.failure || result?.code !== 0) {
			if (result?.failure === "invalid_credentials") {
				await deleteInvalidStoredCredential();
				throw new BrokerError("invalid_credentials");
			}
			throw new BrokerError(result?.failure ?? "cli_error");
		}
		try { establishSession(result.session); }
		catch (error) { await expireSession(); throw error; }
		promptRequired = false;
		return true;
	};

	const getStatus = async () => {
		await checkSessionLease();
		if (!(await profileExists())) {
			if (session !== undefined) await expireSession();
			return "unconfigured";
		}
		let result = await cli.status({ session });
		if (result?.failure || result?.code !== 0 || !result?.state) throw new BrokerError(failureCode(result, "status"));
		if (session !== undefined && result.state === "unlocked") {
			sessionLastActivity = now();
			scheduleLease();
			return "unlocked";
		}
		if (session !== undefined) await expireSession();
		if (result.state === "unlocked") {
			// A broker restart cannot adopt a CLI session it did not create. Lock
			// that private CLI state first, then create a fresh broker-owned session.
			if (typeof cli.lock !== "function") throw new BrokerError("cli_unavailable");
			try { throwFailure(await cli.lock(undefined), "lock"); }
			catch (error) { throw error instanceof BrokerError ? error : new BrokerError("cli_error"); }
			result = { ...result, state: "locked" };
		}
		if (result.state === "unauthenticated" || result.state === "locked") {
			if (await useStoredCredential(result)) return "unlocked";
		}
		return result.state;
	};

	const reauthenticateAfterSyncFailure = async () => {
		if (typeof cli.status !== "function" || typeof cli.logout !== "function" || typeof cli.login !== "function") throw new BrokerError("cli_unavailable");
		const current = session;
		let before = await cli.status({ session: current });
		if (before?.failure || before?.code !== 0 || !before?.state) before = await cli.status({});
		throwFailure(before, "status");
		const userEmail = before.userEmail;

		// Drop every lease before replacing authentication. The stale session and
		// CLI diagnostics remain private even if logout cannot contact the server.
		sessionCleared = true;
		clearSession();
		try { await cli.logout(current); } catch { /* Status below is authoritative. */ }
		let loggedOut = await cli.status({});
		if (loggedOut?.state !== "unauthenticated") {
			try { await cli.logout(undefined); } catch { /* Retry local cleanup once. */ }
			loggedOut = await cli.status({});
		}
		throwFailure(loggedOut, "status");
		if (loggedOut.state !== "unauthenticated") throw new BrokerError("cli_state");
		if (!(await useStoredCredential({ ...loggedOut, userEmail: userEmail ?? loggedOut.userEmail }))) throw new BrokerError("cli_state");
	};

	const syncVault = async () => {
		if (typeof cli.sync !== "function") return;
		let synced = await cli.sync({ session });
		if (synced?.code !== 0 || synced?.failure) {
			// A transient server/network failure must not make the already-synced
			// local vault unusable. Authentication failures still recover or fail.
			if (synced?.failure === "network_error") return;
			if (!synced?.reauthenticationRequired) throwFailure(synced, "sync");
			await reauthenticateAfterSyncFailure();
			synced = await cli.sync({ session });
			throwFailure(synced, "sync");
		}
		sessionLastActivity = now();
		scheduleLease();
	};

	const inspectItems = async (params) => {
		let input;
		try { input = validateItemsInput(params); }
		catch (error) { throw new BrokerError(error instanceof VaultContentError ? error.code : "invalid_input"); }
		const state = await getStatus();
		if (input.action === "status") return { action: "status", state };
		// A stale lease token is an invalid token, not a way to probe the current
		// lock state. This also keeps later lifecycle commands fail-closed.
		if (input.action === "inspect" && !itemHandles.has(input.itemHandle)) throw new BrokerError("invalid_handle");
		if ((input.action === "list" || input.action === "search") && input.cursor !== undefined && !cursors.has(input.cursor)) throw new BrokerError("invalid_cursor");
		if (state !== "unlocked" || session === undefined) return { action: input.action, state };

		if (input.action === "inspect") {
			const record = itemHandles.get(input.itemHandle);
			if (!record || !snapshots.has(record.snapshotId)) throw new BrokerError("invalid_handle");
			const inspection = publicInspection(record);
			// Inspect is not paginated. Keep the model-visible success bounded while
			// still allowing the IPC chunker to carry a large (but valid) list page.
			if (Buffer.byteLength(JSON.stringify(inspection), "utf8") > MAX_MODEL_METADATA_BYTES) throw new BrokerError("invalid_item_data");
			return { action: "inspect", state: "unlocked", ...inspection };
		}

		let records;
		let start = 0;
		if (input.cursor !== undefined) {
			const saved = cursors.get(input.cursor);
			const snapshot = saved ? snapshots.get(saved.snapshotId) : undefined;
			if (!saved || !snapshot || saved.action !== input.action || saved.query !== input.query) throw new BrokerError("invalid_cursor");
			records = snapshot.records;
			start = saved.offset;
		} else {
			if (typeof cli.listItems !== "function") throw new BrokerError("cli_unavailable");
			// A fresh list/search observes server-side changes. Cursor continuations
			// remain pinned to their original bounded snapshot.
			await syncVault();
			const listed = await cli.listItems(input.action === "search" ? { search: input.query, session } : { session });
			throwFailure(listed, "list_items");
			if (!Array.isArray(listed.items)) throw new BrokerError("invalid_cli_json");
			let snapshotBytes;
			try { snapshotBytes = Buffer.byteLength(JSON.stringify(listed.items), "utf8"); }
			catch { throw new BrokerError("invalid_item_data"); }
			if (snapshotBytes > MAX_SNAPSHOT_BYTES) throw new BrokerError("output_overflow");
			let folders = [];
			if (typeof cli.listFolders === "function") {
				const folderResult = await cli.listFolders({ session });
				throwFailure(folderResult, "list_folders");
				folders = Array.isArray(folderResult.folders) ? folderResult.folders : [];
			}
			const folderNames = new Map(folders.filter((folder) => folder && typeof folder.id === "string" && typeof folder.name === "string").map((folder) => [folder.id, folder.name]));
			const snapshotId = opaque("s");
			records = listed.items.map((item) => deriveSafeRecord(item, folderNames, () => opaque("h")));
			for (const record of records) {
				record.snapshotId = snapshotId;
				itemHandles.set(record.itemHandle, record);
				for (const field of record.fields) { field.snapshotId = snapshotId; materialHandles.set(field.handle, field); }
				for (const attachment of record.attachments) { attachment.snapshotId = snapshotId; attachmentHandles.set(attachment.handle, attachment); }
			}
			addSnapshot(snapshotId, records);
		}
		const limit = input.limit ?? 100;
		let page = records.slice(start, start + limit);
		// The T1 socket frame remains bounded at 16 KiB. Keep the contractual
		// maximum of 100 while shrinking only unusually verbose metadata pages so
		// the safe response cannot fail after it has been derived.
		while (page.length > 1 && Buffer.byteLength(JSON.stringify({ id: "page", ok: true, result: { action: input.action, state: "unlocked", items: page.map((record) => record.summary), nextCursor: "c".repeat(48) } }), "utf8") > MAX_MODEL_METADATA_BYTES) page = page.slice(0, -1);
		if (Buffer.byteLength(JSON.stringify({ action: input.action, items: page.map((record) => record.summary) }), "utf8") > MAX_MODEL_METADATA_BYTES) throw new BrokerError("invalid_item_data");
		const nextOffset = start + page.length;
		if (nextOffset < records.length) {
			const cursor = opaque("c");
			const snapshotId = records[0]?.snapshotId;
			if (typeof snapshotId !== "string" || !snapshots.has(snapshotId)) throw new BrokerError("invalid_cursor");
			addCursor(cursor, { action: input.action, query: input.query, snapshotId, offset: nextOffset });
			return { action: input.action, state: "unlocked", items: page.map((record) => record.summary), nextCursor: cursor };
		}
		return { action: input.action, state: "unlocked", items: page.map((record) => record.summary) };
	};

	const runVaultCommand = async (params, signal) => {
		const state = await getStatus();
		if (state !== "unlocked" || session === undefined) throw new BrokerError("vault_not_unlocked");
		return await executeVaultRun(params, {
			resolveMaterial: (handle) => materialHandles.get(handle),
			resolveAttachment: (handle) => attachmentHandles.get(handle),
			adapter: cli,
			session,
			signal,
			spawn: runSpawn,
			now,
		});
	};

	const ensureKnownHosts = async () => {
		if (knownHosts) return knownHosts;
		knownHosts = await createKnownHostsStore({ storePath: knownHostsPath, now });
		return knownHosts;
	};

	const runSshCommand = async (params, signal) => {
		const state = await getStatus();
		if (state !== "unlocked" || session === undefined) throw new BrokerError("vault_not_unlocked");
		const store = await ensureKnownHosts();
		return await executeVaultSsh(params, {
			resolveMaterial: (handle) => materialHandles.get(handle),
			resolveAttachment: (handle) => attachmentHandles.get(handle),
			openAttachment: ({ itemId, attachmentId, signal: sourceSignal }) => {
				if (typeof cli.streamAttachment !== "function") throw new BrokerError("cli_unavailable");
				return cli.streamAttachment({ itemId, attachmentId, session, signal: sourceSignal });
			},
			sshConnect: sshAdapter,
			knownHosts: store,
			signal,
			now,
		});
	};

	const setup = async ({ server, email, masterPassword }) => {
		await checkSessionLease();
		invalidateConfigAcknowledgements();
		if (session !== undefined && !promptRequired) {
			// A setup request can arrive before a status request notices that the
			// CLI profile directory was replaced. Never keep the old lease alive.
			if (!(await profileExists())) await expireSession();
			if (session !== undefined) return { state: "unlocked", serverHost: configuredHost };
		}
		const normalized = normalizeSetup({ server, email, masterPassword });
		let password = normalized.masterPassword;
		try {
			await ensureProfile();
			const configured = await cli.configure(normalized.url);
			throwFailure(configured, "configure");
			const loggedIn = await cli.login(normalized.email, password);
			throwFailure(loggedIn, "login");
			if (!loggedIn.session) throw new BrokerError("invalid_cli_json");
			try { await keychain.set(password); }
			catch {
				try { await cli.lock(loggedIn.session); } catch { /* Clear local references even if lock cannot reach CLI. */ }
				throw new BrokerError("keychain_unavailable");
			}
			clearSession();
			establishSession(loggedIn.session, normalized.host);
			promptRequired = false;
			return { state: "unlocked", serverHost: normalized.host };
		} finally {
			password = undefined;
			normalized.masterPassword = undefined;
		}
	};

	const dedicatedProfilePath = resolve(join(dirname(socketPath), "profile"));
	const assertDedicatedProfile = () => {
		if (resolve(profilePath) !== dedicatedProfilePath) throw new BrokerError("internal_error");
	};

	const profileDirectoryPresent = async () => {
		try {
			const info = await lstat(profilePath);
			if (!info.isDirectory() || (info.mode & 0o777) !== 0o700) throw new BrokerError("internal_error");
			return true;
		} catch (error) {
			if (error instanceof BrokerError) throw error;
			if (error?.code === "ENOENT") return false;
			throw new BrokerError("internal_error");
		}
	};

	const removeDedicatedProfile = async () => {
		assertDedicatedProfile();
		try {
			const info = await lstat(profilePath);
			if (info.isSymbolicLink()) await unlink(profilePath);
			else await rm(profilePath, { recursive: true, force: true });
		} catch (error) {
			if (error?.code !== "ENOENT") throw error;
		}
	};

	const tryLogout = async (token) => {
		if (typeof cli.logout === "function") {
			throwFailure(await cli.logout(token), "logout");
			return;
		}
		if (typeof cli.lock === "function") throwFailure(await cli.lock(token), "lock");
		throw new BrokerError("cli_unavailable");
	};

	const cleanupNewProfile = async ({ profileOwned, newSession, keychainWriteAttempted }) => {
		let partial = false;
		if (newSession !== undefined) {
			try { await tryLogout(newSession); } catch { partial = true; }
		}
		if (keychainWriteAttempted) {
			try { await keychain.delete(); } catch { partial = true; }
		}
		if (profileOwned) {
			try { await removeDedicatedProfile(); } catch { partial = true; }
		}
		return partial;
	};

	const reconfigure = async ({ server, email, masterPassword }) => {
		// Validate before mutation. Invalidate leases, delete the old credential,
		// then remove the old profile. There is deliberately no backup directory:
		// every crash point is either the untouched old state or a credential-less
		// dedicated profile that can only be completed by the local TUI wizard.
		const normalized = normalizeSetup({ server, email, masterPassword });
		assertDedicatedProfile();
		let password = normalized.masterPassword;
		let profileOwned = false;
		let newSession;
		let keychainWriteAttempted = false;
		let oldCredentialDeleted = false;
		try {
			const current = session;
			sessionCleared = true;
			clearSession();
			const hadProfile = await profileDirectoryPresent();
			if (current === undefined && hadProfile) {
				// A broker/Keychain status failure must not suppress old-profile
				// cleanup. This probe is diagnostic only; its result is never exposed.
				try { await cli.status({}); } catch { /* logout below remains best effort */ }
			}
			if (hadProfile || current !== undefined) {
				try { await tryLogout(current); } catch { /* credential/profile deletion isolates old state */ }
			}
			// This is the destructive boundary. If Keychain deletion fails, the
			// old profile remains untouched and no replacement is attempted.
			try { await keychain.delete(); }
			catch { throw new BrokerError("keychain_unavailable"); }
			oldCredentialDeleted = true;
			profileOwned = true;
			if (hadProfile) await removeDedicatedProfile();
			await ensureProfile();
			profileOwned = true;
			throwFailure(await cli.configure(normalized.url), "configure");
			const loggedIn = await cli.login(normalized.email, password);
			throwFailure(loggedIn, "login");
			newSession = loggedIn?.session;
			if (typeof newSession !== "string") throw new BrokerError("invalid_cli_json");
			keychainWriteAttempted = true;
			await keychain.set(password);
			clearSession();
			establishSession(newSession, normalized.host);
			promptRequired = false;
			return { state: "unlocked", serverHost: normalized.host };
		} catch (error) {
			sessionCleared = true;
			clearSession();
			const partial = await cleanupNewProfile({ profileOwned, newSession, keychainWriteAttempted });
			if (oldCredentialDeleted || profileOwned) {
				profileIdentity = undefined;
				configuredHost = undefined;
				promptRequired = true;
			}
			if (partial) throw new BrokerError("cleanup_partial");
			throw error instanceof BrokerError ? error : new BrokerError("cli_error");
		} finally {
			password = undefined;
			normalized.masterPassword = undefined;
		}
	};

	const forget = async () => {
		// Invalidate before logout/deletion so a cancelled, crashed, or partially
		// failing cleanup can never leave an old opaque handle usable.
		const current = session;
		sessionCleared = true;
		clearSession();
		let partial = false;
		try {
			if (typeof cli.logout === "function") throwFailure(await cli.logout(current), "logout");
			else if (typeof cli.lock === "function" && current !== undefined) throwFailure(await cli.lock(current), "lock");
		} catch { partial = true; }
		try { await keychain.delete(); } catch { partial = true; }
		try { await removeDedicatedProfile(); } catch { partial = true; }
		profileIdentity = undefined;
		configuredHost = undefined;
		promptRequired = true;
		return { action: "forget", state: "unconfigured", cleanup: partial ? "partial" : "complete" };
	};

	const stop = () => {
		if (stopPromise) return stopPromise;
		stopping = true;
		if (idleTimer) clearTimeout(idleTimer);
		if (leaseTimer) clearTimeout(leaseTimer);
		idleTimer = undefined;
		leaseTimer = undefined;
		stopPromise = (async () => {
			await serialize(expireSession);
			for (const socket of connections) socket.destroy();
			if (knownHosts) await knownHosts.close().catch(() => {});
			if (startPromise) await startPromise.catch(() => {});
			if (!server || !ownsSocket) return;
			if (server.listening) await new Promise((resolve) => server.close(() => resolve()));
			ownsSocket = false;
			await removeSocketIfPresent(socketPath).catch(() => {});
		})();
		return stopPromise;
	};

	const checkIdle = () => {
		if (!stopping && now() - lastRequestAt >= idleMs) void stop();
		else if (!stopping) scheduleIdleCheck();
	};
	const scheduleIdleCheck = () => {
		if (stopping) return;
		if (idleTimer) clearTimeout(idleTimer);
		const remaining = Math.max(1, idleMs - (now() - lastRequestAt));
		idleTimer = setTimeout(checkIdle, remaining);
		idleTimer.unref?.();
	};

	const performRequest = async (request, signal) => {
		if (request.method === "status") return { id: request.id, ok: true, state: await serialize(getStatus) };
		if (request.method === "lock") return { id: request.id, ok: true, state: await serialize(async () => { invalidateConfigAcknowledgements(); return lockVault(); }) };
		if (request.method === "forget") return { id: request.id, ok: true, result: await serialize(async () => { invalidateConfigAcknowledgements(); return forget(); }) };
		if (request.method === "items") return { id: request.id, ok: true, result: await serialize(() => inspectItems(request.params)) };
		if (request.method === "run") return { id: request.id, ok: true, result: await serialize(() => runVaultCommand(request.params, signal)) };
		if (request.method === "sshRun") return { id: request.id, ok: true, result: await serialize(() => runSshCommand(request.params, signal)) };
		if (request.method === "config") {
			const cached = configAcknowledgements.get(request.id);
			if (cached) return cached;
			const existing = inFlightConfigOperations.get(request.id);
			if (existing) return existing.promise;
			if (inFlightConfigOperations.size >= configCapacity) throw new BrokerError("over_limit");

			// Install the record before calling serialize: a recovery connection can
			// arrive while the first replacement is still waiting on the CLI.
			let resolveOperation;
			let rejectOperation;
			const promise = new Promise((resolve, reject) => { resolveOperation = resolve; rejectOperation = reject; });
			const record = { promise };
			inFlightConfigOperations.set(request.id, record);
			void (async () => {
				try {
					const response = await serialize(async () => {
						invalidateConfigAcknowledgements();
						const result = await reconfigure(request.params);
						const response = { id: request.id, ok: true, state: result.state, serverHost: result.serverHost };
						// Record the safe ack inside the serialized operation, before
						// another lifecycle operation can run after it.
						rememberConfigAcknowledgement(request.id, response);
						return response;
					});
					resolveOperation(response);
				} catch (error) {
					rejectOperation(error);
				} finally {
					if (inFlightConfigOperations.get(request.id) === record) inFlightConfigOperations.delete(request.id);
				}
			})();
			return promise;
		}
		const result = await serialize(() => setup(request.params));
		return { id: request.id, ok: true, state: result.state, serverHost: result.serverHost };
	};

	const onConnection = (socket) => {
		connections.add(socket);
		const parser = new FrameParser();
		const requestIds = new Set();
		const requestAbort = new AbortController();
		let closed = false;
		let queue = Promise.resolve();
		const close = () => { if (!closed) { closed = true; requestAbort.abort(); connections.delete(socket); } };
		socket.on("data", (chunk) => {
			if (closed) return;
			try {
				for (const raw of parser.push(chunk)) {
					const request = validateRequest(raw);
					if (requestIds.has(request.id)) throw new ProtocolError("duplicate request id");
					requestIds.add(request.id);
					onRequest?.(request);
					lastRequestAt = now();
					queue = queue.then(async () => {
						try {
							let response = await performRequest(request, requestAbort.signal);
							// Lifecycle invalidation may have run while this request was
							// awaiting the shared operation. Send the current tombstone,
							// never a stale unlocked config state.
							if (request.method === "config") response = configAcknowledgements.get(request.id) ?? response;
							if (!closed && !socket.destroyed) {
								let frames;
								try { frames = responseFrames(response); }
								catch {
									// A committed config must never be reported as an ordinary
									// internal failure if safe acknowledgement validation fails.
									// Preserve the replay slot and return a bounded recovery code.
									if (request.method !== "config" || !configAcknowledgements.has(request.id)) throw new Error("response validation failed");
									const recovery = { id: request.id, ok: false, error: "config_recovery" };
									rememberConfigAcknowledgement(request.id, recovery);
									frames = responseFrames(recovery);
								}
								for (const frame of frames) writeFrame(socket, frame);
							}
						} catch (error) {
							// Once a config ack exists, this request has crossed the
							// destructive boundary. Do not turn a failed socket write into
							// a misleading internal_error; force the client down its
							// same-id replay path instead.
							if (request.method === "config" && configAcknowledgements.has(request.id)) { socket.destroy(); return; }
							const code = ["invalid_server", "invalid_email", "invalid_password", "invalid_credentials", "network_error", "keychain_unavailable", "cli_unavailable", "cli_error", "cli_state", "invalid_cli_json", "config_recovery", "output_overflow", "invalid_input", "invalid_action", "invalid_cursor", "invalid_handle", "vault_not_unlocked", "invalid_item_data", "over_limit", "duplicate_handle", "wrong_item", "material_incompatible", "material_unavailable", "run_failed", "cleanup_partial", "host_key_changed", "auth_failed", "timed_out", "host_key_unavailable", "internal_error"].includes(errorCode(error)) ? errorCode(error) : "internal_error";
							if (!closed && !socket.destroyed) for (const frame of responseFrames({ id: request.id, ok: false, error: code })) writeFrame(socket, frame);
						}
					}).catch(() => {});
				}
				scheduleIdleCheck();
			} catch {
				socket.destroy();
			}
		});
		socket.on("error", close);
		socket.on("close", close);
		socket.on("end", close);
	};

	const startImplementation = async () => {
		await mkdir(dirname(socketPath), { recursive: true, mode: 0o700 });
		await chmod(dirname(socketPath), 0o700);
		server = createServer(onConnection);
		await new Promise((resolve, reject) => {
			server.once("error", reject);
			server.listen(socketPath, () => resolve());
		});
		ownsSocket = true;
		if (stopping) {
			await new Promise((resolve) => server.close(() => resolve()));
			ownsSocket = false;
			await removeSocketIfPresent(socketPath).catch(() => {});
			return;
		}
		await chmod(socketPath, 0o600);
		const info = await stat(socketPath);
		if ((info.mode & 0o777) !== 0o600) throw new Error("broker socket permissions could not be restricted");
		scheduleIdleCheck();
	};

	const start = () => { if (!startPromise) startPromise = startImplementation(); return startPromise; };
	return {
		start,
		stop,
		checkIdle,
		checkSessionIdle: () => serialize(checkSessionLease),
		// T1 exposed a lifecycle sentinel before the first vault session existed;
		// retain that observable until the first expiry/shutdown while keeping the
		// actual session token private and memory-only.
		isSessionPresent: () => !sessionCleared,
		// Lifecycle seams for later lock/logout/profile replacement commands. They
		// invalidate all opaque leases before any future CLI state is adopted.
		invalidateSession: () => serialize(expireSession),
		logout: () => serialize(async () => { invalidateConfigAcknowledgements(); return expireSession(); }),
		replaceProfile: () => serialize(async () => { invalidateConfigAcknowledgements(); return expireSession(); }),
		isRunning: () => Boolean(server?.listening) && !stopping,
		profilePath,
		// Test/lifecycle seam: this reports only lease presence, never the
		// material itself. T4 will use the same private map for delivery.
		hasMaterialHandle: (handle) => typeof handle === "string" && materialHandles.has(handle),
		hasAttachmentHandle: (handle) => typeof handle === "string" && attachmentHandles.has(handle),
		activeSnapshotCount: () => snapshots.size,
	};
}

async function main() {
	const socketPath = process.argv[2] || process.env.VAULT_BROKER_SOCKET;
	if (!socketPath) process.exitCode = 2;
	else {
		const broker = createBrokerServer({ socketPath });
		try {
			await broker.start();
			const shutdown = () => { void broker.stop().finally(() => process.exit(0)); };
			process.once("SIGTERM", shutdown);
			process.once("SIGINT", shutdown);
			process.once("SIGHUP", shutdown);
		} catch {
			await broker.stop();
			process.exitCode = 1;
		}
	}
}

const invokedPath = process.argv[1] ? pathToFileURL(process.argv[1]).href : "";
if (import.meta.url === invokedPath) void main();
