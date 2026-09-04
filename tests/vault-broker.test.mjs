import assert from "node:assert/strict";
import { spawn as nodeSpawn } from "node:child_process";
import { createConnection, createServer } from "node:net";
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createJiti } from "jiti";

const jiti = createJiti(import.meta.url);
const protocol = await import("../extensions/vault/protocol.mjs");
const { createBrokerServer } = await import("../extensions/vault/broker.mjs");
const { VaultBrokerClient, brokerPaths, requestSetup, requestStatus, requestVaultItems, BrokerRequestError } = await jiti.import("../extensions/vault/client.ts");
const { registerVaultExtension } = await jiti.import("../extensions/vault/index.ts");
const security = await import("../extensions/vault/security.mjs");
const bitwarden = await import("../extensions/vault/bitwarden.mjs");
const { FrameParser, MAX_CHUNKED_ENCODED_BYTES, MAX_FRAME_BYTES, ProtocolError, encodeFrame, validateRequest, validateResponse } = protocol;

async function eventually(predicate, timeout = 2_000) {
	const deadline = Date.now() + timeout;
	while (Date.now() < deadline) { if (await predicate()) return; await new Promise((resolve) => setTimeout(resolve, 10)); }
	assert.fail("condition did not become true");
}
function rawConnection(socketPath, handler) {
	return new Promise((resolve, reject) => {
		const sockets = new Set();
		const server = createServer((socket) => { sockets.add(socket); socket.once("close", () => sockets.delete(socket)); handler(socket); });
		server.destroyConnections = () => { for (const socket of sockets) socket.destroy(); };
		server.once("error", reject); server.listen(socketPath, () => resolve(server));
	});
}

test("length-prefixed framing is bounded and supports partial and multiple frames", () => {
	const parser = new FrameParser(); const first = encodeFrame({ ok: true }); const second = encodeFrame({ id: "two" });
	assert.deepEqual(parser.push(first.subarray(0, 2)), []);
	assert.deepEqual(parser.push(Buffer.concat([first.subarray(2), second])), [{ ok: true }, { id: "two" }]);
	const oversized = Buffer.alloc(4); oversized.writeUInt32BE(MAX_FRAME_BYTES + 1);
	assert.throws(() => parser.push(oversized), ProtocolError); assert.throws(() => parser.push(Buffer.alloc(MAX_FRAME_BYTES + 5)), ProtocolError);
	assert.throws(() => parser.push(Buffer.from([0, 0, 0, 1, 0x7b])), ProtocolError);
});
test("chunk validation matches producer size, padding, and aggregate bounds", () => {
	const full = "A".repeat(10 * 1024);
	assert.doesNotThrow(() => validateResponse({ id: "x", ok: true, chunkIndex: 0, chunkCount: 2, data: full }));
	assert.throws(() => validateResponse({ id: "x", ok: true, chunkIndex: 0, chunkCount: 2, data: "A".repeat(15_000) }), ProtocolError);
	assert.throws(() => validateResponse({ id: "x", ok: true, chunkIndex: 0, chunkCount: 2, data: "YQ==" }), ProtocolError);
	assert.throws(() => validateResponse({ id: "x", ok: true, chunkIndex: 0, chunkCount: 2, data: "AAA" }), ProtocolError);
	assert.throws(() => validateResponse({ id: "x", ok: true, chunkIndex: 0, chunkCount: 1025, data: full }), ProtocolError);
	assert.equal(MAX_CHUNKED_ENCODED_BYTES, 10 * 1024 * 1024);
});

test("request and response schemas are strict and preserve request IDs", () => {
	assert.deepEqual(validateRequest({ id: "abc", method: "status", params: {} }), { id: "abc", method: "status", params: {} });
	assert.throws(() => validateRequest({ id: "abc", method: "status", params: {}, extra: 1 }), ProtocolError);
	assert.throws(() => validateRequest({ id: "abc", method: "status", params: { secret: "no" } }), ProtocolError);
	assert.deepEqual(validateResponse({ id: "abc", ok: true, state: "unconfigured" }), { id: "abc", ok: true, state: "unconfigured" });
	assert.throws(() => validateResponse({ id: "abc", ok: true, state: "unknown" }), ProtocolError);
});
test("extension-to-client-to-broker status returns only a non-secret state", async () => {
	const directory = await mkdtemp(join(tmpdir(), "vault-extension-")); const socketPath = join(directory, "broker.sock"); const broker = createBrokerServer({ socketPath });
	try {
		await broker.start(); const tools = []; const commands = new Map();
		const pi = { registerTool(tool) { tools.push(tool); }, registerCommand(name, command) { commands.set(name, command); }, on() {} };
		const client = new VaultBrokerClient({ paths: { directory, socketPath }, startupTimeoutMs: 500 }); registerVaultExtension(pi, { client });
		const ui = { setStatus() {}, notify() {} }; const result = await tools[0].execute("call-1", { action: "status" }, undefined, undefined, { ui, hasUI: true });
		assert.equal(result.content[0].text, "Vault Broker status: unconfigured"); assert.deepEqual(result.details, { action: "status", state: "unconfigured" }); await commands.get("vault-status").handler("", { ui });
	} finally { await broker.stop(); await rm(directory, { recursive: true, force: true }); }
});
test("repeated concurrent first requests converge on one broker and socket is mode 0600", async () => {
	const directory = await mkdtemp(join(tmpdir(), "vault-race-")); const socketPath = join(directory, "broker.sock"); const brokers = [];
	try {
		for (let round = 0; round < 100; round++) {
			let starts = 0; const spawn = () => { starts++; const broker = createBrokerServer({ socketPath }); brokers.push(broker); void broker.start(); return { unref() {} }; };
			const options = { paths: { directory, socketPath }, startupTimeoutMs: 2_000, spawn };
			const results = await Promise.allSettled([new VaultBrokerClient(options).status(), new VaultBrokerClient(options).status(), new VaultBrokerClient(options).status()]);
			assert(results.every((result) => result.status === "fulfilled"), `round ${round}`); assert.deepEqual(results.map((result) => result.value), ["unconfigured", "unconfigured", "unconfigured"]);
			assert.equal(starts, 1); assert.equal((await stat(socketPath)).mode & 0o777, 0o600); await brokers.at(-1).stop();
		}
	} finally { await Promise.allSettled(brokers.map((broker) => broker.stop())); await rm(directory, { recursive: true, force: true }); }
});
test("the client starts the real detached broker process on demand", async () => {
	const directory = await mkdtemp(join(tmpdir(), "vault-process-")); const paths = brokerPaths({ directory }); let child;
	const client = new VaultBrokerClient({ paths, startupTimeoutMs: 3_000, spawn: (command, args, options) => { child = nodeSpawn(command, args, options); return child; } });
	try { assert.equal(await client.status(), "unconfigured"); assert(child?.pid); }
	finally { if (child?.exitCode === null) { if (!child.killed) child.kill("SIGTERM"); await new Promise((resolve) => child.once("exit", resolve)); } await rm(directory, { recursive: true, force: true }); }
});
test("stale startup lock and socket are recovered", async () => {
	const directory = await mkdtemp(join(tmpdir(), "vault-stale-")); const socketPath = join(directory, "broker.sock"); const lockPath = join(directory, "startup.lock");
	await writeFile(lockPath, JSON.stringify({ pid: 999999, createdAt: Date.now() - 60_000 }), { mode: 0o600 }); let stale = await rawConnection(socketPath, (socket) => socket.destroy()); await new Promise((resolve) => stale.close(resolve)); let broker;
	const client = new VaultBrokerClient({ paths: { directory, socketPath }, startupTimeoutMs: 2_000, spawn: () => { broker = createBrokerServer({ socketPath }); void broker.start(); return { unref() {} }; } });
	try { assert.equal(await client.status(), "unconfigured"); assert.equal((await stat(socketPath)).mode & 0o777, 0o600); assert.equal(await stat(lockPath).catch(() => undefined), undefined); }
	finally { await broker?.stop(); await rm(directory, { recursive: true, force: true }); }
});
test("malformed frames are disconnected without wire-data logging", async () => {
	const directory = await mkdtemp(join(tmpdir(), "vault-malformed-")); const socketPath = join(directory, "broker.sock"); const broker = createBrokerServer({ socketPath }); let socket;
	try { await broker.start(); socket = await new Promise((resolve, reject) => { const c = createConnection(socketPath); c.once("connect", () => resolve(c)); c.once("error", reject); }); const bad = Buffer.alloc(4); bad.writeUInt32BE(MAX_FRAME_BYTES + 1); socket.write(bad); await new Promise((resolve) => socket.once("close", resolve)); }
	finally { socket?.destroy(); await broker.stop(); await rm(directory, { recursive: true, force: true }); }
});
test("client rejects validly-shaped chunk frames containing invalid UTF-8", async () => {
	const directory = await mkdtemp(join(tmpdir(), "vault-chunk-utf8-"));
	const socketPath = join(directory, "broker.sock");
	let server;
	try {
		server = await rawConnection(socketPath, (socket) => {
			const parser = new FrameParser();
			socket.on("data", (chunk) => {
				for (const request of parser.push(chunk)) socket.write(encodeFrame({ id: request.id, ok: true, chunkIndex: 0, chunkCount: 1, data: Buffer.from([0xc3, 0x28]).toString("base64") }));
			});
		});
		await assert.rejects(requestVaultItems(socketPath, { action: "list" }), /invalid response|unavailable|disconnected/);
	} finally { server?.destroyConnections(); if (server) await new Promise((resolve) => server.close(resolve)); await rm(directory, { recursive: true, force: true }); }
});

test("client cancellation and broker disconnection are bounded", async () => {
	const directory = await mkdtemp(join(tmpdir(), "vault-cancel-")); const socketPath = join(directory, "broker.sock"); let stalled;
	try { stalled = await rawConnection(socketPath, () => {}); const controller = new AbortController(); const pending = requestStatus(socketPath, controller.signal); controller.abort(); await assert.rejects(pending, (error) => error?.name === "AbortError"); }
	finally { stalled?.destroyConnections(); if (stalled) await new Promise((resolve) => stalled.close(resolve)); await rm(directory, { recursive: true, force: true }); }
	const disconnectDir = await mkdtemp(join(tmpdir(), "vault-disconnect-")); const disconnectPath = join(disconnectDir, "broker.sock"); let disconnect;
	try { disconnect = await rawConnection(disconnectPath, (socket) => socket.end()); await assert.rejects(requestStatus(disconnectPath), /disconnected|unavailable/); }
	finally { disconnect?.destroyConnections(); if (disconnect) await new Promise((resolve) => disconnect.close(resolve)); await rm(disconnectDir, { recursive: true, force: true }); }
});
test("idle shutdown drops the in-memory session using injected time", async () => {
	const directory = await mkdtemp(join(tmpdir(), "vault-idle-")); const socketPath = join(directory, "broker.sock"); let clock = 10_000; const broker = createBrokerServer({ socketPath, idleMs: 30 * 60 * 1_000, now: () => clock });
	try { await broker.start(); assert.equal(broker.isSessionPresent(), true); await requestStatus(socketPath); clock += 30 * 60 * 1_000; broker.checkIdle(); await eventually(() => !broker.isRunning()); assert.equal(broker.isSessionPresent(), false); }
	finally { await broker.stop(); await rm(directory, { recursive: true, force: true }); }
});
test("package manifest registers vault runtime dependencies reproducibly", async () => {
	const packageJson = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
	const lock = JSON.parse(await readFile(new URL("../package-lock.json", import.meta.url), "utf8"));
	assert(packageJson.pi.extensions.includes("./extensions/vault/index.ts"));
	assert.equal(packageJson.dependencies["@earendil-works/pi-ai"], "0.80.10");
	assert.equal(lock.packages[""].dependencies["@earendil-works/pi-ai"], "0.80.10");
	assert.equal(lock.packages["node_modules/@earendil-works/pi-ai"].version, "0.80.10");
	assert.equal(packageJson.dependencies.ssh2, "1.17.0");
	assert.equal(lock.packages[""].dependencies.ssh2, "1.17.0");
	assert.equal(lock.packages["node_modules/ssh2"].version, "1.17.0");
});

function fakeVaultAdapter({ initialState = "unauthenticated", loginPassword = "correct-password", unlockPassword = loginPassword, failure } = {}) {
	let state = initialState; const calls = []; const session = "SESSION_SENTINEL_SHOULD_STAY_PRIVATE_123456";
	return { calls, get state() { return state; }, async status() { return { code: 0, state, userEmail: "user@example.com", serverUrl: "https://vault.example.test" }; },
		async configure(server) { calls.push(["configure", server]); return { code: 0 }; },
		async login(email, password) { calls.push(["login", email, password]); if (password !== loginPassword) return { code: 1, failure: "invalid_credentials", stdout: "secret-output-should-never-cross-broker" }; state = "unlocked"; return { code: 0, session }; },
		async unlock(password) { calls.push(["unlock", password]); if (failure || password !== unlockPassword) return { code: 1, failure: failure ?? "invalid_credentials", stdout: "secret-output-should-never-cross-broker" }; state = "unlocked"; return { code: 0, session }; },
		async lock(token) { calls.push(["lock", token]); state = "locked"; return { code: 0 }; } };
}
function fakeKeychain(value = "correct-password", options = {}) { let stored = value; const calls = []; return { calls, async get() { calls.push(["get"]); if (options.getError) throw options.getError; return stored; }, async set(password) { calls.push(["set", password]); if (options.setError) throw options.setError; stored = password; }, async delete() { calls.push(["delete"]); stored = undefined; if (options.deleteError) throw options.deleteError; } }; }
async function createFakeBroker({ adapter, keychain, now = Date.now, sessionIdleMs, profile = false } = {}) { const directory = await mkdtemp(join(tmpdir(), "vault-t2-")); const socketPath = join(directory, "broker.sock"); if (profile) await mkdir(join(directory, "profile"), { mode: 0o700 }); const broker = createBrokerServer({ socketPath, adapter, keychain, now, sessionIdleMs, idleMs: 60 * 60 * 1_000 }); await broker.start(); return { directory, socketPath, broker }; }

test("setup validation accepts cloud/custom HTTPS only and never normalizes secrets into errors", () => {
	assert.equal(security.normalizeServer("https://Example.COM/").host, "example.com"); assert.equal(security.normalizeServer("https://vault.example.com:8443").url, "https://vault.example.com:8443");
	assert.throws(() => security.normalizeServer("http://vault.example.com"), (e) => e.code === "invalid_server"); assert.throws(() => security.normalizeServer("https://vault.example.com/path"), (e) => e.code === "invalid_server"); assert.throws(() => security.normalizeServer("https://user:pass@vault.example.com"), (e) => e.code === "invalid_server");
	assert.equal(security.normalizeEmail(" User@Example.COM "), "user@example.com"); assert.throws(() => security.normalizeEmail("not-an-email"), (e) => e.code === "invalid_email"); assert.throws(() => security.validateMasterPassword("short"), (e) => e.code === "invalid_password");
});
test("Bitwarden adapter uses direct children and no secret argv", async () => {
	const seen = []; const adapter = bitwarden.createBitwardenAdapter({ profilePath: "/private/profile", run: async (args, options) => {
		seen.push({ args, env: options.env });
		if (args[0] === "status") return { code: 0, stdout: JSON.stringify({ status: "locked" }), stderr: "" };
		if (args[0] === "sync") return { code: 1, stdout: "", stderr: "invalid_grant" };
		return { code: 0, stdout: `export BW_SESSION=\"${"A".repeat(32)}\"`, stderr: "" };
	} });
	assert.equal((await adapter.status()).state, "locked");
	const result = await adapter.unlock("PASSWORD_SENTINEL");
	assert.equal(result.session, "A".repeat(32)); assert(!seen[1].args.includes("PASSWORD_SENTINEL")); assert(!seen[1].args.includes(result.session)); assert.equal(seen[1].env.BW_PASSWORD, "PASSWORD_SENTINEL"); assert.equal(seen[1].env.BW_SESSION, undefined); assert.equal(seen[1].env.BITWARDENCLI_APPDATA_DIR, "/private/profile");
	const synced = await adapter.sync({ session: result.session });
	assert.equal(synced.reauthenticationRequired, true); assert.deepEqual(seen[2].args, ["sync", "--nointeraction"]); assert.equal(seen[2].env.BW_SESSION, result.session); assert(!seen[2].args.includes(result.session));
});

test("fresh search syncs and privately reauthenticates an invalid-grant broker profile", async () => {
	let state = "unauthenticated"; let loginCount = 0; let syncCount = 0; const calls = [];
	const adapter = {
		async status() { calls.push(["status", state]); return { code: 0, state, userEmail: "user@example.com", serverUrl: "https://vault.example.test" }; },
		async configure() { return { code: 0 }; },
		async login() { loginCount++; state = "unlocked"; calls.push(["login", loginCount]); return { code: 0, session: `SESSION_${String(loginCount).padEnd(24, "A")}` }; },
		async unlock() { state = "unlocked"; return { code: 0, session: "SESSION_UNLOCKED_AAAAAAAAAAAAAAAA" }; },
		async lock() { state = "locked"; return { code: 0 }; },
		async logout() { calls.push(["logout"]); state = "unauthenticated"; return { code: 0 }; },
		async sync() { syncCount++; calls.push(["sync", syncCount]); return syncCount === 1 ? { code: 1, failure: "invalid_credentials", reauthenticationRequired: true } : { code: 0 }; },
		async listItems() { return { code: 0, items: [{ id: "item-id", type: 2, name: "ESP32 Admin Interface Password", secureNote: { type: 0 }, notes: "private" }] }; },
		async listFolders() { return { code: 0, folders: [] }; },
	};
	const keychain = fakeKeychain("correct-password");
	const { directory, socketPath, broker } = await createFakeBroker({ adapter, keychain });
	try {
		await requestSetup(socketPath, { server: "https://vault.example.test", email: "user@example.com", masterPassword: "correct-password" });
		const result = await requestVaultItems(socketPath, { action: "search", query: "ESP32 Admin Interface Password" });
		assert.equal(result.items[0]?.title, "ESP32 Admin Interface Password");
		assert.equal(syncCount, 2); assert.equal(loginCount, 2); assert.equal(calls.filter(([name]) => name === "logout").length, 1); assert.equal(keychain.calls.some(([name]) => name === "delete"), false);
	} finally { await broker.stop(); await rm(directory, { recursive: true, force: true }); }
});
test("first setup returns only normalized host and retains credential in fake Keychain", async () => {
	const sentinel = "PASSWORD_SENTINEL_123"; const adapter = fakeVaultAdapter({ initialState: "unauthenticated", loginPassword: sentinel }); const keychain = fakeKeychain(); const { directory, socketPath, broker } = await createFakeBroker({ adapter, keychain });
	try { const response = await requestSetup(socketPath, { server: "https://Vault.Example.test/", email: "user@example.com", masterPassword: sentinel }); assert.deepEqual(response, { state: "unlocked", serverHost: "vault.example.test" }); assert.deepEqual(keychain.calls, [["set", sentinel]]); assert(!JSON.stringify(response).includes(sentinel)); assert.equal(await requestStatus(socketPath), "unlocked"); assert.equal((await stat(join(directory, "profile"))).mode & 0o777, 0o700); }
	finally { await broker.stop(); await rm(directory, { recursive: true, force: true }); }
});
test("invalid stored credentials are deleted, while network failures are retained", async () => {
	for (const failure of ["invalid_credentials", "network_error"]) { const adapter = fakeVaultAdapter({ initialState: "locked", unlockPassword: "different", failure }); const keychain = fakeKeychain("stored-password"); const { directory, socketPath, broker } = await createFakeBroker({ adapter, keychain, profile: true }); try { await assert.rejects(requestStatus(socketPath), (e) => e instanceof BrokerRequestError && e.code === failure); assert.equal(keychain.calls.some((c) => c[0] === "delete"), failure === "invalid_credentials"); if (failure === "invalid_credentials") { assert.deepEqual(await requestSetup(socketPath, { server: "https://vault.example.test", email: "user@example.com", masterPassword: "correct-password" }), { state: "unlocked", serverHost: "vault.example.test" }); } } finally { await broker.stop(); await rm(directory, { recursive: true, force: true }); } }
});
test("Keychain failures are safe and concurrent valid setup responses converge on first winner", async () => {
	const adapter = fakeVaultAdapter({ initialState: "unauthenticated" }); const keychain = fakeKeychain(undefined, { getError: new Error("Keychain unavailable") }); const first = await createFakeBroker({ adapter, keychain, profile: true });
	try { await assert.rejects(requestStatus(first.socketPath), (e) => e instanceof BrokerRequestError && e.code === "keychain_unavailable"); assert(!keychain.calls.some((c) => c[0] === "delete")); } finally { await first.broker.stop(); await rm(first.directory, { recursive: true, force: true }); }
	const winningAdapter = fakeVaultAdapter({ initialState: "unauthenticated" }); const winningKeychain = fakeKeychain(); const concurrent = await createFakeBroker({ adapter: winningAdapter, keychain: winningKeychain }); const setup = { server: "https://vault.example.test", email: "user@example.com", masterPassword: "correct-password" };
	try { const responses = await Promise.all([requestSetup(concurrent.socketPath, setup), requestSetup(concurrent.socketPath, { ...setup, masterPassword: "redundant-password" })]); assert.deepEqual(responses[0], { state: "unlocked", serverHost: "vault.example.test" }); assert.deepEqual(responses[1], responses[0]); assert.equal(winningAdapter.calls.filter((c) => c[0] === "login").length, 1); assert.equal(winningKeychain.calls.filter((c) => c[0] === "set").length, 1); } finally { await concurrent.broker.stop(); await rm(concurrent.directory, { recursive: true, force: true }); }
});
test("session lease locks and clears the handle, then silently unlocks from Keychain", async () => {
	let clock = 1000; const adapter = fakeVaultAdapter({ initialState: "unauthenticated" }); const keychain = fakeKeychain(); const { directory, socketPath, broker } = await createFakeBroker({ adapter, keychain, now: () => clock, sessionIdleMs: 100 });
	try { await requestSetup(socketPath, { server: "https://vault.example.test", email: "user@example.com", masterPassword: "correct-password" }); clock += 101; await broker.checkSessionIdle(); assert.equal(broker.isSessionPresent(), false); assert.equal(adapter.calls.at(-1)?.[0], "lock"); assert.equal(await requestStatus(socketPath), "unlocked"); assert.equal(adapter.calls.at(-1)?.[0], "unlock"); } finally { await broker.stop(); await rm(directory, { recursive: true, force: true }); }
});
test("non-TUI extension setup fails closed without invoking UI", async () => {
	const tools = []; const pi = { registerTool(tool) { tools.push(tool); }, registerCommand() {}, on() {} }; const client = { async status() { return "unconfigured"; } }; registerVaultExtension(pi, { client }); let customCalled = false;
	const result = await tools[0].execute("call", { action: "status" }, undefined, undefined, { mode: "print", ui: { setStatus() {}, custom() { customCalled = true; } } }); assert.equal(customCalled, false); assert.equal(result.details.error, "ui_unavailable"); assert(!JSON.stringify(result).includes("PASSWORD_SENTINEL"));
});

test("TUI wizard masks the master password, validates through the broker, and cancellation leaves no secret result", async () => {
	const theme = { fg: (_color, text) => text, bold: (text) => text };
	const runWizard = async (send) => {
		const tools = []; let captured; let setupCalls = 0; const client = { async status() { return "unauthenticated"; }, async setup(input) { setupCalls++; captured = { ...input }; return { state: "unlocked", serverHost: "vault.bitwarden.com" }; } };
		const pi = { registerTool(tool) { tools.push(tool); }, registerCommand() {}, on() {} }; registerVaultExtension(pi, { client }); let component;
		const ui = { setStatus() {}, custom(factory) { return new Promise((resolve) => { component = factory({ requestRender() {} }, theme, {}, resolve); send(component); }); } };
		const result = await tools[0].execute("call", { action: "status" }, undefined, undefined, { mode: "tui", ui }); return { result, captured, setupCalls, component };
	};
	const success = await runWizard((component) => { component.handleInput("\n"); for (const char of "user@example.com") component.handleInput(char); component.handleInput("\n"); for (const char of "PASSWORD_SENTINEL_123") component.handleInput(char); assert(!component.render(80).join("\n").includes("PASSWORD_SENTINEL_123")); component.handleInput("\n"); });
	assert.equal(success.setupCalls, 1); assert.equal(success.captured.masterPassword, "PASSWORD_SENTINEL_123"); assert(!JSON.stringify(success.result).includes("PASSWORD_SENTINEL_123"));
	const cancelled = await runWizard((component) => component.handleInput("\x1b")); assert.equal(cancelled.setupCalls, 0); assert.equal(cancelled.result.details.cancelled, true); assert(!JSON.stringify(cancelled.result).includes("PASSWORD_SENTINEL_123"));
});
