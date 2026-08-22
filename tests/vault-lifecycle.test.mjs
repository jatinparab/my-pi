import assert from "node:assert/strict";
import { Readable } from "node:stream";
import { createConnection, createServer } from "node:net";
import { mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createBrokerServer } from "../extensions/vault/broker.mjs";
import { isAgentBitwardenCommandBlocked } from "../extensions/vault/guard.mjs";
import { createJiti } from "jiti";

const jiti = createJiti(import.meta.url);
const { requestConfig, requestForget, requestLock, requestSetup, requestStatus, requestVaultItems, requestVaultRun, BrokerRequestError } = await jiti.import("../extensions/vault/client.ts");
const { registerVaultExtension } = await jiti.import("../extensions/vault/index.ts");
const { FrameParser, configFrame, encodeFrame, lifecycleFrame, validateResponse } = await import("../extensions/vault/protocol.mjs");

const SECRET = "LIFECYCLE_SECRET_SENTINEL";

function fakeVault(options = {}) {
	let state = "unauthenticated";
	const calls = [];
	let credential;
	const item = { id: "private-id", type: 1, name: "lifecycle fixture", login: { username: "fixture-user", password: SECRET, uris: [{ uri: "https://example.test/private/path" }] }, attachments: [{ id: "private-attachment", fileName: "payload.bin", size: "4" }] };
	const adapter = {
		calls,
		async status() {
			calls.push(["status"]);
			if (options.statusFailure) throw new Error("status failure");
			return { code: 0, state, userEmail: "fixture@example.test", serverUrl: "https://old.example.test" };
		},
		async configure(server) {
			calls.push(["configure", server]);
			if (options.configureGate && calls.filter(([name]) => name === "configure").length > 1) {
				options.configureStarted?.();
				await options.configureGate;
			}
			return options.configureFailure ? { code: 1, failure: options.configureFailure } : { code: 0 };
		},
		async login(email, password) { calls.push(["login", email, password]); if (options.loginFailure) return { code: 1, failure: options.loginFailure }; state = "unlocked"; return { code: 0, session: `private-session-${email}` }; },
		async unlock(password) { calls.push(["unlock", password]); state = "unlocked"; return { code: 0, session: "private-unlock-session" }; },
		async lock(session) { calls.push(["lock", session]); state = "locked"; return { code: 0 }; },
		async logout(session) { calls.push(["logout", session]); if (options.logoutFailure) return { code: 1, failure: options.logoutFailure }; state = "unauthenticated"; return { code: 0 }; },
		async listItems() { return { code: 0, items: [item] }; },
		async listFolders() { return { code: 0, folders: [] }; },
		streamAttachment() { return { stream: Readable.from([Buffer.from("BIN!")]) }; },
	};
	const keychain = {
		async get() { if (options.keychainGetFailure) throw new Error("Keychain unavailable"); return credential; },
		async set(value) { calls.push(["keychain-set", value]); if (options.keychainSetFailure) throw new Error("Keychain unavailable"); credential = value; },
		async delete() { calls.push(["keychain-delete"]); if (options.keychainDeleteFailure) throw new Error("Keychain unavailable"); credential = undefined; },
	};
	return { ...adapter, keychain, get credential() { return credential; } };
}

const nodeArgs = (source) => ["-e", source];

function connectSocket(socketPath) {
	return new Promise((resolve, reject) => {
		const socket = createConnection(socketPath);
		socket.once("connect", () => resolve(socket));
		socket.once("error", reject);
	});
}
function readResponse(socket) {
	const parser = new FrameParser();
	return new Promise((resolve, reject) => {
		socket.on("data", (chunk) => {
			try {
				const frames = parser.push(chunk);
				if (frames.length) resolve(validateResponse(frames[0]));
			} catch (error) { reject(error); }
		});
		socket.once("error", reject);
	});
}

async function startFixture(options = {}) {
	const directory = await mkdtemp(join(tmpdir(), "vault-lifecycle-focused-"));
	const socketPath = join(directory, "broker.sock");
	const fake = fakeVault(options);
	const broker = createBrokerServer({ socketPath, adapter: fake, keychain: fake.keychain, idleMs: 60_000, writeResponse: options.writeResponse, onRequest: options.onRequest });
	await broker.start();
	await requestSetup(socketPath, { server: "https://old.example.test", email: "fixture@example.test", masterPassword: "old-password" });
	return { directory, socketPath, fake, broker };
}

async function closeFixture(fixture) {
	await fixture.broker.stop();
	await rm(fixture.directory, { recursive: true, force: true });
}

test("disposable vault lifecycle smoke covers silent recovery, mediation, reconfiguration, and forget cleanup", async () => {
	const directory = await mkdtemp(join(tmpdir(), "vault-lifecycle-smoke-"));
	const socketPath = join(directory, "broker.sock");
	const fake = fakeVault();
	const broker = createBrokerServer({ socketPath, adapter: fake, keychain: fake.keychain, idleMs: 60_000 });
	await broker.start();
	try {
		const setup = await requestSetup(socketPath, { server: "https://old.example.test", email: "fixture@example.test", masterPassword: "fixture-password" });
		assert.deepEqual(setup, { state: "unlocked", serverHost: "old.example.test" });
		assert.equal(await requestLock(socketPath), "locked");
		assert.equal(await requestStatus(socketPath), "unlocked", "lock retains silent-unlock credential");
		const page = await requestVaultItems(socketPath, { action: "list" });
		const search = await requestVaultItems(socketPath, { action: "search", query: "private" });
		assert.equal(search.items.length, 1);
		const inspection = await requestVaultItems(socketPath, { action: "inspect", itemHandle: page.items[0].handle });
		assert.equal(inspection.materials.length, 3);
		assert(!JSON.stringify({ page, search, inspection }).includes(SECRET));
		const password = inspection.materials.find((entry) => entry.type === "password");
		const scalar = await requestVaultRun(socketPath, { executable: process.execPath, argv: nodeArgs("process.stdout.write(process.env.VALUE)"), materialEnv: { VALUE: password.handle } });
		assert.equal(scalar.exitCode, 0);
		assert(!JSON.stringify(scalar).includes(SECRET));
		const binary = await requestVaultRun(socketPath, { executable: process.execPath, argv: nodeArgs("process.stdin.resume(); process.stdin.on('end',()=>process.exit(0))"), stdin: inspection.attachments[0].handle });
		assert.equal(binary.mode, "bulk");
		assert.equal(binary.stdout, undefined);
		assert.equal(await requestLock(socketPath), "locked");
		await assert.rejects(requestVaultItems(socketPath, { action: "inspect", itemHandle: page.items[0].handle }), (error) => error instanceof BrokerRequestError && error.code === "invalid_handle");
		assert.equal(await requestStatus(socketPath), "unlocked");
		const reconfigured = await requestConfig(socketPath, { server: "https://new.example.test", email: "new@example.test", masterPassword: "new-password" });
		assert.deepEqual(reconfigured, { state: "unlocked", serverHost: "new.example.test" });
		await assert.rejects(stat(join(directory, ".profile-replaced")));
		const forgotten = await requestForget(socketPath);
		assert.deepEqual(forgotten, { action: "forget", state: "unconfigured", cleanup: "complete" });
		assert.equal(await requestStatus(socketPath), "unconfigured");
		await assert.rejects(stat(join(directory, "profile")));
		assert(fake.calls.some(([name]) => name === "logout"));
		assert.equal(fake.keychain ? await fake.keychain.get() : undefined, undefined);
	} finally {
		await broker.stop();
		await rm(directory, { recursive: true, force: true });
	}
});

test("same-id recovery joins an in-flight replacement before commit and executes it once", async () => {
	let release;
	let signalStarted;
	const options = {
		configureGate: new Promise((resolve) => { release = resolve; }),
		configureStarted: () => signalStarted?.(),
	};
	const started = new Promise((resolve) => { signalStarted = resolve; });
	const fixture = await startFixture(options);
	const params = { server: "https://replacement.example.test", email: "replacement@example.test", masterPassword: "replacement-password" };
	const id = "config-race-id";
	let first;
	let second;
	try {
		first = await connectSocket(fixture.socketPath);
		first.write(configFrame(id, params));
		await started;
		first.destroy();

		second = await connectSocket(fixture.socketPath);
		const responsePromise = readResponse(second);
		second.write(configFrame(id, params));
		await new Promise((resolve) => setImmediate(resolve));
		assert.equal(fixture.fake.calls.filter(([name]) => name === "configure").length, 2);
		assert.equal(fixture.fake.calls.filter(([name]) => name === "login").length, 1, "replay must wait, not start a second login");
		release();
		assert.deepEqual(await responsePromise, { id, ok: true, state: "unlocked", serverHost: "replacement.example.test" });
		assert.equal(fixture.fake.calls.filter(([name]) => name === "configure").length, 2);
		assert.equal(fixture.fake.calls.filter(([name]) => name === "login").length, 2);
	} finally {
		release();
		first?.destroy();
		second?.destroy();
		await closeFixture(fixture);
	}
});

test("queued lock and forget tombstone blocked config replays after lifecycle completion", async () => {
	for (const lifecycle of ["lock", "forget"]) {
		let release;
		let signalStarted;
		let signalLifecycle;
		const options = {
			configureGate: new Promise((resolve) => { release = resolve; }),
			configureStarted: () => signalStarted?.(),
			onRequest: (request) => { if (request.method === lifecycle) signalLifecycle?.(); },
		};
		const started = new Promise((resolve) => { signalStarted = resolve; });
		const lifecycleReceived = new Promise((resolve) => { signalLifecycle = resolve; });
		const fixture = await startFixture(options);
		const params = { server: "https://blocked.example.test", email: "blocked@example.test", masterPassword: "blocked-password" };
		const id = `blocked-${lifecycle}-id`;
		let first;
		let replay;
		try {
			first = await connectSocket(fixture.socketPath);
			first.write(configFrame(id, params));
			await started;
			first.destroy();

			const lifecyclePromise = lifecycle === "lock" ? requestLock(fixture.socketPath) : requestForget(fixture.socketPath);
			await lifecycleReceived;
			release();
			if (lifecycle === "lock") assert.equal(await lifecyclePromise, "locked");
			else assert.deepEqual(await lifecyclePromise, { action: "forget", state: "unconfigured", cleanup: "complete" });

			replay = await connectSocket(fixture.socketPath);
			const replayResponse = readResponse(replay);
			replay.write(configFrame(id, params));
			assert.deepEqual(await replayResponse, { id, ok: false, error: "config_recovery" });
			assert.equal(fixture.fake.calls.filter(([name]) => name === "configure").length, 2, "lifecycle replay must not replace twice");
		} finally {
			release();
			first?.destroy();
			replay?.destroy();
			await closeFixture(fixture);
		}
	}
});

test("failed config settlement removes the in-flight entry and permits a same-id retry", async () => {
	const options = {};
	const fixture = await startFixture(options);
	const params = { server: "https://replacement.example.test", email: "replacement@example.test", masterPassword: "replacement-password" };
	const id = "config-failure-id";
	let first;
	let second;
	try {
		options.configureFailure = "cli_error";
		first = await connectSocket(fixture.socketPath);
		const firstResponse = readResponse(first);
		first.write(configFrame(id, params));
		assert.deepEqual(await firstResponse, { id, ok: false, error: "cli_error" });
		options.configureFailure = undefined;
		second = await connectSocket(fixture.socketPath);
		const secondResponse = readResponse(second);
		second.write(configFrame(id, params));
		assert.deepEqual(await secondResponse, { id, ok: true, state: "unlocked", serverHost: "replacement.example.test" });
		assert.equal(fixture.fake.calls.filter(([name]) => name === "configure").length, 3);
		assert.equal(fixture.fake.calls.filter(([name]) => name === "login").length, 2);
	} finally { first?.destroy(); second?.destroy(); await closeFixture(fixture); }
});

test("config operation capacity fails closed while an earlier replacement is in flight", async () => {
	let release;
	let signalStarted;
	const options = {
		configureGate: new Promise((resolve) => { release = resolve; }),
		configureStarted: () => signalStarted?.(),
	};
	const started = new Promise((resolve) => { signalStarted = resolve; });
	const directory = await mkdtemp(join(tmpdir(), "vault-config-capacity-"));
	const socketPath = join(directory, "broker.sock");
	const fake = fakeVault(options);
	const broker = createBrokerServer({ socketPath, adapter: fake, keychain: fake.keychain, idleMs: 60_000, maxInFlightConfigOperations: 1 });
	let first;
	let second;
	try {
		await broker.start();
		await requestSetup(socketPath, { server: "https://old.example.test", email: "fixture@example.test", masterPassword: "old-password" });
		first = await connectSocket(socketPath);
		first.write(configFrame("capacity-first", { server: "https://first.example.test", email: "first@example.test", masterPassword: "first-password" }));
		await started;
		second = await connectSocket(socketPath);
		const responsePromise = readResponse(second);
		second.write(configFrame("capacity-second", { server: "https://second.example.test", email: "second@example.test", masterPassword: "second-password" }));
		assert.deepEqual(await responsePromise, { id: "capacity-second", ok: false, error: "over_limit" });
		release();
		assert.deepEqual(await readResponse(first), { id: "capacity-first", ok: true, state: "unlocked", serverHost: "first.example.test" });
	} finally {
		release();
		first?.destroy();
		second?.destroy();
		await broker.stop();
		await rm(directory, { recursive: true, force: true });
	}
});

test("lock, replacement, and forget invalidate delayed config acknowledgements", async () => {
	const fixture = await startFixture();
	const params = { server: "https://replacement.example.test", email: "replacement@example.test", masterPassword: "replacement-password" };
	const id = "stale-config-id";
	let socket;
	try {
		socket = await connectSocket(fixture.socketPath);
		const initial = readResponse(socket);
		socket.write(configFrame(id, params));
		assert.deepEqual(await initial, { id, ok: true, state: "unlocked", serverHost: "replacement.example.test" });
		socket.destroy(); socket = undefined;
		assert.equal(await requestLock(fixture.socketPath), "locked");

		socket = await connectSocket(fixture.socketPath);
		const afterLock = readResponse(socket);
		socket.write(configFrame(id, params));
		assert.deepEqual(await afterLock, { id, ok: false, error: "config_recovery" });
		socket.destroy(); socket = undefined;

		assert.deepEqual(await requestConfig(fixture.socketPath, { server: "https://new.example.test", email: "new@example.test", masterPassword: "new-password" }), { state: "unlocked", serverHost: "new.example.test" });
		socket = await connectSocket(fixture.socketPath);
		const afterReplacement = readResponse(socket);
		socket.write(configFrame(id, params));
		assert.deepEqual(await afterReplacement, { id, ok: false, error: "config_recovery" });
		socket.destroy(); socket = undefined;

		assert.deepEqual(await requestForget(fixture.socketPath), { action: "forget", state: "unconfigured", cleanup: "complete" });
		socket = await connectSocket(fixture.socketPath);
		const afterForget = readResponse(socket);
		socket.write(configFrame(id, params));
		assert.deepEqual(await afterForget, { id, ok: false, error: "config_recovery" });
		assert.equal(fixture.fake.calls.filter(([name]) => name === "configure").length, 3);
	} finally { socket?.destroy(); await closeFixture(fixture); }
});

test("custom self-hosted HTTPS reconfiguration with a port is acknowledged safely", async () => {
	const fixture = await startFixture();
	try {
		const result = await requestConfig(fixture.socketPath, { server: "https://Self-Hosted.Example.test:8443", email: "replacement@example.test", masterPassword: "replacement-password" });
		assert.deepEqual(result, { state: "unlocked", serverHost: "self-hosted.example.test:8443" });
		assert.deepEqual(fixture.fake.calls.filter(([name]) => name === "configure").at(-1), ["configure", "https://self-hosted.example.test:8443"]);
		assert.equal(await requestStatus(fixture.socketPath), "unlocked");
		assert(!JSON.stringify(result).includes("replacement@example.test"));
	} finally { await closeFixture(fixture); }
});

test("a committed config replays its bounded acknowledgement after the response socket is lost", async () => {
	let drop = false;
	const fixture = await startFixture({ writeResponse(socket, frame) {
		const value = JSON.parse(frame.subarray(4).toString("utf8"));
		if (drop && value.serverHost === "replacement.example.test") { drop = false; socket.destroy(); return true; }
		return socket.write(frame);
	} });
	try {
		drop = true;
		const result = await requestConfig(fixture.socketPath, { server: "https://replacement.example.test", email: "replacement@example.test", masterPassword: "replacement-password" });
		assert.deepEqual(result, { state: "unlocked", serverHost: "replacement.example.test" });
		assert.equal(fixture.fake.calls.filter(([name]) => name === "configure").length, 2);
		assert.equal(fixture.fake.calls.filter(([name]) => name === "login").length, 2);
	} finally { await closeFixture(fixture); }
});

test("a post-commit response writer failure is replayed instead of mapped to internal_error", async () => {
	let fail = true;
	const fixture = await startFixture({ writeResponse(socket, frame) {
		const value = JSON.parse(frame.subarray(4).toString("utf8"));
		if (fail && value.serverHost === "replacement.example.test") { fail = false; throw new Error("fixture write failure"); }
		return socket.write(frame);
	} });
	try {
		const result = await requestConfig(fixture.socketPath, { server: "https://replacement.example.test", email: "replacement@example.test", masterPassword: "replacement-password" });
		assert.deepEqual(result, { state: "unlocked", serverHost: "replacement.example.test" });
		assert.equal(fixture.fake.calls.filter(([name]) => name === "configure").length, 2);
	} finally { await closeFixture(fixture); }
});

test("config transport and response-validation failures retry the same id, then map bounded recovery", async () => {
	for (const firstFailure of ["disconnect", "malformed"]) {
		const directory = await mkdtemp(join(tmpdir(), `vault-config-${firstFailure}-`));
		const socketPath = join(directory, "broker.sock");
		let attempts = 0;
		const ids = [];
		const server = createServer((socket) => {
			const parser = new FrameParser();
			socket.on("data", (chunk) => {
				for (const request of parser.push(chunk)) {
					ids.push(request.id);
					attempts++;
					if (attempts === 1 && firstFailure === "disconnect") { socket.destroy(); continue; }
					if (attempts === 1) { socket.write(encodeFrame({ id: request.id, ok: true, state: "unlocked" })); socket.end(); continue; }
					socket.end(encodeFrame({ id: request.id, ok: true, state: "unlocked", serverHost: "self-hosted.example.test:8443" }));
				}
			});
		});
		await new Promise((resolve, reject) => { server.once("error", reject); server.listen(socketPath, resolve); });
		try {
			const result = await requestConfig(socketPath, { server: "https://self-hosted.example.test:8443", email: "replacement@example.test", masterPassword: "replacement-password" });
			assert.deepEqual(result, { state: "unlocked", serverHost: "self-hosted.example.test:8443" });
			assert.equal(attempts, 2);
			assert.equal(ids[0], ids[1], "recovery must replay the same request id");
		} finally { await new Promise((resolve) => server.close(resolve)); await rm(directory, { recursive: true, force: true }); }
	}

	const directory = await mkdtemp(join(tmpdir(), "vault-config-recovery-"));
	const socketPath = join(directory, "broker.sock");
	let attempts = 0;
	const server = createServer((socket) => { socket.on("data", () => { attempts++; socket.destroy(); }); });
	await new Promise((resolve, reject) => { server.once("error", reject); server.listen(socketPath, resolve); });
	try {
		await assert.rejects(requestConfig(socketPath, { server: "https://self-hosted.example.test:8443", email: "replacement@example.test", masterPassword: "replacement-password" }), (error) => error instanceof BrokerRequestError && error.code === "config_recovery");
		assert.equal(attempts, 2);
	} finally { await new Promise((resolve) => server.close(resolve)); await rm(directory, { recursive: true, force: true }); }
});

test("reconfiguration logs out and deletes an old profile without a broker session", async () => {
	const options = { statusFailure: true, keychainGetFailure: true };
	const fixture = await startFixture(options);
	try {
		await fixture.broker.invalidateSession();
		fixture.fake.calls.length = 0;
		const result = await requestConfig(fixture.socketPath, { server: "https://replacement.example.test", email: "replacement@example.test", masterPassword: "replacement-password" });
		assert.deepEqual(result, { state: "unlocked", serverHost: "replacement.example.test" });
		assert.deepEqual(fixture.fake.calls.map(([name]) => name), ["status", "logout", "keychain-delete", "configure", "login", "keychain-set"]);
	} finally { await closeFixture(fixture); }
});

test("failed configure/login replacement deletes the stale credential and partial profile", async () => {
	for (const failureKey of ["configureFailure", "loginFailure", "keychainSetFailure"]) {
		const options = {};
		const fixture = await startFixture(options);
		try {
			options[failureKey] = failureKey === "configureFailure" ? "cli_error" : failureKey === "loginFailure" ? "invalid_credentials" : true;
			await assert.rejects(requestConfig(fixture.socketPath, { server: "https://replacement.example.test", email: "replacement@example.test", masterPassword: "replacement-password" }));
			assert.equal(fixture.fake.credential, undefined);
			await assert.rejects(stat(join(fixture.directory, "profile")));
			await assert.rejects(stat(join(fixture.directory, ".profile-replaced")));
			assert.equal(await requestStatus(fixture.socketPath), "unconfigured");
			options[failureKey] = undefined;
			assert.deepEqual(await requestSetup(fixture.socketPath, { server: "https://recovered.example.test", email: "fixture@example.test", masterPassword: "recovered-password" }), { state: "unlocked", serverHost: "recovered.example.test" });
		} finally { await closeFixture(fixture); }
	}
});

test("reconfiguration aborts before profile removal when old Keychain deletion fails", async () => {
	const options = { keychainDeleteFailure: true };
	const fixture = await startFixture(options);
	try {
		fixture.fake.calls.length = 0;
		await assert.rejects(requestConfig(fixture.socketPath, { server: "https://replacement.example.test", email: "replacement@example.test", masterPassword: "replacement-password" }), (error) => error instanceof BrokerRequestError && error.code === "keychain_unavailable");
		assert.equal(fixture.fake.credential, "old-password");
		assert.deepEqual(fixture.fake.calls.map(([name]) => name), ["logout", "keychain-delete"]);
		assert.equal((await stat(join(fixture.directory, "profile"))).isDirectory(), true);
		await assert.rejects(stat(join(fixture.directory, ".profile-replaced")));
	} finally { await closeFixture(fixture); }
});

test("forget reports partial cleanup but continues after logout or Keychain deletion failure", async () => {
	for (const options of [{ logoutFailure: "cli_error" }, { keychainDeleteFailure: true }]) {
		const fixture = await startFixture(options);
		try {
			const page = await requestVaultItems(fixture.socketPath, { action: "list" });
			const result = await requestForget(fixture.socketPath);
			assert.deepEqual(result, { action: "forget", state: "unconfigured", cleanup: "partial" });
			await assert.rejects(requestVaultItems(fixture.socketPath, { action: "inspect", itemHandle: page.items[0].handle }), (error) => error instanceof BrokerRequestError && error.code === "invalid_handle");
			await assert.rejects(stat(join(fixture.directory, "profile")), "profile cleanup must continue");
			assert.equal(await requestStatus(fixture.socketPath), "unconfigured");
		} finally { await closeFixture(fixture); }
	}
});

test("lifecycle commands refuse non-TUI and require TUI confirmation/wizard input", async () => {
	const commands = new Map();
	const calls = [];
	const pi = { registerTool() {}, registerCommand(name, definition) { commands.set(name, definition); }, on() {} };
	registerVaultExtension(pi, { client: {
		async lock() { calls.push("lock"); return "locked"; },
		async config(input) { calls.push(["config", { ...input }]); return { state: "unlocked", serverHost: "new.example.test" }; },
		async forget() { calls.push("forget"); return { action: "forget", state: "unconfigured", cleanup: "complete" }; },
	} });
	const notifications = [];
	const nonTui = { mode: "print", hasUI: false, ui: { notify(message) { notifications.push(message); }, setStatus() {}, async confirm() { throw new Error("must not confirm"); } } };
	await commands.get("vault-lock").handler("", nonTui);
	await commands.get("vault-config").handler("", nonTui);
	await commands.get("vault-forget").handler("", nonTui);
	assert.deepEqual(calls, []);
	assert.equal(notifications.length, 3);

	const theme = { fg: (_color, text) => text, bold: (text) => text };
	let component;
	const tui = {
		mode: "tui", hasUI: true,
		ui: {
			notify() {}, setStatus() {},
			async confirm() { return true; },
			custom(factory) { return new Promise((resolve) => { component = factory({ requestRender() {} }, theme, {}, resolve); }); },
		},
	};
	await commands.get("vault-lock").handler("", tui);
	const configuring = commands.get("vault-config").handler("", tui);
	component.handleInput("\n");
	for (const character of "new@example.test") component.handleInput(character);
	component.handleInput("\n");
	for (const character of "new-password") component.handleInput(character);
	component.handleInput("\n");
	await configuring;
	await commands.get("vault-forget").handler("", tui);
	assert.equal(calls[0], "lock");
	assert.equal(calls[1][0], "config");
	assert.equal(calls[1][1].masterPassword, "new-password");
	assert.equal(calls[2], "forget");
	assert(!JSON.stringify(notifications).includes("new-password"));
});

test("ambiguous config recovery is actionable but remains bounded and non-secret", async () => {
	const commands = new Map();
	const notifications = [];
	const pi = { registerTool() {}, registerCommand(name, definition) { commands.set(name, definition); }, on() {} };
	registerVaultExtension(pi, { client: { async config() { throw new BrokerRequestError("config_recovery"); } } });
	const theme = { fg: (_color, text) => text, bold: (text) => text };
	let component;
	const ctx = { mode: "tui", hasUI: true, ui: {
		setStatus() {},
		notify(message, level) { notifications.push({ message, level }); },
		custom(factory) { return new Promise((resolve) => { component = factory({ requestRender() {} }, theme, {}, resolve); }); },
	} };
	const pending = commands.get("vault-config").handler("", ctx);
	component.handleInput("\n");
	for (const character of "fixture@example.test") component.handleInput(character);
	component.handleInput("\n");
	for (const character of "CONFIG_SECRET_SENTINEL") component.handleInput(character);
	component.handleInput("\n");
	await pending;
	assert.deepEqual(notifications, [{ message: "Vault configuration may have completed; retry /vault-config to confirm.", level: "warning" }]);
	assert(!JSON.stringify(notifications).includes("CONFIG_SECRET_SENTINEL"));
});

test("agent Bitwarden guard blocks common direct forms but permits help/version and broker-owned tool names", () => {
	for (const command of [
		"bw get item x", "bw list items", "bw export", "bw serve", "bw login user@example.test", "bw unlock",
		"env -i BW_SESSION=x command /opt/homebrew/bin/bw list items", "sudo -n bw serve", "bw --session x list items", "npx bw get item x", "npx @bitwarden/cli get item x", "npm exec -- bw unlock", "npm exec @bitwarden/cli -- list items", "pnpm dlx @bitwarden/cli export", "yarn exec @bitwarden/cli login user@example.test",
		"bw list items && echo done",
	]) assert.equal(isAgentBitwardenCommandBlocked(command), true, command);
	for (const command of ["bw --help", "bw --version", "bw list --help", "npx @bitwarden/cli --version", "npm exec @bitwarden/cli --help", "command bw get --version", "echo bw get item x", "npm install @bitwarden/cli", "sudo echo bw get item x", "vault_run executable=bw"]) assert.equal(isAgentBitwardenCommandBlocked(command), false, command);
});
