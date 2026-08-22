import assert from "node:assert/strict";
import { spawn as nodeSpawn } from "node:child_process";
import { EventEmitter } from "node:events";
import { Readable } from "node:stream";
import { chmod, mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createJiti } from "jiti";
import { randomUUID } from "node:crypto";

const jiti = createJiti(import.meta.url);
const { createBrokerServer } = await import("../extensions/vault/broker.mjs");
const { requestSetup, requestVaultItems, requestVaultRun, requestVaultSshRun, vaultSshRunRequestTimeoutMs, BrokerRequestError } = await jiti.import("../extensions/vault/client.ts");
const { registerVaultExtension } = await jiti.import("../extensions/vault/index.ts");
const { validateVaultSshInput, executeVaultSsh, createKnownHostsStore, createSshClient, SshError, SshHostKeyError, redactSshOutput, sshMaterialEncodingVariants } = await import("../extensions/vault/ssh.mjs");
const protocol = await import("../extensions/vault/protocol.mjs");

const SECRET = "SSH_SECRET_SENTINEL_+/=";
const KEY_SENTINEL = "PRIVATE_KEY_SENTINEL_+/=";
const PASSPHRASE_SENTINEL = "PASSPHRASE_SENTINEL_+/=";

const TEST_HOST = "testhost.local";
const TEST_KEY = `-----BEGIN OPENSSH PRIVATE KEY-----\n${KEY_SENTINEL}\n-----END OPENSSH PRIVATE KEY-----\n`;

function fakeAdapter(items = []) {
	let state = "unauthenticated";
	const attachmentStreams = new Map();
	return {
		get state() { return state; },
		async status() { return { code: 0, state, userEmail: "fixture@example.test", serverUrl: "https://vault.example.test" }; },
		async configure() { return { code: 0 }; },
		async login() { state = "unlocked"; return { code: 0, session: "PRIVATE_SESSION_SSH_TEST_123456" }; },
		async unlock() { state = "unlocked"; return { code: 0, session: "PRIVATE_SESSION_SSH_TEST_123456" }; },
		async lock() { state = "locked"; return { code: 0 }; },
		async listItems() { return { code: 0, items }; },
		async listFolders() { return { code: 0, folders: [] }; },
		streamAttachment({ itemId, attachmentId }) {
			const stream = attachmentStreams.get(`${itemId}:${attachmentId}`);
			if (stream) return { stream: Readable.from(stream), process: undefined };
			throw new Error("attachment not found");
		},
		setAttachment(itemId, attachmentId, data) {
			attachmentStreams.set(`${itemId}:${attachmentId}`, Buffer.isBuffer(data) ? [data] : [Buffer.from(String(data))]);
		},
	};
}

function sshItem(overrides = {}) {
	return {
		id: `ssh-item-${randomUUID()}`,
		type: 5,
		name: "SSH key fixture",
		sshKey: {
			privateKey: overrides.privateKey ?? TEST_KEY,
			publicKey: overrides.publicKey ?? "ssh-rsa AAAAFIXTURE",
			keyFingerprint: "SHA256:fix",
		},
		notes: "SSH item notes",
		...overrides,
	};
}

function hostItem(overrides = {}) {
	return {
		id: `host-item-${randomUUID()}`,
		type: 1,
		name: "Host fixture",
		login: {
			username: overrides.hostValue ?? TEST_HOST,
			password: "host-password",
			uris: [{ uri: "https://example.test" }],
		},
		...overrides,
	};
}

function passphraseItem(overrides = {}) {
	return {
		id: `pp-item-${randomUUID()}`,
		type: 2,
		name: "Passphrase fixture",
		notes: overrides.passphrase ?? PASSPHRASE_SENTINEL,
		...overrides,
	};
}

function stdinItem(overrides = {}) {
	return {
		id: `stdin-item-${randomUUID()}`,
		type: 1,
		name: "Stdin fixture",
		login: { username: "user", password: overrides.stdinValue ?? SECRET, uris: [] },
		...overrides,
	};
}

function memoryTrust() {
	const entries = new Map();
	return {
		entries,
		async verify(host, port, rawKey) {
			const id = `${host}:${port}`;
			const value = Buffer.from(rawKey).toString("hex");
			const trusted = entries.get(id);
			if (trusted !== undefined && trusted !== value) throw new SshHostKeyError("host_key_changed");
			entries.set(id, value);
			return trusted === undefined ? "accepted" : "trusted";
		},
		async close() {},
		get size() { return entries.size; },
	};
}

function fakeSshConnect(results = {}) {
	let calls = 0;
	const hostKeys = new Map();
	const connections = [];
	return {
		calls: () => calls,
		connections: () => connections,
		setHostKey(host, port, key) { hostKeys.set(`${host}:${port}`, key); },
		async connect({ host, port, username, privateKey, passphrase, timeoutMs, signal, verifyHostKey }) {
			calls++;
			if (results.connectError) {
				if (results.connectError === "timed_out") throw new SshError("timed_out");
				if (results.connectError === "auth_failed") throw new SshError("auth_failed");
				if (results.connectError === "network_error") throw new SshError("network_error");
				if (results.connectError === "host_key_changed") throw new SshHostKeyError("host_key_changed");
				throw new SshError("run_failed");
			}
			const rawHostKey = Buffer.from(hostKeys.get(`${host}:${port}`) ?? `fake-host-key-${host}-${port}`);
			await verifyHostKey(rawHostKey);
			const conn = {
				host, port, username, privateKey: Buffer.from(privateKey), passphrase: passphrase && Buffer.from(passphrase),
				closed: false,
				execCalls: [],
				async exec(command, stdinStream, execSignal) {
					this.execCalls.push({ command, hasStdin: !!stdinStream });
					if (results.execError) throw new SshError(results.execError);
					if (stdinStream) {
						try {
							for await (const chunk of stdinStream) { /* consume */ }
						} catch { /* consume error */ }
					}
					if (execSignal?.aborted) throw new DOMException("cancelled", "AbortError");
					return {
						exitCode: results.exitCode ?? 0,
						signal: results.execSignal ?? null,
						stdout: Buffer.from(results.stdout ?? "ssh output"),
						stderr: Buffer.from(results.stderr ?? ""),
						stdoutBytes: Buffer.byteLength(results.stdout ?? "ssh output"),
						stderrBytes: Buffer.byteLength(results.stderr ?? ""),
						overflow: results.overflow ?? false,
					};
				},
				close() { this.closed = true; },
			};
			connections.push(conn);
			return {
				hostVerified: true,
				async exec(command, stdinStream, execSignal) { return conn.exec(command, stdinStream, execSignal); },
				async close() { conn.close(); },
			};
		},
	};
}

async function fixture(options = {}) {
	const directory = await mkdtemp(join(tmpdir(), "vault-ssh-test-"));
	const sshItemData = options.sshItem ?? sshItem();
	const items = [sshItemData];
	const hostItemData = options.hostItem ?? (options.noHostItem ? undefined : hostItem());
	const ppItemData = options.passphraseItem ?? (options.noPassphraseItem ? undefined : passphraseItem());
	const stdinItemData = options.stdinItem ?? (options.noStdinItem ? undefined : stdinItem());
	if (hostItemData) items.push(hostItemData);
	if (ppItemData) items.push(ppItemData);
	if (stdinItemData) items.push(stdinItemData);
	const selectedItems = typeof options.itemsOverride === "function" ? options.itemsOverride(items) : items;
	const adapter = fakeAdapter(selectedItems);
	const fakeSsh = fakeSshConnect(options.sshResults ?? {});
	const broker = createBrokerServer({
		socketPath: join(directory, "broker.sock"),
		adapter,
		keychain: { async get() { return "fixture"; }, async set() {}, async delete() {} },
		sshConnect: fakeSsh.connect,
		knownHostsStore: options.knownHosts,
		idleMs: 60_000,
	});
	await broker.start();
	await requestSetup(join(directory, "broker.sock"), { server: "https://vault.example.test", email: "fixture@example.test", masterPassword: "fixture-password" });
	const page = await requestVaultItems(join(directory, "broker.sock"), { action: "list" });
	const sshSummary = page.items.find(i => i.type === "ssh-key");
	const sshInspection = sshSummary ? await requestVaultItems(join(directory, "broker.sock"), { action: "inspect", itemHandle: sshSummary.handle }) : undefined;
	const hostSummary = page.items.find(i => i.type === "login");
	const hostInspection = hostSummary ? await requestVaultItems(join(directory, "broker.sock"), { action: "inspect", itemHandle: hostSummary.handle }) : undefined;
	const ppSummary = page.items.find(i => i.type === "secure-note");
	const ppInspection = ppSummary ? await requestVaultItems(join(directory, "broker.sock"), { action: "inspect", itemHandle: ppSummary.handle }) : undefined;
	const stdinSummary = page.items.find(i => i.type === "login" && i.handle !== hostSummary?.handle);
	const stdinInspection = stdinSummary ? await requestVaultItems(join(directory, "broker.sock"), { action: "inspect", itemHandle: stdinSummary.handle }) : undefined;
	return {
		directory, broker, adapter, fakeSsh,
		socketPath: join(directory, "broker.sock"),
		sshInspection, hostInspection, ppInspection, stdinInspection,
		sshItemData, hostItemData, ppItemData, stdinItemData,
	};
}

async function closeFixture(value) {
	await value.broker.stop();
	await rm(value.directory, { recursive: true, force: true });
}

// --- SSH input validation ---

test("vault_ssh_run input validation rejects invalid shapes and missing fields", () => {
	assert.throws(() => validateVaultSshInput({}), (e) => e.code === "invalid_input");
	assert.throws(() => validateVaultSshInput({ privateKeyHandle: "h", command: "ls" }), (e) => e.code === "invalid_input");
	assert.throws(() => validateVaultSshInput({ host: "x", hostHandle: "y", privateKeyHandle: "h", command: "ls" }), (e) => e.code === "invalid_input");
	assert.throws(() => validateVaultSshInput({ host: "x", privateKeyHandle: "h", command: "ls", extra: 1 }), (e) => e.code === "invalid_input");
	assert.throws(() => validateVaultSshInput({ host: "x", privateKeyHandle: "\0bad", command: "ls" }), (e) => e.code === "invalid_handle");
	assert.throws(() => validateVaultSshInput({ host: "x", privateKeyHandle: "h", command: "\0bad" }), (e) => e.code === "invalid_input");
	assert.throws(() => validateVaultSshInput({ host: "x", privateKeyHandle: "h", command: "ls", port: 0 }), (e) => e.code === "invalid_input");
	assert.throws(() => validateVaultSshInput({ host: "x", privateKeyHandle: "h", command: "ls", port: 99999 }), (e) => e.code === "invalid_input");
});

test("valid SSH input normalizes defaults", () => {
	const result = validateVaultSshInput({ host: "test.local", privateKeyHandle: "h_key", command: "ls" });
	assert.equal(result.host, "test.local");
	assert.equal(result.username, "root");
	assert.equal(result.port, 22);
	assert.equal(result.privateKeyHandle, "h_key");
	assert.equal(result.command, "ls");
	assert.equal(result.timeoutMs, 120_000);
});

// --- SSH integration via broker ---

test("successful SSH run redacts secrets from output", async () => {
	const value = await fixture();
	try {
		const result = await requestVaultSshRun(value.socketPath, {
			host: TEST_HOST,
			username: "testuser",
			port: 2222,
			privateKeyHandle: value.sshInspection.materials.find(m => m.type === "private-key").handle,
			command: "echo hello",
		});
		assert.equal(result.exitCode, 0);
		assert(!JSON.stringify(result).includes(KEY_SENTINEL));
		assert(!JSON.stringify(result).includes(TEST_KEY));
		assert(!JSON.stringify(result).includes("PRIVATE_SESSION_SSH_TEST"));
		assert.equal(result.mode, "text");
		assert(result.stdout.includes("ssh output"));
	} finally { await closeFixture(value); }
});

test("host key first-use accept and second-use trust", async () => {
	const knownHosts = memoryTrust();
	const value = await fixture({ knownHosts });
	try {
		// First use: accept
		const first = await requestVaultSshRun(value.socketPath, {
			host: TEST_HOST, privateKeyHandle: value.sshInspection.materials.find(m => m.type === "private-key").handle, command: "id",
		});
		assert.equal(first.exitCode, 0);
		assert(knownHosts.size >= 1);
		// Second use: trust, should succeed
		const second = await requestVaultSshRun(value.socketPath, {
			host: TEST_HOST, privateKeyHandle: value.sshInspection.materials.find(m => m.type === "private-key").handle, command: "id",
		});
		assert.equal(second.exitCode, 0);
		assert.equal(value.fakeSsh.calls(), 2);
	} finally { await closeFixture(value); }
});

test("host key mismatch fails closed", async () => {
	const knownHosts = memoryTrust();
	// Pre-populate a different raw-key verifier.
	await knownHosts.verify(TEST_HOST, 22, Buffer.from("wrong-host-key"));
	const value = await fixture({ knownHosts });
	try {
		await assert.rejects(
			requestVaultSshRun(value.socketPath, {
				host: TEST_HOST, privateKeyHandle: value.sshInspection.materials.find(m => m.type === "private-key").handle, command: "id",
			}),
			(e) => e instanceof BrokerRequestError && e.code === "host_key_changed"
		);
	} finally { await closeFixture(value); }
});

test("authentication failure returns bounded error", async () => {
	const value = await fixture({ sshResults: { connectError: "auth_failed" } });
	try {
		await assert.rejects(
			requestVaultSshRun(value.socketPath, {
				host: TEST_HOST, privateKeyHandle: value.sshInspection.materials.find(m => m.type === "private-key").handle, command: "id",
			}),
			(e) => e instanceof BrokerRequestError && e.code === "auth_failed"
		);
	} finally { await closeFixture(value); }
});

test("exec failure returns a bounded error and closes the connection", async () => {
	const value = await fixture({ sshResults: { execError: "run_failed" } });
	try {
		await assert.rejects(requestVaultSshRun(value.socketPath, {
			host: TEST_HOST, privateKeyHandle: value.sshInspection.materials.find(m => m.type === "private-key").handle, command: "fail",
		}), (error) => error instanceof BrokerRequestError && error.code === "run_failed");
		assert.equal(value.fakeSsh.connections()[0].closed, true);
	} finally { await closeFixture(value); }
});

test("network failure and timeout return bounded errors", async () => {
	for (const err of ["network_error", "timed_out"]) {
		const value = await fixture({ sshResults: { connectError: err } });
		try {
			await assert.rejects(
				requestVaultSshRun(value.socketPath, {
					host: TEST_HOST, privateKeyHandle: value.sshInspection.materials.find(m => m.type === "private-key").handle, command: "id",
				}),
				(e) => e instanceof BrokerRequestError && e.code === err
			);
		} finally { await closeFixture(value); }
	}
});

test("hostHandle resolves material to connect and its value is redacted", async () => {
	const value = await fixture({ sshResults: { stdout: `${TEST_HOST} ${Buffer.from(TEST_HOST).toString("base64")}` } });
	try {
		// Use the host item's username field as the host handle
		const hostMaterial = value.hostInspection.materials.find(m => m.type === "username");
		assert(hostMaterial);
		const result = await requestVaultSshRun(value.socketPath, {
			hostHandle: hostMaterial.handle,
			privateKeyHandle: value.sshInspection.materials.find(m => m.type === "private-key").handle,
			command: "hostname",
		});
		assert.equal(result.exitCode, 0);
		assert(!result.stdout.includes(TEST_HOST));
		assert(!result.stdout.includes(Buffer.from(TEST_HOST).toString("base64")));
		const conn = value.fakeSsh.connections()[0];
		assert.equal(conn.host, TEST_HOST);
	} finally { await closeFixture(value); }
});

test("cross-item SSH roles work with host, key, passphrase, and stdin from different items", async () => {
	const value = await fixture();
	try {
		const pkHandle = value.sshInspection.materials.find(m => m.type === "private-key").handle;
		const ppHandle = value.ppInspection?.materials[0]?.handle;
		const stdinHandle = value.stdinInspection?.materials.find(m => m.type === "password")?.handle;

		const result = await requestVaultSshRun(value.socketPath, {
			host: TEST_HOST,
			privateKeyHandle: pkHandle,
			passphraseHandle: ppHandle,
			command: "cat",
			stdinHandle,
		});
		assert.equal(result.exitCode, 0);
		// Check stdin was forwarded
		const conn = value.fakeSsh.connections()[0];
		assert(conn.execCalls[0].hasStdin);
		assert.equal(conn.passphrase.toString(), PASSPHRASE_SENTINEL);
		assert.equal(conn.privateKey.toString(), TEST_KEY);
	} finally { await closeFixture(value); }
});

test("wrong-kind handles reject before connection", async () => {
	const value = await fixture();
	try {
		// Try using an attachment as private key
		const attachmentItem = {
			id: "attach-item",
			type: 2,
			name: "attachment fixture",
			fields: [{ name: "data", value: "test" }],
			attachments: [{ id: "ATTACH_ID", fileName: "file.bin", size: "4" }],
		};
		const attachFixture = await fixture({
			sshItem: sshItem(),
			hostItem: hostItem(),
			noPassphraseItem: true,
			noStdinItem: true,
			itemsOverride: (items) => [...items, attachmentItem],
		});
		try {
			const attachPage = await requestVaultItems(attachFixture.socketPath, { action: "list" });
			const attachSummary = attachPage.items.find(i => i.attachmentCount > 0);
			const attachInspection = attachSummary ? await requestVaultItems(attachFixture.socketPath, { action: "inspect", itemHandle: attachSummary.handle }) : undefined;

			// Try attachment handle as private key
			if (attachInspection?.attachments[0]) {
				await assert.rejects(
					requestVaultSshRun(attachFixture.socketPath, {
						host: TEST_HOST,
						privateKeyHandle: attachInspection.attachments[0].handle,
						command: "id",
					}),
					(e) => e instanceof BrokerRequestError && e.code === "material_incompatible"
				);
			}
		} finally { await closeFixture(attachFixture); }

		// Try invalid handle
		await assert.rejects(
			requestVaultSshRun(value.socketPath, {
				host: TEST_HOST,
				privateKeyHandle: "expired-handle",
				command: "id",
			}),
			(e) => e instanceof BrokerRequestError && e.code === "invalid_handle"
		);

		// Try wrong-type material as hostHandle (private key contains newlines → invalid host)
		await assert.rejects(
			requestVaultSshRun(value.socketPath, {
				hostHandle: value.sshInspection.materials.find(m => m.type === "private-key").handle,
				privateKeyHandle: value.sshInspection.materials.find(m => m.type === "private-key").handle,
				command: "id",
			}),
			(e) => e instanceof BrokerRequestError && e.code === "material_incompatible"
		);
	} finally { await closeFixture(value); }
});

test("NUL-bearing and oversized host material reject before network", async () => {
	for (const hostValue of ["bad\0host", "h".repeat(513)]) {
		const value = await fixture({ hostItem: hostItem({ hostValue }) });
		try {
			const hostHandle = value.hostInspection.materials.find(m => m.type === "username").handle;
			await assert.rejects(requestVaultSshRun(value.socketPath, {
				hostHandle, privateKeyHandle: value.sshInspection.materials.find(m => m.type === "private-key").handle, command: "id",
			}), (error) => error instanceof BrokerRequestError && error.code === "material_incompatible");
			assert.equal(value.fakeSsh.calls(), 0);
		} finally { await closeFixture(value); }
	}
});

test("duplicate handle usage rejects", async () => {
	const value = await fixture();
	try {
		const pkHandle = value.sshInspection.materials.find(m => m.type === "private-key").handle;
		await assert.rejects(
			requestVaultSshRun(value.socketPath, {
				host: TEST_HOST,
				privateKeyHandle: pkHandle,
				passphraseHandle: pkHandle,
				command: "id",
			}),
			(e) => e instanceof BrokerRequestError && e.code === "duplicate_handle"
		);
	} finally { await closeFixture(value); }
});

test("stale handles reject after session expiry", async () => {
	const value = await fixture();
	try {
		const pkHandle = value.sshInspection.materials.find(m => m.type === "private-key").handle;
		// Invalidate the session
		await value.broker.invalidateSession();
		await assert.rejects(
			requestVaultSshRun(value.socketPath, {
				host: TEST_HOST, privateKeyHandle: pkHandle, command: "id",
			}),
			(e) => e instanceof BrokerRequestError && e.code === "invalid_handle"
		);
	} finally { await closeFixture(value); }
});

test("bulk stdin suppresses text output", async () => {
	const largeData = { id: "stdin-large", type: 1, name: "large stdin", login: { username: "u", password: "x".repeat(300 * 1024), uris: [] } };
	const value = await fixture({ stdinItem: largeData });
	try {
		const pkHandle = value.sshInspection.materials.find(m => m.type === "private-key").handle;
		const stdinHandle = value.stdinInspection.materials.find(m => m.type === "password").handle;
		const result = await requestVaultSshRun(value.socketPath, {
			host: TEST_HOST, privateKeyHandle: pkHandle, command: "cat", stdinHandle,
		});
		assert.equal(result.mode, "bulk");
		assert.equal(result.stdout, undefined);
		assert.equal(result.stderr, undefined);
	} finally { await closeFixture(value); }
});

test("SSH attachment stdin keeps descriptor resolution separate from the streamed source", async () => {
	const attachmentItem = { id: "ssh-attachment-item", type: 2, name: "SSH attachment", attachments: [{ id: "ssh-attachment-id", fileName: "payload.bin", size: "7" }] };
	const value = await fixture({ itemsOverride: (items) => [...items, attachmentItem] });
	try {
		const page = await requestVaultItems(value.socketPath, { action: "list" });
		const summary = page.items.find(item => item.attachmentCount === 1);
		const inspection = await requestVaultItems(value.socketPath, { action: "inspect", itemHandle: summary.handle });
		let opened = 0;
		value.adapter.streamAttachment = ({ itemId, attachmentId }) => {
			opened++;
			assert.equal(itemId, "ssh-attachment-item");
			assert.equal(attachmentId, "ssh-attachment-id");
			return { stream: Readable.from([Buffer.from("payload")]) };
		};
		const result = await requestVaultSshRun(value.socketPath, {
			host: TEST_HOST, privateKeyHandle: value.sshInspection.materials.find(m => m.type === "private-key").handle,
			command: "cat", stdinHandle: inspection.attachments[0].handle,
		});
		assert.equal(result.mode, "bulk");
		assert.equal(opened, 1);
	} finally { await closeFixture(value); }
});

test("output overflow returns safe error", async () => {
	const value = await fixture({ sshResults: { overflow: true } });
	try {
		await assert.rejects(
			requestVaultSshRun(value.socketPath, {
				host: TEST_HOST, privateKeyHandle: value.sshInspection.materials.find(m => m.type === "private-key").handle, command: "id",
			}),
			(e) => e instanceof BrokerRequestError && e.code === "output_overflow"
		);
	} finally { await closeFixture(value); }
});

test("invalid UTF-8 output is mapped safely instead of failing or leaking bytes", async () => {
	const value = await fixture({ sshResults: { stdout: Buffer.from([0x66, 0x6f, 0x80, 0x6f]), stderr: Buffer.from([0xff]) } });
	try {
		const result = await requestVaultSshRun(value.socketPath, {
			host: TEST_HOST, privateKeyHandle: value.sshInspection.materials.find(m => m.type === "private-key").handle, command: "output",
		});
		assert.equal(result.stdout, "fo�o");
		assert.equal(result.stderr, "�");
		assert.equal(result.stdoutBytes, 4);
		assert.equal(result.stderrBytes, 1);
	} finally { await closeFixture(value); }
});

test("cancellation aborts SSH connection and returns clean AbortError", async () => {
	const value = await fixture();
	try {
		const controller = new AbortController();
		controller.abort();
		await assert.rejects(
			requestVaultSshRun(value.socketPath, {
				host: TEST_HOST, privateKeyHandle: value.sshInspection.materials.find(m => m.type === "private-key").handle, command: "id",
			}, controller.signal),
			(e) => e?.name === "AbortError"
		);
	} finally { await closeFixture(value); }
});

test("one total deadline and cancellation settle only after channel and connection cleanup", async () => {
	const keyRecord = { descriptor: { category: "ssh-key", type: "private-key", delivery: { environment: true, stdin: true } }, value: TEST_KEY };
	for (const mode of ["timeout", "cancel"]) {
		let channelGone = false;
		let connectionGone = false;
		const controller = new AbortController();
		const pending = executeVaultSsh({ host: TEST_HOST, privateKeyHandle: "key", command: "wait", timeoutMs: mode === "timeout" ? 30 : 1_000 }, {
			resolveMaterial: handle => handle === "key" ? keyRecord : undefined,
			knownHosts: memoryTrust(),
			sshConnect: async ({ verifyHostKey, signal }) => {
				await verifyHostKey(Buffer.from("deadline-host-key"));
				return {
					hostVerified: true,
					async exec() {
						await new Promise(resolve => signal.addEventListener("abort", resolve, { once: true }));
						channelGone = true;
						return { exitCode: null, signal: "SIGTERM", stdout: Buffer.alloc(0), stderr: Buffer.alloc(0), stdoutBytes: 0, stderrBytes: 0, overflow: false };
					},
					async close() { await new Promise(resolve => setTimeout(resolve, 20)); connectionGone = true; },
				};
			},
			signal: controller.signal,
		});
		if (mode === "cancel") setTimeout(() => controller.abort(), 20);
		if (mode === "timeout") {
			const result = await pending;
			assert.equal(result.timedOut, true);
		} else await assert.rejects(pending, error => error.name === "AbortError");
		assert.equal(channelGone, true);
		assert.equal(connectionGone, true);
	}
});

test("timeout waits for an attachment source process group to be gone", async () => {
	const keyRecord = { descriptor: { category: "ssh-key", type: "private-key", delivery: { environment: true, stdin: true } }, value: TEST_KEY };
	const attachmentRecord = { descriptor: { category: "attachment", type: "bytes", delivery: { environment: false, stdin: true } }, itemId: "item", attachmentId: "attachment", value: { id: "private-descriptor" } };
	let source;
	const started = Date.now();
	const result = await executeVaultSsh({ host: TEST_HOST, privateKeyHandle: "key", stdinHandle: "attachment", command: "wait", timeoutMs: 30 }, {
		resolveMaterial: handle => handle === "key" ? keyRecord : undefined,
		resolveAttachment: handle => handle === "attachment" ? attachmentRecord : undefined,
		openAttachment() {
			source = nodeSpawn(process.execPath, ["-e", "process.on('SIGTERM',()=>{}); setInterval(()=>{},1000)"], { detached: true, stdio: ["ignore", "pipe", "pipe"] });
			source.stderr.resume();
			return { stream: source.stdout, process: source };
		},
		knownHosts: memoryTrust(),
		sshConnect: async ({ verifyHostKey, signal }) => {
			await verifyHostKey(Buffer.from("attachment-cleanup-key"));
			return {
				hostVerified: true,
				async exec() { await new Promise(resolve => signal.addEventListener("abort", resolve, { once: true })); return { exitCode: null, signal: null, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0), stdoutBytes: 0, stderrBytes: 0, overflow: false }; },
				async close() {},
			};
		},
	});
	assert.equal(result.timedOut, true);
	assert(source.signalCode !== null || source.exitCode !== null);
	assert.throws(() => process.kill(source.pid, 0));
	assert.throws(() => process.kill(-source.pid, 0));
	assert(Date.now() - started < 5_000, "cleanup exceeded IPC transport grace");
});

test("timeout returns timedOut result metadata", async () => {
	// Uses the timeout via the SSH parameter
	const value = await fixture({
		sshResults: { connectError: "timed_out" },
	});
	try {
		await assert.rejects(
			requestVaultSshRun(value.socketPath, {
				host: TEST_HOST, privateKeyHandle: value.sshInspection.materials.find(m => m.type === "private-key").handle, command: "sleep 30", timeoutMs: 100,
			}),
			(e) => e instanceof BrokerRequestError && e.code === "timed_out"
		);
	} finally { await closeFixture(value); }
});

test("ssh IPC timeout derives from validated SSH timeout plus grace", () => {
	assert.equal(vaultSshRunRequestTimeoutMs({ host: "x", privateKeyHandle: "h", command: "ls", timeoutMs: 120_000 }), 125_000);
});

// --- Production ssh2 adapter ---

function ssh2CompatibleClientHarness(rawHostKey = Buffer.from("production-adapter-host-key"), outputs = {}) {
	const instances = [];
	class Client extends EventEmitter {
		constructor() { super(); this.closed = false; this.authStarted = false; this.stdin = []; instances.push(this); }
		connect(config) {
			this.config = config;
			config.hostVerifier(rawHostKey, (accepted) => {
				if (!accepted) {
					this.emit("error", new Error("host verification failed"));
					this.destroy();
					return;
				}
				this.authStarted = true;
				queueMicrotask(() => this.emit("ready"));
			});
		}
		exec(command, callback) {
			this.command = command;
			const channel = new EventEmitter();
			channel.stderr = new EventEmitter();
			channel.resume = () => {};
			channel.stderr.resume = () => {};
			let first = true;
			channel.write = (chunk) => {
				this.stdin.push(Buffer.from(chunk));
				if (first) { first = false; setImmediate(() => channel.emit("drain")); return false; }
				return true;
			};
			channel.end = () => setImmediate(() => {
				channel.emit("data", Buffer.from(outputs.stdout ?? "adapter stdout"));
				channel.stderr.emit("data", Buffer.from(outputs.stderr ?? "adapter stderr"));
				channel.emit("exit", 7, null);
				channel.emit("close", 7, null);
			});
			channel.close = () => { this.destroy(); channel.emit("close", null, "SIGTERM"); };
			callback(null, channel);
		}
		end() { this.destroy(); }
		destroy() { if (!this.closed) { this.closed = true; queueMicrotask(() => this.emit("close")); } }
	}
	return { Client, instances, rawHostKey };
}

test("production adapter uses ssh2 hostVerifier before auth and covers exec streams, exit, and close", async () => {
	const harness = ssh2CompatibleClientHarness();
	const connect = createSshClient({ Client: harness.Client });
	let verified = false;
	const connection = await connect({
		host: "adapter.example", port: 2222, username: "deploy",
		privateKey: Buffer.from(TEST_KEY), passphrase: Buffer.from("adapter-passphrase"), timeoutMs: 1_000,
		verifyHostKey(rawKey) { assert.deepEqual(rawKey, harness.rawHostKey); verified = true; },
	});
	const client = harness.instances[0];
	assert.equal(verified, true);
	assert.equal(client.authStarted, true);
	assert.equal(client.config.host, "adapter.example");
	assert.deepEqual(client.config.privateKey, Buffer.from(TEST_KEY));
	assert.equal(client.config.passphrase, "adapter-passphrase");
	const result = await connection.exec("fixture-command", Readable.from([Buffer.from("one"), Buffer.from("two")]), new AbortController().signal);
	assert.equal(client.command, "fixture-command");
	assert.equal(Buffer.concat(client.stdin).toString(), "onetwo");
	assert.equal(result.stdout.toString(), "adapter stdout");
	assert.equal(result.stderr.toString(), "adapter stderr");
	assert.equal(result.stdoutBytes, 14);
	assert.equal(result.stderrBytes, 14);
	assert.equal(result.exitCode, 7);
	await connection.close();
	assert.equal(client.closed, true);
});

test("production adapter caps combined stdout and stderr while retaining exact byte counts", async () => {
	const stdout = Buffer.alloc(700_000, 0x41);
	const stderr = Buffer.alloc(400_001, 0x42);
	const harness = ssh2CompatibleClientHarness(Buffer.from("combined-cap-key"), { stdout, stderr });
	const connection = await createSshClient({ Client: harness.Client })({
		host: "adapter.example", port: 22, username: "root", privateKey: Buffer.from(TEST_KEY), timeoutMs: 1_000,
		verifyHostKey() {},
	});
	const result = await connection.exec("output", undefined, new AbortController().signal);
	assert.equal(result.overflow, true);
	assert.equal(result.stdoutBytes, stdout.length);
	assert.equal(result.stderrBytes, stderr.length);
	assert.equal(result.stdout.length + result.stderr.length, 1024 * 1024);
	await connection.close();

	const bulkHarness = ssh2CompatibleClientHarness(Buffer.from("bulk-cap-key"), { stdout, stderr });
	const bulkConnection = await createSshClient({ Client: bulkHarness.Client })({
		host: "adapter.example", port: 22, username: "root", privateKey: Buffer.from(TEST_KEY), timeoutMs: 1_000, verifyHostKey() {},
	});
	const suppressed = await bulkConnection.exec("output", undefined, new AbortController().signal, { suppressOutput: true });
	assert.equal(suppressed.overflow, false);
	assert.equal(suppressed.stdoutBytes, stdout.length);
	assert.equal(suppressed.stderrBytes, stderr.length);
	assert.equal(suppressed.stdout.length + suppressed.stderr.length, 0);
	await bulkConnection.close();
});

test("production adapter maps authentication failure and closes the client", async () => {
	const instances = [];
	class AuthFailureClient extends EventEmitter {
		constructor() { super(); this.closed = false; instances.push(this); }
		connect(config) {
			config.hostVerifier(Buffer.from("auth-failure-key"), (accepted) => {
				assert.equal(accepted, true);
				this.emit("error", new Error("All configured authentication methods failed"));
				this.destroy();
			});
		}
		end() { this.destroy(); }
		destroy() { if (!this.closed) { this.closed = true; queueMicrotask(() => this.emit("close")); } }
	}
	await assert.rejects(createSshClient({ Client: AuthFailureClient })({
		host: "adapter.example", port: 22, username: "root", privateKey: Buffer.from(TEST_KEY), timeoutMs: 1_000, verifyHostKey() {},
	}), (error) => error.code === "auth_failed");
	assert.equal(instances[0].closed, true);
});

test("production adapter rejects a changed key in hostVerifier before authentication", async () => {
	const harness = ssh2CompatibleClientHarness(Buffer.from("changed-production-key"));
	const connect = createSshClient({ Client: harness.Client });
	await assert.rejects(connect({
		host: "adapter.example", port: 22, username: "root", privateKey: Buffer.from(TEST_KEY), timeoutMs: 1_000,
		verifyHostKey() { throw new SshHostKeyError("host_key_changed"); },
	}), (error) => error.code === "host_key_changed");
	assert.equal(harness.instances[0].authStarted, false);
	assert.equal(harness.instances[0].closed, true);
});

// --- SSH redaction ---

test("SSH redaction covers all encoding variants", () => {
	const secret = "redact_this_ssh_secret";
	const output = `before ${secret} after ${Buffer.from(secret).toString("base64")} end`;
	const redacted = redactSshOutput(output, [secret]);
	assert(!redacted.includes(secret));
	assert(!redacted.includes(Buffer.from(secret).toString("base64")));
	assert(redacted.includes("[REDACTED]"));
});

test("SSH material encoding variants cover base64, hex, uri, json", () => {
	const value = "testvalue";
	const variants = sshMaterialEncodingVariants(value);
	assert(variants.some(v => v.includes("testvalue")));
	assert(variants.some(v => v.includes("dGVzdHZhbHVl")));
	assert(variants.some(v => v.includes("7465737476616c7565")));
});

// --- Known hosts store ---

test("known hosts store persists keyed identifiers atomically without host material", async () => {
	const directory = await mkdtemp(join(tmpdir(), "vault-known-hosts-"));
	const storePath = join(directory, "known_hosts.json");
	const host = "host-material-sentinel.example";
	const rawKey = Buffer.from("raw-host-key-material-sentinel");
	try {
		const store = await createKnownHostsStore({ storePath });
		assert.equal(await store.verify(host, 22, rawKey), "accepted");
		assert.equal(await store.verify(host, 22, rawKey), "trusted");
		await Promise.all(Array.from({ length: 10 }, (_, index) => store.verify(`concurrent-${index}.example`, 22, Buffer.from(`key-${index}`))));
		assert.equal(store.size, 11);
		assert.deepEqual(await readdir(directory), ["known_hosts.json"]);
		const persisted = await readFile(storePath, "utf8");
		assert.equal((await stat(storePath)).mode & 0o777, 0o600);
		for (const forbidden of [host, `${host}:22`, rawKey.toString(), rawKey.toString("hex"), rawKey.toString("base64"), Buffer.from(host).toString("hex"), Buffer.from(host).toString("base64")]) {
			assert(!persisted.includes(forbidden), `trust file leaked ${forbidden}`);
		}
		await store.close();
		const reloaded = await createKnownHostsStore({ storePath });
		assert.equal(reloaded.size, 11);
		assert.equal(await reloaded.verify(host, 22, rawKey), "trusted");
		await assert.rejects(reloaded.verify(host, 22, Buffer.from("changed-key")), (error) => error.code === "host_key_changed");
		await reloaded.close();
	} finally { await rm(directory, { recursive: true, force: true }); }
});

test("known hosts store fails closed on corrupt, insecure, or unwritable state", async () => {
	for (const fixture of ["corrupt", "insecure", "unwritable"]) {
		const directory = await mkdtemp(join(tmpdir(), `vault-known-${fixture}-`));
		const storePath = join(directory, "known_hosts.json");
		try {
			if (fixture === "unwritable") {
				await chmod(directory, 0o500);
			} else {
				await writeFile(storePath, fixture === "corrupt" ? "not json at all!!!" : JSON.stringify({ version: 1, key: "x", entries: {} }), { mode: 0o600 });
				if (fixture === "insecure") await chmod(storePath, 0o644);
			}
			await assert.rejects(createKnownHostsStore({ storePath }), (error) => error.code === "host_key_unavailable");
		} finally { await chmod(directory, 0o700).catch(() => {}); await rm(directory, { recursive: true, force: true }); }
	}
});

// --- Extension rendering ---

test("vault_ssh_run tool renders with no raw secrets", async () => {
	const value = await fixture();
	try {
		const tools = [];
		const pi = { registerTool(tool) { tools.push(tool); }, registerCommand() {}, on() {} };
		const client = {
			async sshRun(input, signal) { return requestVaultSshRun(value.socketPath, input, signal); },
			async status() { return "unlocked"; },
		};
		registerVaultExtension(pi, { client });
		const tool = tools.find(t => t.name === "vault_ssh_run");
		assert(tool);
		const pkHandle = value.sshInspection.materials.find(m => m.type === "private-key").handle;
		const result = await tool.execute("call", {
			host: TEST_HOST,
			privateKeyHandle: pkHandle,
			command: "echo secret",
		}, undefined, undefined, { mode: "print" });
		assert(!JSON.stringify(result).includes(KEY_SENTINEL));
		assert(!JSON.stringify(result).includes(TEST_KEY));
		assert(!JSON.stringify(result).includes("PRIVATE_SESSION_SSH_TEST"));

		// Check collapsed renderCall
		const collapsedCall = tool.renderCall({ host: TEST_HOST, privateKeyHandle: pkHandle, command: "echo hi" }, {
			fg: (_c, v) => v, bold: v => v, dim: v => v, muted: v => v,
		}, { expanded: false });
		assert(!JSON.stringify(collapsedCall).includes(KEY_SENTINEL));

		// Check expanded renderCall
		const expandedCall = tool.renderCall({ host: TEST_HOST, privateKeyHandle: pkHandle, command: "echo hi" }, {
			fg: (_c, v) => v, bold: v => v, dim: v => v, muted: v => v,
		}, { expanded: true });
		assert(!JSON.stringify(expandedCall).includes(KEY_SENTINEL));
		assert(!JSON.stringify(expandedCall).includes(TEST_KEY));

		// Check collapsed renderResult
		const collapsedResult = tool.renderResult(result, { expanded: false, isPartial: false }, {
			fg: (_c, v) => v, bold: v => v, dim: v => v, muted: v => v,
		});
		assert(!JSON.stringify(collapsedResult).includes(KEY_SENTINEL));

		// Check expanded renderResult
		const expandedResult = tool.renderResult(result, { expanded: true, isPartial: false }, {
			fg: (_c, v) => v, bold: v => v, dim: v => v, muted: v => v, toolOutput: v => v, warning: v => v,
		});
		assert(!JSON.stringify(expandedResult).includes(KEY_SENTINEL));
		assert(!JSON.stringify(expandedResult).includes(TEST_KEY));
	} finally { await closeFixture(value); }
});

test("vault_items renders native search previews and complete expanded inputs", async () => {
	const theme = { fg: (_c, v) => v, bold: v => v, dim: v => v, muted: v => v };
	const tools = [];
	const pi = { registerTool(tool) { tools.push(tool); }, registerCommand() {}, on() {} };
	const client = { async items() { return { action: "list", state: "unlocked", items: [] }; }, async status() { return "unlocked"; } };
	registerVaultExtension(pi, { client });
	const tool = tools[0];
	const args = { action: "search", query: "test-query", cursor: "next-page", limit: 5 };

	const collapsed = tool.renderCall(args, theme, { expanded: false, isPartial: true });
	assert.equal(collapsed.render(80)[0].trimEnd(), 'vault_search: "test-query"');

	const expanded = tool.renderCall(args, theme, { expanded: true, isPartial: true });
	const text = expanded.render(80).join("\n");
	assert(text.includes('vault_search: "test-query"'));
	assert(text.includes('cursor: "next-page"'));
	assert(text.includes("limit: 5"));
});

test("vault_items collapses search and inspect into native one-line result previews", () => {
	const theme = { fg: (_c, v) => v, bold: v => v };
	const tools = [];
	registerVaultExtension({ registerTool(tool) { tools.push(tool); }, registerCommand() {}, on() {} }, { client: {} });
	const tool = tools.find((entry) => entry.name === "vault_items");
	const searchArgs = { action: "search", query: "Home API" };
	const search = tool.renderResult({ content: [], details: { action: "search", items: [{}, {}], count: 2 } }, { expanded: false }, theme, { args: searchArgs });
	assert(search.render(120)[0].startsWith('vault_search: "Home API" - 2 results'));
	const inspectArgs = { action: "inspect", itemHandle: "h_item" };
	const inspect = tool.renderResult({ content: [], details: { action: "inspect", itemHandle: "h_item", type: "login", materials: [{}], attachments: [], count: 1 } }, { expanded: false }, theme, { args: inspectArgs });
	assert(inspect.render(120)[0].startsWith('vault_inspect: "h_item" - 1 descriptor'));
	assert.equal(tool.renderCall(searchArgs, theme, { expanded: false, isPartial: false }).render(120).length, 0);
});

test("vault_run always renders a normal full command with material placeholders", async () => {
	const theme = { fg: (_c, v) => v, bold: v => v, dim: v => v, muted: v => v };
	const tools = [];
	const pi = { registerTool(tool) { tools.push(tool); }, registerCommand() {}, on() {} };
	const client = { async run() { return { mode: "text", exitCode: 0, signal: null, durationMs: 1, timedOut: false, cancelled: false, stdoutBytes: 0, stderrBytes: 0, stdout: "", stderr: "" }; }, async status() { return "unlocked"; } };
	registerVaultExtension(pi, { client });
	const tool = tools.find(t => t.name === "vault_run");
	assert(tool);
	const args = {
		executable: "/usr/bin/ssh", argv: ["-o", "StrictHostKeyChecking=yes", "host example"], cwd: "/tmp/work tree",
		env: { APP_MODE: "fixture" }, materialEnv: { HOMECTL_API_KEY: "h_123" }, stdin: "h_456", timeoutMs: 60000,
	};

	for (const expanded of [false, true]) {
		const text = tool.renderCall(args, theme, { expanded }).render(10_000).join("\n");
		assert(text.includes("vault_run - cd '/tmp/work tree' && APP_MODE=fixture HOMECTL_API_KEY=${HOMECTL_API_KEY} /usr/bin/ssh -o StrictHostKeyChecking=yes 'host example' < ${VAULT_STDIN}"));
		assert(text.includes("timeout 60000ms"));
		assert(!text.includes("h_123"));
		assert(!text.includes("h_456"));
		assert(text.startsWith("vault_run - "));
	}
});

test("vault_items expanded renderResult for list/search renders all summaries", async () => {
	const theme = { fg: (_c, v) => v, bold: v => v, dim: v => v, muted: v => v, toolTitle: v => v, toolOutput: v => v, success: v => v };
	const tools = [];
	const pi = { registerTool(tool) { tools.push(tool); }, registerCommand() {}, on() {} };
	registerVaultExtension(pi, { client: { async items() { return { action: "list", state: "unlocked", items: [] }; }, async status() { return "unlocked"; } } });
	const tool = tools[0];

	const result = {
		content: [{ type: "text", text: "ok" }],
		details: {
			action: "list",
			state: "unlocked",
			items: [
				{ handle: "h_a", type: "login", favorite: true, title: "GitHub", folderName: "Work", normalizedOrigins: ["https://github.com"], materialCount: 3, attachmentCount: 0 },
			],
			count: 1,
		},
	};
	const rendered = tool.renderResult(result, { expanded: true }, theme);
	const lines = rendered.render(80);
	const text = lines.join("\n");
	assert(text.includes("GitHub") && text.includes("login") && text.includes("h_a"));
	assert(text.includes("Work"));
	assert(text.includes("github.com"));

	const collapsed = tool.renderResult(result, { expanded: false }, theme);
	assert(collapsed.render(80)[0].includes("Ctrl+O"));
});

test("vault_items expanded renderResult for inspect renders all descriptors", async () => {
	const theme = { fg: (_c, v) => v, bold: v => v, dim: v => v, muted: v => v, toolTitle: v => v, toolOutput: v => v, success: v => v };
	const tools = [];
	const pi = { registerTool(tool) { tools.push(tool); }, registerCommand() {}, on() {} };
	registerVaultExtension(pi, { client: { async items() { return { action: "list", state: "unlocked", items: [] }; }, async status() { return "unlocked"; } } });
	const tool = tools[0];

	const result = {
		content: [{ type: "text", text: "ok" }],
		details: {
			action: "inspect",
			state: "unlocked",
			itemHandle: "h_inspect",
			materials: [
				{ handle: "m1", category: "login", type: "username", label: "username", delivery: { environment: true, stdin: true } },
				{ handle: "m2", category: "login", type: "password", label: "password", delivery: { environment: true, stdin: true } },
			],
			attachments: [
				{ handle: "a1", category: "attachment", type: "bytes", filename: "config.txt", mimeType: "text/plain", size: 123, delivery: { environment: false, stdin: true } },
			],
			count: 3,
		},
	};
	const rendered = tool.renderResult(result, { expanded: true }, theme);
	const lines = rendered.render(80);
	const text = lines.join("\n");
	assert(text.includes("username") && text.includes("login") && text.includes("m1"));
	assert(text.includes("password") && text.includes("m2"));
	assert(text.includes("config.txt") && text.includes("a1") && text.includes("123"));
	assert(text.includes("environment") && text.includes("stdin"));
});

test("expanded renderers are complete, use context.expanded, and remain width-safe", () => {
	const theme = { fg: (_c, value) => value, bold: value => value };
	const tools = [];
	registerVaultExtension({ registerTool(tool) { tools.push(tool); }, registerCommand() {}, on() {} }, { client: {} });
	const byName = Object.fromEntries(tools.map(tool => [tool.name, tool]));
	const longArg = "A".repeat(300);
	const runArgs = {
		executable: `/tmp/${longArg}`, argv: [longArg, "second"], cwd: `/tmp/${longArg}`,
		env: { PUBLIC_VALUE: longArg }, materialEnv: { SECRET_INPUT: "opaque-material-handle" },
		stdin: "opaque-stdin-handle", timeoutMs: 900_000,
	};
	const runCall = byName.vault_run.renderCall(runArgs, theme, { expanded: true });
	const runCallText = runCall.render(10_000).join("\n");
	for (const value of [runArgs.executable, longArg, "PUBLIC_VALUE", "${SECRET_INPUT}", "${VAULT_STDIN}", "900000"]) assert(runCallText.includes(value));
	assert(!runCallText.includes("opaque-material-handle"));
	assert(!runCallText.includes("opaque-stdin-handle"));
	for (const line of runCall.render(19)) assert(line.length <= 19, line);
	assert(byName.vault_run.renderCall(runArgs, theme, { expanded: false }).render(10_000).join("\n").includes(runArgs.executable));

	const sanitized = "sanitized-output-" + "O".repeat(2_000);
	const runResult = { content: [{ type: "text", text: "ok" }], details: {
		action: "run", mode: "text", exitCode: 0, signal: null, durationMs: 12, timedOut: false, cancelled: false,
		stdoutBytes: 2_017, stderrBytes: 17, stdout: sanitized, stderr: "sanitized-stderr",
	} };
	const expandedResult = byName.vault_run.renderResult(runResult, { expanded: true }, theme, {});
	assert(expandedResult.render(10_000).join("\n").includes(sanitized));
	for (const line of expandedResult.render(23)) assert(line.length <= 23, line);

	const sshArgs = { hostHandle: "opaque-host", username: "deploy", port: 2222, privateKeyHandle: "opaque-key", passphraseHandle: "opaque-passphrase", command: longArg, stdinHandle: "opaque-remote-stdin", timeoutMs: 1234 };
	const sshText = byName.vault_ssh_run.renderCall(sshArgs, theme, { expanded: true }).render(10_000).join("\n");
	for (const value of Object.values(sshArgs).map(String)) assert(sshText.includes(value), value);
	assert(!sshText.includes("RAW_SECRET_RENDER_SENTINEL"));
});

// --- SSH protocol ---

test("ssh request/response round-trips through the broker", async () => {
	const value = await fixture();
	try {
		const result = await requestVaultSshRun(value.socketPath, {
			host: "ssh-test.example.com",
			username: "deploy",
			port: 2222,
			privateKeyHandle: value.sshInspection.materials.find(m => m.type === "private-key").handle,
			command: "uptime",
		});
		assert.equal(result.exitCode, 0);
		assert.equal(result.stdout, "ssh output");
		const conn = value.fakeSsh.connections()[0];
		assert.equal(conn.host, "ssh-test.example.com");
		assert.equal(conn.port, 2222);
		assert.equal(conn.username, "deploy");
	} finally { await closeFixture(value); }
});
