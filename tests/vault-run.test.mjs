import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { Readable } from "node:stream";
import { spawn as nodeSpawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createJiti } from "jiti";

const { createBrokerServer } = await import("../extensions/vault/broker.mjs");
const bitwarden = await import("../extensions/vault/bitwarden.mjs");
const runModule = await import("../extensions/vault/run.mjs");
const protocol = await import("../extensions/vault/protocol.mjs");
const jiti = createJiti(import.meta.url);
const { requestSetup, requestVaultItems, requestVaultRun, vaultRunRequestTimeoutMs, BrokerRequestError } = await jiti.import("../extensions/vault/client.ts");
const { registerVaultExtension } = await jiti.import("../extensions/vault/index.ts");

const SECRET = "RUN_SECRET_SENTINEL_+/=";
const ATTACHMENT = "ATTACHMENT_STREAM_SENTINEL";

function fakeAdapter() {
	let state = "unauthenticated";
	let spawnAttachmentCalls = 0;
	const item = {
		id: "DURABLE_ITEM_ID",
		type: 1,
		name: "run fixture",
		login: { username: "user", password: SECRET, totp: "TOTP_RUN_SENTINEL", notes: "LOGIN_NOTES_RUN_SENTINEL", uris: [{ uri: "https://uri-user:uri-pass@example.test/full/path?q=URI_QUERY_RUN_SENTINEL#URI_FRAGMENT_RUN_SENTINEL" }] },
		notes: "ITEM_NOTES_RUN_SENTINEL",
		passwordHistory: [{ lastUsedDate: "2041-01-02T03:04:05.000Z", password: "PASSWORD_HISTORY_RUN_SENTINEL" }],
		fields: [{ name: "custom", type: 1, value: "CUSTOM_RUN_SENTINEL" }, { name: "large", type: 1, value: "L".repeat(65 * 1024) }, { name: "one-byte", type: 1, value: "x" }, { name: "nul", type: 1, value: "a\u0000b" }],
		attachments: [{ id: "DURABLE_ATTACHMENT_ID", fileName: "payload.bin", size: String(ATTACHMENT.length), data: ATTACHMENT }],
	};
	const second = { id: "DURABLE_ITEM_ID_2", type: 2, name: "second fixture", notes: "SECOND_NOTE_SENTINEL", attachments: [{ id: "DURABLE_ATTACHMENT_ID_2", fileName: "second.bin", size: "6", data: "SECOND" }] };
	const card = { id: "DURABLE_CARD_ID", type: 3, name: "card fixture", card: { cardholderName: "CARDHOLDER_RUN_SENTINEL", number: "CARD_NUMBER_RUN_SENTINEL", expMonth: "01", expYear: "2040", code: "123", brand: "brand" } };
	const identity = { id: "DURABLE_IDENTITY_ID", type: 4, name: "identity fixture", identity: { firstName: "IDENTITY_FIRST_RUN_SENTINEL", email: "IDENTITY_EMAIL_RUN_SENTINEL" } };
	const ssh = { id: "DURABLE_SSH_ID", type: 5, name: "ssh fixture", sshKey: { privateKey: "SSH_PRIVATE_RUN_SENTINEL", publicKey: "SSH_PUBLIC_RUN_SENTINEL" } };
	const items = [item, second, card, identity, ssh];
	return {
		item,
		items,
		get spawnAttachmentCalls() { return spawnAttachmentCalls; },
		async status() { return { code: 0, state, userEmail: "fixture@example.test" }; },
		async configure() { return { code: 0 }; },
		async login() { state = "unlocked"; return { code: 0, session: "PRIVATE_SESSION_SENTINEL_123456" }; },
		async unlock() { state = "unlocked"; return { code: 0, session: "PRIVATE_SESSION_SENTINEL_123456" }; },
		async lock() { state = "locked"; return { code: 0 }; },
		async listItems() { return { code: 0, items }; },
		async listFolders() { return { code: 0, folders: [] }; },
		streamAttachment({ itemId, attachmentId, session }) {
			assert.equal(session, "PRIVATE_SESSION_SENTINEL_123456");
			spawnAttachmentCalls++;
			if (itemId === "DURABLE_ITEM_ID" && attachmentId === "DURABLE_ATTACHMENT_ID") return { stream: Readable.from([Buffer.from(ATTACHMENT.slice(0, 5)), Buffer.from(ATTACHMENT.slice(5))]) };
			if (itemId === "DURABLE_ITEM_ID_2" && attachmentId === "DURABLE_ATTACHMENT_ID_2") return { stream: Readable.from([Buffer.from("SECOND")]) };
			throw new Error("wrong attachment");
		},
	};
}

async function fixture(options = {}) {
	const directory = await mkdtemp(join(tmpdir(), "vault-run-test-"));
	const adapter = fakeAdapter();
	const broker = createBrokerServer({ socketPath: join(directory, "broker.sock"), adapter, keychain: { async get() { return "fixture"; }, async set() {}, async delete() {} }, idleMs: 60_000, runSpawn: options.runSpawn });
	await broker.start();
	await requestSetup(join(directory, "broker.sock"), { server: "https://vault.example.test", email: "fixture@example.test", masterPassword: "fixture-password" });
	const page = await requestVaultItems(join(directory, "broker.sock"), { action: "list" });
	const inspection = await requestVaultItems(join(directory, "broker.sock"), { action: "inspect", itemHandle: page.items[0].handle });
	return { directory, broker, adapter, socketPath: join(directory, "broker.sock"), page, inspection };
}

const nodeArgs = (source) => ["-e", source];
function exists(pid, group = false) {
	if (!pid) return false;
	try { process.kill(group ? -pid : pid, 0); return true; } catch { return false; }
}
const readEnvSource = `const s=process.env.APP_SECRET; const values=[s,JSON.stringify(s),encodeURIComponent(s),Buffer.from(s).toString('base64'),Buffer.from(s).toString('base64url'),Buffer.from(s).toString('hex')]; for (const v of values) { process.stdout.write(v.slice(0,2)); process.stdout.write(v.slice(2)); } process.stderr.write(s);`;

async function closeFixture(value) {
	await value.broker.stop();
	await rm(value.directory, { recursive: true, force: true });
}

function fakeAttachmentChild(code = 0) {
	const child = new EventEmitter();
	child.stdout = Readable.from([Buffer.from("attachment")]);
	child.stderr = Readable.from([Buffer.from("diagnostic")]);
	child.exitCode = null;
	child.signalCode = null;
	child.kill = () => { child.exitCode = null; child.signalCode = "SIGTERM"; child.emit("close", null, "SIGTERM"); return true; };
	setImmediate(() => { child.exitCode = code; child.emit("close", code, null); });
	return child;
}

test("production attachment adapter uses exact raw argv and session-only child environment", async () => {
	const seen = [];
	const adapter = bitwarden.createBitwardenAdapter({ profilePath: "/private/profile", spawn: (command, args, options) => { seen.push({ command, args, options }); return fakeAttachmentChild(); } });
	const result = adapter.streamAttachment({ itemId: "ITEM_ID", attachmentId: "ATTACHMENT_ID", session: "SESSION_ONLY_123456789" });
	const chunks = [];
	for await (const chunk of result.stream) chunks.push(chunk);
	assert.deepEqual(seen[0].args, ["get", "attachment", "ATTACHMENT_ID", "--itemid", "ITEM_ID", "--raw", "--nointeraction"]);
	assert.equal(seen[0].options.shell, false);
	assert.equal(seen[0].options.detached, true);
	assert.deepEqual(seen[0].options.stdio, ["ignore", "pipe", "pipe"]);
	assert.equal(seen[0].options.env.BW_SESSION, "SESSION_ONLY_123456789");
	assert.equal(seen[0].options.env.BW_PASSWORD, undefined);
	assert.equal(seen[0].options.env.SECRET_SENTINEL, undefined);
	assert.equal(seen[0].options.stdio[2], "pipe");
	assert.equal(result.process.stderr.readableFlowing, true);
	assert.equal(Buffer.concat(chunks).toString(), "attachment");
});

test("production adapter source failures stay bounded and never create decrypted files", async () => {
	const adapter = bitwarden.createBitwardenAdapter({ profilePath: "/private/profile", spawn: () => fakeAttachmentChild(1) });
	const record = { descriptor: { category: "attachment", delivery: { environment: false, stdin: true } }, ownerItemHandle: "owner", itemId: "ITEM_ID", attachmentId: "ATTACHMENT_ID", value: "private" };
	await assert.rejects(runModule.executeVaultRun({ executable: process.execPath, argv: ["-e", "process.stdin.resume()"], stdin: "attachment-handle", timeoutMs: 100 }, {
		resolveAttachment: () => record,
		adapter,
		session: "SESSION_ONLY_123456789",
		spawn: nodeSpawn,
	}), (error) => error.code === "cli_error");
});

test("a real non-detached ignoring source is dead before timeout result settles, including target spawn failure", async () => {
	let source;
	const sourceCode = "process.on('SIGTERM',()=>{}); setInterval(()=>{},1000);";
	const value = await fixture();
	try {
		value.adapter.streamAttachment = () => { source = nodeSpawn(process.execPath, ["-e", sourceCode], { detached: false, stdio: ["ignore", "pipe", "pipe"] }); source.stderr.resume(); return { stream: source.stdout, process: source }; };
		const result = await requestVaultRun(value.socketPath, { executable: process.execPath, argv: nodeArgs("setInterval(()=>{},1000)"), stdin: value.inspection.attachments[0].handle, timeoutMs: 100 });
		assert.equal(result.timedOut, true);
		assert(source.signalCode !== null || source.exitCode !== null);
		assert.equal(exists(source.pid), false);
	} finally { await closeFixture(value); }

	let failedSource;
	const failed = await fixture({ runSpawn: () => { throw new Error("target spawn failure"); } });
	try {
		failed.adapter.streamAttachment = () => { failedSource = nodeSpawn(process.execPath, ["-e", sourceCode], { detached: false, stdio: ["ignore", "pipe", "pipe"] }); failedSource.stderr.resume(); return { stream: failedSource.stdout, process: failedSource }; };
		await assert.rejects(requestVaultRun(failed.socketPath, { executable: process.execPath, argv: [], stdin: failed.inspection.attachments[0].handle }), (error) => error instanceof BrokerRequestError && error.code === "run_failed");
		assert(failedSource.signalCode !== null || failedSource.exitCode !== null);
		assert.equal(exists(failedSource.pid), false);
	} finally { await closeFixture(failed); }
});

test("run IPC deadlines derive from validated run timeout, not the 35-second generic bound", () => {
	assert.equal(vaultRunRequestTimeoutMs({ executable: "/bin/echo", argv: [], timeoutMs: 120_000 }), 125_000);
	assert.equal(vaultRunRequestTimeoutMs({ executable: "/bin/echo", argv: [], timeoutMs: 900_000 }), 905_000);
});

test("run input bounds reject every oversized frame seam before framing", () => {
	assert.throws(() => runModule.validateVaultRunInput({ executable: "/bin/echo", argv: [], env: { X: "x".repeat(20_000) } }), (error) => error.code === "over_limit");
	assert.throws(() => runModule.validateVaultRunInput({ executable: "/bin/echo", argv: Array.from({ length: 128 }, () => "a".repeat(512)) }), (error) => error.code === "over_limit");
	assert.throws(() => runModule.validateVaultRunInput({ executable: "/bin/echo", argv: [], env: Object.fromEntries(Array.from({ length: 64 }, (_, index) => [`X${index}`, "x".repeat(250)])) }), (error) => error.code === "over_limit");
	assert.throws(() => protocol.runFrame("run", { executable: "/bin/echo", argv: [], env: { X: "x".repeat(20_000) } }), (error) => error.code === "over_limit");
});

test("redaction covers escaped inner JSON and final combined output bounds", async () => {
	const secret = "line\nquote\"slash\\";
	const escapedInner = JSON.stringify(secret).slice(1, -1);
	const redacted = runModule.redactVaultOutput(runModule.materialEncodingVariants(secret).join("|"), [secret]);
	for (const encoded of runModule.materialEncodingVariants(secret)) assert(!redacted.includes(encoded), `encoded form leaked: ${encoded}`);
	assert(!runModule.redactVaultOutput(escapedInner, [secret]).includes(escapedInner));
	assert(!runModule.redactVaultOutput(`${Buffer.from(secret).toString("base64").replace(/=+$/u, "")} ${Buffer.from(secret).toString("base64url")} ${encodeURIComponent(secret)}`, [secret]).includes(secret));
	assert.throws(() => protocol.validateResponse({ id: "run", ok: true, result: { mode: "text", exitCode: 0, signal: null, durationMs: 1, timedOut: false, cancelled: false, stdoutBytes: 600_000, stderrBytes: 500_000, stdout: "x".repeat(600_000), stderr: "y".repeat(500_000) } }), protocol.ProtocolError);
});

test("final redaction expansion returns safe output_overflow instead of an internal error", async () => {
	const value = await fixture();
	try {
		const oneByte = value.inspection.materials.find((entry) => entry.label === "one-byte");
		await assert.rejects(requestVaultRun(value.socketPath, { executable: process.execPath, argv: nodeArgs("process.stdout.write('x'.repeat(1024*1024))"), materialEnv: { X: oneByte.handle } }), (error) => error instanceof BrokerRequestError && error.code === "output_overflow");
	} finally { await closeFixture(value); }
});

test("vault_run delivers selected material to the requested child channels and redacts split encodings", async () => {
	const value = await fixture();
	try {
		const password = value.inspection.materials.find((entry) => entry.type === "password");
		assert(password);
		const result = await requestVaultRun(value.socketPath, { executable: process.execPath, argv: nodeArgs(readEnvSource), env: { APP_MODE: "fixture" }, materialEnv: { APP_SECRET: password.handle } });
		assert.equal(result.mode, "text");
		assert.equal(result.exitCode, 0);
		assert.match(result.stdout, /\[REDACTED\]/u);
		assert.match(result.stderr, /\[REDACTED\]/u);
		assert(!JSON.stringify(result).includes(SECRET));
		assert(!JSON.stringify(result).includes("PRIVATE_SESSION_SENTINEL"));

		const stdinSource = "process.stdin.on('data',()=>{}); process.stdin.on('end',()=>process.stdout.write('stdin complete'));";
		const stdin = await requestVaultRun(value.socketPath, { executable: process.execPath, argv: nodeArgs(stdinSource), stdin: password.handle });
		assert.equal(stdin.exitCode, 0);
		assert.equal(stdin.stdout, "stdin complete");
	} finally { await closeFixture(value); }
});

test("all scalar categories reach only the requested child channel with no secret process surfaces", async () => {
	const captures = [];
	const value = await fixture({ runSpawn: (command, args, options) => {
		const child = nodeSpawn(command, args, options);
		let stdin = "";
		const write = child.stdin.write.bind(child.stdin);
		const end = child.stdin.end.bind(child.stdin);
		child.stdin.write = (chunk, ...rest) => { stdin += Buffer.from(chunk).toString("utf8"); return write(chunk, ...rest); };
		child.stdin.end = (chunk, ...rest) => { if (chunk !== undefined) stdin += Buffer.from(chunk).toString("utf8"); return end(chunk, ...rest); };
		captures.push({ command, args: [...args], cwd: options.cwd, env: { ...options.env }, get stdin() { return stdin; } });
		return child;
	} });
	try {
		const selected = [
			["login", "password", SECRET], ["login", "TOTP", "TOTP_RUN_SENTINEL"], ["login", "notes", "ITEM_NOTES_RUN_SENTINEL"],
			["login", "URI 1", "https://uri-user:uri-pass@example.test/full/path?q=URI_QUERY_RUN_SENTINEL#URI_FRAGMENT_RUN_SENTINEL"],
			["login", "password history 1", "PASSWORD_HISTORY_RUN_SENTINEL"], ["login", "custom", "CUSTOM_RUN_SENTINEL"],
			["secure-note", "notes", "SECOND_NOTE_SENTINEL"], ["card", "card number", "CARD_NUMBER_RUN_SENTINEL"],
			["identity", "first name", "IDENTITY_FIRST_RUN_SENTINEL"], ["ssh-key", "private key", "SSH_PRIVATE_RUN_SENTINEL"],
		];
		for (const [type, label, expected] of selected) {
			const summary = value.page.items.find((entry) => entry.type === type);
			const inspected = summary && await requestVaultItems(value.socketPath, { action: "inspect", itemHandle: summary.handle });
			const descriptor = inspected.materials.find((entry) => entry.label === label);
			assert(descriptor);
			const useEnv = captures.length % 2 === 0;
			const params = useEnv ? { executable: process.execPath, argv: nodeArgs("process.exit(0)"), materialEnv: { APP_SECRET: descriptor.handle } } : { executable: process.execPath, argv: nodeArgs("process.stdin.resume(); process.stdin.on('end',()=>process.exit(0))"), stdin: descriptor.handle };
			const result = await requestVaultRun(value.socketPath, params);
			const capture = captures.at(-1);
			assert.equal(result.exitCode, 0);
			assert.equal(useEnv ? capture.env.APP_SECRET : capture.stdin, expected);
			assert.equal(useEnv ? capture.stdin : capture.env.APP_SECRET, useEnv ? "" : undefined);
			assert(!capture.args.join(" ").includes(expected));
			assert(!String(capture.cwd).includes(expected));
			assert(!JSON.stringify(Object.fromEntries(Object.entries(capture.env).filter(([key]) => key !== "APP_SECRET"))).includes(expected));
			assert(!JSON.stringify(result).includes(expected));
			assert(!Object.values(process.env).includes(expected));
		}
	} finally { await closeFixture(value); }
});

test("the Pi tool content, details, renderers, and updates contain no raw selected material", async () => {
	const value = await fixture();
	try {
		const password = value.inspection.materials.find((entry) => entry.type === "password");
		const tools = [];
		const pi = { registerTool(tool) { tools.push(tool); }, registerCommand() {}, on() {} };
		registerVaultExtension(pi, { client: { async run(input, signal) { return requestVaultRun(value.socketPath, input, signal); }, async status() { return "unlocked"; } } });
		const tool = tools.find((entry) => entry.name === "vault_run");
		const updates = [];
		const logs = [];
		const methods = ["debug", "error", "info", "log", "warn"];
		const originals = new Map(methods.map((method) => [method, console[method]]));
		for (const method of methods) console[method] = (...args) => logs.push(args);
		try {
			const result = await tool.execute("call", { executable: process.execPath, argv: nodeArgs("process.stdout.write(process.env.APP_SECRET)"), materialEnv: { APP_SECRET: password.handle } }, undefined, (update) => updates.push(update), { mode: "print" });
			assert(!JSON.stringify(result).includes(SECRET));
			assert(!JSON.stringify(updates).includes(SECRET));
			assert(!JSON.stringify(tool.renderCall({}, { fg: (_color, text) => text, bold: (text) => text }, { expanded: true })).includes(SECRET));
			assert(!JSON.stringify(tool.renderResult(result, { expanded: true, isPartial: false }, { fg: (_color, text) => text, bold: (text) => text }, {})).includes(SECRET));
		} finally {
			for (const [method, original] of originals) console[method] = original;
		}
		assert.deepEqual(logs, []);
	} finally { await closeFixture(value); }
});

test("bulk output is drained and suppressed beyond the text cap", async () => {
	const value = await fixture();
	try {
		const attachment = value.inspection.attachments[0];
		const source = "process.stdin.resume(); process.stdin.on('end',()=>process.stdout.write('x'.repeat(1024*1024+1)));";
		const result = await requestVaultRun(value.socketPath, { executable: process.execPath, argv: nodeArgs(source), stdin: attachment.handle });
		assert.equal(result.mode, "bulk");
		assert.equal(result.stdout, undefined);
		assert.equal(result.stdoutBytes, 1024 * 1024 + 1);
		assert.equal(result.stderrBytes, 0);
	} finally { await closeFixture(value); }
});

test("attachments stream through the injected adapter, suppress output, and do not create files", async () => {
	const value = await fixture();
	try {
		const attachment = value.inspection.attachments[0];
		const source = "let d=''; process.stdin.setEncoding('utf8'); process.stdin.on('data',c=>d+=c); process.stdin.on('end',()=>{process.stdout.write(d); process.stderr.write(d);});";
		const result = await requestVaultRun(value.socketPath, { executable: process.execPath, argv: nodeArgs(source), stdin: attachment.handle });
		assert.equal(result.mode, "bulk");
		assert.equal(result.stdout, undefined);
		assert.equal(result.stderr, undefined);
		assert.equal(result.stdoutBytes, ATTACHMENT.length);
		assert.equal(result.stderrBytes, ATTACHMENT.length);
		assert.equal(value.adapter.spawnAttachmentCalls, 1);
		assert(!JSON.stringify(result).includes(ATTACHMENT));
	} finally { await closeFixture(value); }
});

test("attachment pumping honors child backpressure instead of buffering the payload", async () => {
	const value = await fixture();
	try {
		let produced = 0;
		value.adapter.streamAttachment = () => ({ stream: { destroy() {}, async *[Symbol.asyncIterator]() { for (let index = 0; index < 128; index++) { produced++; yield Buffer.alloc(65_536, 0x41); } } } });
		const attachment = value.inspection.attachments[0];
		const result = await requestVaultRun(value.socketPath, { executable: process.execPath, argv: nodeArgs("setInterval(()=>{},1000)"), stdin: attachment.handle, timeoutMs: 100 });
		assert.equal(result.mode, "bulk");
		assert(produced < 128, `source was drained without backpressure: ${produced}`);
	} finally { await closeFixture(value); }
});

test("stalled, failing, and early-closed attachment streams settle and clean up", async () => {
	const stalled = await fixture();
	try {
		let source;
		stalled.adapter.streamAttachment = () => { source = new Readable({ read() {} }); return { stream: source }; };
		const result = await requestVaultRun(stalled.socketPath, { executable: process.execPath, argv: nodeArgs("setInterval(()=>{},1000)"), stdin: stalled.inspection.attachments[0].handle, timeoutMs: 100 });
		assert.equal(result.timedOut, true);
		assert.equal(source.destroyed, true);
	} finally { await closeFixture(stalled); }

	const failing = await fixture();
	try {
		failing.adapter.streamAttachment = () => ({ stream: Readable.from((async function* () { yield Buffer.from("partial"); throw new Error("source diagnostic secret"); })()) });
		await assert.rejects(requestVaultRun(failing.socketPath, { executable: process.execPath, argv: nodeArgs("setInterval(()=>{},1000)"), stdin: failing.inspection.attachments[0].handle }), (error) => error instanceof BrokerRequestError && error.code === "run_failed");
	} finally { await closeFixture(failing); }

	const early = await fixture();
	try {
		early.adapter.streamAttachment = () => ({ stream: Readable.from([Buffer.alloc(1024 * 1024, 0x41)]) });
		await assert.rejects(requestVaultRun(early.socketPath, { executable: process.execPath, argv: nodeArgs("process.stdin.destroy(); process.exit(0)"), stdin: early.inspection.attachments[0].handle }), (error) => error instanceof BrokerRequestError && error.code === "run_failed");
	} finally { await closeFixture(early); }
});

test("vault_run rejects unsafe, duplicate, stale, incompatible, and over-limit selections before spawning", async () => {
	let spawns = 0;
	const second = await fixture({ runSpawn: (...args) => { spawns++; return nodeSpawn(...args); } });
	try {
		const password = second.inspection.materials.find((entry) => entry.type === "password");
		const attachment = second.inspection.attachments[0];
		const large = second.inspection.materials.find((entry) => entry.label === "large");
		await assert.rejects(requestVaultRun(second.socketPath, { executable: process.execPath, argv: [], materialEnv: { PATH: password.handle } }), (error) => error.code === "material_incompatible");
		await assert.rejects(requestVaultRun(second.socketPath, { executable: process.execPath, argv: [], materialEnv: { A: password.handle, B: password.handle } }), (error) => error instanceof BrokerRequestError && error.code === "duplicate_handle");
		await assert.rejects(requestVaultRun(second.socketPath, { executable: process.execPath, argv: [], materialEnv: { A: attachment.handle } }), (error) => error instanceof BrokerRequestError && error.code === "material_incompatible");
		await assert.rejects(requestVaultRun(second.socketPath, { executable: process.execPath, argv: [], stdin: "expired-handle" }), (error) => error instanceof BrokerRequestError && error.code === "invalid_handle");
		await assert.rejects(requestVaultRun(second.socketPath, { executable: process.execPath, argv: [], materialEnv: { LARGE: large.handle } }), (error) => error instanceof BrokerRequestError && error.code === "over_limit");
		assert.equal(spawns, 0);
	} finally { await closeFixture(second); }
});

test("NUL-bearing scalars reject env delivery before spawn but remain valid on stdin", async () => {
	let spawns = 0;
	const value = await fixture({ runSpawn: (...args) => { spawns++; return nodeSpawn(...args); } });
	try {
		const nul = value.inspection.materials.find((entry) => entry.label === "nul");
		await assert.rejects(requestVaultRun(value.socketPath, { executable: process.execPath, argv: [], materialEnv: { NUL_VALUE: nul.handle } }), (error) => error instanceof BrokerRequestError && error.code === "material_incompatible");
		assert.equal(spawns, 0);
		const stdin = await requestVaultRun(value.socketPath, { executable: process.execPath, argv: nodeArgs("process.stdin.resume(); process.stdin.on('end',()=>process.exit(0))"), stdin: nul.handle });
		assert.equal(stdin.exitCode, 0);
		assert.equal(spawns, 1);
	} finally { await closeFixture(value); }
});

test("owner association rejects cross-item env, stdin, and attachment selections", async () => {
	const value = await fixture();
	try {
		const secondItem = value.page.items[1];
		const secondInspection = await requestVaultItems(value.socketPath, { action: "inspect", itemHandle: secondItem.handle });
		const password = value.inspection.materials.find((entry) => entry.type === "password");
		const note = secondInspection.materials[0];
		const attachment = secondInspection.attachments[0];
		await assert.rejects(requestVaultRun(value.socketPath, { executable: process.execPath, argv: [], materialEnv: { A: password.handle }, stdin: note.handle }), (error) => error instanceof BrokerRequestError && error.code === "wrong_item");
		await assert.rejects(requestVaultRun(value.socketPath, { executable: process.execPath, argv: [], materialEnv: { A: password.handle }, stdin: attachment.handle }), (error) => error instanceof BrokerRequestError && error.code === "wrong_item");
		for (let index = 0; index < 5; index++) await requestVaultItems(value.socketPath, { action: "list" });
		await assert.rejects(requestVaultRun(value.socketPath, { executable: process.execPath, argv: [], stdin: value.inspection.materials[0].handle }), (error) => error instanceof BrokerRequestError && error.code === "invalid_handle");
	} finally { await closeFixture(value); }
});

test("process-group cleanup kills a SIGTERM-ignoring leader and descendant after the grace", async () => {
	let child;
	let descendantPid;
	const descendantSource = "process.on('SIGTERM',()=>{}); setInterval(()=>{},1000);";
	const leaderSource = `const {spawn}=require('node:child_process'); const d=spawn(process.execPath,['-e',${JSON.stringify(descendantSource)}],{stdio:'ignore'}); process.stdout.write(String(d.pid)); process.on('SIGTERM',()=>{}); setInterval(()=>{},1000);`;
	const value = await fixture({ runSpawn: (...args) => { child = nodeSpawn(...args); child.stdout.on("data", (chunk) => { descendantPid = Number(String(chunk)); }); return child; } });
	try {
		const controller = new AbortController();
		const pending = requestVaultRun(value.socketPath, { executable: process.execPath, argv: nodeArgs(leaderSource) }, controller.signal);
		await new Promise((resolve) => setTimeout(resolve, 100));
		assert(child);
		const pid = child.pid;
		assert(Number.isSafeInteger(descendantPid));
		const closed = new Promise((resolve) => child.once("close", resolve));
		controller.abort();
		await assert.rejects(pending, (error) => error?.name === "AbortError");
		await Promise.race([closed, new Promise((_, reject) => setTimeout(() => reject(new Error("child did not close")), 5_000))]);
		assert(child.exitCode !== null || child.signalCode !== null);
		assert.equal(exists(pid), false);
		assert.equal(exists(pid, true), false);
		assert.equal(exists(descendantPid), false);
	} finally { await closeFixture(value); }
});

test("timeout escalates after SIGTERM and text overflow never returns partial output", async () => {
	const value = await fixture();
	try {
		const ignoreTerm = "process.on('SIGTERM',()=>{}); setInterval(()=>{},1000);";
		const timed = await requestVaultRun(value.socketPath, { executable: process.execPath, argv: nodeArgs(ignoreTerm), timeoutMs: 100 });
		assert.equal(timed.timedOut, true);
		assert.equal(timed.cancelled, false);
		const overflow = "process.stdout.write('x'.repeat(1024*1024+1));";
		await assert.rejects(requestVaultRun(value.socketPath, { executable: process.execPath, argv: nodeArgs(overflow) }), (error) => error instanceof BrokerRequestError && error.code === "output_overflow");
	} finally { await closeFixture(value); }
});
