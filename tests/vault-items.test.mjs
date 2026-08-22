import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createJiti } from "jiti";

const jiti = createJiti(import.meta.url);
const { createBrokerServer, MAX_ACTIVE_SNAPSHOTS } = await import("../extensions/vault/broker.mjs");
const { requestSetup, requestStatus, requestVaultItems, BrokerRequestError } = await jiti.import("../extensions/vault/client.ts");
const { registerVaultExtension } = await jiti.import("../extensions/vault/index.ts");
const { MAX_FRAME_BYTES, FrameParser, responseFrames, validateRequest, ProtocolError } = await import("../extensions/vault/protocol.mjs");
const { createBitwardenAdapter, MAX_OUTPUT_BYTES } = await import("../extensions/vault/bitwarden.mjs");
const { deriveSafeRecord, publicInspection, MAX_MATERIAL_DESCRIPTORS, MAX_ATTACHMENT_DESCRIPTORS } = await import("../extensions/vault/metadata.mjs");

const SECRET_SENTINELS = [
	"LOGIN_USERNAME_SENTINEL", "LOGIN_PASSWORD_SENTINEL", "LOGIN_TOTP_SENTINEL", "LOGIN_NOTES_SENTINEL", "CUSTOM_HIDDEN_SENTINEL", "PASSWORD_HISTORY_SENTINEL",
	"SECURE_NOTE_SENTINEL", "CARDHOLDER_SENTINEL", "CARD_NUMBER_SENTINEL", "CARD_EXP_MONTH_SENTINEL", "CARD_EXP_YEAR_SENTINEL", "CARD_CODE_SENTINEL", "CARD_BRAND_SENTINEL", "CARD_NOTES_SENTINEL",
	"IDENTITY_TITLE_SENTINEL", "IDENTITY_FIRST_SENTINEL", "IDENTITY_MIDDLE_SENTINEL", "IDENTITY_LAST_SENTINEL", "IDENTITY_ADDRESS1_SENTINEL", "IDENTITY_ADDRESS2_SENTINEL", "IDENTITY_ADDRESS3_SENTINEL", "IDENTITY_CITY_SENTINEL", "IDENTITY_STATE_SENTINEL", "IDENTITY_POSTAL_SENTINEL", "IDENTITY_COUNTRY_SENTINEL", "IDENTITY_COMPANY_SENTINEL", "IDENTITY_EMAIL_SENTINEL", "IDENTITY_PHONE_SENTINEL", "IDENTITY_SSN_SENTINEL", "IDENTITY_USERNAME_SENTINEL", "IDENTITY_PASSPORT_SENTINEL", "IDENTITY_LICENSE_SENTINEL", "IDENTITY_NOTES_SENTINEL",
	"SSH_PRIVATE_SENTINEL", "SSH_PUBLIC_SENTINEL", "SSH_FINGERPRINT_SENTINEL", "SSH_NOTES_SENTINEL", "ATTACHMENT_BYTES_SENTINEL", "ATTACHMENT_URL_SENTINEL",
	"PASSKEY_CREDENTIAL_ID_SENTINEL", "PASSKEY_KEY_TYPE_SENTINEL", "PASSKEY_ALGORITHM_SENTINEL", "PASSKEY_CURVE_SENTINEL", "PASSKEY_KEY_VALUE_SENTINEL", "PASSKEY_RP_ID_SENTINEL", "PASSKEY_USER_HANDLE_SENTINEL", "PASSKEY_USER_NAME_SENTINEL", "PASSKEY_COUNTER_SENTINEL", "PASSKEY_RP_NAME_SENTINEL", "PASSKEY_USER_DISPLAY_NAME_SENTINEL", "PASSKEY_DISCOVERABLE_SENTINEL", "PASSKEY_CREATION_DATE_SENTINEL", "PASSKEY_DEVICE_TYPE_SENTINEL", "PASSKEY_BACKED_UP_SENTINEL", "PASSKEY_AAGUID_SENTINEL", "PASSKEY_PRIVATE_KEY_SENTINEL", "PASSKEY_TRANSPORT_SENTINEL",
	"DURABLE_ITEM_UUID_SENTINEL", "DURABLE_FOLDER_UUID_SENTINEL", "DURABLE_ORGANIZATION_UUID_SENTINEL", "DURABLE_COLLECTION_UUID_SENTINEL", "DURABLE_ATTACHMENT_UUID_SENTINEL", "DURABLE_FIELD_UUID", "CIPHER_KEY_SENTINEL",
	"URI_USERNAME_SENTINEL", "URI_PASSWORD_SENTINEL", "URI_PATH_SENTINEL", "URI_QUERY_SENTINEL", "URI_FRAGMENT_SENTINEL", "2041-01-02T03:04:05.000Z", "2042-02-03T04:05:06.000Z",
];
const MATERIAL_SENTINELS = SECRET_SENTINELS.filter((sentinel) => ![
	"DURABLE_ITEM_UUID_SENTINEL", "DURABLE_FOLDER_UUID_SENTINEL", "DURABLE_ORGANIZATION_UUID_SENTINEL", "DURABLE_COLLECTION_UUID_SENTINEL", "DURABLE_ATTACHMENT_UUID_SENTINEL", "DURABLE_FIELD_UUID", "CIPHER_KEY_SENTINEL",
	"2041-01-02T03:04:05.000Z", "2042-02-03T04:05:06.000Z",
].includes(sentinel));
const UUID = "DURABLE_ITEM_UUID_SENTINEL";

// Mirrors the decrypted scalar-bearing shapes emitted by CLI v2026.2.0's
// CipherResponse/CipherExport and nested response/export classes. Metadata-only
// dates, matching modes, and durable/internal IDs are seeded solely for leak checks.
function fixtures() {
	const attachment = { id: "DURABLE_ATTACHMENT_UUID_SENTINEL", fileName: "ssh-config.txt", size: "23", sizeName: "23 Bytes", url: "ATTACHMENT_URL_SENTINEL", data: "ATTACHMENT_BYTES_SENTINEL" };
	return [
		{ id: UUID, organizationId: "DURABLE_ORGANIZATION_UUID_SENTINEL", collectionIds: ["DURABLE_COLLECTION_UUID_SENTINEL"], key: "CIPHER_KEY_SENTINEL", type: 1, name: "Login fixture", favorite: true, folderId: "DURABLE_FOLDER_UUID_SENTINEL", login: { username: "LOGIN_USERNAME_SENTINEL", password: "LOGIN_PASSWORD_SENTINEL", totp: "LOGIN_TOTP_SENTINEL", passwordRevisionDate: "2042-02-03T04:05:06.000Z", uris: [{ uri: "https://URI_USERNAME_SENTINEL:URI_PASSWORD_SENTINEL@example.test/URI_PATH_SENTINEL?URI_QUERY_SENTINEL#URI_FRAGMENT_SENTINEL", match: 1 }], fido2Credentials: [{ credentialId: "PASSKEY_CREDENTIAL_ID_SENTINEL", keyType: "PASSKEY_KEY_TYPE_SENTINEL", keyAlgorithm: "PASSKEY_ALGORITHM_SENTINEL", keyCurve: "PASSKEY_CURVE_SENTINEL", keyValue: "PASSKEY_KEY_VALUE_SENTINEL", rpId: "PASSKEY_RP_ID_SENTINEL", rpName: "PASSKEY_RP_NAME_SENTINEL", userHandle: "PASSKEY_USER_HANDLE_SENTINEL", userName: "PASSKEY_USER_NAME_SENTINEL", userDisplayName: "PASSKEY_USER_DISPLAY_NAME_SENTINEL", counter: "PASSKEY_COUNTER_SENTINEL", discoverable: "PASSKEY_DISCOVERABLE_SENTINEL", creationDate: "PASSKEY_CREATION_DATE_SENTINEL", deviceType: "PASSKEY_DEVICE_TYPE_SENTINEL", backedUp: "PASSKEY_BACKED_UP_SENTINEL", aaguid: "PASSKEY_AAGUID_SENTINEL", privateKey: "PASSKEY_PRIVATE_KEY_SENTINEL", transports: ["PASSKEY_TRANSPORT_SENTINEL"] }] }, passwordHistory: [{ lastUsedDate: "2041-01-02T03:04:05.000Z", password: "PASSWORD_HISTORY_SENTINEL" }], notes: "LOGIN_NOTES_SENTINEL", fields: [{ id: "DURABLE_FIELD_UUID", name: "custom label", type: 1, linkedId: 100, value: "CUSTOM_HIDDEN_SENTINEL" }], attachments: [attachment] },
		{ id: "secure-note-id", type: 2, name: "Secure note fixture", secureNote: { type: 0 }, notes: "SECURE_NOTE_SENTINEL" },
		{ id: "card-id", type: 3, name: "Card fixture", card: { cardholderName: "CARDHOLDER_SENTINEL", number: "CARD_NUMBER_SENTINEL", expMonth: "CARD_EXP_MONTH_SENTINEL", expYear: "CARD_EXP_YEAR_SENTINEL", code: "CARD_CODE_SENTINEL", brand: "CARD_BRAND_SENTINEL" }, notes: "CARD_NOTES_SENTINEL" },
		{ id: "identity-id", type: 4, name: "Identity fixture", identity: { title: "IDENTITY_TITLE_SENTINEL", firstName: "IDENTITY_FIRST_SENTINEL", middleName: "IDENTITY_MIDDLE_SENTINEL", lastName: "IDENTITY_LAST_SENTINEL", address1: "IDENTITY_ADDRESS1_SENTINEL", address2: "IDENTITY_ADDRESS2_SENTINEL", address3: "IDENTITY_ADDRESS3_SENTINEL", city: "IDENTITY_CITY_SENTINEL", state: "IDENTITY_STATE_SENTINEL", postalCode: "IDENTITY_POSTAL_SENTINEL", country: "IDENTITY_COUNTRY_SENTINEL", company: "IDENTITY_COMPANY_SENTINEL", email: "IDENTITY_EMAIL_SENTINEL", phone: "IDENTITY_PHONE_SENTINEL", ssn: "IDENTITY_SSN_SENTINEL", username: "IDENTITY_USERNAME_SENTINEL", passportNumber: "IDENTITY_PASSPORT_SENTINEL", licenseNumber: "IDENTITY_LICENSE_SENTINEL" }, notes: "IDENTITY_NOTES_SENTINEL" },
		{ id: "ssh-id", type: 5, name: "SSH fixture", sshKey: { privateKey: "SSH_PRIVATE_SENTINEL", publicKey: "SSH_PUBLIC_SENTINEL", keyFingerprint: "SSH_FINGERPRINT_SENTINEL" }, notes: "SSH_NOTES_SENTINEL" },
	];
}

function fakeAdapter(items, options = {}) {
	let state = "unauthenticated";
	const calls = [];
	const session = "FIXTURE_SESSION_STAYS_PRIVATE_123456";
	return {
		calls,
		async status() { return { code: 0, state, userEmail: "fixture@example.test", serverUrl: "https://vault.example.test" }; },
		async configure() { return { code: 0 }; },
		async login() { state = "unlocked"; return { code: 0, session }; },
		async unlock() { state = "unlocked"; return { code: 0, session }; },
		async lock() { state = "locked"; return { code: 0 }; },
		async listItems({ search } = {}) {
			calls.push(["listItems", search]);
			if (options.failure) return { code: 1, stdout: "", stderr: SECRET_SENTINELS.join("|"), diagnostics: SECRET_SENTINELS.join("|"), failure: options.failure };
			const result = search === undefined ? items : items.filter((item) => JSON.stringify(item).includes(search));
			return { code: 0, items: result };
		},
		async listFolders() { calls.push(["listFolders"]); return { code: 0, folders: [{ id: "DURABLE_FOLDER_UUID_SENTINEL", name: "Engineering" }] }; },
	};
}
function keychain() { return { async get() { return "fixture-password"; }, async set() {}, async delete() {} }; }
async function createFixtureBroker(options = {}) {
	const directory = await mkdtemp(join(tmpdir(), "vault-items-"));
	await mkdir(join(directory, "profile"), { mode: 0o700 });
	const adapter = fakeAdapter(options.items ?? fixtures(), options);
	const broker = createBrokerServer({ socketPath: join(directory, "broker.sock"), adapter, keychain: keychain(), now: options.now, sessionIdleMs: options.sessionIdleMs, idleMs: 60 * 60 * 1000 });
	await broker.start();
	await requestSetup(join(directory, "broker.sock"), { server: "https://vault.example.test", email: "fixture@example.test", masterPassword: "fixture-password" });
	return { directory, broker, socketPath: join(directory, "broker.sock"), adapter };
}
function textOf(value) { return JSON.stringify(value); }
function assertNoSentinels(value) {
	const text = textOf(value);
	for (const sentinel of SECRET_SENTINELS) assert(!text.includes(sentinel), `leaked sentinel: ${sentinel}`);
}

 test("password-history passwords get opaque descriptors while dates stay private", () => {
	let next = 0;
	const record = deriveSafeRecord({
		type: 1,
		name: "history",
		login: {},
		passwordHistory: [{ lastUsedDate: "2041-01-02T03:04:05.000Z", password: "PASSWORD_HISTORY_SENTINEL" }],
	}, new Map(), () => `opaque_${++next}`);
	const inspection = publicInspection(record);
	assert.equal("raw" in record, false);
	assert.equal(record.summary.materialCount, 1);
	assert.equal(inspection.materials.length, 1);
	assert.deepEqual({ ...inspection.materials[0], handle: "opaque" }, {
		handle: "opaque",
		category: "password-history",
		type: "password",
		label: "password history 1",
		delivery: { environment: true, stdin: true },
	});
	assert.equal(new Map(record.fields.map((field) => [field.handle, field.value])).get(inspection.materials[0].handle), "PASSWORD_HISTORY_SENTINEL");
	assertNoSentinels(record.summary);
	assertNoSentinels(inspection);
});

test("CLI response-shape fixture represents every secret-bearing value only behind handles", () => {
	let next = 0;
	const records = fixtures().map((item) => deriveSafeRecord(item, new Map(), () => `opaque_${++next}`));
	const inspections = records.map(publicInspection);
	const privateByHandle = new Map(records.flatMap((record) => [
		...record.fields.map((field) => [field.handle, field.value]),
		...record.attachments.map((attachment) => [attachment.handle, attachment.value]),
	]));
	for (const inspection of inspections) {
		assertNoSentinels(inspection);
		for (const descriptor of [...inspection.materials, ...inspection.attachments]) assert.equal(privateByHandle.has(descriptor.handle), true);
	}
	assertNoSentinels(records.map((record) => record.summary));
	const privateText = JSON.stringify([...privateByHandle.values()]);
	for (const sentinel of MATERIAL_SENTINELS) assert(privateText.includes(sentinel), `fixture material omitted: ${sentinel}`);
	const loginInspection = inspections[0];
	assert(loginInspection.materials.some((field) => field.category === "login" && field.type === "uri"));
	assert(loginInspection.materials.some((field) => field.category === "password-history" && field.type === "password"));
	const attachment = loginInspection.attachments[0];
	assert(JSON.stringify(privateByHandle.get(attachment.handle)).includes("ATTACHMENT_URL_SENTINEL"));
});

test("Safe Metadata pages, native search, folder resolution, and every descriptor category are mediated", async () => {
	const fixture = await createFixtureBroker();
	try {
		const first = await requestVaultItems(fixture.socketPath, { action: "list", limit: 2 });
		assert.equal(first.items.length, 2);
		assert(first.nextCursor);
		assert(first.items.every((item) => Object.keys(item).sort().join(",") === "attachmentCount,favorite,folderName,handle,materialCount,normalizedOrigins,title,type"));
		assert.equal(first.items[0].folderName, "Engineering");
		assert.deepEqual(first.items[0].normalizedOrigins, ["https://example.test"]);
		assert.equal(first.items[0].attachmentCount, 1);
		assert(first.items.length <= 100);
		assertNoSentinels(first);
		assert(!first.nextCursor.includes(UUID));

		const second = await requestVaultItems(fixture.socketPath, { action: "list", cursor: first.nextCursor, limit: 100 });
		assert.equal(second.items.length, 3);
		assertNoSentinels(second);
		const inspect = await requestVaultItems(fixture.socketPath, { action: "inspect", itemHandle: first.items[0].handle });
		assert.equal(inspect.materials.some((field) => field.category === "login" && field.type === "username"), true);
		assert.equal(inspect.materials.some((field) => field.type === "totp"), true);
		assert.equal(inspect.materials.some((field) => field.category === "login" && field.type === "uri"), true);
		assert.equal(inspect.materials.some((field) => field.category === "password-history" && field.type === "password"), true);
		assert.equal(inspect.materials.some((field) => field.category === "custom-field"), true);
		assert.equal(inspect.materials.some((field) => field.category === "passkey" && field.type === "privateKey"), true);
		assert.equal(inspect.materials.some((field) => field.category === "passkey" && field.type === "rpName"), true);
		assert.equal(inspect.materials.some((field) => field.category === "passkey" && field.type === "userDisplayName"), true);
		assert.equal(inspect.attachments[0].filename, "ssh-config.txt");
		assert.equal(inspect.attachments[0].mimeType, "text/plain");
		assert.equal(inspect.attachments[0].size, 23);
		assert(!JSON.stringify(inspect.attachments[0]).includes("DURABLE_ATTACHMENT_UUID_SENTINEL"));
		assert(!JSON.stringify(inspect.attachments[0]).includes("ATTACHMENT_URL_SENTINEL"));
		assert.equal(inspect.attachments[0].delivery.stdin, true);
		assert.equal(inspect.materials.find((field) => field.type === "notes").delivery.stdin, true);
		assert.equal(inspect.materials.find((field) => field.type === "password").delivery.environment, true);
		assert.equal(inspect.materials.find((field) => field.type === "password").delivery.stdin, true);
		const secureInspect = await requestVaultItems(fixture.socketPath, { action: "inspect", itemHandle: first.items[1].handle });
		const cardInspect = await requestVaultItems(fixture.socketPath, { action: "inspect", itemHandle: second.items[0].handle });
		const identityInspect = await requestVaultItems(fixture.socketPath, { action: "inspect", itemHandle: second.items[1].handle });
		const sshInspect = await requestVaultItems(fixture.socketPath, { action: "inspect", itemHandle: second.items[2].handle });
		assert.equal(secureInspect.materials.some((field) => field.category === "secure-note"), true);
		assert.equal(cardInspect.materials.some((field) => field.category === "card"), true);
		assert.equal(identityInspect.materials.some((field) => field.category === "identity"), true);
		assert.equal(sshInspect.materials.some((field) => field.category === "ssh-key"), true);
		assert.equal(sshInspect.materials.every((field) => field.delivery.stdin === true), true);
		assertNoSentinels(inspect);
		assertNoSentinels(secureInspect);
		assertNoSentinels(cardInspect);
		assertNoSentinels(identityInspect);
		assertNoSentinels(sshInspect);

		const searched = await requestVaultItems(fixture.socketPath, { action: "search", query: "LOGIN_PASSWORD_SENTINEL" });
		assert.equal(searched.items.length, 1);
		assert.deepEqual(fixture.adapter.calls.find((call) => call[0] === "listItems" && call[1]), ["listItems", "LOGIN_PASSWORD_SENTINEL"]);
		assertNoSentinels(searched);
	} finally { await fixture.broker.stop(); await rm(fixture.directory, { recursive: true, force: true }); }
});

test("leases invalidate handles and cursors, with wrong-kind and bounded validation failures", async () => {
	const fixture = await createFixtureBroker();
	try {
		const page = await requestVaultItems(fixture.socketPath, { action: "list", limit: 1 });
		await assert.rejects(() => requestVaultItems(fixture.socketPath, { action: "inspect", itemHandle: page.nextCursor }), (error) => error instanceof BrokerRequestError && error.code === "invalid_handle");
		await rm(join(fixture.directory, "profile"), { recursive: true, force: true });
		await assert.rejects(() => requestVaultItems(fixture.socketPath, { action: "inspect", itemHandle: page.items[0].handle }), (error) => error instanceof BrokerRequestError && error.code === "invalid_handle");
		await fixture.broker.invalidateSession();
		await assert.rejects(() => requestVaultItems(fixture.socketPath, { action: "list", cursor: page.nextCursor }), (error) => error instanceof BrokerRequestError && error.code === "invalid_cursor");
		assert.throws(() => validateRequest({ id: "x", method: "items", params: { action: "list", limit: 101 } }), ProtocolError);
		assert.throws(() => validateRequest({ id: "x", method: "items", params: { action: "search", query: "x", extra: "no" } }), ProtocolError);
		assertNoSentinels(await requestVaultItems(fixture.socketPath, { action: "status" }));
	} finally { await fixture.broker.stop(); await rm(fixture.directory, { recursive: true, force: true }); }
});

test("native adapter uses Bitwarden search and bounded pages remain opaque", async () => {
	const seen = [];
	const adapter = createBitwardenAdapter({ profilePath: "/fake/profile", run: async (args, options) => {
		seen.push({ args, env: options.env });
		return { code: 0, stdout: args[0] === "list" ? "[]" : "", stderr: "" };
	} });
	await adapter.listItems({ search: "hidden query", session: "S".repeat(32) });
	assert.deepEqual(seen[0].args, ["list", "items", "--search", "hidden query", "--nointeraction"]);
	assert.equal(seen[0].env.BW_SESSION, "S".repeat(32));

	const many = Array.from({ length: 105 }, (_, index) => ({ id: `item-${index}`, type: 2, name: `item-${index}`, notes: `note-${index}` }));
	const fixture = await createFixtureBroker({ items: many });
	try {
		let page = await requestVaultItems(fixture.socketPath, { action: "list" });
		assert(page.items.length <= 100);
		let total = page.items.length;
		while (page.nextCursor) {
			page = await requestVaultItems(fixture.socketPath, { action: "list", cursor: page.nextCursor });
			assert(page.items.length <= 100);
			total += page.items.length;
		}
		assert.equal(total, 105);
		assertNoSentinels(page);
	} finally { await fixture.broker.stop(); await rm(fixture.directory, { recursive: true, force: true }); }
});

test("bounded Bitwarden retrieval accepts valid JSON beyond 256 KiB and rejects overflow explicitly", async () => {
	const large = JSON.stringify([{ id: "small-item", type: 2, name: "small", notes: "L".repeat(300 * 1024) }]);
	const adapter = createBitwardenAdapter({ profilePath: "/fake/profile", run: async () => ({ code: 0, stdout: large, stderr: "" }) });
	const result = await adapter.listItems();
	assert.equal(result.failure, undefined);
	assert.equal(result.items.length, 1);
	assert(Buffer.byteLength(result.stdout) > 256 * 1024);

	const directory = await mkdtemp(join(tmpdir(), "vault-overflow-"));
	const executable = join(directory, "fake-bw");
	await writeFile(executable, `#!/usr/bin/env node\nprocess.stdout.write("[" + "x".repeat(${MAX_OUTPUT_BYTES + 1024}) + "]");\n`);
	await chmod(executable, 0o700);
	try {
		const overflowing = createBitwardenAdapter({ profilePath: "/fake/profile", executable });
		const rejected = await overflowing.listItems();
		assert.equal(rejected.failure, "output_overflow");
		assert.equal(rejected.items, undefined);
		assert.equal(Buffer.byteLength(rejected.stdout), MAX_OUTPUT_BYTES);
	} finally { await rm(directory, { recursive: true, force: true }); }
});

test("allowlisted Unicode strings are truncated and validated by UTF-8 byte boundaries", async () => {
	const value = "😀".repeat(256);
	const record = deriveSafeRecord({ type: 2, name: value, folderId: "folder", fields: [{ name: value, value: "private" }], attachments: [{ id: "attachment-id", fileName: value, size: "7", contentType: value }] }, new Map([["folder", value]]));
	assert.equal(Buffer.byteLength(record.summary.title, "utf8"), 512);
	assert.equal(Buffer.byteLength(record.summary.folderName, "utf8"), 512);
	const inspection = publicInspection(record);
	assert.equal(Buffer.byteLength(inspection.materials[0].label, "utf8"), 256);
	assert.equal(Buffer.byteLength(inspection.attachments[0].filename, "utf8"), 512);
	assert.equal(Buffer.byteLength(inspection.attachments[0].mimeType, "utf8"), 256);
	assert.doesNotThrow(() => responseFrames({ id: "unicode", ok: true, result: { action: "inspect", state: "unlocked", ...inspection } }));
});

test("declared descriptor upper limits remain inspectable through the bounded broker result", async () => {
	const items = [{
		id: "upper-limit-item",
		type: 2,
		name: "upper limit",
		fields: Array.from({ length: MAX_MATERIAL_DESCRIPTORS }, (_, index) => ({ name: `field-${index}-${"😀".repeat(64)}`, value: `private-${index}` })),
		attachments: Array.from({ length: MAX_ATTACHMENT_DESCRIPTORS }, (_, index) => ({ id: `attachment-${index}`, fileName: `file-${index}.txt`, size: "7", sizeName: "7 Bytes" })),
	}];
	const fixture = await createFixtureBroker({ items });
	try {
		const page = await requestVaultItems(fixture.socketPath, { action: "list" });
		const inspection = await requestVaultItems(fixture.socketPath, { action: "inspect", itemHandle: page.items[0].handle });
		assert.equal(inspection.materials.length, MAX_MATERIAL_DESCRIPTORS);
		assert.equal(inspection.attachments.length, MAX_ATTACHMENT_DESCRIPTORS);
		assert(Buffer.byteLength(JSON.stringify(inspection), "utf8") <= 256 * 1024);
		assertNoSentinels(inspection);
	} finally { await fixture.broker.stop(); await rm(fixture.directory, { recursive: true, force: true }); }
});

test("one oversized Safe Metadata item is chunked without weakening frame validation", async () => {
	const origins = Array.from({ length: 100 }, (_, index) => ({ uri: `https://origin-${index.toString().padStart(3, "0")}-${"x".repeat(190)}.example.test/path-${index}?q=secret-${index}#fragment-${index}` }));
	const fixture = await createFixtureBroker({ items: [{ id: "large-origin-item", type: 1, name: "large origins", login: { uris: origins } }] });
	try {
		const result = await requestVaultItems(fixture.socketPath, { action: "list" });
		assert.equal(result.items.length, 1);
		assert.equal(result.items[0].normalizedOrigins.length, 100);
		const frames = responseFrames({ id: "chunk-test", ok: true, result: { action: "list", state: "unlocked", items: [result.items[0]] } });
		assert(frames.length > 1);
		assert(frames.every((frame) => frame.length <= MAX_FRAME_BYTES + 4));
		const parser = new FrameParser();
		assert.equal(parser.push(Buffer.concat(frames)).length, frames.length);
	} finally { await fixture.broker.stop(); await rm(fixture.directory, { recursive: true, force: true }); }
});

test("Vault Session expiry invalidates prior item handles before unattended re-unlock", async () => {
	let clock = 10_000;
	const fixture = await createFixtureBroker({ now: () => clock, sessionIdleMs: 100 });
	try {
		const page = await requestVaultItems(fixture.socketPath, { action: "list", limit: 1 });
		clock += 101;
		await fixture.broker.checkSessionIdle();
		await assert.rejects(() => requestVaultItems(fixture.socketPath, { action: "inspect", itemHandle: page.items[0].handle }), (error) => error instanceof BrokerRequestError && error.code === "invalid_handle");
	} finally { await fixture.broker.stop(); await rm(fixture.directory, { recursive: true, force: true }); }
});

test("lock, logout, profile replacement, and expiry invalidate item/material handles and cursors", async () => {
	const cases = ["lock", "logout", "replaceProfile", "expiry"];
	for (const lifecycle of cases) {
		let clock = 10_000;
		const fixture = await createFixtureBroker({ now: () => clock, sessionIdleMs: lifecycle === "expiry" ? 100 : undefined });
		try {
			const page = await requestVaultItems(fixture.socketPath, { action: "list", limit: 1 });
			const inspection = await requestVaultItems(fixture.socketPath, { action: "inspect", itemHandle: page.items[0].handle });
			const materialHandle = inspection.materials[0].handle;
			const attachmentHandle = inspection.attachments[0]?.handle;
			assert.equal(fixture.broker.hasMaterialHandle(materialHandle), true);
			if (attachmentHandle) assert.equal(fixture.broker.hasAttachmentHandle(attachmentHandle), true);
			if (lifecycle === "lock") {
				await fixture.adapter.lock("fixture-session");
				await requestStatus(fixture.socketPath);
			} else if (lifecycle === "expiry") {
				clock += 101;
				await fixture.broker.checkSessionIdle();
			} else if (lifecycle === "replaceProfile") {
				await rm(join(fixture.directory, "profile"), { recursive: true, force: true });
				await mkdir(join(fixture.directory, "profile"), { mode: 0o700 });
				await requestStatus(fixture.socketPath);
			} else await fixture.broker[lifecycle]();
			assert.equal(fixture.broker.hasMaterialHandle(materialHandle), false);
			if (attachmentHandle) assert.equal(fixture.broker.hasAttachmentHandle(attachmentHandle), false);
			await assert.rejects(() => requestVaultItems(fixture.socketPath, { action: "inspect", itemHandle: page.items[0].handle }), (error) => error instanceof BrokerRequestError && error.code === "invalid_handle");
			await assert.rejects(() => requestVaultItems(fixture.socketPath, { action: "list", cursor: page.nextCursor }), (error) => error instanceof BrokerRequestError && error.code === "invalid_cursor");
		} finally { await fixture.broker.stop(); await rm(fixture.directory, { recursive: true, force: true }); }
	}
});



test("fresh list roots have finite snapshot eviction while normal continuation survives", async () => {
	const fixture = await createFixtureBroker();
	try {
		const roots = [];
		for (let index = 0; index < MAX_ACTIVE_SNAPSHOTS + 1; index++) {
			roots.push(await requestVaultItems(fixture.socketPath, { action: "list", limit: 1 }));
			if (index === 0) {
				const firstInspection = await requestVaultItems(fixture.socketPath, { action: "inspect", itemHandle: roots[0].items[0].handle });
				roots.firstMaterialHandle = firstInspection.materials[0].handle;
				roots.firstAttachmentHandle = firstInspection.attachments[0].handle;
			}
		}
		assert.equal(fixture.broker.activeSnapshotCount(), MAX_ACTIVE_SNAPSHOTS);
		assert.equal(fixture.broker.hasMaterialHandle(roots.firstMaterialHandle), false);
		assert.equal(fixture.broker.hasAttachmentHandle(roots.firstAttachmentHandle), false);
		await assert.rejects(() => requestVaultItems(fixture.socketPath, { action: "inspect", itemHandle: roots[0].items[0].handle }), (error) => error instanceof BrokerRequestError && error.code === "invalid_handle");
		await assert.rejects(() => requestVaultItems(fixture.socketPath, { action: "list", cursor: roots[0].nextCursor }), (error) => error instanceof BrokerRequestError && error.code === "invalid_cursor");
		const continuation = await requestVaultItems(fixture.socketPath, { action: "list", cursor: roots.at(-1).nextCursor });
		assert.equal(continuation.items.length, 4);
	} finally { await fixture.broker.stop(); await rm(fixture.directory, { recursive: true, force: true }); }
});

test("items tool forwards AbortSignal and returns bounded cancellation", async () => {
	const tools = [];
	let receivedSignal;
	const pi = { registerTool(tool) { tools.push(tool); }, registerCommand() {}, on() {} };
	const client = { async items(_input, signal) {
		receivedSignal = signal;
		return await new Promise((_resolve, reject) => signal.addEventListener("abort", () => reject(new DOMException("cancelled", "AbortError")), { once: true }));
	}, async status() { return "unlocked"; } };
	registerVaultExtension(pi, { client });
	const controller = new AbortController();
	const pending = tools[0].execute("call", { action: "list" }, controller.signal, undefined, { ui: { setStatus() {} }, mode: "print" });
	controller.abort();
	const result = await pending;
	assert.equal(receivedSignal, controller.signal);
	assert.equal(result.details.error, "cancelled");
	assert.equal(result.details.cancelled, true);
});

test("successful extension results put bounded Safe Metadata in content and keep details/renderers safe", async () => {
	const fixture = await createFixtureBroker();
	try {
		const tools = [];
		const pi = { registerTool(tool) { tools.push(tool); }, registerCommand() {}, on() {} };
		const client = { async items(input) { return requestVaultItems(fixture.socketPath, input); }, async status() { return "unlocked"; } };
		registerVaultExtension(pi, { client });
		const ui = { setStatus() {} };
		const list = await tools[0].execute("call", { action: "list", limit: 2 }, undefined, undefined, { ui, mode: "print" });
		const listContent = JSON.parse(list.content[0].text);
		assert.equal(listContent.action, "list");
		assert.equal(listContent.items.length, 2);
		assert(listContent.items[0].handle);
		assert(listContent.nextCursor);
		assert.deepEqual(list.details.items, listContent.items);
		assertNoSentinels(list);
		assertNoSentinels(tools[0].renderCall({ action: "list" }, { fg: (_c, value) => value, bold: (value) => value }, { expanded: true }));
		assertNoSentinels(tools[0].renderResult(list, { expanded: true, isPartial: false }, { fg: (_c, value) => value }, {}));

		const search = await tools[0].execute("call", { action: "search", query: "LOGIN_PASSWORD_SENTINEL" }, undefined, undefined, { ui, mode: "print" });
		assert.equal(JSON.parse(search.content[0].text).items.length, 1);
		const inspect = await tools[0].execute("call", { action: "inspect", itemHandle: listContent.items[0].handle }, undefined, undefined, { ui, mode: "print" });
		const inspectContent = JSON.parse(inspect.content[0].text);
		assert(inspectContent.materials.some((descriptor) => descriptor.delivery.environment));
		assert(inspectContent.attachments.every((descriptor) => descriptor.delivery.environment === false && descriptor.delivery.stdin === true));
		assertNoSentinels(search);
		assertNoSentinels(inspect);
		assertNoSentinels(tools[0].renderResult(inspect, { expanded: true, isPartial: false }, { fg: (_c, value) => value }, {}));
	} finally { await fixture.broker.stop(); await rm(fixture.directory, { recursive: true, force: true }); }
});

test("tool errors discard CLI diagnostics and never log or render fixture material", async () => {
	const fixture = await createFixtureBroker({ failure: "cli_error" });
	const logged = [];
	const methods = ["debug", "error", "info", "log", "warn"];
	const originals = new Map(methods.map((method) => [method, console[method]]));
	for (const method of methods) console[method] = (...args) => logged.push([method, ...args]);
	try {
		const tools = [];
		const pi = { registerTool(tool) { tools.push(tool); }, registerCommand() {}, on() {} };
		const client = { async items(input) { return requestVaultItems(fixture.socketPath, input); }, async status() { return "unlocked"; } };
		registerVaultExtension(pi, { client });
		const ui = { setStatus() {} };
		const errorResult = await tools[0].execute("call", { action: "list" }, undefined, undefined, { ui, mode: "print" });
		assert.equal(errorResult.details.error, "cli_error");
		assertNoSentinels(errorResult);
		assertNoSentinels(tools[0].renderCall({ action: "search", query: "fixture-query" }, { fg: (_c, value) => value, bold: (value) => value }, { expanded: true }));
		assertNoSentinels(tools[0].renderResult(errorResult, { expanded: true, isPartial: false }, { fg: (_c, value) => value }, {}));
	} finally {
		for (const [method, original] of originals) console[method] = original;
		await fixture.broker.stop();
		await rm(fixture.directory, { recursive: true, force: true });
	}
	assertNoSentinels(logged);
	assert.deepEqual(logged, []);
});
