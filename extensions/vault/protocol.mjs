import {
	MAX_CURSOR_LENGTH,
	MAX_HANDLE_LENGTH,
	MAX_PAGE_SIZE,
	MAX_ORIGINS,
	MAX_MATERIAL_DESCRIPTORS,
	MAX_ATTACHMENT_DESCRIPTORS,
	validateItemsInput,
} from "./metadata.mjs";
import { validateVaultRunInput } from "./run.mjs";
import { validateVaultSshInput } from "./ssh.mjs";

export const MAX_FRAME_BYTES = 16 * 1024;
export const MAX_REQUEST_ID_BYTES = 128;
export const MAX_CHUNK_COUNT = 1024;
export const MAX_FRAMES_PER_PUSH = MAX_CHUNK_COUNT;
export const RESPONSE_CHUNK_BYTES = 10 * 1024;
// A chunked result is still bounded: 1024 frames of 10,000 base64
// characters is about 7.5 MiB of decoded JSON. Safe Metadata is much smaller,
// but the explicit ceiling prevents a peer from making the reassembler grow
// without bound.
export const MAX_CHUNKED_RESULT_BYTES = Math.floor(RESPONSE_CHUNK_BYTES * 3 / 4 * MAX_CHUNK_COUNT);
export const MAX_CHUNKED_ENCODED_BYTES = RESPONSE_CHUNK_BYTES * MAX_CHUNK_COUNT;
export const STATUS_STATES = Object.freeze(["unconfigured", "unauthenticated", "locked", "unlocked"]);
export const SAFE_ERRORS = Object.freeze([
	"invalid_server", "invalid_email", "invalid_password", "invalid_credentials", "network_error",
	"keychain_unavailable", "cli_unavailable", "cli_error", "cli_state", "invalid_cli_json", "cancelled",
	"ui_unavailable", "internal_error", "config_recovery", "output_overflow", "invalid_input", "invalid_action", "invalid_cursor", "invalid_handle",
	"vault_not_unlocked", "invalid_item_data", "over_limit", "duplicate_handle", "wrong_item", "material_incompatible", "material_unavailable", "run_failed", "cleanup_partial",
	"host_key_changed", "auth_failed", "timed_out", "host_key_unavailable",
]);

export class ProtocolError extends Error {
	constructor(message) { super(message); this.name = "ProtocolError"; }
}

function isPlainObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
function exactKeys(value, keys) {
	const actual = Object.keys(value).sort();
	const expected = [...keys].sort();
	return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}
function validateId(id) {
	if (typeof id !== "string" || id.length === 0 || Buffer.byteLength(id, "utf8") > MAX_REQUEST_ID_BYTES || /[\u0000-\u001f\u007f]/u.test(id)) throw new ProtocolError("invalid request id");
	return id;
}
function safeInput(value, max) {
	return typeof value === "string" && value.length > 0 && value.length <= max && !/[\u0000-\u001f\u007f]/u.test(value);
}
function safeHost(value) {
	return typeof value === "string" && value.length > 0 && value.length <= 512 && /^[A-Za-z0-9.:[\]-]+(?::\d+)?$/u.test(value);
}
function safeText(value, max = 1024) { return typeof value === "string" && Buffer.byteLength(value, "utf8") <= max && !/[\u0000-\u001f\u007f]/u.test(value); }
function safeDelivery(value) { return isPlainObject(value) && exactKeys(value, ["environment", "stdin"]) && typeof value.environment === "boolean" && typeof value.stdin === "boolean"; }
function safeChunk(value) {
	if (!isPlainObject(value) || !exactKeys(value, ["id", "ok", "chunkIndex", "chunkCount", "data"]) ||
		typeof value.chunkIndex !== "number" || !Number.isSafeInteger(value.chunkIndex) || value.chunkIndex < 0 ||
		typeof value.chunkCount !== "number" || !Number.isSafeInteger(value.chunkCount) || value.chunkCount <= 0 || value.chunkCount > MAX_CHUNK_COUNT || value.chunkIndex >= value.chunkCount ||
		typeof value.data !== "string" || value.data.length === 0 || value.data.length > RESPONSE_CHUNK_BYTES || value.data.length % 4 !== 0 ||
		!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value.data) || value.data.includes("=") && value.chunkIndex !== value.chunkCount - 1 ||
		value.chunkCount * RESPONSE_CHUNK_BYTES > MAX_CHUNKED_ENCODED_BYTES) return false;
	return value.chunkIndex === value.chunkCount - 1 || (value.data.length === RESPONSE_CHUNK_BYTES && !value.data.includes("="));
}
function safeMaterial(value) {
	return isPlainObject(value) && exactKeys(value, ["handle", "category", "type", "label", "delivery"]) &&
		safeText(value.handle, MAX_HANDLE_LENGTH) && safeText(value.category, 64) && safeText(value.type, 64) && safeText(value.label, 256) && safeDelivery(value.delivery);
}
function safeAttachment(value) {
	return isPlainObject(value) && exactKeys(value, ["handle", "category", "type", "filename", "mimeType", "size", "delivery"]) &&
		safeText(value.handle, MAX_HANDLE_LENGTH) && value.category === "attachment" && value.type === "bytes" &&
		safeText(value.filename, 512) && safeText(value.mimeType, 256) && Number.isSafeInteger(value.size) && value.size >= 0 && safeDelivery(value.delivery);
}
function safeSummary(value) {
	return isPlainObject(value) && exactKeys(value, ["handle", "type", "favorite", "title", "folderName", "normalizedOrigins", "materialCount", "attachmentCount"]) &&
		safeText(value.handle, MAX_HANDLE_LENGTH) && safeText(value.type, 64) && typeof value.favorite === "boolean" && safeText(value.title, 512) &&
		(value.folderName === null || safeText(value.folderName, 512)) && Array.isArray(value.normalizedOrigins) && value.normalizedOrigins.length <= MAX_ORIGINS && value.normalizedOrigins.every((origin) => safeText(origin, 512)) &&
		Number.isSafeInteger(value.materialCount) && value.materialCount >= 0 && value.materialCount <= MAX_MATERIAL_DESCRIPTORS &&
		Number.isSafeInteger(value.attachmentCount) && value.attachmentCount >= 0 && value.attachmentCount <= MAX_ATTACHMENT_DESCRIPTORS;
}
function safeLifecycleResult(value) {
	return isPlainObject(value) && exactKeys(value, ["action", "state", "cleanup"]) && value.action === "forget" && value.state === "unconfigured" && ["complete", "partial"].includes(value.cleanup);
}

function safeRunResult(value) {
	if (!isPlainObject(value) || !["text", "bulk"].includes(value.mode) || !exactKeys(value, value.mode === "text"
		? ["mode", "exitCode", "signal", "durationMs", "timedOut", "cancelled", "stdoutBytes", "stderrBytes", "stdout", "stderr"]
		: ["mode", "exitCode", "signal", "durationMs", "timedOut", "cancelled", "stdoutBytes", "stderrBytes"])) return false;
	return (value.exitCode === null || (Number.isSafeInteger(value.exitCode) && value.exitCode >= 0)) &&
		(value.signal === null || safeText(value.signal, 32)) && Number.isSafeInteger(value.durationMs) && value.durationMs >= 0 &&
		typeof value.timedOut === "boolean" && typeof value.cancelled === "boolean" && Number.isSafeInteger(value.stdoutBytes) && value.stdoutBytes >= 0 &&
		Number.isSafeInteger(value.stderrBytes) && value.stderrBytes >= 0 && (value.mode === "bulk" || (typeof value.stdout === "string" && typeof value.stderr === "string" && Buffer.byteLength(value.stdout, "utf8") + Buffer.byteLength(value.stderr, "utf8") <= 1_048_576));
}

function safeItemsResult(value) {
	if (!isPlainObject(value) || typeof value.action !== "string" || !["status", "list", "search", "inspect"].includes(value.action)) return false;
	if (value.state !== undefined && !STATUS_STATES.includes(value.state)) return false;
	if (value.action === "status") return exactKeys(value, ["action", "state"]);
	if (value.state !== "unlocked") return exactKeys(value, ["action", "state"]);
	if (value.action === "list" || value.action === "search") {
		if (!exactKeys(value, ["action", "state", "items", "nextCursor"]) && !exactKeys(value, ["action", "state", "items"])) return false;
		return value.state === "unlocked" && Array.isArray(value.items) && value.items.length <= MAX_PAGE_SIZE && value.items.every(safeSummary) &&
			(value.nextCursor === undefined || safeText(value.nextCursor, MAX_CURSOR_LENGTH));
	}
	if (!exactKeys(value, ["action", "state", "itemHandle", "type", "materials", "attachments"])) return false;
	return value.state === "unlocked" && safeText(value.itemHandle, MAX_HANDLE_LENGTH) && safeText(value.type, 64) &&
		Array.isArray(value.materials) && value.materials.length <= MAX_MATERIAL_DESCRIPTORS && value.materials.every(safeMaterial) &&
		Array.isArray(value.attachments) && value.attachments.length <= MAX_ATTACHMENT_DESCRIPTORS && value.attachments.every(safeAttachment);
}

export function validateRequest(value) {
	if (!isPlainObject(value) || typeof value.method !== "string" || !isPlainObject(value.params)) throw new ProtocolError("invalid request shape");
	const id = validateId(value.id);
	if (value.method === "status") {
		if (!exactKeys(value, ["id", "method", "params"]) || !exactKeys(value.params, [])) throw new ProtocolError("invalid status request");
		return { id, method: "status", params: {} };
	}
	if (value.method === "setup") {
		if (!exactKeys(value, ["id", "method", "params"]) || !exactKeys(value.params, ["server", "email", "masterPassword"])) throw new ProtocolError("invalid setup request");
		if (!safeInput(value.params.server, 512) || !safeInput(value.params.email, 320) || !safeInput(value.params.masterPassword, 1024)) throw new ProtocolError("invalid setup input");
		return { id, method: "setup", params: { server: value.params.server, email: value.params.email, masterPassword: value.params.masterPassword } };
	}
	if (value.method === "config") {
		if (!exactKeys(value, ["id", "method", "params"]) || !exactKeys(value.params, ["server", "email", "masterPassword"])) throw new ProtocolError("invalid config request");
		if (!safeInput(value.params.server, 512) || !safeInput(value.params.email, 320) || !safeInput(value.params.masterPassword, 1024)) throw new ProtocolError("invalid config input");
		return { id, method: "config", params: { server: value.params.server, email: value.params.email, masterPassword: value.params.masterPassword } };
	}
	if (["lock", "forget"].includes(value.method)) {
		if (!exactKeys(value, ["id", "method", "params"]) || !exactKeys(value.params, [])) throw new ProtocolError(`invalid ${value.method} request`);
		return { id, method: value.method, params: {} };
	}
	if (value.method === "items") {
		if (!exactKeys(value, ["id", "method", "params"])) throw new ProtocolError("invalid items request");
		try { return { id, method: "items", params: validateItemsInput(value.params) }; }
		catch { throw new ProtocolError("invalid items request"); }
	}
	if (value.method === "run") {
		if (!exactKeys(value, ["id", "method", "params"])) throw new ProtocolError("invalid run request");
		try { return { id, method: "run", params: validateVaultRunInput(value.params) }; }
		catch { throw new ProtocolError("invalid run request"); }
	}
	if (value.method === "sshRun") {
		if (!exactKeys(value, ["id", "method", "params"])) throw new ProtocolError("invalid ssh request");
		try { return { id, method: "sshRun", params: validateVaultSshInput(value.params) }; }
		catch { throw new ProtocolError("invalid ssh request"); }
	}
	throw new ProtocolError("unsupported method");
}

export function validateResponse(value) {
	if (!isPlainObject(value) || typeof value.id !== "string") throw new ProtocolError("invalid response shape");
	const id = validateId(value.id);
	if (value.ok === true) {
		if (Object.prototype.hasOwnProperty.call(value, "chunkIndex")) {
			if (!safeChunk(value) || value.id !== id) throw new ProtocolError("invalid response chunk");
			return { id, ok: true, chunkIndex: value.chunkIndex, chunkCount: value.chunkCount, data: value.data };
		}
		if (Object.prototype.hasOwnProperty.call(value, "result")) {
			if (!exactKeys(value, ["id", "ok", "result"]) || (!safeItemsResult(value.result) && !safeRunResult(value.result) && !safeLifecycleResult(value.result))) throw new ProtocolError("invalid result response");
			return { id, ok: true, result: value.result };
		}
		const keys = Object.keys(value);
		if (!(keys.length === 3 || keys.length === 4) || !["id", "ok", "state"].every((key) => key in value) || (keys.length === 4 && !Object.prototype.hasOwnProperty.call(value, "serverHost"))) throw new ProtocolError("invalid success response");
		if (!STATUS_STATES.includes(value.state) || (value.serverHost !== undefined && !safeHost(value.serverHost))) throw new ProtocolError("invalid success state");
		return value.serverHost === undefined ? { id, ok: true, state: value.state } : { id, ok: true, state: value.state, serverHost: value.serverHost };
	}
	if (value.ok === false) {
		if (!exactKeys(value, ["id", "ok", "error"]) || typeof value.error !== "string" || !SAFE_ERRORS.includes(value.error)) throw new ProtocolError("invalid error response");
		return { id, ok: false, error: value.error };
	}
	throw new ProtocolError("invalid response status");
}

export function encodeFrame(value) {
	let body;
	try { body = Buffer.from(JSON.stringify(value), "utf8"); } catch { throw new ProtocolError("value is not JSON serializable"); }
	if (body.length > MAX_FRAME_BYTES) throw new ProtocolError("frame exceeds maximum size");
	const frame = Buffer.allocUnsafe(4 + body.length);
	frame.writeUInt32BE(body.length, 0); body.copy(frame, 4); return frame;
}

export class FrameParser {
	#buffer = Buffer.alloc(0);
	push(chunk) {
		if (!Buffer.isBuffer(chunk)) chunk = Buffer.from(chunk);
		if (chunk.length === 0) return [];
		// Process complete frames directly from the input and retain only the
		// incomplete prefix. This avoids concatenating an arbitrarily large TCP
		// read before enforcing the 16 KiB per-frame bound.
		const values = [];
		let offset = 0;
		while (offset < chunk.length || this.#buffer.length > 0) {
			if (this.#buffer.length < 4) {
				const needed = 4 - this.#buffer.length;
				const take = Math.min(needed, chunk.length - offset);
				if (take > 0) {
					this.#buffer = Buffer.concat([this.#buffer, chunk.subarray(offset, offset + take)]);
					offset += take;
				}
				if (this.#buffer.length < 4) break;
			}
			const length = this.#buffer.readUInt32BE(0);
			if (length === 0 || length > MAX_FRAME_BYTES) throw new ProtocolError("invalid frame length");
			const total = length + 4;
			if (this.#buffer.length < total) {
				const needed = total - this.#buffer.length;
				const take = Math.min(needed, chunk.length - offset);
				if (take > 0) {
					this.#buffer = Buffer.concat([this.#buffer, chunk.subarray(offset, offset + take)]);
					offset += take;
				}
				if (this.#buffer.length < total) break;
			}
			const body = this.#buffer.subarray(4, total);
			try { values.push(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body))); }
			catch { throw new ProtocolError("invalid JSON frame"); }
			this.#buffer = this.#buffer.subarray(total);
			if (values.length >= MAX_FRAMES_PER_PUSH && (offset < chunk.length || this.#buffer.length > 0)) throw new ProtocolError("too many frames in one read");
		}
		if (this.#buffer.length > MAX_FRAME_BYTES + 4) throw new ProtocolError("input buffer exceeds maximum size");
		return values;
	}
}

export function responseFrames(response) {
	const validated = validateResponse(response);
	if (!validated.ok || !Object.prototype.hasOwnProperty.call(validated, "result")) return [encodeFrame(validated)];
	const resultBytes = Buffer.from(JSON.stringify(validated.result), "utf8");
	const wholeBody = Buffer.from(JSON.stringify(validated), "utf8");
	if (wholeBody.length + 4 <= MAX_FRAME_BYTES) return [encodeFrame(validated)];
	const encoded = resultBytes.toString("base64");
	const chunkCount = Math.ceil(encoded.length / RESPONSE_CHUNK_BYTES);
	if (chunkCount > MAX_CHUNK_COUNT || resultBytes.length > MAX_CHUNKED_RESULT_BYTES || encoded.length > MAX_CHUNKED_ENCODED_BYTES) throw new ProtocolError("response exceeds chunk bound");
	return Array.from({ length: chunkCount }, (_, chunkIndex) => encodeFrame({
		id: validated.id,
		ok: true,
		chunkIndex,
		chunkCount,
		data: encoded.slice(chunkIndex * RESPONSE_CHUNK_BYTES, (chunkIndex + 1) * RESPONSE_CHUNK_BYTES),
	}));
}

export function requestFrame(id) { return encodeFrame({ id: validateId(id), method: "status", params: {} }); }
export function setupFrame(id, params) { return encodeFrame({ id: validateId(id), method: "setup", params }); }
export function configFrame(id, params) { return encodeFrame({ id: validateId(id), method: "config", params }); }
export function lifecycleFrame(id, method) { return encodeFrame({ id: validateId(id), method, params: {} }); }
export function itemsFrame(id, params) { return encodeFrame({ id: validateId(id), method: "items", params: validateItemsInput(params) }); }
export function runFrame(id, params) { return encodeFrame({ id: validateId(id), method: "run", params: validateVaultRunInput(params) }); }
export function sshFrame(id, params) { return encodeFrame({ id: validateId(id), method: "sshRun", params: validateVaultSshInput(params) }); }
export function responseFrame(response) { return Buffer.concat(responseFrames(response)); }
