import { randomUUID } from "node:crypto";

export const MAX_PAGE_SIZE = 100;
export const MAX_SEARCH_LENGTH = 256;
export const MAX_HANDLE_LENGTH = 256;
export const MAX_CURSOR_LENGTH = 256;
export const MAX_ORIGINS = 100;
export const MAX_MATERIAL_DESCRIPTORS = 256;
export const MAX_ATTACHMENT_DESCRIPTORS = 64;

export const ITEM_TYPES = Object.freeze(["login", "secure-note", "card", "identity", "ssh-key", "unknown"]);

export class VaultContentError extends Error {
	constructor(code) { super(code); this.name = "VaultContentError"; this.code = code; }
}

const TYPE_NAMES = new Map([[1, "login"], [2, "secure-note"], [3, "card"], [4, "identity"], [5, "ssh-key"]]);
const FIELD_TYPES = new Map([[0, "text"], [1, "hidden"], [2, "boolean"], [3, "linked"]]);
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/gu;

function text(value, max = 512) {
	if (typeof value !== "string") return "";
	const normalized = value.replace(CONTROL_CHARACTERS, "�");
	if (Buffer.byteLength(normalized, "utf8") <= max) return normalized;
	let result = "";
	let bytes = 0;
	for (const character of normalized) {
		const characterBytes = Buffer.byteLength(character, "utf8");
		if (bytes + characterBytes > max) break;
		result += character;
		bytes += characterBytes;
	}
	return result;
}

function typeName(value) {
	if (typeof value === "number") return TYPE_NAMES.get(value) ?? "unknown";
	if (typeof value === "string") {
		const normalized = value.trim().toLowerCase();
		if (normalized === "securenote" || normalized === "secure_note") return "secure-note";
		if (normalized === "sshkey" || normalized === "ssh_key") return "ssh-key";
		return ITEM_TYPES.includes(normalized) ? normalized : "unknown";
	}
	return "unknown";
}

function delivery(environment, stdin) {
	return { environment, stdin };
}

function descriptor(handle, category, kind, label, supportsEnvironment = true, supportsStdin = true) {
	return {
		handle,
		category,
		type: kind,
		label: text(label, 256),
		delivery: delivery(supportsEnvironment, supportsStdin),
	};
}

function has(source, key) {
	return source !== null && typeof source === "object" && Object.prototype.hasOwnProperty.call(source, key);
}

function scalar(fields, source, key, category, kind, label, makeHandle) {
	if (!has(source, key)) return;
	const handle = makeHandle();
	fields.push({ descriptor: descriptor(handle, category, kind, label), handle, value: source[key] });
}

function customFields(fields, item, makeHandle) {
	if (!Array.isArray(item?.fields)) return;
	item.fields.forEach((field, index) => {
		if (!field || typeof field !== "object" || !has(field, "value")) return;
		const kind = FIELD_TYPES.get(field.type) ?? (typeof field.type === "string" ? text(field.type, 64) : "text");
		const label = typeof field.name === "string" && field.name.length > 0 ? field.name : `custom-${index + 1}`;
		const handle = makeHandle();
		fields.push({ descriptor: descriptor(handle, "custom-field", kind, label), handle, value: field.value });
	});
}

function loginUriFields(fields, login, makeHandle) {
	if (!Array.isArray(login?.uris)) return;
	login.uris.forEach((uri, index) => {
		scalar(fields, uri, "uri", "login", "uri", `URI ${index + 1}`, makeHandle);
	});
}

function passwordHistoryFields(fields, item, makeHandle) {
	if (!Array.isArray(item?.passwordHistory)) return;
	item.passwordHistory.forEach((history, index) => {
		// lastUsedDate is intentionally neither a descriptor label nor a value:
		// only the structurally secret password is selectable Vault Material.
		scalar(fields, history, "password", "password-history", "password", `password history ${index + 1}`, makeHandle);
	});
}

function passkeyFields(fields, item, makeHandle) {
	const roots = [
		["login.fido2Credentials", item?.login?.fido2Credentials], ["login.passkey", item?.login?.passkey],
		["login.passkeys", item?.login?.passkeys], ["login.fido2", item?.login?.fido2],
		["fido2Credentials", item?.fido2Credentials], ["passkey", item?.passkey], ["passkeys", item?.passkeys],
	];
	const seen = new Set();
	const visit = (value, path) => {
		if (value === undefined) return;
		if (value !== null && typeof value === "object") {
			if (seen.has(value)) return;
			seen.add(value);
			if (Array.isArray(value)) { value.forEach((entry, index) => visit(entry, `${path}[${index}]`)); return; }
			for (const [key, entry] of Object.entries(value)) visit(entry, `${path}.${key}`);
			return;
		}
		const handle = makeHandle();
		fields.push({ descriptor: descriptor(handle, "passkey", path.slice(path.lastIndexOf(".") + 1) || "field", path), handle, value });
	};
	for (const [path, value] of roots) visit(value, path);
}

function normalizeOrigin(value) {
	if (typeof value !== "string" || value.length === 0) return undefined;
	try {
		const parsed = new URL(value);
		if ((parsed.protocol !== "https:" && parsed.protocol !== "http:") || !parsed.hostname) return undefined;
		// URL.origin intentionally discards every path, query, and fragment, and
		// canonicalizes case/default ports at the Safe Metadata boundary.
		return parsed.origin.toLowerCase();
	} catch {
		return undefined;
	}
}

function origins(item) {
	const uris = item?.login?.uris;
	if (!Array.isArray(uris)) return [];
	const normalized = [...new Set(uris.map((entry) => normalizeOrigin(entry?.uri)).filter(Boolean))].sort();
	if (normalized.length > MAX_ORIGINS) throw new VaultContentError("invalid_item_data");
	return normalized;
}

function attachmentDescriptor(attachment, makeHandle, itemId) {
	if (!attachment || typeof attachment !== "object") return undefined;
	const handle = makeHandle();
	const sizeValue = typeof attachment.size === "string" && /^[0-9]+$/u.test(attachment.size.trim()) ? Number(attachment.size.trim()) : attachment.size;
	const size = Number.isSafeInteger(sizeValue) && sizeValue >= 0 ? sizeValue : 0;
	const filename = text(attachment.fileName ?? attachment.filename, 512);
	const extension = filename.toLowerCase().match(/\.([a-z0-9]+)$/u)?.[1];
	const mimeTypes = new Map([
		["txt", "text/plain"], ["log", "text/plain"], ["json", "application/json"], ["csv", "text/csv"],
		["pdf", "application/pdf"], ["png", "image/png"], ["jpg", "image/jpeg"], ["jpeg", "image/jpeg"],
		["gif", "image/gif"], ["webp", "image/webp"], ["yaml", "application/yaml"], ["yml", "application/yaml"],
	]);
	const mimeType = text(attachment.contentType ?? attachment.mimeType ?? (extension ? mimeTypes.get(extension) : undefined) ?? "application/octet-stream", 256);
	return {
		descriptor: {
			handle,
			category: "attachment",
			type: "bytes",
			filename,
			mimeType,
			size,
			delivery: delivery(false, true),
		},
		handle,
		value: attachment,
		itemId,
		attachmentId: typeof attachment.id === "string" ? attachment.id : undefined,
	};
}

/**
 * Derive Safe Metadata while retaining raw values only in the broker's private
 * in-memory record. The returned public members never contain a Bitwarden id
 * or any field value.
 */
export function deriveSafeRecord(item, folderNames = new Map(), makeHandle = () => `h_${randomUUID()}`) {
	if (!item || typeof item !== "object" || Array.isArray(item)) throw new VaultContentError("invalid_item_data");
	const itemHandle = makeHandle();
	const type = typeName(item.type);
	const fields = [];
	const login = item.login && typeof item.login === "object" ? item.login : {};
	const card = item.card && typeof item.card === "object" ? item.card : {};
	const identity = item.identity && typeof item.identity === "object" ? item.identity : {};
	const ssh = item.sshKey && typeof item.sshKey === "object" ? item.sshKey : {};

	if (type === "login") {
		scalar(fields, login, "username", "login", "username", "username", makeHandle);
		scalar(fields, login, "password", "login", "password", "password", makeHandle);
		scalar(fields, login, "totp", "login", "totp", "TOTP", makeHandle);
		loginUriFields(fields, login, makeHandle);
		scalar(fields, item, "notes", "login", "notes", "notes", makeHandle);
	} else if (type === "secure-note") {
		scalar(fields, item, "notes", "secure-note", "notes", "notes", makeHandle);
	} else if (type === "card") {
		for (const [key, label, kind] of [
			["cardholderName", "cardholder name", "text"], ["number", "card number", "number"],
			["expMonth", "expiration month", "number"], ["expYear", "expiration year", "number"],
			["code", "security code", "security-code"], ["brand", "brand", "text"],
		]) scalar(fields, card, key, "card", kind, label, makeHandle);
		scalar(fields, item, "notes", "card", "notes", "notes", makeHandle);
	} else if (type === "identity") {
		for (const [key, label] of [
			["title", "title"], ["firstName", "first name"], ["middleName", "middle name"], ["lastName", "last name"],
			["address1", "address 1"], ["address2", "address 2"], ["address3", "address 3"], ["city", "city"],
			["state", "state"], ["postalCode", "postal code"], ["country", "country"], ["company", "company"],
			["email", "email"], ["phone", "phone"], ["ssn", "SSN"], ["username", "username"],
			["passportNumber", "passport number"], ["licenseNumber", "license number"],
		]) scalar(fields, identity, key, "identity", "text", label, makeHandle);
		scalar(fields, item, "notes", "identity", "notes", "notes", makeHandle);
	} else if (type === "ssh-key") {
		scalar(fields, ssh, "privateKey", "ssh-key", "private-key", "private key", makeHandle);
		scalar(fields, ssh, "publicKey", "ssh-key", "public-key", "public key", makeHandle);
		scalar(fields, ssh, "keyFingerprint", "ssh-key", "fingerprint", "key fingerprint", makeHandle);
		scalar(fields, item, "notes", "ssh-key", "notes", "notes", makeHandle);
	}
	passwordHistoryFields(fields, item, makeHandle);
	passkeyFields(fields, item, makeHandle);
	customFields(fields, item, makeHandle);

	if (fields.length > MAX_MATERIAL_DESCRIPTORS) throw new VaultContentError("invalid_item_data");
	const itemId = typeof item.id === "string" ? item.id : undefined;
	const attachments = (Array.isArray(item.attachments) ? item.attachments : []).map((entry) => attachmentDescriptor(entry, makeHandle, itemId)).filter(Boolean);
	if (attachments.length > MAX_ATTACHMENT_DESCRIPTORS) throw new VaultContentError("invalid_item_data");
	const folderId = typeof item.folderId === "string" ? item.folderId : undefined;
	const folderName = folderId !== undefined ? text(folderNames.get(folderId), 512) || null : null;
	for (const field of fields) field.ownerItemHandle = itemHandle;
	for (const attachment of attachments) attachment.ownerItemHandle = itemHandle;
	const summary = {
		handle: itemHandle,
		type,
		favorite: item.favorite === true,
		title: text(item.name ?? item.title, 512),
		folderName,
		normalizedOrigins: origins(item),
		materialCount: fields.length,
		attachmentCount: attachments.length,
	};
	return { summary, itemHandle, itemId, fields, attachments };
}

export function publicInspection(record) {
	return {
		itemHandle: record.itemHandle,
		type: record.summary.type,
		materials: record.fields.map(({ descriptor }) => ({ ...descriptor })),
		attachments: record.attachments.map(({ descriptor }) => ({ ...descriptor })),
	};
}

export function validateItemsInput(input) {
	if (!input || typeof input !== "object" || Array.isArray(input)) throw new VaultContentError("invalid_input");
	const allowed = new Set(["action", "query", "cursor", "itemHandle", "limit"]);
	if (Object.keys(input).some((key) => !allowed.has(key))) throw new VaultContentError("invalid_input");
	if (!["status", "list", "search", "inspect"].includes(input.action)) throw new VaultContentError("invalid_action");
	if (input.limit !== undefined && (!Number.isSafeInteger(input.limit) || input.limit < 1 || input.limit > MAX_PAGE_SIZE)) throw new VaultContentError("invalid_input");
	for (const key of ["query", "cursor", "itemHandle"]) {
		if (input[key] !== undefined && (typeof input[key] !== "string" || input[key].length === 0 || /[\u0000-\u001f\u007f]/u.test(input[key]))) throw new VaultContentError("invalid_input");
	}
	if (typeof input.query === "string" && input.query.length > MAX_SEARCH_LENGTH) throw new VaultContentError("invalid_input");
	if (typeof input.cursor === "string" && input.cursor.length > MAX_CURSOR_LENGTH) throw new VaultContentError("invalid_input");
	if (typeof input.itemHandle === "string" && input.itemHandle.length > MAX_HANDLE_LENGTH) throw new VaultContentError("invalid_input");
	if (input.action === "search" && typeof input.query !== "string") throw new VaultContentError("invalid_input");
	if (input.action === "inspect" && typeof input.itemHandle !== "string") throw new VaultContentError("invalid_input");
	if (input.action === "status" && (input.query !== undefined || input.cursor !== undefined || input.itemHandle !== undefined || input.limit !== undefined)) throw new VaultContentError("invalid_input");
	if (input.action === "list" && (input.query !== undefined || input.itemHandle !== undefined)) throw new VaultContentError("invalid_input");
	if (input.action === "search" && input.itemHandle !== undefined) throw new VaultContentError("invalid_input");
	if (input.action === "inspect" && (input.query !== undefined || input.cursor !== undefined || input.limit !== undefined)) throw new VaultContentError("invalid_input");
	if (input.action === "search" && input.cursor !== undefined && typeof input.query !== "string") throw new VaultContentError("invalid_input");
	if (input.action === "status" && input.limit !== undefined) throw new VaultContentError("invalid_input");
	return {
		action: input.action,
		...(input.query === undefined ? {} : { query: input.query }),
		...(input.cursor === undefined ? {} : { cursor: input.cursor }),
		...(input.itemHandle === undefined ? {} : { itemHandle: input.itemHandle }),
		...(input.limit === undefined ? {} : { limit: input.limit }),
	};
}
