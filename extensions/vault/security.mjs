export const US_SERVER = "https://vault.bitwarden.com";
export const EU_SERVER = "https://vault.bitwarden.eu";
export const MAX_SERVER_LENGTH = 512;
export const MAX_EMAIL_LENGTH = 320;
export const MAX_PASSWORD_LENGTH = 1024;

export class ValidationError extends Error {
	constructor(code) {
		super(code);
		this.name = "ValidationError";
		this.code = code;
	}
}

function reject(code) {
	throw new ValidationError(code);
}

export function normalizeServer(value) {
	if (typeof value !== "string" || value.length === 0 || value.length > MAX_SERVER_LENGTH || /[\u0000-\u001f\u007f]/u.test(value)) {
		reject("invalid_server");
	}
	const text = value.trim();
	let parsed;
	try { parsed = new URL(text); } catch { reject("invalid_server"); }
	if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.search || parsed.hash || parsed.pathname !== "/") {
		reject("invalid_server");
	}
	const hostname = parsed.hostname.toLowerCase();
	if (!hostname || hostname === "localhost" || hostname.endsWith(".localhost") || hostname.includes("..")) {
		reject("invalid_server");
	}
	// URL validates ports, but reject an explicitly empty/invalid host form and
	// make the returned value deterministic for both cloud and self-hosted use.
	const host = parsed.host.toLowerCase();
	if (!host || host.length > MAX_SERVER_LENGTH || /[\u0000-\u001f\u007f]/u.test(host)) reject("invalid_server");
	return { url: `https://${host}`, host };
}

export function normalizeEmail(value) {
	if (typeof value !== "string" || value.length > MAX_EMAIL_LENGTH || /[\u0000-\u001f\u007f]/u.test(value)) {
		reject("invalid_email");
	}
	const email = value.trim().toLowerCase();
	const at = email.lastIndexOf("@");
	const local = at > 0 ? email.slice(0, at) : "";
	const domain = at > 0 ? email.slice(at + 1) : "";
	if (!local || !domain || local.length > 64 || local.startsWith(".") || local.endsWith(".") || local.includes("..") || domain.includes("..")) {
		reject("invalid_email");
	}
	if (!/^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+$/u.test(local) || !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/u.test(domain)) {
		reject("invalid_email");
	}
	return email;
}

export function validateMasterPassword(value) {
	if (typeof value !== "string" || value.length < 8 || value.length > MAX_PASSWORD_LENGTH || /[\u0000-\u001f\u007f]/u.test(value)) {
		reject("invalid_password");
	}
	return value;
}

export function normalizeSetup({ server, email, masterPassword } = {}) {
	const normalized = normalizeServer(server);
	return { ...normalized, email: normalizeEmail(email), masterPassword: validateMasterPassword(masterPassword) };
}

export function errorCode(error) {
	return error && typeof error.code === "string" ? error.code : "internal_error";
}
