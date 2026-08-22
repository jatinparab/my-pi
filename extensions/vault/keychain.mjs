export const KEYCHAIN_SERVICE = "pi.vault-broker";
export const KEYCHAIN_ACCOUNT = "bitwarden-master-password";

export function isMissingCredentialError(error) {
	const text = `${error?.name ?? ""} ${error?.code ?? ""} ${error?.message ?? ""}`.toLowerCase();
	return /noentry|no entry|not found|not_found|credential.*does not exist/u.test(text);
}

export function createKeychainAdapter({ Entry } = {}) {
	let EntryClass = Entry;
	const getEntry = async () => {
		if (!EntryClass) ({ Entry: EntryClass } = await import("@napi-rs/keyring"));
		return new EntryClass(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT);
	};
	return {
		async get() {
			try {
				const value = await (await getEntry()).getPassword();
				return typeof value === "string" && value.length > 0 ? value : undefined;
			} catch (error) {
				if (isMissingCredentialError(error)) return undefined;
				throw error;
			}
		},
		async set(password) {
			await (await getEntry()).setPassword(password);
		},
		async delete() {
			try {
				await (await getEntry()).deletePassword();
			} catch (error) {
				if (!isMissingCredentialError(error)) throw error;
			}
		},
	};
}

export const defaultKeychain = createKeychainAdapter();
