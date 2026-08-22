const OPERATIONS = new Set(["get", "list", "export", "serve", "login", "unlock"]);
const HELP = new Set(["help", "-h", "--help", "-v", "--version", "version"]);
const SEPARATORS = new Set([";", "|", "||", "&&", "&", "\n"]);
const BITWARDEN_PACKAGE = /^@bitwarden\/cli(?:@[^\s]+)?$/u;

// This is deliberately a small shell lexer, not a shell parser. It recognizes
// the command forms an agent commonly sends to Pi's bash-like tools without
// executing or normalizing the command. False negatives are part of the
// documented cooperative-agent boundary.
function words(command) {
	const result = [];
	let word = "";
	let quote = "";
	let escaped = false;
	const push = () => { if (word) { result.push(word); word = ""; } };
	for (let index = 0; index < command.length; index++) {
		const character = command[index];
		if (escaped) { word += character; escaped = false; continue; }
		if (character === "\\" && quote !== "'") { escaped = true; continue; }
		if (quote) {
			if (character === quote) quote = "";
			else word += character;
			continue;
		}
		if (character === "'" || character === '"') { quote = character; continue; }
		if (character === "\n" || character === ";" || character === "|" || character === "&") {
			push();
			const next = command[index + 1];
			if ((character === "|" || character === "&") && next === character) { result.push(character + next); index++; }
			else result.push(character);
			continue;
		}
		if (/\s/u.test(character)) { push(); continue; }
		if (character === "#" && !word) { while (index < command.length && command[index] !== "\n") index++; index--; continue; }
		word += character;
	}
	if (escaped) word += "\\";
	push();
	return result;
}

function isBitwardenCli(value) {
	if (typeof value !== "string") return false;
	const name = value.split("/").at(-1);
	return name === "bw" || name === "bitwarden" || name === "bitwarden-cli" || BITWARDEN_PACKAGE.test(value);
}

function skipSudoOptions(tokens, index) {
	while (index < tokens.length) {
		const token = tokens[index];
		if (token === "--") return index + 1;
		if (!token.startsWith("-")) return index;
		// These options consume a value; handling them prevents a username or
		// directory from being mistaken for the command after sudo.
		if (["-u", "--user", "-g", "--group", "-C", "--chdir", "-R"].includes(token)) index += 2;
		else index++;
	}
	return index;
}

function skipPackageWrapper(tokens, index, wrapper) {
	index++;
	if (wrapper === "npm" && tokens[index] === "exec") index++;
	if ((wrapper === "pnpm" || wrapper === "yarn") && ["exec", "dlx"].includes(tokens[index])) index++;
	while (index < tokens.length) {
		const token = tokens[index];
		if (token === "--") { index++; break; }
		if (isBitwardenCli(token)) return index;
		if (token === "-p" || token === "--package") { index += 2; continue; }
		if (token.startsWith("--package=")) { index++; continue; }
		if (token.startsWith("-") || token === "--yes" || token === "--quiet") { index++; continue; }
		// A non-package positional argument means this is not a Bitwarden CLI
		// wrapper (for example `npm install @bitwarden/cli`).
		return -1;
	}
	return isBitwardenCli(tokens[index]) ? index : -1;
}

function findCli(tokens) {
	let index = 0;
	while (index < tokens.length) {
		const token = tokens[index];
		if (token === "env") {
			index++;
			while (index < tokens.length && (/^[A-Za-z_][A-Za-z0-9_]*=/u.test(tokens[index]) || tokens[index].startsWith("-"))) index++;
			continue;
		}
		if (token === "sudo") { index = skipSudoOptions(tokens, index + 1); continue; }
		if (token === "command" || token === "exec") { index++; continue; }
		if (token === "--") { index++; continue; }
		if (/^[A-Za-z_][A-Za-z0-9_]*=/u.test(token)) { index++; continue; }
		if (["npx", "npm", "pnpm", "yarn"].includes(token)) return skipPackageWrapper(tokens, index, token);
		return isBitwardenCli(token) ? index : -1;
	}
	return -1;
}

function segment(tokens) {
	const cliIndex = findCli(tokens);
	if (cliIndex < 0) return false;
	const args = tokens.slice(cliIndex + 1);
	if (args.some((arg) => HELP.has(arg))) return false;
	return args.some((arg) => OPERATIONS.has(arg));
}

export function isAgentBitwardenCommandBlocked(command) {
	if (typeof command !== "string" || command.length === 0) return false;
	const tokens = words(command);
	let current = [];
	for (const token of [...tokens, ";"]) {
		if (SEPARATORS.has(token)) {
			if (segment(current)) return true;
			current = [];
		} else current.push(token);
	}
	return false;
}

export function bitwardenGuardReason(command) {
	return isAgentBitwardenCommandBlocked(command)
		? "Direct agent Bitwarden CLI access is blocked; use vault_items or vault_run. Help/version remains allowed."
		: undefined;
}
