import type { VaultStatus } from "./client.ts";

export type VaultItemsAction = "status" | "list" | "search" | "inspect";
export type VaultItemsInput = {
	action: VaultItemsAction;
	query?: string;
	cursor?: string;
	itemHandle?: string;
	limit?: number;
};
export type DeliverySupport = { environment: boolean; stdin: boolean };
export type VaultMaterialDescriptor = {
	handle: string;
	category: string;
	type: string;
	label: string;
	delivery: DeliverySupport;
};
export type VaultAttachmentDescriptor = {
	handle: string;
	category: "attachment";
	type: "bytes";
	filename: string;
	mimeType: string;
	size: number;
	delivery: DeliverySupport;
};
export type VaultItemSummary = {
	handle: string;
	type: string;
	favorite: boolean;
	title: string;
	folderName: string | null;
	normalizedOrigins: string[];
	materialCount: number;
	attachmentCount: number;
};
export type VaultItemsResult =
	| { action: "status"; state: VaultStatus }
	| { action: "list" | "search"; state: "unlocked"; items: VaultItemSummary[]; nextCursor?: string }
	| { action: "inspect"; state: "unlocked"; itemHandle: string; type: string; materials: VaultMaterialDescriptor[]; attachments: VaultAttachmentDescriptor[] }
	| { action: VaultItemsAction; state: Exclude<VaultStatus, "unlocked"> };

export type VaultRunInput = {
	executable: string;
	argv: string[];
	cwd?: string;
	env?: Record<string, string>;
	materialEnv?: Record<string, string>;
	stdin?: string;
	timeoutMs?: number;
};
export type VaultRunResult = {
	mode: "text" | "bulk";
	exitCode: number | null;
	signal: string | null;
	durationMs: number;
	timedOut: boolean;
	cancelled: boolean;
	stdoutBytes: number;
	stderrBytes: number;
	stdout?: string;
	stderr?: string;
};

export type VaultSshRunInput = {
	host?: string;
	hostHandle?: string;
	username?: string;
	port?: number;
	privateKeyHandle: string;
	passphraseHandle?: string;
	command: string;
	stdinHandle?: string;
	timeoutMs?: number;
};

export type VaultSshRunResult = VaultRunResult;
