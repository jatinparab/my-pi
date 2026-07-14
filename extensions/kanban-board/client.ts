import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

export const STATUSES = ["TODO", "BLOCKED", "IN_PROGRESS", "IN_REVIEW", "DONE"] as const;
export type TaskStatus = (typeof STATUSES)[number];

export interface KanbanTask {
	id: number;
	title: string;
	status: TaskStatus;
	created_at: string;
	updated_at: string;
	body: string;
}

export interface KanbanBoard {
	id: string;
	name: string;
	identity_path: string;
	created_at: string;
}

export interface BoardSnapshot {
	board: KanbanBoard | null;
	attached?: boolean;
	counts?: Record<TaskStatus, number>;
	tasks?: KanbanTask[];
	message?: string;
}

type Envelope<T> = { ok: true; data: T } | { ok: false; error: { code: string; message: string } };

export class KanbanClient {
	constructor(private readonly pi: ExtensionAPI, private readonly cwd: string) {}

	private async run<T>(args: string[]): Promise<T> {
		const result = await this.pi.exec("kanban", [...args, "--json"], { cwd: this.cwd, timeout: 15_000 });
		let parsed: Envelope<T> | undefined;
		try {
			parsed = JSON.parse(result.stdout.trim()) as Envelope<T>;
		} catch {
			throw new Error(result.stderr.trim() || result.stdout.trim() || "kanban returned invalid JSON");
		}
		if (!parsed.ok) throw new Error(parsed.error.message);
		return parsed.data;
	}

	status(): Promise<BoardSnapshot> {
		return this.run<BoardSnapshot>(["status"]);
	}

	async createBoard(name: string): Promise<BoardSnapshot> {
		await this.run(["init", name]);
		return this.status();
	}

	async createTask(title: string, body: string, status: TaskStatus): Promise<KanbanTask> {
		const data = await this.run<{ task: KanbanTask }>(["task", "create", title, "--body", body]);
		if (status !== "TODO") await this.setStatus(data.task.id, status);
		return (await this.showTask(data.task.id));
	}

	async editTask(id: number, title: string, body: string, status: TaskStatus): Promise<KanbanTask> {
		const current = await this.showTask(id);
		if (current.title !== title || current.body !== body) {
			await this.run(["task", "--id", String(id), "edit", "--title", title, "--body", body]);
		}
		if (current.status !== status) await this.setStatus(id, status);
		return this.showTask(id);
	}

	async showTask(id: number): Promise<KanbanTask> {
		const data = await this.run<{ tasks: KanbanTask[] }>(["task", "--id", String(id), "show"]);
		const task = data.tasks[0];
		if (!task) throw new Error(`Task ${id} was not returned`);
		return task;
	}

	async setStatus(id: number, status: TaskStatus): Promise<void> {
		await this.run(["task", "--id", String(id), "status", status]);
	}

	async archive(): Promise<void> {
		await this.run(["archive", "--yes"]);
	}
}
