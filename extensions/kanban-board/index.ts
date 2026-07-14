import type { ExtensionAPI, ExtensionContext, Theme } from "@earendil-works/pi-coding-agent";
import {
	Editor,
	type EditorTheme,
	type Focusable,
	Input,
	Key,
	matchesKey,
	truncateToWidth,
	visibleWidth,
} from "@earendil-works/pi-tui";
import { BoardSnapshot, KanbanClient, type KanbanTask, STATUSES, type TaskStatus } from "./client.ts";

const STATUS_META: Record<TaskStatus, { label: string; color: "muted" | "warning" | "accent" | "success" | "error"; mark: string }> = {
	TODO: { label: "TODO", color: "muted", mark: "○" },
	BLOCKED: { label: "BLOCKED", color: "error", mark: "◆" },
	IN_PROGRESS: { label: "IN PROGRESS", color: "warning", mark: "◒" },
	IN_REVIEW: { label: "IN REVIEW", color: "accent", mark: "◇" },
	DONE: { label: "DONE", color: "success", mark: "●" },
};

type View = "board" | "detail" | "init" | "discard" | "archive";
type FormFocus = 0 | 1 | 2 | 3 | 4;

function pad(text: string, width: number): string {
	return truncateToWidth(text, width, "") + " ".repeat(Math.max(0, width - visibleWidth(truncateToWidth(text, width, ""))));
}

function boxLine(theme: Theme, content: string, width: number, selected = false): string {
	const inner = Math.max(1, width - 2);
	const body = pad(` ${content}`, inner);
	const line = `${theme.fg(selected ? "borderAccent" : "borderMuted", "│")}${body}${theme.fg(selected ? "borderAccent" : "borderMuted", "│")}`;
	return selected ? theme.bg("selectedBg", line) : line;
}

function border(theme: Theme, width: number, top: boolean, selected = false): string {
	const color = selected ? "borderAccent" : "borderMuted";
	return theme.fg(color, `${top ? "╭" : "╰"}${"─".repeat(Math.max(0, width - 2))}${top ? "╮" : "╯"}`);
}

function age(iso: string): string {
	const seconds = Math.max(0, Math.floor((Date.now() - Date.parse(iso)) / 1000));
	if (seconds < 60) return "now";
	if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
	if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
	return `${Math.floor(seconds / 86400)}d`;
}

class KanbanOverlay implements Focusable {
	focused = false;
	private view: View;
	private previousView: View = "board";
	private lane = 0;
	private selectedByLane = new Map<number, number>();
	private scrollByLane = new Map<number, number>();
	private moveTarget: number | null = null;
	private busy = false;
	private error = "";
	private confirmChoice = 0;
	private formFocus: FormFocus = 0;
	private editingTask: KanbanTask | null = null;
	private createStatus: TaskStatus = "TODO";
	private original = { title: "", body: "", status: "TODO" as TaskStatus };
	private titleInput = new Input();
	private boardNameInput = new Input();
	private bodyEditor: Editor;

	constructor(
		private readonly tui: { requestRender(): void },
		private readonly theme: Theme,
		private readonly client: KanbanClient,
		private snapshot: BoardSnapshot,
		private readonly done: () => void,
		private readonly onChanged: (snapshot: BoardSnapshot) => void,
	) {
		this.view = snapshot.board ? "board" : "init";
		const editorTheme: EditorTheme = {
			borderColor: (text) => theme.fg(this.formFocus === 1 ? "accent" : "borderMuted", text),
			selectList: {
				selectedPrefix: (text) => theme.fg("accent", text),
				selectedText: (text) => theme.fg("accent", text),
				description: (text) => theme.fg("muted", text),
				scrollInfo: (text) => theme.fg("dim", text),
				noMatch: (text) => theme.fg("warning", text),
			},
		};
		this.bodyEditor = new Editor(tui as never, editorTheme, { paddingX: 1 });
		this.bodyEditor.disableSubmit = true;
		this.bodyEditor.onChange = () => this.refresh();
	}

	private refresh(): void {
		this.tui.requestRender();
	}

	private tasks(status: TaskStatus): KanbanTask[] {
		return (this.snapshot.tasks ?? []).filter((task) => task.status === status);
	}

	private selectedTask(): KanbanTask | undefined {
		const tasks = this.tasks(STATUSES[this.lane]!);
		return tasks[this.selectedByLane.get(this.lane) ?? 0];
	}

	private select(delta: number): void {
		const tasks = this.tasks(STATUSES[this.lane]!);
		if (!tasks.length) return;
		const next = Math.max(0, Math.min(tasks.length - 1, (this.selectedByLane.get(this.lane) ?? 0) + delta));
		this.selectedByLane.set(this.lane, next);
		const offset = this.scrollByLane.get(this.lane) ?? 0;
		if (next < offset) this.scrollByLane.set(this.lane, next);
		if (next >= offset + 4) this.scrollByLane.set(this.lane, next - 3);
	}

	private openTask(task: KanbanTask): void {
		this.editingTask = task;
		this.createStatus = task.status;
		this.original = { title: task.title, body: task.body, status: task.status };
		this.titleInput.setValue(task.title);
		this.bodyEditor.setText(task.body);
		this.formFocus = 0;
		this.view = "detail";
		this.updateFocus();
	}

	private openCreate(status: TaskStatus): void {
		this.editingTask = null;
		this.createStatus = status;
		this.original = { title: "", body: "", status };
		this.titleInput.setValue("");
		this.bodyEditor.setText("");
		this.formFocus = 0;
		this.view = "detail";
		this.updateFocus();
	}

	private currentStatus(): TaskStatus {
		return this.createStatus;
	}

	private isDirty(): boolean {
		return this.titleInput.getValue() !== this.original.title ||
			this.bodyEditor.getExpandedText() !== this.original.body ||
			this.currentStatus() !== this.original.status;
	}

	private updateFocus(): void {
		this.titleInput.focused = this.focused && this.view === "detail" && this.formFocus === 0;
		this.bodyEditor.focused = this.focused && this.view === "detail" && this.formFocus === 1;
		this.boardNameInput.focused = this.focused && this.view === "init";
	}

	private goBack(): void {
		if (this.view === "detail" && this.isDirty()) {
			this.previousView = "detail";
			this.confirmChoice = 0;
			this.view = "discard";
		} else if (this.view === "detail") {
			this.view = "board";
		} else {
			this.done();
		}
		this.updateFocus();
		this.refresh();
	}

	private async reload(): Promise<void> {
		this.busy = true;
		this.error = "";
		this.refresh();
		try {
			this.snapshot = await this.client.status();
			this.onChanged(this.snapshot);
		} catch (error) {
			this.error = error instanceof Error ? error.message : String(error);
		} finally {
			this.busy = false;
			this.refresh();
		}
	}

	private async save(): Promise<void> {
		const title = this.titleInput.getValue().trim();
		if (!title) {
			this.error = "A concise task title is required.";
			this.formFocus = 0;
			this.updateFocus();
			this.refresh();
			return;
		}
		this.busy = true;
		this.error = "";
		this.refresh();
		try {
			const body = this.bodyEditor.getExpandedText();
			if (this.editingTask) await this.client.editTask(this.editingTask.id, title, body, this.currentStatus());
			else await this.client.createTask(title, body, this.currentStatus());
			await this.reload();
			this.view = "board";
			this.editingTask = null;
		} catch (error) {
			this.error = error instanceof Error ? error.message : String(error);
		} finally {
			this.busy = false;
			this.updateFocus();
			this.refresh();
		}
	}

	private async commitMove(): Promise<void> {
		const task = this.selectedTask();
		if (!task || this.moveTarget == null) return;
		this.busy = true;
		this.refresh();
		try {
			await this.client.setStatus(task.id, STATUSES[this.moveTarget]!);
			this.lane = this.moveTarget;
			this.moveTarget = null;
			await this.reload();
		} catch (error) {
			this.error = error instanceof Error ? error.message : String(error);
			this.moveTarget = null;
			this.busy = false;
			this.refresh();
		}
	}

	private async initialize(): Promise<void> {
		const name = this.boardNameInput.getValue().trim();
		if (!name) {
			this.error = "Give the board a memorable name.";
			this.refresh();
			return;
		}
		this.busy = true;
		this.error = "";
		this.refresh();
		try {
			this.snapshot = await this.client.createBoard(name);
			this.onChanged(this.snapshot);
			this.view = "board";
		} catch (error) {
			this.error = error instanceof Error ? error.message : String(error);
		} finally {
			this.busy = false;
			this.updateFocus();
			this.refresh();
		}
	}

	private async archive(): Promise<void> {
		this.busy = true;
		this.error = "";
		this.refresh();
		try {
			await this.client.archive();
			this.snapshot = await this.client.status();
			this.onChanged(this.snapshot);
			this.boardNameInput.setValue("");
			this.view = "init";
		} catch (error) {
			this.error = error instanceof Error ? error.message : String(error);
		} finally {
			this.busy = false;
			this.updateFocus();
			this.refresh();
		}
	}

	handleInput(data: string): void {
		if (this.busy) return;
		if (this.view === "init") {
			if (matchesKey(data, Key.escape)) return this.done();
			if (matchesKey(data, Key.enter)) void this.initialize();
			else this.boardNameInput.handleInput(data);
			this.refresh();
			return;
		}
		if (this.view === "discard") {
			if (matchesKey(data, Key.left) || matchesKey(data, Key.right) || matchesKey(data, Key.tab)) this.confirmChoice = 1 - this.confirmChoice;
			else if (matchesKey(data, Key.escape)) this.view = this.previousView;
			else if (matchesKey(data, Key.enter)) {
				if (this.confirmChoice === 0) void this.save();
				else this.view = "board";
			}
			this.updateFocus(); this.refresh(); return;
		}
		if (this.view === "archive") {
			if (matchesKey(data, Key.left) || matchesKey(data, Key.right) || matchesKey(data, Key.tab)) this.confirmChoice = 1 - this.confirmChoice;
			else if (matchesKey(data, Key.escape)) this.view = "board";
			else if (matchesKey(data, Key.enter)) {
				if (this.confirmChoice === 0) void this.archive();
				else this.view = "board";
			}
			this.refresh(); return;
		}
		if (this.view === "detail") {
			if (matchesKey(data, Key.ctrl("s"))) { void this.save(); return; }
			if (matchesKey(data, Key.escape)) { this.goBack(); return; }
			if (matchesKey(data, Key.tab)) {
				this.formFocus = ((this.formFocus + 1) % 5) as FormFocus;
				this.updateFocus(); this.refresh(); return;
			}
			if (matchesKey(data, Key.shift("tab"))) {
				this.formFocus = ((this.formFocus + 4) % 5) as FormFocus;
				this.updateFocus(); this.refresh(); return;
			}
			if (this.formFocus === 0) this.titleInput.handleInput(data);
			else if (this.formFocus === 1) this.bodyEditor.handleInput(data);
			else if (this.formFocus === 2 && (matchesKey(data, Key.left) || matchesKey(data, Key.up))) this.createStatus = STATUSES[(STATUSES.indexOf(this.createStatus) + 4) % 5]!;
			else if (this.formFocus === 2 && (matchesKey(data, Key.right) || matchesKey(data, Key.down))) this.createStatus = STATUSES[(STATUSES.indexOf(this.createStatus) + 1) % 5]!;
			else if (matchesKey(data, Key.enter) && this.formFocus === 3) void this.save();
			else if (matchesKey(data, Key.enter) && this.formFocus === 4) this.goBack();
			this.refresh(); return;
		}

		if (matchesKey(data, Key.escape)) { this.done(); return; }
		if (data === "r" || data === "R") { void this.reload(); return; }
		if (data === "a" || data === "A") { this.view = "archive"; this.confirmChoice = 1; this.refresh(); return; }
		if (this.moveTarget != null) {
			if (matchesKey(data, Key.left)) this.moveTarget = Math.max(0, this.moveTarget - 1);
			else if (matchesKey(data, Key.right)) this.moveTarget = Math.min(4, this.moveTarget + 1);
			else if (matchesKey(data, Key.enter)) void this.commitMove();
			else if (matchesKey(data, Key.escape) || data === "m") this.moveTarget = null;
			this.refresh(); return;
		}
		if (matchesKey(data, Key.left)) this.lane = Math.max(0, this.lane - 1);
		else if (matchesKey(data, Key.right)) this.lane = Math.min(4, this.lane + 1);
		else if (matchesKey(data, Key.up)) this.select(-1);
		else if (matchesKey(data, Key.down)) this.select(1);
		else if (matchesKey(data, Key.enter)) { const task = this.selectedTask(); if (task) this.openTask(task); }
		else if (data === "+" || data === "n" || data === "N") this.openCreate(STATUSES[this.lane]!);
		else if ((data === "m" || data === "M") && this.selectedTask()) this.moveTarget = this.lane;
		this.updateFocus(); this.refresh();
	}

	private renderHeader(width: number): string[] {
		const name = this.snapshot.board?.name ?? "KANBAN";
		const active = (this.snapshot.counts?.IN_PROGRESS ?? 0) + (this.snapshot.counts?.IN_REVIEW ?? 0);
		const title = `${this.theme.fg("accent", this.theme.bold("◆ KANBAN"))}  ${this.theme.fg("text", name)}`;
		const pulse = active ? this.theme.fg("warning", `◒ ${active} active`) : this.theme.fg("success", "● clear");
		const right = `${pulse}  ${this.theme.fg("dim", "R refresh  A archive  Esc close")}`;
		return [border(this.theme, width, true, true), boxLine(this.theme, `${title}${" ".repeat(Math.max(1, width - 4 - visibleWidth(title) - visibleWidth(right)))}${right}`, width, true)];
	}

	private renderBoard(width: number): string[] {
		const lines = this.renderHeader(width);
		const total = this.snapshot.tasks?.length ?? 0;
		const active = (this.snapshot.counts?.IN_PROGRESS ?? 0) + (this.snapshot.counts?.IN_REVIEW ?? 0);
		lines.push(boxLine(this.theme, `${this.theme.fg("muted", "ALL WORK")}  ${this.theme.fg("text", `${total} issues`)}  ${this.theme.fg("dim", "·")}  ${this.theme.fg(active ? "warning" : "success", active ? `${active} moving` : "inbox clear")}`, width));
		lines.push(boxLine(this.theme, "", width));

		const inner = Math.max(20, width - 2);
		const gap = 2;
		const columnWidth = Math.max(16, Math.floor((inner - gap * 4) / 5));
		const laneHeight = 30;
		const laneBlocks: string[][] = [];

		for (let lane = 0; lane < 5; lane++) {
			const status = STATUSES[lane]!;
			const meta = STATUS_META[status];
			const tasks = this.tasks(status);
			const selectedLane = lane === this.lane;
			const movingHere = lane === this.moveTarget;
			const laneSelected = selectedLane || movingHere;
			const laneColor = laneSelected ? "borderAccent" : "borderMuted";
			const laneInner = Math.max(8, columnWidth - 2);
			const cardWidth = Math.max(8, laneInner - 2);
			const laneRow = (content: string, selected = false) => {
				const row = `${this.theme.fg(laneColor, "│")}${pad(content, laneInner)}${this.theme.fg(laneColor, "│")}`;
				return selected ? this.theme.bg("selectedBg", row) : row;
			};
			const divider = this.theme.fg(laneColor, `├${"─".repeat(laneInner)}┤`);
			const block: string[] = [
				this.theme.fg(laneColor, `╭${"─".repeat(laneInner)}╮`),
			];
			const heading = `${this.theme.fg(meta.color, meta.mark)} ${this.theme.fg(selectedLane ? "accent" : "text", this.theme.bold(meta.label))}`;
			const badge = this.theme.bg("selectedBg", this.theme.fg(meta.color, ` ${tasks.length} `));
			const add = this.theme.fg(selectedLane ? "accent" : "muted", "＋");
			block.push(laneRow(` ${heading}${" ".repeat(Math.max(1, laneInner - 4 - visibleWidth(heading) - visibleWidth(badge)))}${badge} ${add}`, selectedLane));
			block.push(divider);
			block.push(laneRow(""));

			const offset = this.scrollByLane.get(lane) ?? 0;
			const shown = tasks.slice(offset, offset + 4);
			if (!shown.length) {
				const emptyBorder = this.theme.fg("borderMuted", `╭${"┄".repeat(Math.max(0, cardWidth - 2))}╮`);
				block.push(laneRow(` ${emptyBorder}`));
				block.push(laneRow(` ${this.theme.fg("borderMuted", "│")}${pad(this.theme.fg("dim", "  No issues here"), cardWidth - 2)}${this.theme.fg("borderMuted", "│")}`));
				block.push(laneRow(` ${this.theme.fg("borderMuted", "│")}${pad(this.theme.fg("muted", "  Press + to create"), cardWidth - 2)}${this.theme.fg("borderMuted", "│")}`));
				block.push(laneRow(` ${this.theme.fg("borderMuted", `╰${"┄".repeat(Math.max(0, cardWidth - 2))}╯`)}`));
				block.push(laneRow(""));
			} else {
				for (let index = 0; index < shown.length; index++) {
					const task = shown[index]!;
					const actualIndex = offset + index;
					const selected = selectedLane && actualIndex === (this.selectedByLane.get(lane) ?? 0);
					const cardColor = selected ? "borderAccent" : "borderMuted";
					const cardRow = (content: string) => {
						const row = `${this.theme.fg(cardColor, "│")}${pad(` ${content}`, cardWidth - 2)}${this.theme.fg(cardColor, "│")}`;
						return selected ? this.theme.bg("selectedBg", row) : row;
					};
					const cardTop = this.theme.fg(cardColor, `╭${"─".repeat(Math.max(0, cardWidth - 2))}╮`);
					const cardBottom = this.theme.fg(cardColor, `╰${"─".repeat(Math.max(0, cardWidth - 2))}╯`);
					const key = `${selected ? this.theme.fg("accent", "▸") : this.theme.fg(meta.color, "▪")} ${this.theme.fg("muted", `KB-${task.id}`)}`;
					const elapsed = this.theme.fg("dim", age(task.updated_at));
					const title = truncateToWidth(task.title, Math.max(3, cardWidth - 5));
					const description = truncateToWidth(task.body.replace(/\s+/g, " ").trim() || "No description", Math.max(3, cardWidth - 5));
					block.push(laneRow(` ${selected ? this.theme.bg("selectedBg", cardTop) : cardTop}`));
					block.push(laneRow(` ${cardRow(`${key}${" ".repeat(Math.max(1, cardWidth - 4 - visibleWidth(key) - visibleWidth(elapsed)))}${elapsed}`)}`));
					block.push(laneRow(` ${cardRow(this.theme.fg("text", this.theme.bold(title)))}`));
					block.push(laneRow(` ${cardRow(this.theme.fg("muted", description))}`));
					block.push(laneRow(` ${selected ? this.theme.bg("selectedBg", cardBottom) : cardBottom}`));
					block.push(laneRow(""));
				}
			}

			if (tasks.length > offset + 4) block.push(laneRow(`  ${this.theme.fg("accent", `↓ ${tasks.length - offset - 4} more issues`)}`));
			while (block.length < laneHeight - 1) block.push(laneRow(""));
			block.push(this.theme.fg(laneColor, `╰${"─".repeat(laneInner)}╯`));
			laneBlocks.push(block);
		}

		const maxHeight = Math.max(...laneBlocks.map((block) => block.length));
		for (let row = 0; row < maxHeight; row++) {
			lines.push(" " + laneBlocks.map((block) => block[row] ?? " ".repeat(columnWidth)).join("  "));
		}
		lines.push(boxLine(this.theme, "", width));
		const help = this.moveTarget == null
			? "←→ lanes   ↑↓ issues   Enter open   + create   M move   R refresh   A archive"
			: `MOVE ISSUE  ←→ choose destination   Enter move to ${STATUS_META[STATUSES[this.moveTarget]!].label}   Esc cancel`;
		lines.push(boxLine(this.theme, this.theme.fg(this.moveTarget == null ? "dim" : "warning", help), width));
		if (this.error) lines.push(boxLine(this.theme, this.theme.fg("error", this.error), width));
		if (this.busy) lines.push(boxLine(this.theme, this.theme.fg("warning", "◒ Syncing with kanban CLI…"), width));
		lines.push(border(this.theme, width, false, true));
		return lines;
	}

	private renderDetail(width: number): string[] {
		const lines = this.renderHeader(width);
		const inner = Math.max(1, width - 4);
		const title = this.editingTask ? `EDIT TASK #${this.editingTask.id}` : `CREATE IN ${STATUS_META[this.createStatus].label}`;
		lines.push(boxLine(this.theme, this.theme.fg("accent", this.theme.bold(`← BOARD  /  ${title}`)), width));
		lines.push(boxLine(this.theme, "", width));
		lines.push(boxLine(this.theme, `${this.formFocus === 0 ? this.theme.fg("accent", "◆") : this.theme.fg("dim", "◇")}  TITLE`, width));
		if (!this.titleInput.getValue()) lines.push(boxLine(this.theme, this.theme.fg("dim", "   A concise, outcome-oriented title…"), width));
		for (const line of this.titleInput.render(inner - 2)) lines.push(boxLine(this.theme, `  ${line}`, width, this.formFocus === 0));
		lines.push(boxLine(this.theme, "", width));
		lines.push(boxLine(this.theme, `${this.formFocus === 1 ? this.theme.fg("accent", "◆") : this.theme.fg("dim", "◇")}  DESCRIPTION`, width));
		if (!this.bodyEditor.getText()) lines.push(boxLine(this.theme, this.theme.fg("dim", "   Scope, context, and how completion will be verified…"), width));
		for (const line of this.bodyEditor.render(inner - 2).slice(0, 8)) lines.push(boxLine(this.theme, `  ${line}`, width, this.formFocus === 1));
		lines.push(boxLine(this.theme, "", width));
		const statuses = STATUSES.map((status) => {
			const meta = STATUS_META[status];
			const active = status === this.currentStatus();
			return active ? this.theme.bg("selectedBg", this.theme.fg(meta.color, ` ${meta.mark} ${meta.label} `)) : this.theme.fg("dim", ` ${meta.mark} ${meta.label} `);
		}).join(" ");
		lines.push(boxLine(this.theme, `${this.formFocus === 2 ? this.theme.fg("accent", "◆") : this.theme.fg("dim", "◇")}  STATUS  ${statuses}`, width, this.formFocus === 2));
		lines.push(boxLine(this.theme, "", width));
		const save = this.formFocus === 3 ? this.theme.bg("selectedBg", this.theme.fg("success", `  ${this.editingTask ? "SAVE" : "CREATE"}  `)) : this.theme.fg("success", `  ${this.editingTask ? "SAVE" : "CREATE"}  `);
		const back = this.formFocus === 4 ? this.theme.bg("selectedBg", this.theme.fg("muted", "  BACK  ")) : this.theme.fg("muted", "  BACK  ");
		lines.push(boxLine(this.theme, `${save}   ${back}`, width));
		if (this.error) lines.push(boxLine(this.theme, this.theme.fg("error", this.error), width));
		if (this.busy) lines.push(boxLine(this.theme, this.theme.fg("warning", "◒ Saving through kanban CLI…"), width));
		lines.push(boxLine(this.theme, this.theme.fg("dim", "Tab fields  Shift+Tab back  Ctrl+S save  Esc board  Shift+Enter newline"), width));
		lines.push(border(this.theme, width, false, true));
		return lines;
	}

	private renderInit(width: number): string[] {
		const lines = [border(this.theme, width, true, true)];
		lines.push(boxLine(this.theme, this.theme.fg("accent", this.theme.bold("◆ KANBAN  /  NEW BOARD")), width, true));
		lines.push(boxLine(this.theme, "", width));
		lines.push(boxLine(this.theme, this.theme.fg("text", "No board is initialized for this repository."), width));
		lines.push(boxLine(this.theme, this.theme.fg("muted", "Create a local Markdown board attached to this worktree."), width));
		lines.push(boxLine(this.theme, "", width));
		lines.push(boxLine(this.theme, this.theme.fg("dim", "BOARD NAME"), width));
		if (!this.boardNameInput.getValue()) lines.push(boxLine(this.theme, this.theme.fg("dim", "  e.g. Product launch"), width));
		for (const line of this.boardNameInput.render(Math.max(10, width - 6))) lines.push(boxLine(this.theme, `  ${line}`, width, true));
		lines.push(boxLine(this.theme, "", width));
		lines.push(boxLine(this.theme, this.theme.fg("success", "  CREATE BOARD  "), width));
		if (this.error) lines.push(boxLine(this.theme, this.theme.fg("error", this.error), width));
		if (this.busy) lines.push(boxLine(this.theme, this.theme.fg("warning", "◒ Initializing…"), width));
		lines.push(boxLine(this.theme, this.theme.fg("dim", "Enter create  Esc close"), width));
		lines.push(border(this.theme, width, false, true));
		return lines;
	}

	private renderConfirm(width: number, archive: boolean): string[] {
		const lines = [border(this.theme, width, true, true)];
		lines.push(boxLine(this.theme, this.theme.fg(archive ? "error" : "warning", this.theme.bold(archive ? "ARCHIVE BOARD?" : "UNSAVED CHANGES")), width, true));
		lines.push(boxLine(this.theme, "", width));
		lines.push(boxLine(this.theme, archive ? "The board will be detached and moved to canonical archive storage." : "You changed this ticket. Save before returning to the board?", width));
		lines.push(boxLine(this.theme, "", width));
		const yesLabel = archive ? "ARCHIVE" : "SAVE";
		const noLabel = archive ? "CANCEL" : "DISCARD";
		const yes = this.confirmChoice === 0 ? this.theme.bg("selectedBg", this.theme.fg(archive ? "error" : "success", `  ${yesLabel}  `)) : this.theme.fg(archive ? "error" : "success", `  ${yesLabel}  `);
		const no = this.confirmChoice === 1 ? this.theme.bg("selectedBg", this.theme.fg("muted", `  ${noLabel}  `)) : this.theme.fg("muted", `  ${noLabel}  `);
		lines.push(boxLine(this.theme, `${yes}   ${no}`, width));
		lines.push(boxLine(this.theme, this.theme.fg("dim", "←→ choose  Enter confirm  Esc back"), width));
		lines.push(border(this.theme, width, false, true));
		return lines;
	}

	render(width: number): string[] {
		this.updateFocus();
		if (this.view === "init") return this.renderInit(width);
		if (this.view === "detail") return this.renderDetail(width);
		if (this.view === "discard") return this.renderConfirm(width, false);
		if (this.view === "archive") return this.renderConfirm(width, true);
		return this.renderBoard(width);
	}

	invalidate(): void {
		this.titleInput.invalidate();
		this.bodyEditor.invalidate();
		this.boardNameInput.invalidate();
	}
}

export default function kanbanBoardExtension(pi: ExtensionAPI) {
	let snapshot: BoardSnapshot = { board: null };
	let pollTimer: ReturnType<typeof setInterval> | undefined;
	let widgetRender: (() => void) | undefined;
	let currentClient: KanbanClient | undefined;
	let overlayOpen = false;
	let overlayHandle: { focus(): void } | undefined;

	const updateSnapshot = (next: BoardSnapshot) => {
		snapshot = next;
		widgetRender?.();
	};

	const poll = async () => {
		if (!currentClient || overlayOpen) return;
		try { updateSnapshot(await currentClient.status()); } catch { /* topbar stays quiet when CLI is unavailable */ }
	};

	const open = async (ctx: ExtensionContext) => {
		if (ctx.mode !== "tui") return;
		if (overlayOpen) { overlayHandle?.focus(); return; }
		currentClient = new KanbanClient(pi, ctx.cwd);
		try { updateSnapshot(await currentClient.status()); }
		catch (error) { ctx.ui.notify(error instanceof Error ? error.message : String(error), "error"); return; }
		overlayOpen = true;
		try {
			await ctx.ui.custom<void>((tui, theme, _keys, done) => new KanbanOverlay(
				tui,
				theme,
				currentClient!,
				snapshot,
				() => done(undefined),
				updateSnapshot,
			), {
				overlay: true,
				overlayOptions: { width: "96%", minWidth: 88, maxHeight: "92%", anchor: "center", margin: 1 },
				onHandle: (handle) => { overlayHandle = handle; },
			});
		} finally {
			overlayOpen = false;
			overlayHandle = undefined;
			void poll();
		}
	};

	pi.registerCommand("kanban", { description: "Open the interactive Kanban board", handler: async (_args, ctx) => open(ctx) });

	pi.on("session_start", (_event, ctx) => {
		if (ctx.mode !== "tui") return;
		currentClient = new KanbanClient(pi, ctx.cwd);
		ctx.ui.setWidget("kanban-topbar", (tui, theme) => {
			widgetRender = () => tui.requestRender();
			return {
				render(width: number): string[] {
					if (!snapshot.board) {
						return [truncateToWidth(`${theme.fg("borderMuted", "╭─")} ${theme.fg("accent", theme.bold("KANBAN"))} ${theme.fg("muted", "No board")} ${theme.fg("borderMuted", "─╮")}`, width)];
					}
					const active = (snapshot.tasks ?? []).filter((task) => task.status === "IN_PROGRESS" || task.status === "IN_REVIEW");
					const preview = active.length
						? active.slice(0, 2).map((task) => `${theme.fg(task.status === "IN_PROGRESS" ? "warning" : "accent", task.status === "IN_PROGRESS" ? "◒" : "◇")} ${truncateToWidth(task.title, 28)}`).join(theme.fg("dim", "  ·  "))
						: theme.fg("success", "● No active work");
					const counts = STATUSES.map((status) => `${STATUS_META[status].mark}${snapshot.counts?.[status] ?? 0}`).join(" ");
					return [truncateToWidth(`${theme.fg("borderMuted", "╭─")} ${theme.fg("accent", theme.bold("KANBAN"))} ${theme.fg("dim", counts)}  ${preview} ${theme.fg("borderMuted", "─╮")}`, width)];
				},
				invalidate() {},
			};
		});
		void poll();
		pollTimer = setInterval(() => void poll(), 5_000);
	});

	pi.on("session_shutdown", () => {
		if (pollTimer) clearInterval(pollTimer);
		pollTimer = undefined;
		widgetRender = undefined;
		currentClient = undefined;
	});
}
