import assert from "node:assert/strict";
import test from "node:test";
import { createJiti } from "jiti";

const jiti = createJiti(import.meta.url);
const askQuestionsExtension = await jiti.import("../extensions/ask-questions.ts", { default: true });

const theme = {
	fg: (_color, text) => text,
	bg: (_color, text) => text,
	bold: (text) => text,
};

function createHarness(rows = 12) {
	let tool;
	let component;
	const workingVisibility = [];
	const tui = {
		terminal: { rows },
		requestRender() {},
	};

	askQuestionsExtension({
		registerTool(definition) {
			tool = definition;
		},
	});

	const ctx = {
		mode: "tui",
		ui: {
			setWorkingVisible(visible) {
				workingVisibility.push(visible);
			},
			custom(factory) {
				return new Promise((resolve) => {
					component = factory(tui, theme, undefined, resolve);
				});
			},
		},
	};

	return {
		ctx,
		get component() {
			return component;
		},
		get tool() {
			return tool;
		},
		tui,
		workingVisibility,
	};
}

test("renders long questions for native scrolling without an animated refresh loop", async () => {
	const harness = createHarness(12);
	const execution = harness.tool.execute(
		"call-1",
		{
			questions: [{
				id: "scope",
				label: "Scope",
				prompt: Array.from({ length: 80 }, (_, index) => `word${index + 1}`).join(" "),
				options: [
					{ value: "small", label: "Small change" },
					{ value: "large", label: "Large change" },
				],
			}],
		},
		undefined,
		undefined,
		harness.ctx,
	);

	const initial = harness.component.render(32);
	const renderedText = initial.join("\n");
	assert.ok(initial.length > harness.tui.terminal.rows, "the full question should be available in terminal scrollback");
	assert.match(renderedText, /word1/);
	assert.match(renderedText, /word80/);
	assert.match(renderedText, /Small change/);
	assert.doesNotMatch(renderedText, /PgUp|PgDn/);

	// Paging keys are intentionally not captured; terminal-native scrolling owns the viewport.
	harness.component.handleInput("\x1b[5~");
	assert.deepEqual(harness.component.render(32), initial);

	harness.component.handleInput("\x1b");
	const result = await execution;
	assert.equal(result.details.cancelled, true);
	assert.deepEqual(harness.workingVisibility, [false, true]);
});
