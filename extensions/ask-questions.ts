import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import {
	Editor,
	type EditorTheme,
	Key,
	Markdown,
	type MarkdownTheme,
	matchesKey,
	Text,
	visibleWidth,
	wrapTextWithAnsi,
} from "@earendil-works/pi-tui";
import { Type } from "typebox";

interface QuestionOption {
	value: string;
	label: string;
	description?: string;
}

interface Question {
	id: string;
	label: string;
	prompt: string;
	options: QuestionOption[];
}

interface Answer {
	id: string;
	value: string;
	label: string;
	wasCustom: boolean;
	index?: number;
}

interface AskQuestionsResult {
	questions: Question[];
	answers: Answer[];
	cancelled: boolean;
}

type DisplayOption = QuestionOption & { isCustom?: boolean };

const OptionSchema = Type.Object({
	value: Type.String({ description: "Stable value returned for this option" }),
	label: Type.String({ description: "Short, human-readable option label" }),
	description: Type.Optional(Type.String({ description: "Helpful context shown below the option" })),
});

const QuestionSchema = Type.Object({
	id: Type.Optional(Type.String({ description: "Stable identifier for this question" })),
	label: Type.Optional(Type.String({ description: "Short label used in the result, such as Scope or Priority" })),
	prompt: Type.String({ description: "Markdown-formatted question body shown to the user" }),
	options: Type.Array(OptionSchema, { description: "The options the user can choose from" }),
});

const AskQuestionsParams = Type.Object({
	questions: Type.Array(QuestionSchema, {
		description: "Questions to ask. They are shown one at a time, in order.",
	}),
});

function resultFor(
	message: string,
	questions: Question[] = [],
	answers: Answer[] = [],
): { content: { type: "text"; text: string }[]; details: AskQuestionsResult } {
	return {
		content: [{ type: "text", text: message }],
		details: { questions, answers, cancelled: true },
	};
}

export default function askQuestions(pi: ExtensionAPI) {
	pi.registerTool({
		name: "ask_questions",
		label: "Ask Questions",
		description:
			"Ask the user one or more clarifying questions. Question prompts support Markdown and are shown one at a time with selectable options. The tool automatically appends a custom free-text option — do NOT add any 'Other', 'Custom', 'Write', or free-text option in the options array. Use when the user's preference or decision is needed before continuing.",
		promptSnippet: "Ask the user a sequence of questions with options and custom answers",
		promptGuidelines: [
			"Use ask_questions when you need the user's decision, preference, or clarification before proceeding.",
			"Question prompts support Markdown; put decision context that the user must see in the prompt body.",
			"Use concise option labels and descriptions; ask related questions together and order them logically.",
			"The tool automatically adds a custom free-text option. Do NOT add any 'Other', 'Custom', 'Write in', or free-text options in your options array.",
		],
		parameters: AskQuestionsParams,
		executionMode: "sequential",

		async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
			const questions: Question[] = params.questions.map((question, index) => ({
				id: question.id?.trim() || `question-${index + 1}`,
				label: question.label?.trim() || `Question ${index + 1}`,
				prompt: question.prompt,
				options: question.options,
			}));

			if (questions.length === 0) {
				return resultFor("Error: No questions provided");
			}

			const invalid = questions.find((question) => question.options.length === 0);
			if (invalid) {
				return resultFor(`Error: ${invalid.label} has no options`, questions);
			}

			if (ctx.mode !== "tui") {
				return resultFor("Error: ask_questions requires interactive TUI mode", questions);
			}

			ctx.ui.setWorkingVisible(false);
			const result = await ctx.ui.custom<AskQuestionsResult>((tui, theme, _keybindings, done) => {
				let questionIndex = 0;
				let optionIndex = 0;
				let customMode = false;
				let customError = "";
				let cachedLines: string[] | undefined;
				let cachedWidth: number | undefined;
				let cachedHeight: number | undefined;
				const answers: Answer[] = [];

				const markdownTheme: MarkdownTheme = {
					heading: (text) => theme.fg("mdHeading", text),
					link: (text) => theme.fg("mdLink", text),
					linkUrl: (text) => theme.fg("mdLinkUrl", text),
					code: (text) => theme.fg("mdCode", text),
					codeBlock: (text) => theme.fg("mdCodeBlock", text),
					codeBlockBorder: (text) => theme.fg("mdCodeBlockBorder", text),
					quote: (text) => theme.fg("mdQuote", text),
					quoteBorder: (text) => theme.fg("mdQuoteBorder", text),
					hr: (text) => theme.fg("mdHr", text),
					listBullet: (text) => theme.fg("mdListBullet", text),
					bold: (text) => theme.bold(text),
					italic: (text) => theme.italic(text),
					strikethrough: (text) => theme.strikethrough(text),
					underline: (text) => theme.underline(text),
				};
				const promptMarkdown = questions.map((question) => new Markdown(
					question.prompt,
					1,
					0,
					markdownTheme,
					{ color: (text) => theme.fg("text", text) },
					{ preserveOrderedListMarkers: true, preserveBackslashEscapes: true },
				));

				const editorTheme: EditorTheme = {
					borderColor: (s) => theme.fg("accent", s),
					selectList: {
						selectedPrefix: (text) => theme.fg("accent", text),
						selectedText: (text) => theme.fg("accent", text),
						description: (text) => theme.fg("muted", text),
						scrollInfo: (text) => theme.fg("dim", text),
						noMatch: (text) => theme.fg("warning", text),
					},
				};
				const editor = new Editor(tui, editorTheme);

				const refresh = () => {
					cachedLines = undefined;
					cachedWidth = undefined;
					cachedHeight = undefined;
					tui.requestRender();
				};

				const currentQuestion = () => questions[questionIndex]!;
				const customAnswerPatterns = [
					/custom/i,
					/write/i,
					/type/i,
					/free.?text/i,
					/other/i,
					/manual/i,
					/custom.?answer/i,
				];
				const isCustomAnswerOption = (o: QuestionOption) =>
					customAnswerPatterns.some((re) => re.test(o.label) || re.test(o.value));
				const currentOptions = (): DisplayOption[] => [
					...currentQuestion().options.filter((o) => !isCustomAnswerOption(o)),
					{ value: "__custom__", label: "Write a custom answer…", isCustom: true },
				];

				const cancel = () => done({ questions, answers: [...answers], cancelled: true });

				const advance = (answer: Answer) => {
					answers[questionIndex] = answer;
					if (questionIndex === questions.length - 1) {
						done({ questions, answers: [...answers], cancelled: false });
						return;
					}
					questionIndex += 1;
					optionIndex = 0;
					customMode = false;
					customError = "";
					editor.setText("");
					refresh();
				};

				editor.onSubmit = (value) => {
					const answer = value.trim();
					if (!answer) {
						customError = "Please write an answer, or press Esc to go back.";
						refresh();
						return;
					}
					advance({
						id: currentQuestion().id,
						value: answer,
						label: answer,
						wasCustom: true,
					});
				};

				const handleInput = (data: string) => {
					if (customMode) {
						if (matchesKey(data, Key.escape)) {
							customMode = false;
							customError = "";
							editor.setText("");
							refresh();
							return;
						}
						editor.handleInput(data);
						refresh();
						return;
					}

					const options = currentOptions();
					if (matchesKey(data, Key.up)) {
						optionIndex = Math.max(0, optionIndex - 1);
						refresh();
						return;
					}
					if (matchesKey(data, Key.down)) {
						optionIndex = Math.min(options.length - 1, optionIndex + 1);
						refresh();
						return;
					}
					if (matchesKey(data, Key.enter)) {
						const selected = options[optionIndex]!;
						if (selected.isCustom) {
							customMode = true;
							customError = "";
							editor.setText("");
							refresh();
							return;
						}
						advance({
							id: currentQuestion().id,
							value: selected.value,
							label: selected.label,
							wasCustom: false,
							index: optionIndex + 1,
						});
						return;
					}
					if (matchesKey(data, Key.escape)) cancel();
				};

				const render = (width: number): string[] => {
					const terminalHeight = tui.terminal.rows;
					if (cachedLines && cachedWidth === width && cachedHeight === terminalHeight) return cachedLines;

					const lines: string[] = [];
					const renderWidth = Math.max(1, width);
					const question = currentQuestion();
					const options = currentOptions();

					const addWrapped = (text: string) => {
						lines.push(...wrapTextWithAnsi(text, renderWidth));
					};
					const addWrappedWithPrefix = (prefix: string, text: string) => {
						const prefixWidth = visibleWidth(prefix);
						if (prefixWidth >= renderWidth) {
							addWrapped(prefix + text);
							return;
						}
						const wrapped = wrapTextWithAnsi(text, renderWidth - prefixWidth);
						const continuation = " ".repeat(prefixWidth);
						for (let index = 0; index < wrapped.length; index++) {
							lines.push(`${index === 0 ? prefix : continuation}${wrapped[index]}`);
						}
					};

					lines.push(theme.fg("accent", "━".repeat(renderWidth)));
					const progress = questions.map((_item, index) => {
						if (index < questionIndex) return theme.fg("success", "●");
						if (index === questionIndex) return theme.fg("accent", "◆");
						return theme.fg("dim", "○");
					}).join(theme.fg("dim", "  "));
					addWrappedWithPrefix(" ", `${progress}  ${theme.fg("muted", `${questionIndex + 1} / ${questions.length}`)}`);
					lines.push("");

					addWrappedWithPrefix(" ", theme.fg("accent", theme.bold(question.label.toUpperCase())));
					lines.push(...promptMarkdown[questionIndex]!.render(renderWidth));
					lines.push("");

					for (let index = 0; index < options.length; index++) {
						const option = options[index]!;
						const selected = index === optionIndex;
						const isCustom = option.isCustom === true;
						const prefix = selected ? theme.fg("accent", "❯ ") : "  ";
						const label = `${index + 1}. ${option.label}${isCustom && customMode ? "  ✎" : ""}`;
						const labelColor = selected || (isCustom && customMode) ? "accent" : "text";
						addWrappedWithPrefix(prefix, theme.fg(labelColor, label));
						if (option.description) addWrappedWithPrefix("     ", theme.fg("muted", option.description));
					}

					if (customMode) {
						lines.push("");
						addWrappedWithPrefix(" ", theme.fg("muted", "Your answer"));
						for (const line of editor.render(Math.max(1, renderWidth - 2))) lines.push(` ${line}`);
						if (customError) addWrappedWithPrefix(" ", theme.fg("warning", customError));
					}

					lines.push("");
					addWrappedWithPrefix(
						" ",
						theme.fg(
							"dim",
							customMode ? "Enter submit  •  Esc back" : "↑↓ choose  •  Enter continue  •  Esc cancel",
						),
					);
					lines.push(theme.fg("accent", "━".repeat(renderWidth)));

					cachedLines = lines;
					cachedWidth = width;
					cachedHeight = terminalHeight;
					return lines;
				};

				return {
					render,
					invalidate: () => {
						for (const markdown of promptMarkdown) markdown.invalidate();
						cachedLines = undefined;
						cachedWidth = undefined;
						cachedHeight = undefined;
					},
					handleInput,
				};
			}).finally(() => ctx.ui.setWorkingVisible(true));

			if (result.cancelled) {
				const answered = result.answers.length;
				return {
					content: [{ type: "text", text: `User cancelled after answering ${answered} of ${questions.length} question(s)` }],
					details: result,
				};
			}

			return {
				content: [{
					type: "text",
					text: result.answers
						.map((answer) => `${answer.id}: ${answer.wasCustom ? `user wrote: ${answer.value}` : `user selected: ${answer.value}`}`)
						.join("\n"),
				}],
				details: result,
			};
		},

		renderCall(args, theme) {
			const questions = Array.isArray(args.questions) ? args.questions : [];
			const count = questions.length;
			const labels = questions
				.map((question: { label?: string; id?: string }, index: number) => question.label || question.id || `Q${index + 1}`)
				.join("  ·  ");
			let text = theme.fg("toolTitle", theme.bold("ask_questions "));
			text += theme.fg("muted", `${count} question${count === 1 ? "" : "s"}`);
			if (labels) text += `\n${theme.fg("dim", `  ${labels}`)}`;
			return new Text(text, 0, 0);
		},

		renderResult(result, _options, theme) {
			const details = result.details as AskQuestionsResult | undefined;
			if (!details) return new Text(result.content[0]?.type === "text" ? result.content[0].text : "", 0, 0);
			if (details.cancelled) {
				return new Text(
					theme.fg("warning", "⚠ Cancelled") + theme.fg("dim", `  (${details.answers.length}/${details.questions.length} answered)`),
					0,
					0,
				);
			}
			const lines = details.answers.map((answer) => {
				const question = details.questions.find((item) => item.id === answer.id);
				const label = question?.label || answer.id;
				const source = answer.wasCustom ? theme.fg("muted", "wrote") : theme.fg("muted", "selected");
				return `${theme.fg("success", "✓ ")}${theme.fg("accent", label)}  ${source}: ${theme.fg("text", answer.label)}`;
			});
			return new Text(lines.join("\n"), 0, 0);
		},
	});
}
