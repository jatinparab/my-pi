import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

const ketchInstructions = `
## External Research with Ketch

Use \`ketch\` for external research — web pages, OSS code, library docs.

- \`ketch search "query"\` / \`ketch search "query" --scrape\` — web results with optional full content (add \`--multi\` to federate across backends and rank-fuse)
- \`ketch scrape <url> [url...]\` — clean markdown from one or more URLs
- \`ketch extract\` — for already-fetched/piped HTML (\`curl ... | ketch extract\`) — no fetch, no cache, no browser
- \`ketch code "query" --lang go\` — real OSS code with repo/line context
- \`ketch docs "query" --library /org/repo\` — version-aware library docs
- All commands support \`--json\`. \`ketch config\` reports active backends.
`;

export default function (pi: ExtensionAPI) {
  pi.on("before_agent_start", async (event, _ctx) => {
    return {
      systemPrompt: event.systemPrompt + ketchInstructions,
    };
  });
}
