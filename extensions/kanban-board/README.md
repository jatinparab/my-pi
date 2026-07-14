# Kanban Board

A live Pi topbar and large overlay backed exclusively by the `kanban` CLI.

## Open and focus

- `/kanban`: open/focus the board
- `Esc`: close the overlay

## Board

- `←` / `→`: select lane
- `↑` / `↓`: select ticket
- `Enter`: edit ticket
- `+` or `N`: create in selected lane
- `M`, then `←` / `→`, `Enter`: move ticket
- `R`: refresh
- `A`: archive (with confirmation)

## Detail editor

- `Tab` / `Shift+Tab`: move between title, description, status, save, and back
- `←` / `→`: change status while status is focused
- `Ctrl+S`: save/create
- `Esc`: return; unsaved changes trigger a save/discard dialog
- `Shift+Enter`: newline in the description editor

The extension auto-detects boards with `kanban status --json`, polls the topbar every five seconds, and offers board initialization when none exists.
