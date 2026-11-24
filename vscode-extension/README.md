# AIOS · VS Code Extension

Wraps [AIOS CLI](https://github.com/christianescamilla15-cell/aios-framework) for Visual Studio Code.

## Features

- **12 commands** in command palette (AIOS: Status · Boot · Task · Refresh · Analyze · Refine · Release · Sync · Test · Handoff · Doctor · Open Spec)
- **Status bar** with current task (auto-refreshes every 30s)
- **Snippets** for EARS requirements + risk entries
- **Auto-sync** option after task creation
- **Output channel** for AIOS CLI output

## Requirements

- VS Code 1.85+
- AIOS CLI installed (`pip install aios-kiro`)
- Workspace with `ai-system/` folder (use `aios init` first)

## Configuration

| Setting | Default | Description |
|---|---|---|
| `aios.cliPath` | `aios` | Path to AIOS executable |
| `aios.autoSync` | `false` | Auto-run sync after task |
| `aios.showStatusBar` | `true` | Show AIOS status in status bar |

## Snippets

In Markdown files inside spec folders:

- `aios-ears-ubiq` → ubiquitous requirement
- `aios-ears-event` → event-driven requirement
- `aios-ears-state` → state-driven requirement
- `aios-ears-unwanted` → unwanted behavior
- `aios-risk` → risk register row
- `aios-ac` → acceptance criterion
- `aios-section` → spec section

## Build

```bash
npm install
npm run compile      # tsc
npm run package      # vsce package → .vsix
```

## Development

```bash
# Open extension folder in VS Code
code .

# F5 to launch Extension Development Host
```

## Status

**v0.1.0 · MVP** · functional core · not yet published to Marketplace.

Roadmap:
- [ ] Spec tree view (sidebar)
- [ ] Inline lint of EARS syntax
- [ ] Code lens for `Tasks defined` count
- [ ] Auto-completion of app names from `apps_code/`
- [ ] Webview dashboard for `aios analyze` results
