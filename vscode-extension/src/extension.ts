/**
 * AIOS VS Code Extension v0.1.0
 *
 * Wraps AIOS CLI for VS Code:
 *  - Command palette integration (12 commands)
 *  - Status bar with current task
 *  - Auto-sync hook
 *  - Output channel for results
 */
import * as vscode from "vscode";
import { exec, ExecException } from "child_process";

let statusBarItem: vscode.StatusBarItem;
let outputChannel: vscode.OutputChannel;

function getCliPath(): string {
    return vscode.workspace.getConfiguration("aios").get("cliPath", "aios");
}

function getWorkspaceRoot(): string | undefined {
    const folders = vscode.workspace.workspaceFolders;
    if (!folders || folders.length === 0) {
        vscode.window.showWarningMessage("AIOS: No workspace folder open");
        return undefined;
    }
    return folders[0].uri.fsPath;
}

async function runAios(subcmd: string, extraArgs: string[] = [], showOutput = true): Promise<string | null> {
    const cwd = getWorkspaceRoot();
    if (!cwd) return null;

    const cli = getCliPath();
    const fullCmd = `${cli} ${subcmd} ${extraArgs.join(" ")}`.trim();

    if (showOutput) {
        outputChannel.appendLine(`\n[AIOS] $ ${fullCmd}`);
        outputChannel.show(true);
    }

    return new Promise((resolve) => {
        exec(fullCmd, { cwd, encoding: "utf-8", maxBuffer: 1024 * 1024 * 5 },
            (err: ExecException | null, stdout: string, stderr: string) => {
                if (stdout && showOutput) outputChannel.append(stdout);
                if (stderr && showOutput) outputChannel.append(stderr);
                if (err) {
                    if (showOutput) outputChannel.appendLine(`[AIOS] Error: exit ${err.code}`);
                    resolve(null);
                } else {
                    resolve(stdout);
                }
            }
        );
    });
}

async function refreshStatusBar() {
    if (!vscode.workspace.getConfiguration("aios").get("showStatusBar", true)) {
        statusBarItem.hide();
        return;
    }
    const out = await runAios("status", [], false);
    if (!out) {
        statusBarItem.text = "$(circle-slash) AIOS";
        statusBarItem.tooltip = "AIOS not initialized · run 'aios init'";
    } else {
        const taskMatch = out.match(/Task\s*:\s*(.+)/);
        const task = taskMatch ? taskMatch[1].trim().substring(0, 40) : "no active task";
        statusBarItem.text = `$(rocket) AIOS: ${task}`;
        statusBarItem.tooltip = `Click for AIOS commands\n\n${out.substring(0, 500)}`;
    }
    statusBarItem.command = "aios.status";
    statusBarItem.show();
}

// =====================
// Command implementations
// =====================

async function cmdStatus() {
    await runAios("status");
    refreshStatusBar();
}

async function cmdBoot() {
    await runAios("boot");
    refreshStatusBar();
}

async function cmdTask() {
    const description = await vscode.window.showInputBox({
        prompt: "AIOS · task description",
        placeHolder: "Refactor SICOFAV credentials migration",
    });
    if (!description) return;

    const mode = await vscode.window.showQuickPick(
        ["BUGFIX", "FEATURE", "MIGRATION", "LEGACY_MODERNIZATION"],
        { placeHolder: "Select mode" }
    );
    if (!mode) return;

    const result = await runAios("task", [`--task "${description}"`, `--mode ${mode}`]);
    if (result) {
        refreshStatusBar();
        // Auto-sync if enabled
        if (vscode.workspace.getConfiguration("aios").get("autoSync", false)) {
            await runAios("sync");
        }
    }
}

async function cmdRefresh() {
    const summary = await vscode.window.showInputBox({
        prompt: "Session summary (what was done)",
    });
    if (!summary) return;
    const nextStep = await vscode.window.showInputBox({
        prompt: "Next step",
    });
    if (!nextStep) return;
    await runAios("refresh", [`--summary "${summary}"`, `--next-step "${nextStep}"`]);
    refreshStatusBar();
}

async function cmdAnalyze() { await runAios("analyze"); }
async function cmdRefine() {
    const spec = await vscode.window.showInputBox({
        prompt: "Spec name (e.g. legacy-01-sicofav)",
    });
    if (!spec) return;
    await runAios("refine", [`--spec ${spec}`]);
}
async function cmdRelease() { await runAios("release"); }
async function cmdSync() { await runAios("sync"); }
async function cmdTest() { await runAios("test"); }
async function cmdHandoff() { await runAios("handoff"); }
async function cmdDoctor() { await runAios("doctor"); }

// ── Security · Arena/Nemesis/Mythos wrappers ──────────────────────────

async function cmdArenaList() {
    await runAios("arena", ["--list"]);
}

async function cmdArena() {
    // Obtiene lista de TUTs via aios arena --list · quickpick
    const listing = await runAios("arena", ["--list"], false);
    const targets: string[] = [];
    if (listing) {
        for (const line of listing.split("\n")) {
            const m = line.match(/^\s*·\s*(\S+)/);
            if (m) targets.push(m[1]);
        }
    }
    if (targets.length === 0) {
        vscode.window.showWarningMessage(
            "Arena: no TUTs detectados · verifica que `arena` este en PATH"
        );
        return;
    }
    const pick = await vscode.window.showQuickPick(targets, {
        placeHolder: "Seleccionar TUT para self-play",
    });
    if (!pick) return;
    const rounds = await vscode.window.showInputBox({
        prompt: "Max rounds",
        value: "10",
        validateInput: (v) => (/^\d+$/.test(v) ? undefined : "Solo numeros"),
    });
    if (!rounds) return;
    const url = await vscode.window.showInputBox({
        prompt: "Target URL (opcional · activa nuclei si esta)",
        placeHolder: "http://localhost:8888 o vacio",
    });
    const args = ["--target", pick, "--max-rounds", rounds];
    if (url && url.trim()) args.push("--target-url", url.trim());
    await runAios("arena", args);
}

async function cmdEngagementList() {
    await runAios("engagement", ["--list"]);
}

async function cmdEngagement() {
    const choice = await vscode.window.showQuickPick(
        [
            { label: "Scaffold UNA app", action: "single" },
            { label: "Scaffold TODAS las pending", action: "all" },
        ],
        { placeHolder: "Tipo de scaffold" },
    );
    if (!choice) return;
    if (choice.action === "all") {
        await runAios("engagement", ["--all"]);
        return;
    }
    const app = await vscode.window.showInputBox({
        prompt: "app_id del catalogo (ej. 02-arc)",
    });
    if (!app) return;
    await runAios("engagement", ["--app", app]);
}

async function cmdReport() {
    await runAios("report");
    // Abre el reporte mas reciente si se genero
    const cwd = getWorkspaceRoot();
    if (!cwd) return;
    const reportsUri = vscode.Uri.file(`${cwd}/reports`);
    try {
        const entries = await vscode.workspace.fs.readDirectory(reportsUri);
        const mds = entries
            .filter(([_, t]) => t === vscode.FileType.File)
            .map(([n]) => n)
            .filter((n) => n.startsWith("aios_report_"))
            .sort()
            .reverse();
        if (mds.length > 0) {
            const latest = vscode.Uri.file(`${cwd}/reports/${mds[0]}`);
            await vscode.window.showTextDocument(latest);
        }
    } catch {
        // reports dir no existe · no-op
    }
}

async function cmdOpenSpec() {
    const cwd = getWorkspaceRoot();
    if (!cwd) return;
    const out = await runAios("status", [], false);
    if (!out) return;
    const taskMatch = out.match(/Task\s*:\s*(.+)/);
    if (!taskMatch) {
        vscode.window.showInformationMessage("No active task");
        return;
    }
    // Try to open the most recent spec folder
    const specsUri = vscode.Uri.file(`${cwd}/specs`);
    try {
        const entries = await vscode.workspace.fs.readDirectory(specsUri);
        const dirs = entries.filter(([_, t]) => t === vscode.FileType.Directory).map(([n]) => n);
        if (dirs.length === 0) {
            vscode.window.showInformationMessage("No specs found");
            return;
        }
        const pick = await vscode.window.showQuickPick(dirs, { placeHolder: "Select spec to open" });
        if (!pick) return;
        const reqFile = vscode.Uri.file(`${cwd}/specs/${pick}/requirements.md`);
        await vscode.window.showTextDocument(reqFile);
    } catch (e) {
        vscode.window.showWarningMessage("Could not list specs");
    }
}

// =====================
// Activation
// =====================

export function activate(context: vscode.ExtensionContext) {
    outputChannel = vscode.window.createOutputChannel("AIOS");
    outputChannel.appendLine("AIOS VS Code extension activated · v0.1.0");

    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    context.subscriptions.push(statusBarItem);
    refreshStatusBar();

    const commands: [string, () => Promise<void>][] = [
        ["aios.status",   cmdStatus],
        ["aios.boot",     cmdBoot],
        ["aios.task",     cmdTask],
        ["aios.refresh",  cmdRefresh],
        ["aios.analyze",  cmdAnalyze],
        ["aios.refine",   cmdRefine],
        ["aios.release",  cmdRelease],
        ["aios.sync",     cmdSync],
        ["aios.test",     cmdTest],
        ["aios.handoff",  cmdHandoff],
        ["aios.doctor",   cmdDoctor],
        ["aios.openSpec", cmdOpenSpec],
        ["aios.arena",           cmdArena],
        ["aios.arenaList",       cmdArenaList],
        ["aios.engagement",      cmdEngagement],
        ["aios.engagementList",  cmdEngagementList],
        ["aios.report",          cmdReport],
    ];

    for (const [id, handler] of commands) {
        context.subscriptions.push(vscode.commands.registerCommand(id, handler));
    }

    // Refresh status bar every 30s
    const interval = setInterval(refreshStatusBar, 30000);
    context.subscriptions.push({ dispose: () => clearInterval(interval) });

    // Listen to config changes
    context.subscriptions.push(
        vscode.workspace.onDidChangeConfiguration((e) => {
            if (e.affectsConfiguration("aios.showStatusBar")) {
                refreshStatusBar();
            }
        })
    );
}

export function deactivate() {
    if (outputChannel) outputChannel.dispose();
    if (statusBarItem) statusBarItem.dispose();
}
