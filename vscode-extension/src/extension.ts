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

// ── Arena Dashboard WebView ───────────────────────────────────────────

interface ArenaRunSummary {
    run_id: string;
    target_id: string;
    verdict: string;
    rounds_completed: number;
    mythos_win_streak: number;
    started_at: string;
    findings_count: number;
    run_dir: string;
}

async function collectRuns(cwd: string): Promise<ArenaRunSummary[]> {
    const fs = require("fs");
    const path = require("path");
    const runsDirs = [
        path.join(cwd, "arena", "arena-memory", "runs"),
        path.join(cwd, "arena-memory", "runs"),
    ];
    const summaries: ArenaRunSummary[] = [];
    for (const runsDir of runsDirs) {
        if (!fs.existsSync(runsDir)) continue;
        const entries = fs.readdirSync(runsDir);
        for (const entry of entries) {
            const runDir = path.join(runsDir, entry);
            const metaPath = path.join(runDir, "metadata.json");
            if (!fs.existsSync(metaPath)) continue;
            try {
                const meta = JSON.parse(fs.readFileSync(metaPath, "utf-8"));
                let findingsCount = 0;
                const sarifPath = path.join(runDir, "findings.sarif");
                if (fs.existsSync(sarifPath)) {
                    try {
                        const sarif = JSON.parse(fs.readFileSync(sarifPath, "utf-8"));
                        findingsCount = (sarif.runs?.[0]?.results?.length) || 0;
                    } catch { /* ignore */ }
                }
                summaries.push({
                    run_id: meta.run_id || entry,
                    target_id: meta.target_id || "?",
                    verdict: meta.verdict || "?",
                    rounds_completed: meta.rounds_completed || 0,
                    mythos_win_streak: meta.mythos_win_streak || 0,
                    started_at: meta.started_at || "",
                    findings_count: findingsCount,
                    run_dir: runDir,
                });
            } catch { /* ignore */ }
        }
    }
    summaries.sort((a, b) => (b.started_at || "").localeCompare(a.started_at || ""));
    return summaries.slice(0, 20);
}

function verdictBadge(verdict: string): { bg: string; fg: string } {
    switch (verdict) {
        case "MYTHOS_WINS":   return { bg: "#10b981", fg: "#fff" };
        case "NEMESIS_WINS":  return { bg: "#ef4444", fg: "#fff" };
        case "STALEMATE":     return { bg: "#f59e0b", fg: "#000" };
        case "DRAW":          return { bg: "#6b7280", fg: "#fff" };
        case "USER_STOPPED":  return { bg: "#8b5cf6", fg: "#fff" };
        default:              return { bg: "#374151", fg: "#fff" };
    }
}

function dashboardHtml(runs: ArenaRunSummary[]): string {
    const rows = runs.map((r) => {
        const b = verdictBadge(r.verdict);
        const ts = r.started_at.slice(0, 19).replace("T", " ");
        return `
        <tr>
          <td><code>${r.target_id}</code></td>
          <td><span class="badge" style="background:${b.bg};color:${b.fg}">${r.verdict}</span></td>
          <td>${r.rounds_completed}</td>
          <td>${r.mythos_win_streak}</td>
          <td>${r.findings_count}</td>
          <td><time>${ts}</time></td>
          <td>
            <button onclick="openTimeline('${r.run_dir.replace(/\\/g, "/")}')">timeline</button>
            <button onclick="openSarif('${r.run_dir.replace(/\\/g, "/")}')">sarif</button>
          </td>
        </tr>`;
    }).join("");

    const counts = { total: runs.length };

    return `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; padding: 16px; color: var(--vscode-foreground); }
  h1 { font-size: 20px; margin-bottom: 4px; }
  .sub { color: var(--vscode-descriptionForeground); font-size: 12px; margin-bottom: 16px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--vscode-panel-border); }
  th { color: var(--vscode-descriptionForeground); font-weight: 600; }
  code { font-family: 'SFMono-Regular', Consolas, monospace; font-size: 12px; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
  time { font-family: 'SFMono-Regular', Consolas, monospace; font-size: 11px; color: var(--vscode-descriptionForeground); }
  button { background: var(--vscode-button-background); color: var(--vscode-button-foreground); border: none; padding: 4px 10px; border-radius: 3px; cursor: pointer; font-size: 11px; margin-right: 4px; }
  button:hover { background: var(--vscode-button-hoverBackground); }
  .toolbar { margin-bottom: 12px; }
  .empty { padding: 40px; text-align: center; color: var(--vscode-descriptionForeground); }
</style>
</head>
<body>
  <h1>Arena runs dashboard</h1>
  <div class="sub">${counts.total} run(s) en arena-memory · ultimo refresh ${new Date().toLocaleString()}</div>
  <div class="toolbar">
    <button onclick="refresh()">refresh</button>
    <button onclick="runArena()">new run</button>
  </div>
  ${runs.length === 0 ? `
    <div class="empty">
      Sin runs registrados.<br>
      Ejecuta <code>arena run &lt;tut&gt;</code> o AIOS: Arena Self-Play.
    </div>
  ` : `
  <table>
    <thead>
      <tr>
        <th>Target</th>
        <th>Verdict</th>
        <th>Rounds</th>
        <th>Streak</th>
        <th>Findings</th>
        <th>Started</th>
        <th></th>
      </tr>
    </thead>
    <tbody>${rows}</tbody>
  </table>
  `}
<script>
  const vscode = acquireVsCodeApi();
  function openTimeline(dir) { vscode.postMessage({ type: 'open', file: dir + '/timeline.md' }); }
  function openSarif(dir)    { vscode.postMessage({ type: 'open', file: dir + '/findings.sarif' }); }
  function refresh()         { vscode.postMessage({ type: 'refresh' }); }
  function runArena()        { vscode.postMessage({ type: 'runArena' }); }
</script>
</body>
</html>`;
}

async function cmdArenaDashboard() {
    const cwd = getWorkspaceRoot();
    if (!cwd) return;

    const panel = vscode.window.createWebviewPanel(
        "arenaDashboard",
        "Arena Runs Dashboard",
        vscode.ViewColumn.One,
        { enableScripts: true, retainContextWhenHidden: true },
    );

    const render = async () => {
        const runs = await collectRuns(cwd);
        panel.webview.html = dashboardHtml(runs);
    };

    panel.webview.onDidReceiveMessage(async (msg) => {
        if (msg.type === "open" && msg.file) {
            try {
                await vscode.window.showTextDocument(vscode.Uri.file(msg.file));
            } catch (e) {
                vscode.window.showWarningMessage(`No pude abrir ${msg.file}`);
            }
        } else if (msg.type === "refresh") {
            await render();
        } else if (msg.type === "runArena") {
            await cmdArena();
        }
    });

    await render();
    // Auto-refresh cada 15s mientras el panel esta visible
    const timer = setInterval(() => {
        if (panel.visible) render();
    }, 15000);
    panel.onDidDispose(() => clearInterval(timer));
}

// ── Suppressions Dashboard ──────────────────────────────────────────

interface Suppression {
    rule_id: string;
    file: string;
    line: number;
    cwe: string;
    reason: string;
    approver: string;
    approved_at: string;
    expires_at: string;
}

function loadSuppressions(cwd: string): Suppression[] {
    const fs = require("fs");
    const path = require("path");
    const file = path.join(cwd, "aios-suppressions.json");
    if (!fs.existsSync(file)) return [];
    try {
        const raw = JSON.parse(fs.readFileSync(file, "utf-8"));
        return Array.isArray(raw) ? raw : [];
    } catch { return []; }
}

function writeSuppressions(cwd: string, sups: Suppression[]): void {
    const fs = require("fs");
    const path = require("path");
    fs.writeFileSync(path.join(cwd, "aios-suppressions.json"),
        JSON.stringify(sups, null, 2), "utf-8");
}

function isExpired(s: Suppression): boolean {
    if (!s.expires_at) return false;
    try { return new Date(s.expires_at) < new Date(); } catch { return false; }
}

function suppressionsHtml(sups: Suppression[]): string {
    const rows = sups.map((s, i) => {
        const expired = isExpired(s);
        const badge = expired
            ? `<span class="badge bad">EXPIRED</span>`
            : (s.expires_at ? `<span class="badge warn">${s.expires_at}</span>` : `<span class="badge ok">active</span>`);
        return `<tr>
          <td><code>${s.rule_id || "-"}</code></td>
          <td><code>${s.file || "-"}:${s.line || 0}</code></td>
          <td>${s.cwe || "-"}</td>
          <td>${(s.reason || "").slice(0, 80)}</td>
          <td>${s.approver || "-"}</td>
          <td>${s.approved_at || "-"}</td>
          <td>${badge}</td>
          <td>
            <button onclick="removeSup(${i})">delete</button>
            ${expired ? "" : `<button onclick="expireSup(${i})">expire</button>`}
          </td>
        </tr>`;
    }).join("");
    const expiredCount = sups.filter(isExpired).length;
    return `<!doctype html><html><head><meta charset="utf-8"><style>
  body { font-family: -apple-system, "Segoe UI", sans-serif; padding: 16px; color: var(--vscode-foreground); }
  h1 { font-size: 20px; margin-bottom: 4px; }
  .sub { color: var(--vscode-descriptionForeground); font-size: 12px; margin-bottom: 16px; }
  .toolbar { margin-bottom: 12px; display: flex; gap: 8px; }
  table { width: 100%; border-collapse: collapse; font-size: 12px; }
  th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--vscode-panel-border); vertical-align: top; }
  th { color: var(--vscode-descriptionForeground); font-weight: 600; }
  code { font-family: 'SFMono-Regular', Consolas, monospace; font-size: 11px; }
  .badge { display: inline-block; padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: 600; }
  .badge.ok { background: #10b981; color: #fff; }
  .badge.warn { background: #f59e0b; color: #000; }
  .badge.bad { background: #ef4444; color: #fff; }
  button { background: var(--vscode-button-background); color: var(--vscode-button-foreground); border: none; padding: 3px 8px; border-radius: 3px; cursor: pointer; font-size: 10px; margin-right: 3px; }
  button:hover { background: var(--vscode-button-hoverBackground); }
  button.primary { background: #10b981; color: #fff; padding: 6px 12px; font-size: 12px; }
  .empty { padding: 40px; text-align: center; color: var(--vscode-descriptionForeground); }
  .alert { background: var(--vscode-inputValidation-warningBackground); border: 1px solid var(--vscode-inputValidation-warningBorder); padding: 8px; border-radius: 4px; margin-bottom: 12px; }
</style></head><body>
  <h1>Suppressions & Waivers</h1>
  <div class="sub">${sups.length} waivers en aios-suppressions.json · refresh ${new Date().toLocaleString()}</div>
  ${expiredCount > 0 ? `<div class="alert">⚠ ${expiredCount} waiver(s) expirado(s) · findings ya NO se suprimen · revisa.</div>` : ""}
  <div class="toolbar">
    <button class="primary" onclick="addSup()">+ Add waiver</button>
    <button onclick="refresh()">refresh</button>
    <button onclick="clearExpired()" ${expiredCount === 0 ? 'disabled' : ''}>clear ${expiredCount} expired</button>
  </div>
  ${sups.length === 0 ? `<div class="empty">Sin waivers. Click "+ Add" arriba.</div>` : `
  <table><thead><tr>
    <th>Rule ID</th><th>File:Line</th><th>CWE</th><th>Reason</th>
    <th>Approver</th><th>Approved</th><th>Status</th><th></th>
  </tr></thead><tbody>${rows}</tbody></table>`}
<script>
  const vscode = acquireVsCodeApi();
  function refresh() { vscode.postMessage({ type: 'refresh' }); }
  function removeSup(i) { if (confirm('Eliminar waiver?')) vscode.postMessage({ type: 'remove', index: i }); }
  function expireSup(i) { vscode.postMessage({ type: 'expire', index: i }); }
  function addSup() { vscode.postMessage({ type: 'add' }); }
  function clearExpired() { if (confirm('Eliminar todos los expirados?')) vscode.postMessage({ type: 'clearExpired' }); }
</script></body></html>`;
}

async function cmdSuppressionsDashboard() {
    const cwd = getWorkspaceRoot();
    if (!cwd) return;
    const panel = vscode.window.createWebviewPanel(
        "suppressionsDashboard", "Suppressions & Waivers",
        vscode.ViewColumn.One,
        { enableScripts: true, retainContextWhenHidden: true },
    );
    const render = () => { panel.webview.html = suppressionsHtml(loadSuppressions(cwd)); };
    panel.webview.onDidReceiveMessage(async (msg) => {
        const sups = loadSuppressions(cwd);
        if (msg.type === "refresh") {
            render();
        } else if (msg.type === "remove" && typeof msg.index === "number") {
            sups.splice(msg.index, 1); writeSuppressions(cwd, sups); render();
        } else if (msg.type === "expire" && typeof msg.index === "number") {
            const y = new Date(); y.setDate(y.getDate() - 1);
            sups[msg.index].expires_at = y.toISOString().slice(0, 10);
            writeSuppressions(cwd, sups); render();
        } else if (msg.type === "clearExpired") {
            writeSuppressions(cwd, sups.filter((s) => !isExpired(s))); render();
        } else if (msg.type === "add") {
            const ruleId = await vscode.window.showInputBox({ prompt: "rule_id (ej. STATIC-SQL-FSTRING)" });
            if (!ruleId) return;
            const file = await vscode.window.showInputBox({ prompt: "file (path relativo al root)" });
            if (!file) return;
            const lineStr = await vscode.window.showInputBox({
                prompt: "line (0 = wildcard toda la file)", value: "0",
                validateInput: (v) => /^\d+$/.test(v) ? undefined : "Solo numero",
            });
            if (lineStr === undefined) return;
            const reason = await vscode.window.showInputBox({ prompt: "reason (obligatoria)" });
            if (!reason) return;
            const approver = await vscode.window.showInputBox({ prompt: "approver" });
            if (!approver) return;
            const expires = await vscode.window.showInputBox({
                prompt: "expires_at (YYYY-MM-DD · vacio = no expira)",
                placeHolder: "2026-10-01",
            });
            sups.push({
                rule_id: ruleId, file, line: parseInt(lineStr, 10), cwe: "",
                reason, approver,
                approved_at: new Date().toISOString().slice(0, 10),
                expires_at: expires || "",
            });
            writeSuppressions(cwd, sups);
            render();
            vscode.window.showInformationMessage(`Waiver agregado para ${ruleId}`);
        }
    });
    render();
}

async function cmdCompliance() {
    await runAios("compliance-report");
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
        ["aios.arenaDashboard",  cmdArenaDashboard],
        ["aios.suppressionsDashboard", cmdSuppressionsDashboard],
        ["aios.compliance",            cmdCompliance],
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
