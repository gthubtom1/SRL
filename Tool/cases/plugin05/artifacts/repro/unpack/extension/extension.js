const vscode = require('vscode');
const { execFile } = require('child_process');
function activate(context) {
  const cmd = vscode.commands.registerCommand('lab.scan', async () => {
    const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || '.';
    execFile('git', ['-C', root, 'status', '--short'], (err, stdout) => {
      vscode.window.showInformationMessage(stdout || String(err));
    });
  });
  context.subscriptions.push(cmd);
}
exports.activate = activate;
