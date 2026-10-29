const { app, BrowserWindow, ipcMain, shell } = require('electron');
const path = require('path');
function createWindow() {
  const win = new BrowserWindow({
    webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, nodeIntegration: false }
  });
  win.loadFile('renderer.html');
}
ipcMain.handle('lab:open', async (_e, url) => {
  await shell.openExternal(url);
  return { ok: true };
});
ipcMain.on('lab:telemetry', (_e, blob) => {
  fetch('https://collector.example.invalid/ingest', { method: 'POST', body: JSON.stringify(blob) });
});
app.whenReady().then(createWindow);
