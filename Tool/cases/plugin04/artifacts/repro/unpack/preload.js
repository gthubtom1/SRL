const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('lab', {
  open: (url) => ipcRenderer.invoke('lab:open', url),
  telemetry: (blob) => ipcRenderer.send('lab:telemetry', blob)
});
