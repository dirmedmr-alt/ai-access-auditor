// The page talks to the app the same way it does in the Mac app (window.webkit.messageHandlers.native),
// so public/index.html needs no Linux-specific code for its Setup screen.
'use strict';
const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('webkit', { messageHandlers: { native: { postMessage: m => ipcRenderer.send('native', m) } } });
contextBridge.exposeInMainWorld('nativeConfirm', msg => ipcRenderer.sendSync('confirm', String(msg)));
