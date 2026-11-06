'use strict';
const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('popup', {
  content: () => ipcRenderer.invoke('popup-content'),
  ready: height => ipcRenderer.send('popup-ready', height),
  decide: (allowed, option) => ipcRenderer.send('popup-decide', allowed, option),
});
