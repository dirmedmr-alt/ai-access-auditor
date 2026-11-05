// AI Access Auditor — native macOS shell.
// - Main window: shows the auditor UI (WKWebView) over a vibrant sidebar.
// - Menu bar shield: stays running after the window closes and watches agents' config files live.
// - LuLu-style prompts: pops up Keep / Remove when an agent gains new access, and Allow / Deny before
//   Claude Code acts (via a PermissionRequest hook, see gate.js).
// - Runs the bundled scanner (server.js) privately on 127.0.0.1.
import Cocoa
import WebKit
import UserNotifications

let CHECK_INTERVAL: TimeInterval = 60 // fallback; most changes arrive instantly through the event stream
let LAUNCH_AGENT_ID = "local.ai-access-auditor"

struct Grant: Decodable { let id, agent, title, category, risk, detail: String; let revocable: Bool? }
struct GateRequest: Decodable { let id, agent, tool, action, text, risk, cwd: String; let canAlways: Bool }
struct Events: Decodable { let gate: [GateRequest]; let changed: Bool; let closed: [String] }
struct GateStatus: Decodable { let installed: Bool }
struct Changes: Decodable { let scannedAt: String; let total, openHigh: Int; let new, toNotify: [Grant]; let expired: [Grant]? }

final class AppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate, WKNavigationDelegate, WKUIDelegate,
                         UNUserNotificationCenterDelegate, NSMenuDelegate, WKScriptMessageHandler {
    var window: NSWindow!
    var webView: WKWebView!
    var server: Process?
    var buffer = ""
    var port: Int?
    var token: String?
    var pageLoaded = false
    var pendingJS: [String] = []
    var statusItem: NSStatusItem!
    var lastChanges: Changes?
    var timer: Timer?
    var panels: [String: PromptPanel] = [:]   // open Allow/Deny prompts by request id
    var gateInstalled = false
    let startHidden = CommandLine.arguments.contains("--background")

    // MARK: launch
    func applicationDidFinishLaunching(_ note: Notification) {
        buildMenu()
        buildWindow()
        buildStatusItem()
        let center = UNUserNotificationCenter.current()
        center.delegate = self
        center.requestAuthorization(options: [.alert, .sound, .badge]) { _, _ in }
        if startHidden { NSApp.setActivationPolicy(.accessory) } else { showWindow() }
        startServer()
    }

    func buildWindow() {
        let config = WKWebViewConfiguration()
        config.userContentController.add(self, name: "native") // bridge for the setup screen
        webView = WKWebView(frame: .zero, configuration: config)
        webView.navigationDelegate = self
        webView.uiDelegate = self
        webView.setValue(false, forKey: "drawsBackground") // let the sidebar vibrancy show through
        webView.loadHTMLString(statusPage("Starting…"), baseURL: nil)

        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1180, height: 780),
                          styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
                          backing: .buffered, defer: false)
        window.title = "AI Access Auditor"
        window.titlebarAppearsTransparent = true
        window.titleVisibility = .hidden
        window.isReleasedWhenClosed = false
        window.delegate = self

        let blur = NSVisualEffectView()
        blur.material = .sidebar
        blur.blendingMode = .behindWindow
        blur.state = .followsWindowActiveState
        webView.translatesAutoresizingMaskIntoConstraints = false
        blur.addSubview(webView)
        let drag = DragStrip()
        drag.translatesAutoresizingMaskIntoConstraints = false
        blur.addSubview(drag)
        NSLayoutConstraint.activate([
            webView.leadingAnchor.constraint(equalTo: blur.leadingAnchor),
            webView.trailingAnchor.constraint(equalTo: blur.trailingAnchor),
            webView.topAnchor.constraint(equalTo: blur.topAnchor),
            webView.bottomAnchor.constraint(equalTo: blur.bottomAnchor),
            drag.leadingAnchor.constraint(equalTo: blur.leadingAnchor, constant: 80),
            drag.trailingAnchor.constraint(equalTo: blur.trailingAnchor),
            drag.topAnchor.constraint(equalTo: blur.topAnchor),
            drag.heightAnchor.constraint(equalToConstant: 14),
        ])
        window.contentView = blur
        window.minSize = NSSize(width: 760, height: 480)
        window.setFrameAutosaveName("MainWindow")
        if !window.setFrameUsingName("MainWindow") { window.center() }
    }

    @objc func showWindow() {
        NSApp.setActivationPolicy(.regular)
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        runJS("window.rescan && window.rescan()")
    }

    // Closing the window keeps the app alive in the menu bar
    func windowWillClose(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
    }
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !flag { showWindow() }
        return true
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

    // MARK: scanner process
    func findNode() -> String? {
        // Release builds carry their own Node.js runtime, so people don't need to install it
        if let bundled = Bundle.main.resourcePath.map({ $0 + "/runtime/node" }),
           FileManager.default.isExecutableFile(atPath: bundled) { return bundled }
        let nvmDir = NSHomeDirectory() + "/.nvm/versions/node"
        let nvm = ((try? FileManager.default.contentsOfDirectory(atPath: nvmDir)) ?? [])
            .sorted().reversed().map { "\(nvmDir)/\($0)/bin/node" }
        let candidates = ["/opt/homebrew/bin/node", "/usr/local/bin/node", "/usr/bin/node"] + nvm
        return candidates.first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    func startServer() {
        guard let node = findNode() else {
            showError("Node.js was not found. Install it with <code>brew install node</code>, then reopen the app."); return
        }
        guard let script = Bundle.main.path(forResource: "server", ofType: "js") else {
            showError("The app bundle is missing server.js."); return
        }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: node)
        p.arguments = [script]
        var env = ProcessInfo.processInfo.environment
        env["PORT"] = "0"
        p.environment = env
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        pipe.fileHandleForReading.readabilityHandler = { [weak self] h in
            guard let s = String(data: h.availableData, encoding: .utf8), !s.isEmpty else { return }
            DispatchQueue.main.async { self?.handleOutput(s) }
        }
        p.terminationHandler = { [weak self] proc in
            DispatchQueue.main.async {
                guard let self, self.server != nil else { return }
                self.showError("The scanner stopped (exit code \(proc.terminationStatus)).<pre>\(self.buffer)</pre>")
            }
        }
        do { try p.run(); server = p } catch { showError("Could not start the scanner: \(error.localizedDescription)") }
    }

    func handleOutput(_ s: String) {
        buffer += s
        if token == nil, let r = buffer.range(of: #"TOKEN [a-f0-9]+"#, options: .regularExpression) {
            token = String(buffer[r].split(separator: " ")[1])
        }
        if port == nil, let r = buffer.range(of: #"LISTENING \d+"#, options: .regularExpression),
           let p = Int(buffer[r].split(separator: " ")[1]) {
            port = p
            webView.load(URLRequest(url: URL(string: "http://127.0.0.1:\(p)/?native=1")!))
            checkForChanges()
            timer = Timer.scheduledTimer(withTimeInterval: CHECK_INTERVAL, repeats: true) { [weak self] _ in self?.checkForChanges() }
            timer?.tolerance = 30
            eventLoop()
        }
    }

    func showError(_ msg: String) {
        webView.loadHTMLString(statusPage(msg), baseURL: nil)
        setStatusIcon(alert: true, count: 0)
    }

    func statusPage(_ msg: String) -> String {
        """
        <html><body style="font:15px -apple-system;display:flex;height:90vh;align-items:center;justify-content:center;
        color:#666;text-align:center;padding:24px">\
        <style>@media(prefers-color-scheme:dark){body{color:#aaa}}</style><div>\(msg)</div></body></html>
        """
    }

    // MARK: API
    func api(_ path: String, method: String = "GET", body: [String: Any]? = nil, done: @escaping (Data?) -> Void) {
        guard let port, let token else { done(nil); return }
        var req = URLRequest(url: URL(string: "http://127.0.0.1:\(port)/api/\(path)")!)
        req.httpMethod = method
        req.timeoutInterval = path == "events" ? 80 : 60
        req.setValue(token, forHTTPHeaderField: "x-token")
        req.setValue("application/json", forHTTPHeaderField: "content-type")
        if let body { req.httpBody = try? JSONSerialization.data(withJSONObject: body) }
        URLSession.shared.dataTask(with: req) { data, resp, _ in
            let ok = (resp as? HTTPURLResponse)?.statusCode == 200
            DispatchQueue.main.async { done(ok ? data : nil) }
        }.resume()
    }

    @objc func checkForChanges() {
        api("changes") { [weak self] data in
            guard let self, let data, let c = try? JSONDecoder().decode(Changes.self, from: data) else { return }
            self.lastChanges = c
            self.refreshGateStatus()
            self.setStatusIcon(alert: !c.new.isEmpty, count: c.new.count)
            NSApp.dockTile.badgeLabel = c.new.isEmpty ? nil : String(c.new.count)
            self.promptNewGrants(c.toNotify)
            self.notifyExpired(c.expired ?? [])
            if self.window.isVisible { self.runJS("window.rescan && window.rescan()") }
        }
    }

    // MARK: live prompts (LuLu-style)
    /// Long-poll the scanner: it answers as soon as Claude Code asks something or an agent's config changes.
    func eventLoop() {
        api("events") { [weak self] data in
            guard let self else { return }
            guard let data, let e = try? JSONDecoder().decode(Events.self, from: data) else {
                DispatchQueue.main.asyncAfter(deadline: .now() + 3) { self.eventLoop() }
                return
            }
            e.closed.forEach { id in self.panels.removeValue(forKey: id)?.dismiss() }
            e.gate.forEach { self.showGatePrompt($0) }
            if e.changed { self.checkForChanges() }
            self.eventLoop()
        }
    }

    func showGatePrompt(_ g: GateRequest) {
        guard panels[g.id] == nil else { return }
        let symbol = g.tool == "Bash" ? "terminal.fill" : g.tool.hasPrefix("mcp__") ? "server.rack"
            : ["Write", "Edit", "MultiEdit", "NotebookEdit"].contains(g.tool) ? "square.and.pencil"
            : g.tool.hasPrefix("Web") ? "globe" : "hand.raised.fill"
        let panel = PromptPanel(.init(
            symbol: symbol, risk: g.risk,
            title: "\(g.agent) wants to \(g.action)",
            subtitle: g.cwd.isEmpty ? "Tool: \(g.tool)" : "Tool: \(g.tool) · in \(g.cwd)",
            detail: g.text,
            footnote: "\(g.agent) is paused until you decide. You can take back this decision later under Decisions.",
            options: g.canAlways ? ["Just this once", "Always (don't ask again)"] : ["Just this once"],
            allowTitle: "Allow", denyTitle: "Deny"))
        panel.onDecision = { [weak self] allowed, option in
            guard let self else { return }
            self.panels.removeValue(forKey: g.id)
            guard let allowed else { return } // closed without deciding → Claude Code will ask normally after timeout
            self.api("gate/decide", method: "POST", body: [
                "id": g.id, "decision": allowed ? "allow" : "deny", "remember": option == 1 ? "always" : "once",
            ]) { _ in }
        }
        panels[g.id] = panel
        panel.present()
    }

    /// Something gained access outside the gate (new MCP server, folder, extension…): keep it or remove it.
    func promptNewGrants(_ grants: [Grant]) {
        let ordered = grants.sorted { rank($0.risk) < rank($1.risk) }
        for g in ordered.prefix(3) where panels["grant-\(g.id)"] == nil {
            let canRemove = g.revocable ?? false
            let isProcess = g.category == "Running agent"
            let panel = PromptPanel(.init(
                symbol: isProcess ? "bolt.trianglebadge.exclamationmark.fill" : "exclamationmark.shield.fill", risk: g.risk,
                title: isProcess ? g.title : "\(g.agent) got new access",
                subtitle: g.category,
                detail: "\(g.title)\n\(g.detail)",
                footnote: isProcess ? "\"Stop it\" ends the process now. \"Let it run\" can also be limited to 1 hour, 1 day or 7 days."
                    : canRemove ? "Remove takes the access away now (a backup is saved, so you can undo it)." : "This one has to be removed by hand. Choose \"Review\" to see how.",
                options: isProcess ? ["Until it ends", "For 1 hour", "For 1 day", "For 7 days"] : ["Keep it", "Keep for 1 hour", "Keep for 1 day", "Keep for 7 days"],
                allowTitle: isProcess ? "Let it run" : "Keep", denyTitle: canRemove ? (isProcess ? "Stop it" : "Remove") : "Review"))
            panel.onDecision = { [weak self] allowed, option in
                guard let self else { return }
                self.panels.removeValue(forKey: "grant-\(g.id)")
                guard let allowed else { return }
                if !allowed {
                    if !canRemove { self.openFinding(g.id); return }
                    self.api("revoke", method: "POST", body: ["id": g.id]) { data in
                        if data == nil {
                            let a = NSAlert(); a.messageText = "Couldn't remove \(g.title)"; a.informativeText = "Open AI Access Auditor to try again."; a.runModal()
                        }
                        self.checkForChanges()
                    }
                } else if option == 0 || !canRemove {
                    self.api("review", method: "POST", body: ["id": g.id, "on": true]) { _ in self.checkForChanges() }
                } else {
                    let hours = [0, 1, 24, 168][option]
                    self.api("expiry", method: "POST", body: ["id": g.id, "hours": hours]) { _ in self.checkForChanges() }
                }
            }
            panels["grant-\(g.id)"] = panel
            panel.present()
        }
        if ordered.count > 3 { notify(Array(ordered.dropFirst(3))) }
    }

    func refreshGateStatus() {
        api("gate/status") { [weak self] data in
            if let data, let s = try? JSONDecoder().decode(GateStatus.self, from: data) { self?.gateInstalled = s.installed }
        }
    }
    @objc func toggleGate() {
        let on = !gateInstalled
        if on {
            let a = NSAlert()
            a.messageText = "Ask before Claude Code acts?"
            a.informativeText = "Whenever Claude Code is about to ask for permission, this app pops up instead so you can Allow or Deny. This adds a hook to ~/.claude/settings.json (a backup is saved). If this app isn't running, Claude Code just asks the usual way."
            a.addButton(withTitle: "Turn On"); a.addButton(withTitle: "Cancel")
            guard a.runModal() == .alertFirstButtonReturn else { return }
        }
        api("gate/install", method: "POST", body: ["on": on]) { [weak self] data in
            if data == nil { let a = NSAlert(); a.messageText = "Couldn't change the Claude Code gate"; a.runModal() }
            self?.refreshGateStatus()
            self?.runJS("window.rescan && window.rescan()")
        }
    }

    // MARK: notifications
    func notify(_ grants: [Grant]) {
        guard !grants.isEmpty else { return }
        let center = UNUserNotificationCenter.current()
        let ordered = grants.sorted { rank($0.risk) < rank($1.risk) }
        for g in ordered.prefix(3) {
            let c = UNMutableNotificationContent()
            c.title = "\(g.agent) gained access"
            c.subtitle = "\(g.category) · \(g.risk == "high" ? "High risk" : g.risk.capitalized)"
            c.body = g.title
            c.sound = g.risk == "high" ? .default : nil
            c.userInfo = ["id": g.id]
            center.add(UNNotificationRequest(identifier: g.id, content: c, trigger: nil))
        }
        if ordered.count > 3 {
            let c = UNMutableNotificationContent()
            c.title = "\(ordered.count - 3) more new AI grants"
            c.body = "Open AI Access Auditor to review them."
            c.userInfo = ["view": "new"]
            center.add(UNNotificationRequest(identifier: "more-\(Date().timeIntervalSince1970)", content: c, trigger: nil))
        }
    }
    func notifyExpired(_ grants: [Grant]) {
        guard !grants.isEmpty else { return }
        let c = UNMutableNotificationContent()
        c.title = grants.count == 1 ? "Access expired and was removed" : "\(grants.count) grants expired and were removed"
        c.body = grants.prefix(4).map { "\($0.agent): \($0.title)" }.joined(separator: "\n")
        c.userInfo = ["view": "history"]
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: "expired-\(Date().timeIntervalSince1970)", content: c, trigger: nil))
    }
    func rank(_ r: String) -> Int { ["high": 0, "medium": 1, "low": 2][r] ?? 3 }

    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
                                withCompletionHandler done: @escaping (UNNotificationPresentationOptions) -> Void) {
        done([.banner, .sound, .list])
    }
    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse,
                                withCompletionHandler done: @escaping () -> Void) {
        let info = response.notification.request.content.userInfo
        DispatchQueue.main.async {
            if let id = info["id"] as? String { self.openFinding(id) } else { self.openView(info["view"] as? String ?? "new") }
        }
        done()
    }

    func openFinding(_ id: String) {
        showWindow()
        runJS("window.selectFinding && window.selectFinding('\(id.filter { $0.isHexDigit })')")
    }
    func openView(_ v: String) {
        showWindow()
        runJS("window.showView && window.showView('\(v.filter { $0.isLetter })')")
    }

    func runJS(_ js: String) {
        if pageLoaded { webView.evaluateJavaScript(js) } else { pendingJS.append(js) }
    }
    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        guard webView.url?.scheme == "http" else { return }
        pageLoaded = true
        pendingJS.forEach { webView.evaluateJavaScript($0) }
        pendingJS = []
    }

    // MARK: menu bar
    func buildStatusItem() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        let menu = NSMenu()
        menu.delegate = self
        statusItem.menu = menu
        setStatusIcon(alert: false, count: 0)
    }

    func setStatusIcon(alert: Bool, count: Int) {
        guard let button = statusItem?.button else { return }
        let name = alert ? "exclamationmark.shield.fill" : "checkmark.shield"
        var img = NSImage(systemSymbolName: name, accessibilityDescription: "AI Access Auditor")
        if alert {
            img = img?.withSymbolConfiguration(.init(paletteColors: [.white, .systemRed]))
            img?.isTemplate = false
        } else {
            img?.isTemplate = true
        }
        button.image = img
        button.imagePosition = .imageLeading
        button.title = count > 0 ? " \(count)" : ""
        button.toolTip = alert ? "\(count) new AI access grant\(count == 1 ? "" : "s")" : "No new AI access"
    }

    // Rebuilt every time the menu opens so it is always current
    func menuNeedsUpdate(_ menu: NSMenu) {
        menu.removeAllItems()
        let c = lastChanges
        let header = NSMenuItem(title: c == nil ? "Checking…" :
            (c!.new.isEmpty ? "No new AI access" : "\(c!.new.count) new grant\(c!.new.count == 1 ? "" : "s") since you last looked"),
            action: nil, keyEquivalent: "")
        header.isEnabled = false
        menu.addItem(header)
        if let c {
            for g in c.new.sorted(by: { rank($0.risk) < rank($1.risk) }).prefix(8) {
                let dot = g.risk == "high" ? "🔴" : g.risk == "medium" ? "🟠" : "🟢"
                let item = NSMenuItem(title: "\(dot)  \(g.agent): \(truncate(g.title, 48))", action: #selector(menuOpenFinding(_:)), keyEquivalent: "")
                item.representedObject = g.id
                item.toolTip = g.detail
                item.target = self
                menu.addItem(item)
            }
            if c.new.count > 8 { addItem(menu, "…and \(c.new.count - 8) more", #selector(menuOpenNew)) }
            if !c.new.isEmpty { addItem(menu, "Mark All as Seen", #selector(ackAll)) }
            menu.addItem(.separator())
            let info = NSMenuItem(title: "\(c.total) grants · \(c.openHigh) high-risk not reviewed", action: nil, keyEquivalent: "")
            info.isEnabled = false
            menu.addItem(info)
            let f = ISO8601DateFormatter(); f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            if let d = f.date(from: c.scannedAt) {
                let t = NSMenuItem(title: "Checked \(RelativeDateTimeFormatter().localizedString(for: d, relativeTo: Date()))", action: nil, keyEquivalent: "")
                t.isEnabled = false
                menu.addItem(t)
            }
        }
        menu.addItem(.separator())
        addItem(menu, "Open AI Access Auditor", #selector(showWindow), "o")
        addItem(menu, "Check Now", #selector(checkForChanges), "r")
        addItem(menu, "Decisions…", #selector(menuOpenDecisions))
        addItem(menu, "Setup…", #selector(menuOpenSetup))
        menu.addItem(.separator())
        let gate = addItem(menu, "Ask Before Claude Code Acts", #selector(toggleGate))
        gate.state = gateInstalled ? .on : .off
        let login = addItem(menu, "Open at Login", #selector(toggleLogin))
        login.state = loginEnabled ? .on : .off
        addItem(menu, "Quit", #selector(NSApplication.terminate(_:)), "q").target = NSApp
    }

    @discardableResult
    func addItem(_ menu: NSMenu, _ title: String, _ action: Selector, _ key: String = "") -> NSMenuItem {
        let i = NSMenuItem(title: title, action: action, keyEquivalent: key)
        i.target = self
        menu.addItem(i)
        return i
    }
    func truncate(_ s: String, _ n: Int) -> String { s.count > n ? String(s.prefix(n - 1)) + "…" : s }

    @objc func menuOpenFinding(_ sender: NSMenuItem) { if let id = sender.representedObject as? String { openFinding(id) } }
    @objc func menuOpenNew() { openView("new") }
    @objc func menuOpenDecisions() { openView("decisions") }
    @objc func menuOpenSetup() { showWindow(); runJS("window.openSetup && window.openSetup()") }
    @objc func ackAll() {
        api("ack", method: "POST", body: [:]) { [weak self] _ in self?.checkForChanges() }
    }

    // MARK: open at login (a per-user LaunchAgent that starts the app in the background)
    var launchAgentURL: URL {
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/LaunchAgents/\(LAUNCH_AGENT_ID).plist")
    }
    var loginEnabled: Bool { FileManager.default.fileExists(atPath: launchAgentURL.path) }

    @objc func toggleLogin() {
        if loginEnabled {
            try? FileManager.default.removeItem(at: launchAgentURL)
            return
        }
        let plist: [String: Any] = [
            "Label": LAUNCH_AGENT_ID,
            "ProgramArguments": ["/usr/bin/open", "-g", "-j", Bundle.main.bundlePath, "--args", "--background"],
            "RunAtLoad": true,
        ]
        do {
            try FileManager.default.createDirectory(at: launchAgentURL.deletingLastPathComponent(), withIntermediateDirectories: true)
            let data = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
            try data.write(to: launchAgentURL)
        } catch {
            let a = NSAlert(); a.messageText = "Couldn't turn on Open at Login"; a.informativeText = error.localizedDescription; a.runModal()
        }
    }

    // MARK: web view plumbing
    // Open links (account pages, System Settings) outside the app window
    func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        if let url = action.request.url, let scheme = url.scheme,
           scheme != "about", !(scheme == "http" && url.host == "127.0.0.1") {
            NSWorkspace.shared.open(url)
            decisionHandler(.cancel); return
        }
        decisionHandler(.allow)
    }
    func webView(_ webView: WKWebView, createWebViewWith c: WKWebViewConfiguration,
                 for action: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
        if let url = action.request.url { NSWorkspace.shared.open(url) }
        return nil
    }
    func webView(_ webView: WKWebView, runJavaScriptAlertPanelWithMessage message: String,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping () -> Void) {
        let a = NSAlert(); a.messageText = message; a.runModal(); completionHandler()
    }
    func webView(_ webView: WKWebView, runJavaScriptConfirmPanelWithMessage message: String,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping (Bool) -> Void) {
        let a = NSAlert()
        let parts = message.components(separatedBy: "\n\n")
        a.messageText = parts.first ?? message
        a.informativeText = parts.dropFirst().joined(separator: "\n\n")
        a.alertStyle = .warning
        a.addButton(withTitle: "Confirm")
        a.addButton(withTitle: "Cancel")
        completionHandler(a.runModal() == .alertFirstButtonReturn)
    }

    // MARK: bridge for the welcome / setup screen
    func userContentController(_ uc: WKUserContentController, didReceive message: WKScriptMessage) {
        guard message.frameInfo.isMainFrame, webView.url?.host == "127.0.0.1",
              let body = message.body as? [String: Any], let cmd = body["cmd"] as? String else { return }
        switch cmd {
        case "setLogin":
            if (body["on"] as? Bool ?? false) != loginEnabled { toggleLogin() }
        case "setTheme":
            let t = body["theme"] as? String ?? "system"
            NSApp.appearance = t == "dark" ? NSAppearance(named: .darkAqua) : t == "light" ? NSAppearance(named: .aqua) : nil
            return
        case "revealApp":
            NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: Bundle.main.bundlePath)])
        case "relaunch":
            let path = Bundle.main.bundlePath
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/bin/sh")
            p.arguments = ["-c", "sleep 1.5; /usr/bin/open \"$0\"", path]
            try? p.run()
            NSApp.terminate(nil)
            return
        default: break
        }
        sendNativeState()
    }
    func sendNativeState() {
        let inApps = Bundle.main.bundlePath.hasPrefix("/Applications/")
        runJS("window.nativeState && window.nativeState({native: true, login: \(loginEnabled), inApplications: \(inApps)})")
    }

    @objc func reload() { webView.reload() }

    func buildMenu() {
        let main = NSMenu()
        let appItem = NSMenuItem(); main.addItem(appItem)
        let appMenu = NSMenu()
        appMenu.addItem(withTitle: "About AI Access Auditor", action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)), keyEquivalent: "")
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "Hide", action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        appMenu.addItem(withTitle: "Quit AI Access Auditor", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        appItem.submenu = appMenu

        let editItem = NSMenuItem(); main.addItem(editItem)
        let edit = NSMenu(title: "Edit")
        edit.addItem(withTitle: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        edit.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        edit.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        edit.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        editItem.submenu = edit

        let viewItem = NSMenuItem(); main.addItem(viewItem)
        let view = NSMenu(title: "View")
        view.addItem(withTitle: "Reload", action: #selector(reload), keyEquivalent: "r").target = self
        viewItem.submenu = view

        let winItem = NSMenuItem(); main.addItem(winItem)
        let win = NSMenu(title: "Window")
        win.addItem(withTitle: "Minimize", action: #selector(NSWindow.miniaturize(_:)), keyEquivalent: "m")
        win.addItem(withTitle: "Close", action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")
        winItem.submenu = win
        NSApp.mainMenu = main
    }

    func applicationWillTerminate(_ note: Notification) {
        let s = server; server = nil
        s?.terminate()
    }
}

// Thin invisible strip along the top edge so the window can still be dragged by its title bar
final class DragStrip: NSView {
    override func mouseDown(with event: NSEvent) {
        if event.clickCount == 2 { window?.performZoom(nil) } else { window?.performDrag(with: event) }
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()
