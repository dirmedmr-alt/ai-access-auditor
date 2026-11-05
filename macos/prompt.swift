// LuLu-style floating Allow / Deny prompt.
import Cocoa

final class PromptPanel: NSPanel {
    struct Content {
        var symbol: String          // SF Symbol for the icon
        var risk: String            // high | medium | low
        var title: String
        var subtitle: String
        var detail: String          // shown in a monospaced box
        var footnote: String = ""
        var options: [String] = []  // scope choices, e.g. "Just this once" / "Always"
        var allowTitle = "Allow"
        var denyTitle = "Deny"
    }

    /// Called once with (allowed, chosen option index). nil allowed = closed without deciding.
    var onDecision: ((Bool?, Int) -> Void)?
    private var decided = false
    private var popup: NSPopUpButton?
    private static var openCount = 0

    init(_ c: Content) {
        super.init(contentRect: NSRect(x: 0, y: 0, width: 460, height: 260),
                   styleMask: [.titled, .closable, .fullSizeContentView, .nonactivatingPanel],
                   backing: .buffered, defer: false)
        titlebarAppearsTransparent = true
        titleVisibility = .hidden
        isMovableByWindowBackground = true
        level = .floating
        hidesOnDeactivate = false
        isReleasedWhenClosed = false
        collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        standardWindowButton(.miniaturizeButton)?.isHidden = true
        standardWindowButton(.zoomButton)?.isHidden = true
        build(c)
    }

    private func riskColor(_ r: String) -> NSColor {
        r == "high" ? .systemRed : r == "medium" ? .systemOrange : .systemGreen
    }

    private func build(_ c: Content) {
        let bg = NSVisualEffectView()
        bg.material = .popover
        bg.state = .active
        bg.blendingMode = .behindWindow

        // icon
        let color = riskColor(c.risk)
        let iconBox = NSView()
        iconBox.wantsLayer = true
        iconBox.layer?.cornerRadius = 11
        iconBox.layer?.backgroundColor = color.withAlphaComponent(0.16).cgColor
        let icon = NSImageView(image: NSImage(systemSymbolName: c.symbol, accessibilityDescription: nil) ?? NSImage())
        icon.symbolConfiguration = .init(pointSize: 21, weight: .semibold)
        icon.contentTintColor = color
        icon.translatesAutoresizingMaskIntoConstraints = false
        iconBox.addSubview(icon)
        iconBox.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            iconBox.widthAnchor.constraint(equalToConstant: 46), iconBox.heightAnchor.constraint(equalToConstant: 46),
            icon.centerXAnchor.constraint(equalTo: iconBox.centerXAnchor), icon.centerYAnchor.constraint(equalTo: iconBox.centerYAnchor),
        ])

        let title = NSTextField(wrappingLabelWithString: c.title)
        title.font = .systemFont(ofSize: 15, weight: .semibold)
        let subtitle = NSTextField(wrappingLabelWithString: c.subtitle)
        subtitle.font = .systemFont(ofSize: 12)
        subtitle.textColor = .secondaryLabelColor
        let pill = NSTextField(labelWithString: c.risk == "high" ? " HIGH RISK " : c.risk == "medium" ? " MEDIUM RISK " : " LOW RISK ")
        pill.font = .systemFont(ofSize: 10, weight: .bold)
        pill.textColor = color
        pill.wantsLayer = true
        pill.layer?.cornerRadius = 4
        pill.layer?.backgroundColor = color.withAlphaComponent(0.14).cgColor
        let titles = NSStackView(views: [title, subtitle, pill])
        titles.orientation = .vertical
        titles.alignment = .leading
        titles.spacing = 3
        let header = NSStackView(views: [iconBox, titles])
        header.alignment = .top
        header.spacing = 14

        // detail box
        let detail = NSTextField(wrappingLabelWithString: c.detail.isEmpty ? "—" : c.detail)
        detail.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        detail.isSelectable = true
        detail.maximumNumberOfLines = 8
        detail.lineBreakMode = .byWordWrapping
        let box = NSView()
        box.wantsLayer = true
        box.layer?.cornerRadius = 8
        box.layer?.backgroundColor = NSColor.labelColor.withAlphaComponent(0.06).cgColor
        detail.translatesAutoresizingMaskIntoConstraints = false
        box.addSubview(detail)
        NSLayoutConstraint.activate([
            detail.leadingAnchor.constraint(equalTo: box.leadingAnchor, constant: 10),
            detail.trailingAnchor.constraint(equalTo: box.trailingAnchor, constant: -10),
            detail.topAnchor.constraint(equalTo: box.topAnchor, constant: 8),
            detail.bottomAnchor.constraint(equalTo: box.bottomAnchor, constant: -8),
        ])

        var rows: [NSView] = [header, box]
        if !c.footnote.isEmpty {
            let foot = NSTextField(wrappingLabelWithString: c.footnote)
            foot.font = .systemFont(ofSize: 11)
            foot.textColor = .secondaryLabelColor
            rows.append(foot)
        }

        // buttons
        let deny = NSButton(title: c.denyTitle, target: self, action: #selector(denyClicked))
        deny.bezelStyle = .rounded
        deny.controlSize = .large
        deny.hasDestructiveAction = c.denyTitle != "Deny" && c.denyTitle != "Review" // Remove / Stop it
        let allow = NSButton(title: c.allowTitle, target: self, action: #selector(allowClicked))
        allow.bezelStyle = .rounded
        allow.controlSize = .large
        // Return picks the safe choice for high-risk requests, so a reflexive Enter can't approve them
        let primary = c.risk == "high" && c.denyTitle == "Deny" ? deny : allow
        let other = primary === deny ? allow : deny
        primary.keyEquivalent = "\r"
        primary.bezelColor = primary === deny ? .systemRed : .controlAccentColor
        other.keyEquivalent = primary === deny ? "" : "\u{1b}"
        var buttonRow: [NSView] = []
        if !c.options.isEmpty {
            let p = NSPopUpButton(frame: .zero, pullsDown: false)
            p.addItems(withTitles: c.options)
            p.controlSize = .large
            popup = p
            buttonRow.append(p)
        }
        let spacer = NSView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        buttonRow += [spacer, deny, allow]
        let buttons = NSStackView(views: buttonRow)
        buttons.spacing = 8
        rows.append(buttons)

        let stack = NSStackView(views: rows)
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 14
        stack.edgeInsets = NSEdgeInsets(top: 30, left: 20, bottom: 18, right: 20)
        stack.translatesAutoresizingMaskIntoConstraints = false
        bg.addSubview(stack)
        for v in [box, buttons] { v.widthAnchor.constraint(equalTo: stack.widthAnchor, constant: -40).isActive = true }
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: bg.leadingAnchor), stack.trailingAnchor.constraint(equalTo: bg.trailingAnchor),
            stack.topAnchor.constraint(equalTo: bg.topAnchor), stack.bottomAnchor.constraint(equalTo: bg.bottomAnchor),
            bg.widthAnchor.constraint(equalToConstant: 460),
        ])
        contentView = bg
    }

    func present() {
        layoutIfNeeded()
        setContentSize(contentView!.fittingSize)
        if let screen = NSScreen.main {
            let f = screen.visibleFrame
            let offset = CGFloat(PromptPanel.openCount % 5) * 26
            setFrameTopLeftPoint(NSPoint(x: f.midX - frame.width / 2 + offset, y: f.maxY - 80 - offset))
        }
        PromptPanel.openCount += 1
        orderFrontRegardless()
        makeKey()
        NSSound(named: "Funk")?.play()
    }

    override var canBecomeKey: Bool { true }

    @objc private func allowClicked() { finish(true) }
    @objc private func denyClicked() { finish(false) }

    private func finish(_ allowed: Bool?) {
        guard !decided else { return }
        decided = true
        onDecision?(allowed, popup?.indexOfSelectedItem ?? 0)
        PromptPanel.openCount = max(0, PromptPanel.openCount - 1)
        orderOut(nil)
    }
    /// Close because the request went away (e.g. Claude Code stopped waiting)
    func dismiss() {
        decided = true
        PromptPanel.openCount = max(0, PromptPanel.openCount - 1)
        orderOut(nil)
    }
    override func close() {
        if !decided { finish(nil) } else { super.close() }
    }
}
