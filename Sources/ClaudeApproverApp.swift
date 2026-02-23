import SwiftUI

@main
struct ClaudeApproverApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate

    var body: some Scene {
        MenuBarExtra {
            ReviewPopoverView(manager: appDelegate.manager)
        } label: {
            Label {
                Text("ClaudeApprover")
            } icon: {
                if appDelegate.manager.hasHighRisk {
                    Image(systemName: "exclamationmark.shield.fill")
                        .symbolRenderingMode(.palette)
                        .foregroundStyle(.white, .red)
                } else if appDelegate.manager.hasNotifications {
                    Image(systemName: "exclamationmark.shield.fill")
                        .symbolRenderingMode(.palette)
                        .foregroundStyle(.white, .orange)
                } else {
                    Image(systemName: "shield.checkmark")
                        .symbolRenderingMode(.palette)
                        .foregroundStyle(.green)
                }
            }
        }
        .menuBarExtraStyle(.window)
        .defaultSize(width: 400, height: 300)
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    let manager = ReviewManager()
    private var server: ReviewServer?
    private var floatingPanel: NSPanel?
    private var observation: NSKeyValueObservation?

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Hide from Dock (LSUIElement equivalent)
        NSApp.setActivationPolicy(.accessory)

        let s = ReviewServer(manager: manager)
        s.start()
        server = s

        // Observe shouldShowPopover to auto-show floating panel
        setupAutoPopover()
    }

    private func setupAutoPopover() {
        // Use withObservationTracking loop to watch for changes
        Task { @MainActor in
            self.startObserving()
        }
    }

    @MainActor
    private func startObserving() {
        withObservationTracking {
            _ = manager.shouldShowPopover
        } onChange: {
            Task { @MainActor in
                if self.manager.shouldShowPopover {
                    self.showFloatingPanel()
                } else {
                    self.hideFloatingPanel()
                }
                // Re-register observation
                self.startObserving()
            }
        }
    }

    @MainActor
    private func showFloatingPanel() {
        if let panel = floatingPanel {
            panel.orderFront(nil)
            return
        }

        let panel = NSPanel(
            contentRect: NSRect(x: 0, y: 0, width: 400, height: 1),
            styleMask: [.titled, .closable, .nonactivatingPanel, .utilityWindow],
            backing: .buffered,
            defer: false
        )
        panel.title = "Claude Code アクション通知"
        panel.isFloatingPanel = true
        panel.level = .floating
        panel.hidesOnDeactivate = false
        panel.isReleasedWhenClosed = false
        panel.animationBehavior = .utilityWindow

        let hostView = NSHostingView(rootView: ReviewPopoverView(manager: manager))
        panel.contentView = hostView

        // Position near top-right of screen (near menu bar)
        if let screen = NSScreen.main {
            let screenFrame = screen.visibleFrame
            let panelWidth: CGFloat = 400
            let x = screenFrame.maxX - panelWidth - 16
            let y = screenFrame.maxY - 16
            panel.setFrameTopLeftPoint(NSPoint(x: x, y: y))
        }

        panel.orderFront(nil)
        self.floatingPanel = panel
    }

    @MainActor
    private func hideFloatingPanel() {
        floatingPanel?.orderOut(nil)
    }
}
