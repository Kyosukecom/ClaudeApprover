import Foundation
import SwiftUI

@Observable
final class ReviewManager {
    var notifications: [NotificationItem] = []
    var shouldShowPopover = false

    /// Pending items waiting to see if they get auto-dismissed quickly
    private var pendingItems: [String: (NotificationItem, Task<Void, Never>)] = [:]

    /// Delay before showing non-high-risk notifications (seconds).
    /// If PostToolUse dismisses within this time, notification is never shown.
    private let displayDelay: TimeInterval = 2

    var notificationCount: Int { notifications.count }
    var hasNotifications: Bool { !notifications.isEmpty }
    var hasHighRisk: Bool { notifications.contains { $0.request.isHighRisk } }
    var hasMediumRisk: Bool { notifications.contains { $0.request.isMediumRisk } }

    @MainActor
    func addNotification(request: ReviewRequest) {
        let item = NotificationItem(request: request)
        let toolUseId = request.toolUseId ?? item.id.uuidString

        if request.isHighRisk {
            // High risk: show immediately
            notifications.append(item)
            shouldShowPopover = true
        } else if request.isDone {
            // Done: show immediately, auto-dismiss after 10s
            notifications.append(item)
            shouldShowPopover = true
            let itemId = item.id
            Task {
                try? await Task.sleep(for: .seconds(10))
                await MainActor.run { self.dismiss(id: itemId) }
            }
        } else {
            // Medium/Low: delay — if PostToolUse comes within 2s, skip entirely
            let task = Task {
                try? await Task.sleep(for: .seconds(displayDelay))
                await MainActor.run {
                    // Still pending? User hasn't approved yet → show it
                    if self.pendingItems.removeValue(forKey: toolUseId) != nil {
                        self.notifications.append(item)
                        self.shouldShowPopover = true
                    }
                }
            }
            pendingItems[toolUseId] = (item, task)
        }
    }

    /// Dismiss by tool_use_id (from PostToolUse hook)
    @MainActor
    func dismiss(toolUseId: String) {
        // Cancel pending (auto-executed, never shown)
        if let (_, task) = pendingItems.removeValue(forKey: toolUseId) {
            task.cancel()
        }
        // Remove from visible notifications
        notifications.removeAll { $0.request.toolUseId == toolUseId }
        if notifications.isEmpty && pendingItems.isEmpty {
            shouldShowPopover = false
        }
    }

    @MainActor
    func dismiss(id: UUID) {
        notifications.removeAll { $0.id == id }
        if notifications.isEmpty && pendingItems.isEmpty {
            shouldShowPopover = false
        }
    }

    @MainActor
    func dismissAll() {
        // Cancel all pending
        for (_, (_, task)) in pendingItems { task.cancel() }
        pendingItems.removeAll()
        notifications.removeAll()
        shouldShowPopover = false
    }
}
