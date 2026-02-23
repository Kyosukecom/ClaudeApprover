import Foundation
import SwiftUI

@Observable
final class ReviewManager {
    var notifications: [NotificationItem] = []
    var shouldShowPopover = false

    var notificationCount: Int { notifications.count }
    var hasNotifications: Bool { !notifications.isEmpty }
    var hasHighRisk: Bool { notifications.contains { $0.request.isHighRisk } }
    var hasMediumRisk: Bool { notifications.contains { $0.request.isMediumRisk } }

    @MainActor
    func addNotification(request: ReviewRequest) {
        let item = NotificationItem(request: request)
        notifications.append(item)
        shouldShowPopover = true
    }

    /// Dismiss by tool_use_id (from PostToolUse hook)
    @MainActor
    func dismiss(toolUseId: String) {
        notifications.removeAll { $0.request.toolUseId == toolUseId }
        if notifications.isEmpty {
            shouldShowPopover = false
        }
    }

    @MainActor
    func dismiss(id: UUID) {
        notifications.removeAll { $0.id == id }
        if notifications.isEmpty {
            shouldShowPopover = false
        }
    }

    @MainActor
    func dismissAll() {
        notifications.removeAll()
        shouldShowPopover = false
    }
}
