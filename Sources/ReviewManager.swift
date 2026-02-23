import Foundation
import SwiftUI

@Observable
final class ReviewManager {
    var notifications: [NotificationItem] = []
    /// Set to true to programmatically open the popover
    var shouldShowPopover = false

    var notificationCount: Int { notifications.count }
    var hasNotifications: Bool { !notifications.isEmpty }
    var hasHighRisk: Bool { notifications.contains { $0.request.isHighRisk } }
    var hasMediumRisk: Bool { notifications.contains { $0.request.isMediumRisk } }

    @MainActor
    func addNotification(request: ReviewRequest) {
        // Replace — always show only the latest one
        notifications = [NotificationItem(request: request)]
        shouldShowPopover = true
        // No auto-dismiss timer — panel stays until PostToolUse dismisses it
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
