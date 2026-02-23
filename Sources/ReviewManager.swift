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

    /// Auto-dismiss interval (seconds). High risk stays longer.
    private let dismissDelay: TimeInterval = 15

    @MainActor
    func addNotification(request: ReviewRequest) {
        // Replace — always show only the latest one
        notifications = [NotificationItem(request: request)]
        shouldShowPopover = true

        // Schedule auto-dismiss
        let itemId = notifications[0].id
        let delay = request.isHighRisk ? dismissDelay * 2 : dismissDelay
        Task {
            try? await Task.sleep(for: .seconds(delay))
            await MainActor.run {
                self.dismiss(id: itemId)
            }
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
