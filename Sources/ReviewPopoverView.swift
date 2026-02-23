import SwiftUI

struct ReviewPopoverView: View {
    let manager: ReviewManager

    private var sortedNotifications: [NotificationItem] {
        manager.notifications.sorted { a, b in
            if a.request.isHighRisk != b.request.isHighRisk { return a.request.isHighRisk }
            return a.receivedAt > b.receivedAt
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            if manager.hasNotifications {
                // Header
                HStack {
                    Text("承認待ち")
                        .font(.headline)
                    Text("(\(manager.notificationCount))")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                    Spacer()
                    Button {
                        manager.dismissAll()
                    } label: {
                        Text("全て閉じる")
                            .font(.caption)
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(.secondary)
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 8)

                Divider()

                // Notification list
                ForEach(sortedNotifications) { item in
                    CompactNotificationView(item: item, manager: manager)
                    Divider()
                }
            } else {
                VStack(spacing: 6) {
                    Image(systemName: "checkmark.shield")
                        .font(.system(size: 28))
                        .foregroundStyle(.green)
                    Text("通知はありません")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity)
                .padding(24)
            }
        }
        .frame(width: 440)
    }
}

// MARK: - Compact notification card (fits 3+ on screen)

struct CompactNotificationView: View {
    let item: NotificationItem
    let manager: ReviewManager

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            // Row 1: icon + action + session tag + risk badge
            HStack(spacing: 8) {
                // Risk colored icon
                Image(systemName: iconName)
                    .font(.system(size: 14))
                    .foregroundStyle(riskColor)
                    .frame(width: 20)

                // Action name
                Text(item.request.riskAction ?? item.request.summary)
                    .font(.system(.callout, weight: .semibold))
                    .lineLimit(1)

                // Session tag
                if let sid = item.request.sessionId, !sid.isEmpty {
                    Text(String(sid.suffix(from: sid.index(sid.startIndex, offsetBy: min(5, sid.count))).prefix(6)))
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .padding(.horizontal, 4)
                        .padding(.vertical, 1)
                        .background(.secondary.opacity(0.1))
                        .clipShape(RoundedRectangle(cornerRadius: 3))
                }

                Spacer()

                riskBadge
            }

            // Row 2: risk description (1 line)
            if let desc = item.request.riskDescription, !desc.isEmpty {
                Text(desc)
                    .font(.caption)
                    .foregroundStyle(riskColor)
                    .lineLimit(2)
            }

            // Row 3: context (what exactly — commits, files, target)
            if let ctx = item.request.context, !ctx.isEmpty {
                Text(ctx)
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(.primary.opacity(0.7))
                    .lineLimit(4)
                    .padding(6)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(.secondary.opacity(0.05))
                    .clipShape(RoundedRectangle(cornerRadius: 4))
            }

            // Row 4: command + dismiss
            HStack(spacing: 8) {
                Text(toolDetail)
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(.tertiary)
                    .lineLimit(1)
                    .truncationMode(.middle)

                Spacer()

                Button("確認OK") {
                    manager.dismiss(id: item.id)
                }
                .buttonStyle(.borderedProminent)
                .tint(item.request.isDone ? .blue : (item.request.isHighRisk ? .red : (isLowRisk ? .green : .accentColor)))
                .controlSize(.mini)
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
    }

    // MARK: - Helpers

    private var isLowRisk: Bool {
        !item.request.isHighRisk && !item.request.isMediumRisk && !item.request.isDone
    }

    @ViewBuilder
    private var riskBadge: some View {
        if item.request.isDone {
            Text("完了")
                .font(.caption2.weight(.bold))
                .foregroundStyle(.white)
                .padding(.horizontal, 6)
                .padding(.vertical, 2)
                .background(Capsule().fill(.blue))
        } else if item.request.isHighRisk {
            Text("高")
                .font(.caption2.weight(.bold))
                .foregroundStyle(.white)
                .padding(.horizontal, 6)
                .padding(.vertical, 2)
                .background(Capsule().fill(.red))
        } else if item.request.isMediumRisk {
            Text("中")
                .font(.caption2.weight(.bold))
                .foregroundStyle(.white)
                .padding(.horizontal, 6)
                .padding(.vertical, 2)
                .background(Capsule().fill(.orange))
        } else {
            Text("安全")
                .font(.caption2.weight(.bold))
                .foregroundStyle(.white)
                .padding(.horizontal, 6)
                .padding(.vertical, 2)
                .background(Capsule().fill(.green))
        }
    }

    private var riskColor: Color {
        if item.request.isDone { return .blue }
        if item.request.isHighRisk { return .red }
        if item.request.isMediumRisk { return .orange }
        return .green
    }

    private var iconName: String {
        if item.request.isDone { return "checkmark.circle.fill" }
        switch item.request.toolName {
        case "Bash": return "terminal"
        case "Write": return "doc.badge.plus"
        case "Edit": return "pencil.line"
        default: return "questionmark.circle"
        }
    }

    private var toolDetail: String {
        switch item.request.toolName {
        case "Bash":
            return "$ \(item.request.toolInput["command"]?.stringValue ?? "?")"
        case "Write":
            return "→ \(item.request.toolInput["file_path"]?.stringValue ?? "?")"
        case "Edit":
            return "→ \(item.request.toolInput["file_path"]?.stringValue ?? "?")"
        default:
            return item.request.toolName
        }
    }
}
