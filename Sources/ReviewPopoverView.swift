import SwiftUI

struct ReviewPopoverView: View {
    let manager: ReviewManager

    private var sortedNotifications: [NotificationItem] {
        manager.notifications.sorted { a, b in
            // High risk first, then by time (newest first)
            if a.request.isHighRisk != b.request.isHighRisk { return a.request.isHighRisk }
            return a.receivedAt > b.receivedAt
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            if manager.hasNotifications {
                // Header with count
                HStack {
                    Text("承認待ち")
                        .font(.headline)
                    Text("(\(manager.notificationCount))")
                        .font(.headline)
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
                .padding(.horizontal, 16)
                .padding(.vertical, 10)

                Divider()

                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(sortedNotifications) { item in
                            NotificationItemView(item: item, manager: manager)
                            Divider()
                        }
                    }
                }
                .frame(maxHeight: 500)
            } else {
                VStack(spacing: 8) {
                    Image(systemName: "checkmark.shield")
                        .font(.system(size: 32))
                        .foregroundStyle(.green)
                    Text("通知はありません")
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity)
                .padding(32)
            }
        }
        .frame(width: 420)
    }
}

struct NotificationItemView: View {
    let item: NotificationItem
    let manager: ReviewManager

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            // Header: risk icon + action name + badge
            HStack(spacing: 10) {
                riskIcon
                VStack(alignment: .leading, spacing: 2) {
                    Text(item.request.riskAction ?? item.request.summary)
                        .font(.system(.body, weight: .semibold))
                        .lineLimit(2)
                    Text(item.request.summary)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                Spacer()
                riskBadge
            }

            // Claude's intent — what it's trying to do and why
            if let claudeDesc = item.request.claudeDescription, !claudeDesc.isEmpty {
                HStack(alignment: .top, spacing: 6) {
                    Image(systemName: "brain")
                        .font(.caption)
                        .foregroundStyle(.purple)
                        .frame(width: 14)
                    Text(claudeDesc)
                        .font(.callout)
                        .foregroundStyle(.primary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(.purple.opacity(0.06))
                .clipShape(RoundedRectangle(cornerRadius: 8))
            }

            // Risk explanation
            if let desc = item.request.riskDescription, !desc.isEmpty {
                HStack(alignment: .top, spacing: 6) {
                    Image(systemName: riskExplainIcon)
                        .font(.caption)
                        .foregroundStyle(riskColor)
                        .frame(width: 14)
                    Text(desc)
                        .font(.callout)
                        .foregroundStyle(riskColor)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(riskBgColor)
                .clipShape(RoundedRectangle(cornerRadius: 8))
            }

            // Context: what exactly will be affected (commits, files, etc.)
            if let ctx = item.request.context, !ctx.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 4) {
                        Image(systemName: "doc.text.magnifyingglass")
                            .font(.caption2)
                        Text("対象の詳細")
                            .font(.caption2.weight(.semibold))
                    }
                    .foregroundStyle(.secondary)

                    Text(ctx)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.primary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(.secondary.opacity(0.06))
                .clipShape(RoundedRectangle(cornerRadius: 8))
            }

            // Session ID + command + dismiss button
            HStack {
                if let sid = item.request.sessionId, !sid.isEmpty {
                    Text("Session: \(String(sid.prefix(8)))")
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.tertiary)
                }

                Spacer()

                Button {
                    manager.dismiss(id: item.id)
                } label: {
                    Text("確認OK")
                        .font(.caption)
                }
                .buttonStyle(.borderedProminent)
                .tint(item.request.isHighRisk ? .red : .accentColor)
                .controlSize(.small)
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    // MARK: - Risk visuals

    @ViewBuilder
    private var riskIcon: some View {
        ZStack {
            Circle()
                .fill(riskColor.opacity(0.15))
                .frame(width: 36, height: 36)
            Image(systemName: iconName)
                .font(.system(size: 16))
                .foregroundStyle(riskColor)
        }
    }

    @ViewBuilder
    private var riskBadge: some View {
        if item.request.isHighRisk {
            Text("高リスク")
                .font(.caption2.weight(.bold))
                .foregroundStyle(.white)
                .padding(.horizontal, 8)
                .padding(.vertical, 3)
                .background(Capsule().fill(.red))
        } else if item.request.isMediumRisk {
            Text("中リスク")
                .font(.caption2.weight(.bold))
                .foregroundStyle(.white)
                .padding(.horizontal, 8)
                .padding(.vertical, 3)
                .background(Capsule().fill(.orange))
        }
    }

    private var riskColor: Color {
        if item.request.isHighRisk { return .red }
        if item.request.isMediumRisk { return .orange }
        return .secondary
    }

    private var riskBgColor: Color {
        if item.request.isHighRisk { return .red.opacity(0.08) }
        if item.request.isMediumRisk { return .orange.opacity(0.08) }
        return .secondary.opacity(0.05)
    }

    private var riskExplainIcon: String {
        if item.request.isHighRisk { return "exclamationmark.triangle.fill" }
        return "info.circle.fill"
    }

    private var iconName: String {
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
            return "Write → \(item.request.toolInput["file_path"]?.stringValue ?? "?")"
        case "Edit":
            return "Edit → \(item.request.toolInput["file_path"]?.stringValue ?? "?")"
        default:
            return item.request.toolName
        }
    }
}
