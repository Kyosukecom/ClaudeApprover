import Foundation

struct ReviewRequest: Codable, Identifiable {
    let id: UUID
    let toolName: String
    let toolInput: [String: AnyCodable]
    let summary: String
    let timestamp: Date
    let riskLevel: String?
    let riskAction: String?
    let riskDescription: String?
    let claudeDescription: String?
    let context: String?

    var isHighRisk: Bool { riskLevel == "high" }
    var isMediumRisk: Bool { riskLevel == "medium" }

    enum CodingKeys: String, CodingKey {
        case toolName = "tool_name"
        case toolInput = "tool_input"
        case summary
        case riskLevel = "risk_level"
        case riskAction = "risk_action"
        case riskDescription = "risk_description"
        case claudeDescription = "claude_description"
        case context
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.id = UUID()
        self.toolName = try container.decode(String.self, forKey: .toolName)
        self.toolInput = try container.decodeIfPresent([String: AnyCodable].self, forKey: .toolInput) ?? [:]
        self.summary = try container.decode(String.self, forKey: .summary)
        self.timestamp = Date()
        self.riskLevel = try container.decodeIfPresent(String.self, forKey: .riskLevel)
        self.riskAction = try container.decodeIfPresent(String.self, forKey: .riskAction)
        self.riskDescription = try container.decodeIfPresent(String.self, forKey: .riskDescription)
        self.claudeDescription = try container.decodeIfPresent(String.self, forKey: .claudeDescription)
        self.context = try container.decodeIfPresent(String.self, forKey: .context)
    }

    init(id: UUID = UUID(), toolName: String, toolInput: [String: AnyCodable], summary: String, timestamp: Date = Date(), riskLevel: String? = nil, riskAction: String? = nil, riskDescription: String? = nil, claudeDescription: String? = nil, context: String? = nil) {
        self.id = id
        self.toolName = toolName
        self.toolInput = toolInput
        self.summary = summary
        self.timestamp = timestamp
        self.riskLevel = riskLevel
        self.riskAction = riskAction
        self.riskDescription = riskDescription
        self.claudeDescription = claudeDescription
        self.context = context
    }
}

struct ReviewResponse: Codable {
    let approved: Bool
}

// Minimal type-erased Codable wrapper
struct AnyCodable: Codable {
    let value: Any

    init(_ value: Any) {
        self.value = value
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let s = try? container.decode(String.self) {
            value = s
        } else if let i = try? container.decode(Int.self) {
            value = i
        } else if let d = try? container.decode(Double.self) {
            value = d
        } else if let b = try? container.decode(Bool.self) {
            value = b
        } else if let arr = try? container.decode([AnyCodable].self) {
            value = arr.map { $0.value }
        } else if let dict = try? container.decode([String: AnyCodable].self) {
            value = dict.mapValues { $0.value }
        } else if container.decodeNil() {
            value = NSNull()
        } else {
            value = ""
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch value {
        case let s as String: try container.encode(s)
        case let i as Int: try container.encode(i)
        case let d as Double: try container.encode(d)
        case let b as Bool: try container.encode(b)
        default: try container.encodeNil()
        }
    }

    var stringValue: String {
        switch value {
        case let s as String: return s
        case let i as Int: return String(i)
        case let d as Double: return String(d)
        case let b as Bool: return b ? "true" : "false"
        default: return String(describing: value)
        }
    }
}

/// A notification item (display-only, no approval needed).
struct NotificationItem: Identifiable {
    let id: UUID
    let request: ReviewRequest
    let receivedAt: Date

    init(request: ReviewRequest) {
        self.id = request.id
        self.request = request
        self.receivedAt = Date()
    }
}
